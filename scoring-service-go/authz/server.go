// Package authz implements the ext_authz gRPC AuthorizationServer — the
// gRPC-mode equivalent of the original scoring-service's main.py check()
// handler.
package authz

import (
	"context"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"scoring-service-go/coraza"
	"scoring-service-go/crowdsec"
	"scoring-service-go/events"
	"scoring-service-go/geoip"
	"scoring-service-go/scoring"
)

type Server struct {
	authv3.UnimplementedAuthorizationServer
}

func (s *Server) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	started := time.Now()

	httpReq := req.GetAttributes().GetRequest().GetHttp()
	allHeaders := httpReq.GetHeaders() // already lower-cased per the ext_authz proto contract
	headers := filterHeaders(allHeaders)

	path, query := splitPathQuery(httpReq.GetPath())
	body := []byte(httpReq.GetBody())
	method := httpReq.GetMethod()

	// Host field, not a headers-map lookup: Envoy resolves this correctly
	// from either the Host header (HTTP/1.1) or :authority (HTTP/2, HTTP/3)
	// regardless of which one the downstream connection actually carried —
	// more robust than digging through the headers map for either name.
	domain := httpReq.GetHost()
	if domain == "" {
		domain = "unknown"
	}
	// Synthesize "host" into the filtered map regardless of what the raw
	// wire header was actually called (host vs :authority) — coraza-service
	// (and CRS rules that key on REQUEST_HEADERS:Host, including every
	// crs-tuner domain-scoped exclusion) needs it reliably present. Found
	// via live testing: filtering strictly to the old HTTP-mode allow-list
	// (which only had ":authority") silently dropped a literal "host"
	// header from HTTP/1.1 requests, and CRS correctly flagged the
	// request as missing one.
	if domain != "unknown" {
		headers["host"] = domain
	}

	clientIP := extractClientIP(headers)
	userAgent := headers["user-agent"]
	protocol := headers["x-request-protocol"]
	if protocol == "" {
		protocol = "unknown"
	}

	anomalyScore, matchedRules := coraza.GetAnomalyScore(method, path, query, headers, body, clientIP)
	// Decisions reflect *prior* requests from this IP, not this one —
	// CrowdSec needs to see a pattern accumulate before it decides, so
	// query before feeding it this request.
	crowdsecDecisions := crowdsec.GetDecisions(clientIP)

	signals := scoring.NormalizeSignals(anomalyScore, crowdsecDecisions)
	score := scoring.CombineScores(signals)
	decision := "allow"
	if score >= scoring.RiskThreshold {
		decision = "deny"
	}
	// decision is the logical verdict (what the dashboard shows and what
	// feeds stats/charts, so audit mode can be evaluated against real
	// traffic); blocked is whether it was actually enforced.
	blocked := decision == "deny" && !scoring.AuditMode
	httpStatus := 200
	if blocked {
		httpStatus = 403
	}
	reasons := scoring.BuildReasons(signals, matchedRules, crowdsecDecisions)
	// Cosmetic enrichment only (dashboard globe), not a scoring input — see
	// geoip package doc comment. Still a synchronous call like coraza/crowdsec
	// above (same short-timeout, fail-soft shape), so it can add up to
	// GEOIP_TIMEOUT to the response — same accepted trade-off as those,
	// and a no-op (immediate zero-value return) whenever ENABLE_GEOIP is
	// false, the default.
	geo := geoip.Lookup(clientIP)
	durationMS := float64(time.Since(started)) / float64(time.Millisecond)

	crowdsec.LogRequest(clientIP, method, path, httpStatus, userAgent)
	crowdsec.LogModsecMatches(clientIP, domain, path, matchedRules)
	for _, rule := range matchedRules {
		events.PublishCRSMatch(ctx, domain, path, clientIP, rule)
	}

	events.PublishDecision(ctx, events.DecisionEvent{
		Method:            method,
		Path:              path,
		UserAgent:         userAgent,
		Protocol:          protocol,
		IP:                clientIP,
		Domain:            domain,
		Score:             score,
		Decision:          decision,
		HTTPStatus:        httpStatus,
		AuditMode:         scoring.AuditMode,
		Signals:           signals,
		CrowdsecDecisions: crowdsecDecisions,
		Reasons:           reasons,
		DurationMS:        durationMS,
		GeoFound:          geo.Found,
		CountryCode:       geo.CountryCode,
		City:              geo.City,
		Lat:               geo.Lat,
		Lon:               geo.Lon,
	})

	if blocked {
		return denyResponse(score, reasons), nil
	}
	if decision == "deny" {
		// audit mode: would have blocked, but didn't
		return auditWouldBlockResponse(score), nil
	}
	return allowResponse(score), nil
}
