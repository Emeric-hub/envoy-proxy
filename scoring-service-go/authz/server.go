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
	"scoring-service-go/honeypot"
	"scoring-service-go/scoring"
)

// honeypotRuleID is a fixed, synthetic pseudo-rule-id for honeypot hits —
// deliberately outside any real CRS range (CRS itself uses
// 900000-999999/9000000+; this repo's own local ranges top out well
// under 100000 — see coraza-service/crs-exclusions/crs_exclusion.conf) so
// it reads unambiguously as "not a real CRS rule" to anyone reviewing
// CrowdSec logs.
const honeypotRuleID = 500001

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

	// Checked before anything else, and skips Coraza/CrowdSec entirely:
	// a honeypot hit carries no ambiguity to resolve, so there's nothing
	// for the rest of the pipeline to usefully contribute.
	if honeypot.Enabled {
		if matched, pattern := honeypot.IsMatch(path); matched {
			return handleHoneypotHit(ctx, domain, path, pattern, clientIP, userAgent, method)
		}
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

// handleHoneypotHit: a bait path that no legitimate traffic should ever
// request — treated as a certain, maximal-confidence signal, not scored
// against a threshold like everything else. Feeds the exact same
// CRITICAL-match-bans-immediately CrowdSec pipeline a real CRS CRITICAL
// match uses (LogModsecMatches), so a hit here bans the IP outright the
// same way a confirmed attack does — no new CrowdSec scenario needed.
func handleHoneypotHit(ctx context.Context, domain, path, pattern, clientIP, userAgent, method string) (*authv3.CheckResponse, error) {
	reason := "Honeypot path accessed: " + pattern
	fakeRule := scoring.MatchedRule{
		ID:           honeypotRuleID,
		Message:      reason,
		Severity:     "critical",
		SeverityCode: 2,
		Tags:         []string{"honeypot"},
	}
	crowdsec.LogModsecMatches(clientIP, domain, path, []scoring.MatchedRule{fakeRule})

	blocked := !scoring.AuditMode
	httpStatus := 200
	if blocked {
		httpStatus = 404
	}
	events.PublishDecision(ctx, events.DecisionEvent{
		Method:     method,
		Path:       path,
		UserAgent:  userAgent,
		IP:         clientIP,
		Domain:     domain,
		Score:      1.0,
		Decision:   "deny",
		HTTPStatus: httpStatus,
		AuditMode:  scoring.AuditMode,
		Signals:    map[string]float64{"honeypot": 1.0},
		Reasons:    []string{reason},
	})

	if blocked {
		return honeypotResponse(), nil
	}
	// audit mode: would have blocked, but didn't
	return auditWouldBlockResponse(1.0), nil
}
