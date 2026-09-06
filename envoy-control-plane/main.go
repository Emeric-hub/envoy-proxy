// envoy-control-plane is a small xDS (ADS) server: it watches routes.csv and
// the ssl/ certificate directory, and pushes a fresh Envoy config snapshot
// (listeners, routes, clusters) to Envoy over gRPC whenever either changes —
// no Envoy restart needed. This is what makes envoy.yaml's dynamic_resources
// possible; a CSV file alone means nothing to Envoy, it only speaks its own
// typed xDS protocol.
package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	streamaccesslogv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/stream/v3"
	extauthzv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	upstreamshttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	tlsinspectorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	quicv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/quic/v3"
	headermutationv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	mutationrulesv3 "github.com/envoyproxy/go-control-plane/envoy/config/common/mutation_rules/v3"
	discoverygrpc "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/fsnotify/fsnotify"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const nodeID = "envoy-node-1"

// Request-handling limits/timeouts, set once in main() from .env (see
// envOr/envOrDuration) and read from every builder function below — package
// level rather than threaded through every function signature since they're
// fixed for the process lifetime, same treatment as nodeID above.
var (
	extAuthzTimeout      time.Duration // how long the ext_authz scoring check itself may take
	extAuthzMaxBodyBytes uint32        // how much of the request body is buffered and handed to scoring-service for inspection
	upstreamConnTimeout  time.Duration // TCP connect timeout to any upstream (scoring-service, default-site, routes.csv targets)
	requestTimeout       time.Duration // overall per-request timeout (RouteAction) — Envoy's own default is 15s if unset
	streamIdleTimeout    time.Duration // how long a stream may go fully silent before Envoy resets it — matters for long-lived SSE responses
	acmeHttp01Port       uint32        // fixed port for Let's Encrypt's HTTP-01 challenge — always 80 in real use, that's the ACME protocol's requirement, not configurable on their end
)

// defaultCatchAllRoute is a synthetic routes.csv row — not read from the
// CSV — backing vh_default's IP-literal-Host branch (see buildRouteConfig).
// Same backend/port/cert-check as every real row: there's only one backend
// in this demo, and this branch exists to get the request scored, not to
// reach a different upstream.
var defaultCatchAllRoute = route{ID: "default", Domain: "*", Target: "backend", Port: 8443, Scoring: true}

type route struct {
	ID          string
	Domain      string
	Target      string
	Port        int
	SSL         bool
	CertCheck   bool
	Scoring     bool
	LetsEncrypt bool
}

func parseBool(s string) bool {
	return strings.EqualFold(strings.TrimSpace(s), "true")
}

// loadRoutes reads routes.csv. A malformed row is skipped with a warning
// rather than taking down the whole config — one typo in one line shouldn't
// break every other domain.
func loadRoutes(path string) ([]route, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}

	var routes []route
	for i, rec := range records[1:] { // skip header
		if len(rec) < 8 {
			log.Printf("routes.csv line %d: expected 8 columns, got %d, skipping", i+2, len(rec))
			continue
		}
		port, err := strconv.Atoi(strings.TrimSpace(rec[3]))
		if err != nil {
			log.Printf("routes.csv line %d: invalid port %q, skipping", i+2, rec[3])
			continue
		}
		routes = append(routes, route{
			ID:          strings.TrimSpace(rec[0]),
			Domain:      strings.TrimSpace(rec[1]),
			Target:      strings.TrimSpace(rec[2]),
			Port:        port,
			SSL:         parseBool(rec[4]),
			CertCheck:   parseBool(rec[5]),
			Scoring:     parseBool(rec[6]),
			LetsEncrypt: parseBool(rec[7]),
		})
	}
	return routes, nil
}

// targetHealth is one target:port's most recent TCP-reachability check — a
// plain connect probe, not an HTTP health check, since each target's actual
// health endpoint (if any) is unknown to this service; "accepts a TCP
// connection" is what "backend availability" means here.
type targetHealth struct {
	Up        bool
	CheckedAt time.Time
	Err       string
}

type backendStatus struct {
	Target    string   `json:"target"`
	Port      int      `json:"port"`
	Up        bool     `json:"up"`
	CheckedAt string   `json:"checked_at,omitempty"`
	Error     string   `json:"error,omitempty"`
	Domains   []string `json:"domains"` // every routes.csv domain fronting this target:port — display only, the probe itself stays deduped per target:port
}

// healthChecker polls every unique target:port on a fixed interval and
// serves the last-known results over HTTP — dashboard polls that endpoint
// rather than probing backends itself (it has no network path to them).
// Keyed by target:port, not by route/domain: several routes.csv rows
// commonly share one backend, and checking (and displaying) the same
// connection once per fronting domain would just be redundant noise.
type healthChecker struct {
	mu      sync.RWMutex
	routes  []route
	results map[string]targetHealth // keyed by "target:port"
	sslDir  string                  // for reading letsencrypt-sidecar's .expiry/.acme-status/.acme-error files
}

func newHealthChecker(sslDir string) *healthChecker {
	return &healthChecker{results: make(map[string]targetHealth), sslDir: sslDir}
}

// letsEncryptStatus mirrors what letsencrypt-sidecar writes next to a
// domain's cert (see that service's certstore package) — read fresh per
// request, same tolerant-of-missing-file treatment as coraza-service's
// VERSION/FETCHED_AT sidecar metadata files elsewhere in this repo.
type letsEncryptStatus struct {
	Enabled   bool   `json:"enabled"`
	Status    string `json:"status"` // "ok" | "failed" | "pending" (no files written yet)
	ExpiresAt string `json:"expires_at,omitempty"`
	LastError string `json:"last_error,omitempty"`
}

func readFileTrim(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func (h *healthChecker) letsEncryptSnapshot() map[string]letsEncryptStatus {
	h.mu.RLock()
	routes := append([]route(nil), h.routes...)
	h.mu.RUnlock()

	out := map[string]letsEncryptStatus{}
	for _, r := range routes {
		if !r.LetsEncrypt {
			continue
		}
		status := readFileTrim(filepath.Join(h.sslDir, r.Domain+".acme-status"))
		if status == "" {
			status = "pending"
		}
		out[r.Domain] = letsEncryptStatus{
			Enabled:   true,
			Status:    status,
			ExpiresAt: readFileTrim(filepath.Join(h.sslDir, r.Domain+".expiry")),
			LastError: readFileTrim(filepath.Join(h.sslDir, r.Domain+".acme-error")),
		}
	}
	return out
}

// setRoutes is called every time routes.csv reloads, so newly added routes
// get probed and removed ones stop being reported.
func (h *healthChecker) setRoutes(routes []route) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.routes = routes
}

func (h *healthChecker) checkOnce() {
	h.mu.RLock()
	routes := append([]route(nil), h.routes...)
	h.mu.RUnlock()

	seen := make(map[string]bool)
	for _, r := range routes {
		addr := net.JoinHostPort(r.Target, strconv.Itoa(r.Port))
		if seen[addr] {
			continue
		}
		seen[addr] = true

		result := targetHealth{CheckedAt: time.Now().UTC()}
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			result.Err = err.Error()
		} else {
			result.Up = true
			conn.Close()
		}
		h.mu.Lock()
		h.results[addr] = result
		h.mu.Unlock()
	}
}

func (h *healthChecker) run(ctx context.Context, interval time.Duration) {
	h.checkOnce()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.checkOnce()
		}
	}
}

func (h *healthChecker) snapshot() []backendStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()
	order := make([]string, 0, len(h.routes))
	domains := make(map[string][]string)
	for _, r := range h.routes {
		addr := net.JoinHostPort(r.Target, strconv.Itoa(r.Port))
		if _, ok := domains[addr]; !ok {
			order = append(order, addr)
		}
		domains[addr] = append(domains[addr], r.Domain)
	}

	out := make([]backendStatus, 0, len(order))
	for _, addr := range order {
		target, portStr, _ := net.SplitHostPort(addr)
		port, _ := strconv.Atoi(portStr)
		res := h.results[addr]
		status := backendStatus{Target: target, Port: port, Up: res.Up, Error: res.Err, Domains: domains[addr]}
		if !res.CheckedAt.IsZero() {
			status.CheckedAt = res.CheckedAt.Format(time.RFC3339)
		}
		out = append(out, status)
	}
	return out
}

func (h *healthChecker) handler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"backends":    h.snapshot(),
		"letsencrypt": h.letsEncryptSnapshot(),
	})
}

func mustAny(msg proto.Message) *anypb.Any {
	a, err := anypb.New(msg)
	if err != nil {
		log.Fatalf("marshaling %T: %v", msg, err)
	}
	return a
}

func exactMatcher(values ...string) *matcherv3.ListStringMatcher {
	patterns := make([]*matcherv3.StringMatcher, len(values))
	for i, v := range values {
		patterns[i] = &matcherv3.StringMatcher{MatchPattern: &matcherv3.StringMatcher_Exact{Exact: v}}
	}
	return &matcherv3.ListStringMatcher{Patterns: patterns}
}

// buildExtAuthzFilter mirrors the ext_authz http_service block that used to
// be hand-written in envoy.yaml — same allowed headers, same fail-closed
// behavior, same scoring-service target.
// gRPC mode (scoring-service is now Go, speaking the ext_authz gRPC
// protocol directly — see scoring-service-go/). Unlike HTTP mode, there's
// no AllowedHeaders/AllowedUpstreamHeaders/PathPrefix here: gRPC mode hands
// the *entire* request (all headers, method, path, body per
// WithRequestBody below) to the authz server via CheckRequest, and the Go
// service is responsible for its own header allow-listing and response
// shaping (see scoring-service-go/authz) — deliberately replicating the
// same 6-header allow-list this filter used to enforce, not silently
// expanding what scoring-service sees.
func buildExtAuthzFilter() *hcmv3.HttpFilter {
	cfg := &extauthzv3.ExtAuthz{
		TransportApiVersion: corev3.ApiVersion_V3,
		FailureModeAllow:    false,
		Services: &extauthzv3.ExtAuthz_GrpcService{
			GrpcService: &corev3.GrpcService{
				TargetSpecifier: &corev3.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &corev3.GrpcService_EnvoyGrpc{ClusterName: "scoring_service"},
				},
				Timeout: durationpb.New(extAuthzTimeout),
			},
		},
		WithRequestBody: &extauthzv3.BufferSettings{
			MaxRequestBytes:     extAuthzMaxBodyBytes,
			AllowPartialMessage: true,
		},
	}
	return &hcmv3.HttpFilter{
		Name:       "envoy.filters.http.ext_authz",
		ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: mustAny(cfg)},
	}
}

// buildProtocolHeaderFilter must run before ext_authz in the filter chain
// (it's listed first in HttpFilters — filters process the request in list
// order): %PROTOCOL% is a command operator (same family used in access log
// formats), evaluated at the point this filter runs, that resolves to the
// actual downstream protocol — HTTP/1.1, HTTP/2, or HTTP/3. This is how
// scoring-service (and from there, the dashboard) learns it; not something
// a client can spoof, since RouteConfiguration-level header mutation runs
// too late (after routing, i.e. after ext_authz has already made its call).
func buildProtocolHeaderFilter() *hcmv3.HttpFilter {
	cfg := &headermutationv3.HeaderMutation{
		Mutations: &headermutationv3.Mutations{
			RequestMutations: []*mutationrulesv3.HeaderMutation{{
				Action: &mutationrulesv3.HeaderMutation_Append{
					Append: headerOpt("x-request-protocol", "%PROTOCOL%"),
				},
			}},
		},
	}
	return &hcmv3.HttpFilter{
		Name:       "envoy.filters.http.header_mutation",
		ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: mustAny(cfg)},
	}
}

func buildRouterFilter() *hcmv3.HttpFilter {
	// SuppressEnvoyHeaders: drop x-envoy-* internals (upstream service time,
	// original path, etc.) from responses — no reason to expose proxy
	// internals to clients outside this demo.
	cfg := &routerv3.Router{SuppressEnvoyHeaders: true}
	return &hcmv3.HttpFilter{
		Name:       wellknown.Router,
		ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: mustAny(cfg)},
	}
}

// buildLocalReplyConfig mirrors the branded 403/5xx error pages, same as the
// old static envoy.yaml — read from disk by Envoy itself at response time,
// so no mount is needed on envoy-control-plane's side for these. Each status
// range has two variants, JSON and HTML; the JSON one only matches when the
// client's Accept header asks for it, so mapper order matters — Envoy uses
// the first matching entry, so the more specific (status + Accept) mappers
// must come before the plain-status HTML fallback for the same range.
func buildLocalReplyConfig() *hcmv3.LocalReplyConfig {
	statusFilter := func(op accesslogv3.ComparisonFilter_Op, value uint32, runtimeKey string) *accesslogv3.AccessLogFilter {
		return &accesslogv3.AccessLogFilter{
			FilterSpecifier: &accesslogv3.AccessLogFilter_StatusCodeFilter{
				StatusCodeFilter: &accesslogv3.StatusCodeFilter{
					Comparison: &accesslogv3.ComparisonFilter{
						Op:    op,
						Value: &corev3.RuntimeUInt32{DefaultValue: value, RuntimeKey: runtimeKey},
					},
				},
			},
		}
	}
	acceptsJSON := &accesslogv3.AccessLogFilter{
		FilterSpecifier: &accesslogv3.AccessLogFilter_HeaderFilter{
			HeaderFilter: &accesslogv3.HeaderFilter{
				Header: &routev3.HeaderMatcher{
					Name: "accept",
					HeaderMatchSpecifier: &routev3.HeaderMatcher_StringMatch{
						StringMatch: &matcherv3.StringMatcher{
							MatchPattern: &matcherv3.StringMatcher_Contains{Contains: "application/json"},
						},
					},
				},
			},
		},
	}
	and := func(filters ...*accesslogv3.AccessLogFilter) *accesslogv3.AccessLogFilter {
		return &accesslogv3.AccessLogFilter{
			FilterSpecifier: &accesslogv3.AccessLogFilter_AndFilter{AndFilter: &accesslogv3.AndFilter{Filters: filters}},
		}
	}
	mapper := func(filter *accesslogv3.AccessLogFilter, file, contentType string) *hcmv3.ResponseMapper {
		return &hcmv3.ResponseMapper{
			Filter: filter,
			Body:   &corev3.DataSource{Specifier: &corev3.DataSource_Filename{Filename: file}},
			HeadersToAdd: []*corev3.HeaderValueOption{
				{Header: &corev3.HeaderValue{Key: "content-type", Value: contentType}},
			},
		}
	}
	return &hcmv3.LocalReplyConfig{
		Mappers: []*hcmv3.ResponseMapper{
			mapper(and(statusFilter(accesslogv3.ComparisonFilter_EQ, 403, "local_reply_403_json"), acceptsJSON),
				"/etc/envoy/error_pages/403.json", "application/json; charset=utf-8"),
			mapper(and(statusFilter(accesslogv3.ComparisonFilter_GE, 500, "local_reply_5xx_json"), acceptsJSON),
				"/etc/envoy/error_pages/5xx.json", "application/json; charset=utf-8"),
			mapper(statusFilter(accesslogv3.ComparisonFilter_EQ, 403, "local_reply_403"),
				"/etc/envoy/error_pages/403.html", "text/html; charset=utf-8"),
			mapper(statusFilter(accesslogv3.ComparisonFilter_GE, 500, "local_reply_5xx"),
				"/etc/envoy/error_pages/5xx.html", "text/html; charset=utf-8"),
		},
	}
}

// headerOpt builds an always-wins response header: OVERWRITE_IF_EXISTS_OR_ADD
// so our hardening value replaces whatever an upstream (nginx, the echo
// backend...) sent, rather than just appending a second copy.
func headerOpt(key, value string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{
		Header:       &corev3.HeaderValue{Key: key, Value: value},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	}
}

// baseSecurityHeaders applies regardless of scheme: MIME sniffing off,
// disallow framing (no legitimate reason to iframe this demo), a
// conservative Referrer-Policy, and a Permissions-Policy that opts out of
// powerful features this proxy has no business granting to any backend.
func baseSecurityHeaders() []*corev3.HeaderValueOption {
	return []*corev3.HeaderValueOption{
		headerOpt("x-content-type-options", "nosniff"),
		headerOpt("x-frame-options", "DENY"),
		headerOpt("referrer-policy", "strict-origin-when-cross-origin"),
		headerOpt("permissions-policy", "camera=(), microphone=(), geolocation=()"),
	}
}

// buildHTTPConnectionManager is shared by both listeners but not identical:
// HSTS only makes sense advertised over a connection that's already TLS —
// sending it over plain HTTP doesn't upgrade anything and just adds noise.
// routeConfigNameHTTP/HTTPS: response security headers (including HSTS,
// HTTPS-only) live on the RouteConfiguration, not the HCM — see
// buildRouteConfig — so each listener's HCM points at its own named
// resource even though the VirtualHosts inside are otherwise identical.
const (
	routeConfigNameHTTP  = "main_routes_http"
	routeConfigNameHTTPS = "main_routes_https"
)

func buildHTTPConnectionManager(routeConfigName string) *hcmv3.HttpConnectionManager {
	return &hcmv3.HttpConnectionManager{
		StatPrefix:       "ingress_http",
		UseRemoteAddress: wrapperspb.Bool(true),
		LocalReplyConfig: buildLocalReplyConfig(),
		// PASS_THROUGH (not the OVERWRITE default): OVERWRITE means Envoy
		// always injects "server: envoy" itself — no version number, but it
		// still names the proxy technology. PASS_THROUGH means Envoy doesn't
		// inject anything of its own, which lets the RouteConfiguration's
		// ResponseHeadersToRemove (see buildRouteConfig) actually strip
		// whatever the upstream sent instead of it coming back right after.
		ServerHeaderTransformation: hcmv3.HttpConnectionManager_PASS_THROUGH,
		StreamIdleTimeout:          durationpb.New(streamIdleTimeout),
		AccessLog: []*accesslogv3.AccessLog{
			{
				Name: "envoy.access_loggers.stdout",
				ConfigType: &accesslogv3.AccessLog_TypedConfig{
					TypedConfig: mustAny(&streamaccesslogv3.StdoutAccessLog{}),
				},
			},
		},
		RouteSpecifier: &hcmv3.HttpConnectionManager_Rds{
			Rds: &hcmv3.Rds{
				RouteConfigName: routeConfigName,
				ConfigSource: &corev3.ConfigSource{
					ResourceApiVersion:   corev3.ApiVersion_V3,
					ConfigSourceSpecifier: &corev3.ConfigSource_Ads{Ads: &corev3.AggregatedConfigSource{}},
				},
			},
		},
		HttpFilters: []*hcmv3.HttpFilter{buildProtocolHeaderFilter(), buildExtAuthzFilter(), buildRouterFilter()},
	}
}

func buildListenerHTTP(port uint32) *listenerv3.Listener {
	hcm := buildHTTPConnectionManager(routeConfigNameHTTP)
	return &listenerv3.Listener{
		Name: "listener_http",
		Address: &corev3.Address{Address: &corev3.Address_SocketAddress{SocketAddress: &corev3.SocketAddress{
			Address:       "0.0.0.0",
			PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: port},
		}}},
		FilterChains: []*listenerv3.FilterChain{{
			Filters: []*listenerv3.Filter{{
				Name:       wellknown.HTTPConnectionManager,
				ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: mustAny(hcm)},
			}},
		}},
	}
}

// buildAcmeChallengeListener serves ONLY Let's Encrypt's HTTP-01 challenge
// path, proxied straight to letsencrypt-sidecar's own tiny HTTP server.
// Deliberately minimal — no ext_authz, no per-domain routing, no
// routes.csv dependency at all in the route itself (a static inline
// RouteConfig, not RDS): this must work identically no matter which
// domain the client's Host header claims, since Let's Encrypt's validator
// doesn't send this demo's usual traffic shape. Built and added to the
// xDS snapshot only when at least one route has LetsEncrypt: true (see
// apply()) — otherwise this listener doesn't exist, so users not using
// the feature see no behavior change and don't need port 80 published.
func buildAcmeChallengeListener(port uint32) *listenerv3.Listener {
	routeConfig := &routev3.RouteConfiguration{
		Name: "acme_challenge_routes",
		VirtualHosts: []*routev3.VirtualHost{{
			Name:    "vh_acme_challenge",
			Domains: []string{"*"},
			Routes: []*routev3.Route{{
				Match: &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"}},
				Action: &routev3.Route_Route{Route: &routev3.RouteAction{
					ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: "acme_challenge"},
					Timeout:          durationpb.New(requestTimeout),
				}},
			}},
		}},
	}
	hcm := &hcmv3.HttpConnectionManager{
		StatPrefix:                 "ingress_acme_challenge",
		UseRemoteAddress:           wrapperspb.Bool(true),
		ServerHeaderTransformation: hcmv3.HttpConnectionManager_PASS_THROUGH,
		AccessLog: []*accesslogv3.AccessLog{{
			Name:       "envoy.access_loggers.stdout",
			ConfigType: &accesslogv3.AccessLog_TypedConfig{TypedConfig: mustAny(&streamaccesslogv3.StdoutAccessLog{})},
		}},
		RouteSpecifier: &hcmv3.HttpConnectionManager_RouteConfig{RouteConfig: routeConfig},
		HttpFilters:    []*hcmv3.HttpFilter{buildRouterFilter()},
	}
	return &listenerv3.Listener{
		Name: "listener_acme_challenge",
		Address: &corev3.Address{Address: &corev3.Address_SocketAddress{SocketAddress: &corev3.SocketAddress{
			Address:       "0.0.0.0",
			PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: port},
		}}},
		FilterChains: []*listenerv3.FilterChain{{
			Filters: []*listenerv3.Filter{{
				Name:       wellknown.HTTPConnectionManager,
				ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: mustAny(hcm)},
			}},
		}},
	}
}

// loadDownstreamTLS reads a domain's cert/key from sslDir and embeds the
// bytes inline (DataSource_InlineBytes) rather than referencing them by
// filename: with a filename reference, replacing a cert's *content* in
// place (same domain, renewed cert) produces a byte-identical Listener
// proto — nothing for LDS to diff — so Envoy never re-reads the file and
// keeps serving the stale cert indefinitely. Inlining the bytes means a
// changed cert changes the proto itself, which is exactly what the existing
// ssl/ fsnotify watcher (see generator.watch) is already triggering a
// rebuild for.
func loadDownstreamTLS(sslDir, domain string) (*tlsv3.DownstreamTlsContext, error) {
	crtBytes, err := os.ReadFile(filepath.Join(sslDir, domain+".crt"))
	if err != nil {
		return nil, err
	}
	keyBytes, err := os.ReadFile(filepath.Join(sslDir, domain+".key"))
	if err != nil {
		return nil, err
	}
	return &tlsv3.DownstreamTlsContext{
		CommonTlsContext: &tlsv3.CommonTlsContext{
			// Explicit floor rather than relying on Envoy's own compiled-in
			// default: TLS 1.0/1.1 are both formally deprecated (RFC 8996)
			// and this pins the demo to 1.2+ regardless of what future
			// Envoy versions default to.
			TlsParams: &tlsv3.TlsParameters{
				TlsMinimumProtocolVersion: tlsv3.TlsParameters_TLSv1_2,
				TlsMaximumProtocolVersion: tlsv3.TlsParameters_TLSv1_3,
			},
			TlsCertificates: []*tlsv3.TlsCertificate{{
				CertificateChain: &corev3.DataSource{Specifier: &corev3.DataSource_InlineBytes{InlineBytes: crtBytes}},
				PrivateKey:       &corev3.DataSource{Specifier: &corev3.DataSource_InlineBytes{InlineBytes: keyBytes}},
			}},
		},
	}, nil
}

// buildListenerHTTPS returns nil (no listener at all) if there's no cert to
// present at all — not even the fallback one — since a TLS listener with no
// filter chain and no default one is meaningless and Envoy would reject it.
//
// The "default" domain (generate-cert.sh default) backs DefaultFilterChain:
// without it, a client connecting with no SNI or an SNI that doesn't match
// any routes.csv domain gets no filter chain match at all, and Envoy just
// drops the connection — no TLS alert, no HTTP response, nothing. That's
// what shows up client-side as a bare "connection reset" / PR_END_OF_FILE_ERROR
// with zero indication a cert was ever the issue. The default chain routes
// through the exact same RouteConfiguration (routeConfigNameHTTPS already
// has a "*" catch-all vhost — see buildRouteConfig), so once the handshake
// can complete at all, the existing default-site behavior takes over
// identically to the HTTP listener.
func buildListenerHTTPS(port uint32, routes []route, sslDir string) *listenerv3.Listener {
	hcm := buildHTTPConnectionManager(routeConfigNameHTTPS)
	makeChain := func(match *listenerv3.FilterChainMatch, tls *tlsv3.DownstreamTlsContext) *listenerv3.FilterChain {
		return &listenerv3.FilterChain{
			FilterChainMatch: match,
			TransportSocket: &corev3.TransportSocket{
				Name:       "envoy.transport_sockets.tls",
				ConfigType: &corev3.TransportSocket_TypedConfig{TypedConfig: mustAny(tls)},
			},
			Filters: []*listenerv3.Filter{{
				Name:       wellknown.HTTPConnectionManager,
				ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: mustAny(hcm)},
			}},
		}
	}

	var chains []*listenerv3.FilterChain
	for _, r := range routes {
		if !r.SSL {
			continue
		}
		tls, err := loadDownstreamTLS(sslDir, r.Domain)
		if err != nil {
			log.Printf("route %s (%s): ssl=true but couldn't load cert, skipping — run generate-cert.sh %s: %v", r.ID, r.Domain, r.Domain, err)
			continue
		}
		chains = append(chains, makeChain(&listenerv3.FilterChainMatch{ServerNames: []string{r.Domain}}, tls))
	}

	var defaultChain *listenerv3.FilterChain
	if tls, err := loadDownstreamTLS(sslDir, "default"); err == nil {
		defaultChain = makeChain(nil, tls)
	} else {
		log.Printf("no fallback cert for unmatched SNI — run generate-cert.sh default: %v", err)
	}

	if len(chains) == 0 && defaultChain == nil {
		return nil
	}
	return &listenerv3.Listener{
		Name: "listener_https",
		Address: &corev3.Address{Address: &corev3.Address_SocketAddress{SocketAddress: &corev3.SocketAddress{
			Address:       "0.0.0.0",
			PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: port},
		}}},
		ListenerFilters: []*listenerv3.ListenerFilter{{
			Name:       "envoy.filters.listener.tls_inspector",
			ConfigType: &listenerv3.ListenerFilter_TypedConfig{TypedConfig: mustAny(&tlsinspectorv3.TlsInspector{})},
		}},
		FilterChains:       chains,
		DefaultFilterChain: defaultChain,
	}
}

// buildListenerHTTPSQuic is HTTP/3: a UDP listener on the *same* port number
// as the TCP HTTPS listener above, advertised to clients via the alt-svc
// response header (see apply()) — that's the standard discovery mechanism,
// browsers/curl try QUIC on that port after seeing it on an HTTPS response,
// they don't guess. Same domains/certs/routes as the TCP listener; no
// tls_inspector (that's TCP-only — QUIC's own initial packet already
// carries SNI, Envoy parses it natively) and no explicit TlsParams (QUIC
// mandates TLS 1.3, there's nothing to pin).
func buildListenerHTTPSQuic(port uint32, routes []route, sslDir string) *listenerv3.Listener {
	hcm := buildHTTPConnectionManager(routeConfigNameHTTPS)
	hcm.CodecType = hcmv3.HttpConnectionManager_HTTP3 // required on a QUIC listener — AUTO (the default) doesn't include HTTP/3 detection

	makeChain := func(match *listenerv3.FilterChainMatch, tls *tlsv3.DownstreamTlsContext) *listenerv3.FilterChain {
		return &listenerv3.FilterChain{
			FilterChainMatch: match,
			TransportSocket: &corev3.TransportSocket{
				Name:       "envoy.transport_sockets.quic",
				ConfigType: &corev3.TransportSocket_TypedConfig{TypedConfig: mustAny(&quicv3.QuicDownstreamTransport{DownstreamTlsContext: tls})},
			},
			Filters: []*listenerv3.Filter{{
				Name:       wellknown.HTTPConnectionManager,
				ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: mustAny(hcm)},
			}},
		}
	}

	var chains []*listenerv3.FilterChain
	for _, r := range routes {
		if !r.SSL {
			continue
		}
		tls, err := loadDownstreamTLS(sslDir, r.Domain)
		if err != nil {
			continue // buildListenerHTTPS already logs the missing-cert case for this tick
		}
		chains = append(chains, makeChain(&listenerv3.FilterChainMatch{ServerNames: []string{r.Domain}}, tls))
	}

	// Same reasoning as buildListenerHTTPS's default chain: without it, a
	// QUIC client with unmatched/no SNI gets no filter chain and the
	// connection just never completes.
	var defaultChain *listenerv3.FilterChain
	if tls, err := loadDownstreamTLS(sslDir, "default"); err == nil {
		defaultChain = makeChain(nil, tls)
	}

	if len(chains) == 0 && defaultChain == nil {
		return nil
	}
	return &listenerv3.Listener{
		Name: "listener_https_quic",
		Address: &corev3.Address{Address: &corev3.Address_SocketAddress{SocketAddress: &corev3.SocketAddress{
			Protocol:      corev3.SocketAddress_UDP,
			Address:       "0.0.0.0",
			PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: port},
		}}},
		UdpListenerConfig: &listenerv3.UdpListenerConfig{QuicOptions: &listenerv3.QuicProtocolOptions{}},
		EnableReusePort:   wrapperspb.Bool(true),
		FilterChains:       chains,
		DefaultFilterChain: defaultChain,
	}
}

func buildStaticCluster(name, address string, port uint32) *clusterv3.Cluster {
	return &clusterv3.Cluster{
		Name:                 name,
		ConnectTimeout:       durationpb.New(upstreamConnTimeout),
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STRICT_DNS},
		LbPolicy:             clusterv3.Cluster_ROUND_ROBIN,
		LoadAssignment: &endpointv3.ClusterLoadAssignment{
			ClusterName: name,
			Endpoints: []*endpointv3.LocalityLbEndpoints{{
				LbEndpoints: []*endpointv3.LbEndpoint{{
					HostIdentifier: &endpointv3.LbEndpoint_Endpoint{Endpoint: &endpointv3.Endpoint{
						Address: &corev3.Address{Address: &corev3.Address_SocketAddress{SocketAddress: &corev3.SocketAddress{
							Address:       address,
							PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: port},
						}}},
					}},
				}},
			}},
		},
	}
}

// buildRouteCluster builds the upstream cluster for one routes.csv row. All
// CSV targets are connected to over HTTPS (that's what makes cert_check
// meaningful); cert_check=false trusts whatever cert the backend presents
// (self-signed/unknown CA), cert_check=true requires it validate normally.
func buildRouteCluster(r route) *clusterv3.Cluster {
	c := buildStaticCluster("cluster_"+r.ID, r.Target, uint32(r.Port))
	validationContext := &tlsv3.CertificateValidationContext{
		TrustChainVerification: tlsv3.CertificateValidationContext_ACCEPT_UNTRUSTED,
	}
	if r.CertCheck {
		// ACCEPT_UNTRUSTED skips verification outright; VERIFY_TRUST_CHAIN by
		// itself has nothing to verify against without an explicit CA bundle
		// — it's a silent no-op, not a stricter mode. The system bundle is
		// what the Envoy image ships for this purpose.
		validationContext.TrustChainVerification = tlsv3.CertificateValidationContext_VERIFY_TRUST_CHAIN
		validationContext.TrustedCa = &corev3.DataSource{
			Specifier: &corev3.DataSource_Filename{Filename: "/etc/ssl/certs/ca-certificates.crt"},
		}
	}
	upstreamTLS := &tlsv3.UpstreamTlsContext{
		CommonTlsContext: &tlsv3.CommonTlsContext{
			TlsParams: &tlsv3.TlsParameters{
				TlsMinimumProtocolVersion: tlsv3.TlsParameters_TLSv1_2,
				TlsMaximumProtocolVersion: tlsv3.TlsParameters_TLSv1_3,
			},
			ValidationContextType: &tlsv3.CommonTlsContext_ValidationContext{
				ValidationContext: validationContext,
			},
		},
		Sni: r.Domain,
	}
	c.TransportSocket = &corev3.TransportSocket{
		Name:       "envoy.transport_sockets.tls",
		ConfigType: &corev3.TransportSocket_TypedConfig{TypedConfig: mustAny(upstreamTLS)},
	}
	return c
}

// buildRouteConfig is called once per listener (name/headers differ) rather
// than shared, so HSTS can be scoped to the HTTPS route config only —
// sending it over the plain HTTP listener wouldn't be dangerous (browsers
// ignore Strict-Transport-Security on a non-HTTPS response per RFC 6797) but
// there's no reason to send it there either.
func buildRouteConfig(routes []route, name string, responseHeaders []*corev3.HeaderValueOption, defaultSiteBody []byte, isHTTP bool, httpsPort uint32) *routev3.RouteConfiguration {
	var vhosts []*routev3.VirtualHost
	for _, r := range routes {
		vh := &routev3.VirtualHost{
			Name:    "vh_" + r.ID,
			// Both forms: a client on a non-default port (e.g. our TLS demo
			// port 10443) sends "Host: domain:port", which won't exact-match
			// a bare domain entry — the ":*" suffix is Envoy's documented
			// wildcard for "this domain on any port".
			Domains: []string{r.Domain, r.Domain + ":*"},
			Routes: []*routev3.Route{{
				Match: &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"}},
				Action: &routev3.Route_Route{Route: &routev3.RouteAction{
					ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: "cluster_" + r.ID},
					Timeout:          durationpb.New(requestTimeout),
				}},
			}},
		}
		// On the plain-HTTP route config only: a domain with ssl=true has a
		// real HTTPS listener to send it to, so redirect rather than serve
		// it in the clear. A domain with ssl=false has no HTTPS listener at
		// all — redirecting it would send clients to a port that rejects
		// them outright, so those keep being served over HTTP directly.
		if isHTTP && r.SSL {
			vh.Routes[0].Action = &routev3.Route_Redirect{Redirect: &routev3.RedirectAction{
				SchemeRewriteSpecifier: &routev3.RedirectAction_HttpsRedirect{HttpsRedirect: true},
				PortRedirect:           httpsPort,
			}}
		}
		// Also skip scoring on the redirect itself — there's nothing to
		// score, the request never reaches an upstream, it just bounces to
		// HTTPS unconditionally.
		if !r.Scoring || (isHTTP && r.SSL) {
			vh.Routes[0].TypedPerFilterConfig = map[string]*anypb.Any{
				"envoy.filters.http.ext_authz": mustAny(&extauthzv3.ExtAuthzPerRoute{
					Override: &extauthzv3.ExtAuthzPerRoute_Disabled{Disabled: true},
				}),
			}
		}
		// Prepended, not appended: routes are matched in order and these
		// are exact-path matches against the catch-all "/" prefix route
		// above, so they need to come first to ever be reached at all.
		// nil (feature off) is a no-op prepend.
		vh.Routes = append(buildSecurityTxtRoutes(r.Domain), vh.Routes...)
		vhosts = append(vhosts, vh)
	}
	// vh_default catches every Host that doesn't match a configured domain.
	// Two routes, evaluated in order (first match wins):
	//
	//  1. Host is an IP literal (e.g. a scanner hitting the proxy directly
	//     by its public IP instead of any real domain — a recon pattern
	//     real domain traffic never produces). This one *proxies* to a real
	//     backend instead of DirectResponseAction, specifically so it goes
	//     through ext_authz/Coraza and can actually be scored — verified
	//     empirically that a DirectResponseAction route never invokes
	//     ext_authz at all (no scoring-service log entry for such a
	//     request), so there was previously no way to flag this traffic.
	//     Coraza's crs-extra rule 10002 does the actual IP-literal check on
	//     REQUEST_HEADERS:Host; this regex only needs to be loose enough to
	//     select the branch, not authoritative.
	//  2. Everything else unmatched (typos, stale DNS, scanners probing
	//     other hostnames) — the original DirectResponseAction, unchanged:
	//     from the mounted envoy/default-site/index.html, read fresh on
	//     every rebuild (see apply()), not compiled into the binary.
	//     Content-type is set here (Route-level response_headers_to_add)
	//     rather than at the RouteConfiguration level, since that level's
	//     headers apply to every other route too, most of which proxy to
	//     backends with their own real content-types.
	vhosts = append(vhosts, &routev3.VirtualHost{
		Name:    "vh_default",
		Domains: []string{"*"},
		Routes: []*routev3.Route{
			{
				Match: &routev3.RouteMatch{
					PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"},
					Headers: []*routev3.HeaderMatcher{{
						Name: ":authority",
						HeaderMatchSpecifier: &routev3.HeaderMatcher_StringMatch{
							StringMatch: &matcherv3.StringMatcher{
								MatchPattern: &matcherv3.StringMatcher_SafeRegex{
									SafeRegex: &matcherv3.RegexMatcher{Regex: `^(\d{1,3}\.){3}\d{1,3}(:\d+)?$`},
								},
							},
						},
					}},
				},
				Action: &routev3.Route_Route{Route: &routev3.RouteAction{
					ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: "cluster_" + defaultCatchAllRoute.ID},
					Timeout:          durationpb.New(requestTimeout),
				}},
			},
			{
				Match: &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"}},
				Action: &routev3.Route_DirectResponse{DirectResponse: &routev3.DirectResponseAction{
					Status: 200,
					Body:   &corev3.DataSource{Specifier: &corev3.DataSource_InlineBytes{InlineBytes: defaultSiteBody}},
				}},
				ResponseHeadersToAdd: []*corev3.HeaderValueOption{headerOpt("content-type", "text/html; charset=utf-8")},
				TypedPerFilterConfig: map[string]*anypb.Any{
					"envoy.filters.http.ext_authz": mustAny(&extauthzv3.ExtAuthzPerRoute{
						Override: &extauthzv3.ExtAuthzPerRoute_Disabled{Disabled: true},
					}),
				},
			},
		},
	})
	return &routev3.RouteConfiguration{
		Name:                    name,
		VirtualHosts:            vhosts,
		ResponseHeadersToAdd:    responseHeaders,
		ResponseHeadersToRemove: []string{"server"}, // strip whatever the upstream sent (nginx, Express...) — see ServerHeaderTransformation above for why this actually sticks
	}
}

type generator struct {
	csvPath       string
	sslDir        string
	defaultSiteDir string
	httpPort      uint32
	httpsPort     uint32
	cache         cachev3.SnapshotCache
	version       int64
	health        *healthChecker
}

// defaultSiteFallback is used only if envoy/default-site/index.html can't be
// read (e.g. a fresh checkout before the mount is populated, or a bad mount)
// — better than failing every unmatched-domain request outright.
const defaultSiteFallback = `<!doctype html><html><body style="font-family:system-ui;background:#0f1115;color:#e6e6e6;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><p>No site configured for this domain.</p></body></html>`

func (g *generator) rebuild(ctx context.Context) error {
	routes, err := loadRoutes(g.csvPath)
	if err != nil {
		return fmt.Errorf("loading %s: %w", g.csvPath, err)
	}
	return g.apply(ctx, routes)
}

// apply turns a parsed routes.csv into a full xDS snapshot (clusters, one
// shared route config, HTTP + optional HTTPS listeners) and pushes it. Every
// route shares the same ext_authz-gated HTTP connection manager — the CSV
// only varies routing/TLS/cert-verification/scoring-toggle per domain, the
// actual scoring pipeline is identical either way.
func (g *generator) apply(ctx context.Context, routes []route) error {
	g.health.setRoutes(routes)

	// gRPC ext_authz requires HTTP/2 on this cluster — no TLS on this
	// internal hop (same as before), so this is h2c (cleartext HTTP/2), set
	// via TypedExtensionProtocolOptions on this cluster object specifically
	// rather than inside buildStaticCluster itself, since that helper is
	// also shared by buildRouteCluster for real TLS backends.
	scoringCluster := buildStaticCluster("scoring_service", "scoring-service", 9001)
	scoringCluster.TypedExtensionProtocolOptions = map[string]*anypb.Any{
		"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": mustAny(&upstreamshttpv3.HttpProtocolOptions{
			UpstreamProtocolOptions: &upstreamshttpv3.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &upstreamshttpv3.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &upstreamshttpv3.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{
						Http2ProtocolOptions: &corev3.Http2ProtocolOptions{},
					},
				},
			},
		}),
	}
	clusters := []cachetypes.Resource{scoringCluster, buildRouteCluster(defaultCatchAllRoute)}
	for _, r := range routes {
		clusters = append(clusters, buildRouteCluster(r))
	}

	// Only present at all when at least one route actually wants an
	// auto-managed certificate — users not using the feature get no
	// behavior change and don't need port 80 published.
	needsAcme := false
	for _, r := range routes {
		if r.LetsEncrypt {
			needsAcme = true
			break
		}
	}
	if needsAcme {
		clusters = append(clusters, buildStaticCluster("acme_challenge", "letsencrypt-sidecar", 8090))
	}

	defaultSiteBody, err := os.ReadFile(filepath.Join(g.defaultSiteDir, "index.html"))
	if err != nil {
		log.Printf("reading default-site index.html: %v — serving a minimal fallback instead", err)
		defaultSiteBody = []byte(defaultSiteFallback)
	}

	listeners := []cachetypes.Resource{buildListenerHTTP(g.httpPort)}
	if httpsListener := buildListenerHTTPS(g.httpsPort, routes, g.sslDir); httpsListener != nil {
		listeners = append(listeners, httpsListener)
	}
	if quicListener := buildListenerHTTPSQuic(g.httpsPort, routes, g.sslDir); quicListener != nil {
		listeners = append(listeners, quicListener)
	}
	if needsAcme {
		listeners = append(listeners, buildAcmeChallengeListener(acmeHttp01Port))
	}

	httpsHeaders := append(append([]*corev3.HeaderValueOption{}, baseSecurityHeaders()...),
		headerOpt("strict-transport-security", "max-age=31536000; includeSubDomains"),
		// Tells clients HTTP/3 is available on the same port over UDP — this is
		// how they discover it; nothing about the TCP/TLS listener itself
		// implies a QUIC listener exists alongside it.
		headerOpt("alt-svc", fmt.Sprintf(`h3=":%d"; ma=86400`, g.httpsPort)))
	routeConfigs := []cachetypes.Resource{
		buildRouteConfig(routes, routeConfigNameHTTP, baseSecurityHeaders(), defaultSiteBody, true, g.httpsPort),
		buildRouteConfig(routes, routeConfigNameHTTPS, httpsHeaders, defaultSiteBody, false, g.httpsPort),
	}

	version := atomic.AddInt64(&g.version, 1)
	snapshot, err := cachev3.NewSnapshot(
		strconv.FormatInt(version, 10),
		map[resourcev3.Type][]cachetypes.Resource{
			resourcev3.ClusterType:  clusters,
			resourcev3.RouteType:    routeConfigs,
			resourcev3.ListenerType: listeners,
		},
	)
	if err != nil {
		return fmt.Errorf("building snapshot: %w", err)
	}
	if err := snapshot.Consistent(); err != nil {
		return fmt.Errorf("inconsistent snapshot: %w", err)
	}
	if err := g.cache.SetSnapshot(ctx, nodeID, snapshot); err != nil {
		return fmt.Errorf("setting snapshot: %w", err)
	}
	log.Printf("applied config: %d route(s), %d cluster(s), %d listener(s), version %d", len(routes), len(clusters), len(listeners), version)
	return nil
}

func main() {
	csvPath := envOr("ROUTES_CSV", "/etc/envoy-cp/routes.csv")
	sslDir := envOr("SSL_DIR", "/etc/envoy-cp/ssl")
	defaultSiteDir := envOr("DEFAULT_SITE_DIR", "/etc/envoy-cp/default-site")
	httpPort := envOrInt("ENVOY_HTTP_PORT", 10000)
	httpsPort := envOrInt("ENVOY_HTTPS_PORT", 10443)
	listenAddr := envOr("LISTEN_ADDR", ":18000")
	healthAddr := envOr("HEALTH_LISTEN_ADDR", ":18001")

	extAuthzTimeout = time.Duration(envOrInt("EXT_AUTHZ_TIMEOUT_MS", 200)) * time.Millisecond
	extAuthzMaxBodyBytes = uint32(envOrInt("EXT_AUTHZ_MAX_BODY_BYTES", 8192))
	upstreamConnTimeout = time.Duration(envOrInt("UPSTREAM_CONNECT_TIMEOUT_MS", 1000)) * time.Millisecond
	requestTimeout = time.Duration(envOrInt("REQUEST_TIMEOUT_S", 15)) * time.Second
	streamIdleTimeout = time.Duration(envOrInt("STREAM_IDLE_TIMEOUT_S", 300)) * time.Second
	acmeHttp01Port = uint32(envOrInt("ACME_HTTP01_PORT", 80))

	snapshotCache := cachev3.NewSnapshotCache(true, cachev3.IDHash{}, nil)

	g := &generator{
		csvPath:        csvPath,
		sslDir:         sslDir,
		defaultSiteDir: defaultSiteDir,
		httpPort:       uint32(httpPort),
		httpsPort:      uint32(httpsPort),
		cache:          snapshotCache,
		health:         newHealthChecker(sslDir),
	}

	ctx := context.Background()
	if err := g.rebuild(ctx); err != nil {
		log.Fatalf("initial config build failed: %v", err)
	}

	go g.watch(ctx)
	go g.health.run(ctx, 5*time.Second)

	mux := http.NewServeMux()
	mux.HandleFunc("/routes/health", g.health.handler)
	go func() {
		log.Printf("backend health endpoint listening on %s (/routes/health)", healthAddr)
		if err := http.ListenAndServe(healthAddr, mux); err != nil {
			log.Fatalf("health HTTP server failed: %v", err)
		}
	}()

	xdsServer := serverv3.NewServer(ctx, snapshotCache, nil)
	grpcServer := grpc.NewServer()
	discoverygrpc.RegisterAggregatedDiscoveryServiceServer(grpcServer, xdsServer)

	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", listenAddr, err)
	}
	log.Printf("envoy-control-plane (ADS) listening on %s, watching %s and %s", listenAddr, csvPath, sslDir)
	log.Fatal(grpcServer.Serve(lis))
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envOrInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func (g *generator) watch(ctx context.Context) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("fsnotify unavailable, dynamic reload disabled: %v", err)
		return
	}
	defer watcher.Close()

	if err := watcher.Add(filepath.Dir(g.csvPath)); err != nil {
		log.Printf("failed to watch %s: %v", filepath.Dir(g.csvPath), err)
	}
	if err := os.MkdirAll(g.sslDir, 0o755); err == nil {
		if err := watcher.Add(g.sslDir); err != nil {
			log.Printf("failed to watch %s: %v", g.sslDir, err)
		}
	}
	if err := watcher.Add(g.defaultSiteDir); err != nil {
		log.Printf("failed to watch %s: %v", g.defaultSiteDir, err)
	}

	var debounce *time.Timer
	for {
		select {
		case _, ok := <-watcher.Events:
			if !ok {
				return
			}
			if debounce != nil {
				debounce.Stop()
			}
			debounce = time.AfterFunc(300*time.Millisecond, func() {
				if err := g.rebuild(ctx); err != nil {
					log.Printf("config rebuild failed, keeping previous snapshot: %v", err)
				}
			})
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("fsnotify error: %v", err)
		}
	}
}
