package authz

import "strings"

// allowedHeaders replicates the same 6-header allow-list Envoy's HTTP-mode
// ext_authz used to enforce at the proxy layer (AllowedHeaders in
// envoy-control-plane's old buildExtAuthzFilter). gRPC mode hands this
// service the entire original request (all headers), so this allow-list
// must now be enforced here instead — a deliberate choice not to silently
// widen what this service reads, not an oversight.
var allowedHeaders = map[string]struct{}{
	"user-agent":               {},
	"x-forwarded-for":          {},
	"x-envoy-external-address": {},
	":authority":               {},
	"content-type":             {},
	"x-request-protocol":       {},
}

// filterHeaders keeps only the allow-listed headers. Envoy's gRPC
// AttributeContext_HttpRequest.Headers keys are already lower-cased per
// the ext_authz proto contract, so no case-folding is needed here.
func filterHeaders(all map[string]string) map[string]string {
	out := make(map[string]string, len(allowedHeaders))
	for k, v := range all {
		if _, ok := allowedHeaders[k]; ok {
			out[k] = v
		}
	}
	return out
}

// extractClientIP: x-forwarded-for's leftmost entry is the original client
// per RFC 7239 convention; x-envoy-external-address is Envoy's own view of
// the downstream peer as a fallback.
func extractClientIP(headers map[string]string) string {
	if fwd := headers["x-forwarded-for"]; fwd != "" {
		if idx := strings.IndexByte(fwd, ','); idx >= 0 {
			return strings.TrimSpace(fwd[:idx])
		}
		return strings.TrimSpace(fwd)
	}
	if v := headers["x-envoy-external-address"]; v != "" {
		return v
	}
	return "unknown"
}

// splitPathQuery: CheckRequest's Path field includes the query string
// (unlike Envoy's old HTTP-mode PathPrefix routing, which handed
// scoring-service a path FastAPI parsed separately from its query) — gRPC
// mode needs to split them itself. coraza-service's /check contract wants
// them separate.
func splitPathQuery(pathAndQuery string) (path, query string) {
	if idx := strings.IndexByte(pathAndQuery, '?'); idx >= 0 {
		return pathAndQuery[:idx], pathAndQuery[idx+1:]
	}
	return pathAndQuery, ""
}
