package authz

import (
	"fmt"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
)

func headerOpt(key, value string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{Header: &corev3.HeaderValue{Key: key, Value: value}}
}

// allowResponse: plain allow, "x-risk-score" only — the gRPC-mode
// equivalent of the old AllowedUpstreamHeaders behavior, now built
// explicitly since there's no Envoy-side allowlist to fall back on.
func allowResponse(score float64) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: []*corev3.HeaderValueOption{
					headerOpt("x-risk-score", fmt.Sprintf("%.2f", score)),
				},
			},
		},
	}
}

// auditWouldBlockResponse: audit mode's "would have blocked, but didn't" —
// HTTP 200 (never actually enforced), both x-risk-score and
// x-audit-would-block headers, empty body. Distinct from both plain-allow
// and a real deny.
func auditWouldBlockResponse(score float64) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: []*corev3.HeaderValueOption{
					headerOpt("x-risk-score", fmt.Sprintf("%.2f", score)),
					headerOpt("x-audit-would-block", "true"),
				},
			},
		},
	}
}

// honeypotResponse: a deliberately unremarkable HTTP 404 — no branded
// "blocked" body, no risk-score headers, nothing that would tell whoever
// requested a bait path that it was recognized as one rather than a
// genuinely missing route. The actual detection (CrowdSec ban, dashboard
// event) already happened server-side before this response is built; the
// client sees exactly what a real 404 looks like.
func honeypotResponse() *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_NotFound},
				Body:   "404 page not found\n",
			},
		},
	}
}

// denyResponse: HTTP 403, plain-text body "blocked (risk=X.XX): <first
// reason>", no headers — matches the original Python response exactly. If
// reasons is somehow empty (deny requires a signal >= threshold, which
// always produces a reason today, but the Python original indexed
// reasons[0] unchecked — a latent panic waiting to happen), fall back to a
// generic message instead of panicking. This is a deliberate correctness
// fix over the original, not a silent behavior change to anything that can
// actually occur today.
func denyResponse(score float64, reasons []string) *authv3.CheckResponse {
	reason := "no specific reason recorded"
	if len(reasons) > 0 {
		reason = reasons[0]
	}
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
				Body:   fmt.Sprintf("blocked (risk=%.2f): %s", score, reason),
			},
		},
	}
}
