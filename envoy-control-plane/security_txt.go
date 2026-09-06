// security_txt.go serves a customizable RFC 9116 security.txt
// (https://www.rfc-editor.org/rfc/rfc9116) for every routes.csv domain, at
// both the canonical location (/.well-known/security.txt) and the legacy
// root location (/security.txt) RFC 9116 §3 says implementations SHOULD
// still accept for backward compatibility. Answered directly by Envoy
// (DirectResponseAction, no upstream, no ext_authz) — same reasoning as
// the default-site fallback in main.go: this is static, unauthenticated,
// informational content, not something that needs scoring.
//
// Off entirely unless SECURITY_TXT_CONTACT is set: RFC 9116 §2.5.3 makes
// Contact mandatory (at least one), so a security.txt with none isn't a
// valid file to publish at all, not just an incomplete one.
package main

import (
	"fmt"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	extauthzv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	"google.golang.org/protobuf/types/known/anypb"
)

func envSlice(key string, def []string) []string {
	raw := envOr(key, "")
	if raw == "" {
		return def
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

var (
	// One or more contact methods (RFC 9116 §2.5.3: "mailto:", "https://",
	// or "tel:" URIs) -- comma-separated, e.g.
	// "mailto:security@example.com,https://example.com/report-a-vulnerability".
	securityTxtContacts = envSlice("SECURITY_TXT_CONTACT", nil)
	// How many days out the Expires field is set, recomputed fresh every
	// time envoy-control-plane rebuilds its config (startup, or a
	// routes.csv/ssl change) -- not a fixed date. RFC 9116 §2.5.5 requires
	// this field and recommends not dating it too far out; it does NOT
	// re-compute on a timer if nothing else changes, so a deployment that
	// goes a long time with no routes.csv/ssl edits will see this date
	// quietly grow stale -- see TODO.md.
	securityTxtExpiresDays        = envOrInt("SECURITY_TXT_EXPIRES_DAYS", 365)
	securityTxtEncryption         = envOr("SECURITY_TXT_ENCRYPTION", "")
	securityTxtAcknowledgments    = envOr("SECURITY_TXT_ACKNOWLEDGMENTS", "")
	securityTxtPreferredLanguages = envOr("SECURITY_TXT_PREFERRED_LANGUAGES", "en")
	securityTxtPolicy             = envOr("SECURITY_TXT_POLICY", "")
	securityTxtHiring             = envOr("SECURITY_TXT_HIRING", "")
)

// buildSecurityTxtBody assembles the file's fields in the RFC's own
// documented order (§3). Canonical is the one field genuinely specific to
// each domain; everything else is shared, .env-driven configuration.
func buildSecurityTxtBody(domain string) []byte {
	var b strings.Builder
	for _, contact := range securityTxtContacts {
		fmt.Fprintf(&b, "Contact: %s\n", contact)
	}
	expires := time.Now().UTC().AddDate(0, 0, securityTxtExpiresDays).Format(time.RFC3339)
	fmt.Fprintf(&b, "Expires: %s\n", expires)
	if securityTxtEncryption != "" {
		fmt.Fprintf(&b, "Encryption: %s\n", securityTxtEncryption)
	}
	if securityTxtAcknowledgments != "" {
		fmt.Fprintf(&b, "Acknowledgments: %s\n", securityTxtAcknowledgments)
	}
	fmt.Fprintf(&b, "Preferred-Languages: %s\n", securityTxtPreferredLanguages)
	if securityTxtPolicy != "" {
		fmt.Fprintf(&b, "Policy: %s\n", securityTxtPolicy)
	}
	if securityTxtHiring != "" {
		fmt.Fprintf(&b, "Hiring: %s\n", securityTxtHiring)
	}
	fmt.Fprintf(&b, "Canonical: https://%s/.well-known/security.txt\n", domain)
	return []byte(b.String())
}

// buildSecurityTxtRoutes returns nil (no routes added) when the feature is
// off, so callers can just append the result without an extra branch.
func buildSecurityTxtRoutes(domain string) []*routev3.Route {
	if len(securityTxtContacts) == 0 {
		return nil
	}
	body := buildSecurityTxtBody(domain)
	perFilterCfg := map[string]*anypb.Any{
		"envoy.filters.http.ext_authz": mustAny(&extauthzv3.ExtAuthzPerRoute{
			Override: &extauthzv3.ExtAuthzPerRoute_Disabled{Disabled: true},
		}),
	}
	buildRoute := func(path string) *routev3.Route {
		return &routev3.Route{
			Match: &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_Path{Path: path}},
			Action: &routev3.Route_DirectResponse{DirectResponse: &routev3.DirectResponseAction{
				Status: 200,
				Body:   &corev3.DataSource{Specifier: &corev3.DataSource_InlineBytes{InlineBytes: body}},
			}},
			ResponseHeadersToAdd: []*corev3.HeaderValueOption{headerOpt("content-type", "text/plain; charset=utf-8")},
			TypedPerFilterConfig: perFilterCfg,
		}
	}
	return []*routev3.Route{
		buildRoute("/.well-known/security.txt"),
		buildRoute("/security.txt"),
	}
}
