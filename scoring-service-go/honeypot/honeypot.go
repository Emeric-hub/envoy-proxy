// Package honeypot checks a request path against a set of known
// scanner-bait paths that no legitimate application traffic should ever
// request. Unlike every other signal in this pipeline (Coraza/CRS,
// CrowdSec, ...), a honeypot hit carries no ambiguity: it's a certain,
// zero-false-positive signal by construction — the whole reason it
// exists is that it needs no scoring/threshold logic at all.
package honeypot

import (
	"os"
	"strings"
)

// Enabled mirrors ENABLE_CORAZA/ENABLE_CROWDSEC/ENABLE_AI_TUNER's on/off
// convention.
var Enabled = envBool("ENABLE_HONEYPOT", true)

// defaultPaths: classic scanner-bait paths (WordPress admin, dotfiles/VCS
// metadata, common credential/backup file names, framework
// health-check/status endpoints) — a starting point to extend, not a
// complete list. A real deployment MUST verify none of these are
// something its actual application legitimately serves before enabling
// this, same as any honeypot: it only works if the bait path is
// genuinely never real traffic.
const defaultPaths = "/wp-admin,/wp-login.php,/.env,/.git/config," +
	"/phpmyadmin,/xmlrpc.php,/.aws/credentials,/admin/config.php.bak," +
	"/.htpasswd,/server-status,/actuator/health"

var paths = loadPaths()

func envBool(name string, def bool) bool {
	v, ok := os.LookupEnv(name)
	if !ok {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func loadPaths() []string {
	raw := os.Getenv("HONEYPOT_PATHS")
	if raw == "" {
		raw = defaultPaths
	}
	var out []string
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// IsMatch reports whether path is a configured honeypot path — either an
// exact match, or a request for something *under* it (e.g. configuring
// "/wp-admin" also catches "/wp-admin/setup-config.php", a real scanner
// probe shape) without accidentally matching an unrelated path that
// merely shares the same prefix string (e.g. NOT "/wp-admin-panel").
func IsMatch(path string) (bool, string) {
	for _, p := range paths {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true, p
		}
	}
	return false, ""
}
