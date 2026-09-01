package crowdsec

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"scoring-service-go/scoring"
)

// Shared with the crowdsec container (see crowdsec/acquis.yaml,
// docker-compose.yml). nginx combined log format — reuses CrowdSec's own
// well-tested nginx-logs parser/scenarios rather than writing a custom one
// for a bespoke format.
var feedPath = envStr("CROWDSEC_FEED_PATH", "/var/log/crowdsec-feed/access.log")

// Separate feed, separate format: a ModSecurity-style error-log line (see
// LogModsecMatches) — reuses CrowdSec's crowdsecurity/modsecurity
// parser+scenario, which fires immediately on a single CRITICAL-severity
// match rather than waiting for a pattern of repeated 403s to accumulate
// the way the generic access-log feed above does.
var modsecFeedPath = envStr("CROWDSEC_MODSEC_FEED_PATH", "/var/log/crowdsec-feed/modsecurity.log")

var severityWords = map[int]string{
	0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "ERROR",
	4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG",
}

// LogRequest feeds this request to CrowdSec's agent as an nginx-style
// access log line, so its scenarios (scanner UAs, probing, aggressive
// crawling, ...) can build up decisions from real traffic patterns over
// time — this is what lets GetDecisions find anything. Best-effort: a
// logging failure must never affect the actual scoring decision.
func LogRequest(ip, method, path string, status int, userAgent string) {
	if !enabled {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("failed to write crowdsec feed log: %v", r)
		}
	}()
	timeLocal := time.Now().UTC().Format("02/Jan/2006:15:04:05 -0700")
	ua := strings.ReplaceAll(userAgent, `"`, "")
	if ua == "" {
		ua = "-"
	}
	line := fmt.Sprintf(`%s - - [%s] "%s %s HTTP/1.1" %d 0 "-" "%s"`+"\n", ip, timeLocal, method, path, status, ua)
	appendToFile(feedPath, line)
}

// LogModsecMatches feeds Coraza/CRS's own rule matches to CrowdSec as
// ModSecurity-format error-log lines (crowdsecurity/modsecurity
// parser+scenario, installed via COLLECTIONS in docker-compose.yml) — a
// *direct* signal (a single CRITICAL match can ban immediately) distinct
// from the indirect "repeated 403s look suspicious" pattern LogRequest
// covers. Best-effort, same as LogRequest.
func LogModsecMatches(ip, domain, path string, matchedRules []scoring.MatchedRule) {
	if !enabled || len(matchedRules) == 0 {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("failed to write crowdsec modsecurity feed log: %v", r)
		}
	}()
	// Go reference layout for "%a %b %d %H:%M:%S.%f %Y" (weekday, month,
	// day, time with microseconds, year). Python's %d always zero-pads
	// (unlike C's classic asctime()/ctime() format, which space-pads the
	// day) — Go's "02" matches that, "_2" (space-padded) would not.
	timestamp := time.Now().UTC().Format("Mon Jan 02 15:04:05.000000 2006")

	var sb strings.Builder
	for _, rule := range matchedRules {
		severity := severityWords[rule.SeverityCode]
		if severity == "" {
			severity = "NOTICE"
		}
		msg := strings.ReplaceAll(rule.Message, `"`, "'")
		// Each tag needs its own trailing space (not space-joined between
		// them) — that's what the upstream grok pattern (MODSECRULETAGS2,
		// `(?:\[tag ...\] )*`) actually expects.
		var tagStr strings.Builder
		for _, t := range rule.Tags {
			tagStr.WriteString(`[tag "` + t + `"] `)
		}
		fmt.Fprintf(&sb,
			`[%s] [security2:error] [pid 1:tid 1] [client %s] [client %s] `+
				`ModSecurity: Access denied with code 403 (phase 2). Matched rule. `+
				`[file "CRS"] [line "1"] [id "%d"] [rev "1"] `+
				`[msg "%s"] [data "-"] [severity "%s"] [ver "OWASP_CRS"] `+
				`%s[hostname "%s"] [uri "%s"] [unique_id "-"]`+"\n",
			timestamp, ip, ip, rule.ID, msg, severity, tagStr.String(), domain, path,
		)
	}
	appendToFile(modsecFeedPath, sb.String())
}

func appendToFile(path, content string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("failed to open %s for crowdsec feed log: %v", path, err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		log.Printf("failed to write %s for crowdsec feed log: %v", path, err)
	}
}
