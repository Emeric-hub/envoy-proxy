// Package events is a 1:1 port of the original scoring-service's events.py
// — Redis pub/sub (decisions, for the dashboard) and a Redis Stream
// (CRS matches, for crs-tuner's async AI-tuning loop).
package events

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"scoring-service-go/scoring"
)

const (
	channel        = "risk-events"
	crsMatchStream = "crs-matches"
)

var (
	redisURL = envStr("REDIS_URL", "redis://redis:6379/0")

	enableAITuner = envBool("ENABLE_AI_TUNER", true)
	// Numeric severity code (0=Emergency..7=Debug, lower = more severe —
	// see coraza-service's severityWeight/matchedRuleOut). Only matches at
	// least this severe are worth crs-tuner's attention.
	aiTunerMinSeverityCode = envInt("AI_TUNER_MIN_SEVERITY_CODE", 3)

	// CRS rule categories (by tag) that must NEVER be eligible for
	// auto-exclusion, no matter what the LLM judges or how many times it
	// repeats — these are CRS's own attack-signature categories (real
	// payload detection: SQLi, XSS, RCE, LFI/RFI, scanner detection, ...),
	// not the generic protocol/format anomaly rules the tuning loop is
	// actually meant for. Verified necessary empirically: a small local
	// model repeatedly judged real SQLi/XSS/RCE/LFI/scanner-detection
	// matches "false positive" under repeated similar traffic and those
	// got auto-excluded (see TODO.md) — this must be preserved exactly,
	// it is a hard security gate, not a performance shortcut. Gated here,
	// before a match even reaches the queue, so no downstream verdict can
	// ever override it.
	aiTunerIneligibleTags = envTagSet("AI_TUNER_INELIGIBLE_TAGS",
		"attack-sqli,attack-xss,attack-rce,attack-lfi,attack-rfi,"+
			"attack-php-injection,attack-nodejs-injection,attack-session-fixation,"+
			"attack-reputation-scanner,attack-disclosure,attack-injection-generic")
)

func envStr(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return def
}

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

func envInt(name string, def int) int {
	if v, ok := os.LookupEnv(name); ok {
		if i, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return i
		}
	}
	return def
}

func envTagSet(name, def string) map[string]struct{} {
	raw := envStr(name, def)
	set := map[string]struct{}{}
	for _, t := range strings.Split(raw, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			set[t] = struct{}{}
		}
	}
	return set
}

var client *redis.Client

func getClient() *redis.Client {
	if client == nil {
		opt, err := redis.ParseURL(redisURL)
		if err != nil {
			log.Fatalf("events: invalid REDIS_URL %q: %v", redisURL, err)
		}
		client = redis.NewClient(opt)
	}
	return client
}

// DecisionEvent mirrors the JSON object published to the risk-events
// channel — read by the dashboard's WebSocket relay.
type DecisionEvent struct {
	TS                string                     `json:"ts"`
	Method            string                     `json:"method"`
	Path              string                     `json:"path"`
	UserAgent         string                     `json:"user_agent"`
	Protocol          string                     `json:"protocol"`
	IP                string                     `json:"ip"`
	Domain            string                     `json:"domain"`
	Score             float64                    `json:"score"`
	Decision          string                     `json:"decision"`
	HTTPStatus        int                        `json:"http_status"`
	AuditMode         bool                       `json:"audit_mode"`
	Signals           map[string]float64         `json:"signals"`
	CrowdsecDecisions []scoring.CrowdsecDecision `json:"crowdsec_decisions"`
	Reasons           []string                   `json:"reasons"`
	DurationMS        float64                    `json:"duration_ms"`
}

// PublishDecision is fire-and-forget: a slow/unreachable Redis must never
// block or fail a scoring decision. Call from a goroutine or accept the
// ~0.2s worst-case latency inline, matching the original's own behavior of
// awaiting this synchronously with a short connect/socket timeout.
func PublishDecision(ctx context.Context, event DecisionEvent) {
	event.TS = time.Now().UTC().Format(time.RFC3339Nano)
	payload, err := json.Marshal(event)
	if err != nil {
		log.Printf("events: failed to marshal risk event: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	if err := getClient().Publish(ctx, channel, payload).Err(); err != nil {
		log.Printf("events: failed to publish risk event: %v", err)
	}
}

// PublishCRSMatch queues one CRS match for crs-tuner's async analysis — a
// Redis Stream, not pub/sub: pub/sub messages are lost if nothing is
// subscribed at publish time, and a missed match here is a missed tuning
// opportunity, not just a missed dashboard update. Self-gates on
// ENABLE_AI_TUNER, severity, AND the ineligible-tags set — see the
// aiTunerIneligibleTags doc comment above, this is a hard security gate.
func PublishCRSMatch(ctx context.Context, domain, path, ip string, rule scoring.MatchedRule) {
	if !enableAITuner {
		return
	}
	if rule.SeverityCode > aiTunerMinSeverityCode {
		return
	}
	for _, tag := range rule.Tags {
		if _, ineligible := aiTunerIneligibleTags[tag]; ineligible {
			return
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	err := getClient().XAdd(ctx, &redis.XAddArgs{
		Stream: crsMatchStream,
		Values: map[string]any{
			"domain":        domain,
			"path":          path,
			"ip":            ip,
			"rule_id":       strconv.Itoa(rule.ID),
			"message":       rule.Message,
			"severity":      rule.Severity,
			"severity_code": strconv.Itoa(rule.SeverityCode),
			"tags":          strings.Join(rule.Tags, ","),
			"variable":      rule.Variable,
			"key":           rule.Key,
			"value":         rule.Value,
		},
	}).Err()
	if err != nil {
		log.Printf("events: failed to publish crs match: %v", err)
	}
}
