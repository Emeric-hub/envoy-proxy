// Package scoring is a 1:1 port of the original Python scoring-service's
// scoring.py — single source of truth for how each tool's raw output maps
// to a [0, 1] signal, kept free of I/O so it's trivially testable.
package scoring

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// A single CRS "critical" rule match (severity weight 5) shouldn't alone
// cross RiskThreshold; two matches, or one plus CrowdSec, should.
const corazaScoreDivisor = 10.0

var (
	RiskThreshold = envFloat("RISK_THRESHOLD", 0.8)
	// When true, scoring/decisions/reasons are computed and published
	// exactly as normal (so the dashboard shows what *would* happen) but
	// nothing is actually enforced — every response is allowed regardless
	// of decision.
	AuditMode = envBool("AUDIT_MODE", false)
)

func envFloat(name string, def float64) float64 {
	if v, ok := os.LookupEnv(name); ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
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

// MatchedRule mirrors coraza-service's matchedRuleOut JSON shape.
type MatchedRule struct {
	ID           int      `json:"id"`
	Message      string   `json:"message"`
	Severity     string   `json:"severity"`
	SeverityCode int      `json:"severity_code"`
	Tags         []string `json:"tags"`
	Variable     string   `json:"variable,omitempty"`
	Key          string   `json:"key,omitempty"`
	Value        string   `json:"value,omitempty"`
}

// CrowdsecDecision mirrors one entry from CrowdSec's LAPI decisions stream.
type CrowdsecDecision struct {
	UUID     string `json:"uuid"`
	Value    string `json:"value"`
	Type     string `json:"type"`
	Scenario string `json:"scenario"`
}

// NormalizeSignals: single source of truth for how each tool's raw output
// maps to a [0, 1] signal — CombineScores and BuildReasons both read from
// this so they can never disagree about what each tool contributed. A
// CrowdSec decision is already the output of its own scenario thresholding
// (capacity/leakspeed), so it's treated as maximal rather than normalized
// like Coraza's raw score.
func NormalizeSignals(corazaAnomalyScore int, crowdsecDecisions []CrowdsecDecision) map[string]float64 {
	coraza := float64(corazaAnomalyScore) / corazaScoreDivisor
	if coraza > 1.0 {
		coraza = 1.0
	}
	crowdsec := 0.0
	if len(crowdsecDecisions) > 0 {
		crowdsec = 1.0
	}
	return map[string]float64{"coraza": coraza, "crowdsec": crowdsec}
}

// CombineScores fuses the advisory signals from Coraza/CRS and CrowdSec.
// Neither ever blocks on its own — they're just signals folded into one
// decision.
func CombineScores(signals map[string]float64) float64 {
	max := 0.0
	for _, v := range signals {
		if v > max {
			max = v
		}
	}
	return max
}

// BuildReasons: human-readable breakdown of what produced the final score,
// ordered so the signal that actually drove CombineScores' max() reads
// first. A tool that found nothing contributes no line.
func BuildReasons(signals map[string]float64, matchedRules []MatchedRule, crowdsecDecisions []CrowdsecDecision) []string {
	type group struct {
		score float64
		lines []string
	}

	corazaLines := make([]string, 0, len(matchedRules))
	for _, rule := range matchedRules {
		msg := rule.Message
		if msg == "" {
			msg = strings.Join(rule.Tags, ", ")
		}
		corazaLines = append(corazaLines, fmt.Sprintf("CRS %d [%s]: %s", rule.ID, rule.Severity, msg))
	}

	crowdsecLines := make([]string, 0, len(crowdsecDecisions))
	for _, d := range crowdsecDecisions {
		crowdsecLines = append(crowdsecLines, fmt.Sprintf("CrowdSec [%s]: active %s decision", d.Scenario, d.Type))
	}

	groups := []group{
		{signals["coraza"], corazaLines},
		{signals["crowdsec"], crowdsecLines},
	}
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].score > groups[j].score })

	reasons := []string{}
	for _, g := range groups {
		reasons = append(reasons, g.lines...)
	}
	return reasons
}
