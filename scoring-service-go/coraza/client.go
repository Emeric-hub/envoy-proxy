// Package coraza is the HTTP client for coraza-service's /check endpoint —
// a 1:1 port of the original scoring-service's coraza_client.py.
package coraza

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"scoring-service-go/scoring"
)

var (
	corazaURL       = envStr("CORAZA_URL", "http://coraza-service:8003/check")
	corazaHealthURL = envStr("CORAZA_HEALTH_URL", "http://coraza-service:8003/healthz")
	timeout         = envDuration("CORAZA_TIMEOUT", 200*time.Millisecond)
	enabled         = envBool("ENABLE_CORAZA", true)
	// Reuses the same poll cadence as the crowdsec stream poller — no need
	// for a separate knob for what's conceptually the same kind of
	// background check.
	pollInterval = envDuration("CROWDSEC_POLL_INTERVAL", 10*time.Second)
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

func envDuration(name string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(name); ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return time.Duration(f * float64(time.Second))
		}
	}
	return def
}

var httpClient = &http.Client{Timeout: timeout}

type checkRequestBody struct {
	Method   string            `json:"method"`
	Path     string            `json:"path"`
	Query    string            `json:"query"`
	Headers  map[string]string `json:"headers"`
	Body     string            `json:"body"`
	ClientIP string            `json:"client_ip"`
}

type checkResponseBody struct {
	AnomalyScore int                    `json:"anomaly_score"`
	MatchedRules []scoring.MatchedRule `json:"matched_rules"`
}

// GetAnomalyScore is advisory only — Coraza runs in SecRuleEngine
// DetectionOnly and never blocks on its own. If it's slow or unreachable,
// contribute nothing rather than delay or fail the actual scoring
// decision. Returns matched rules with CRS's own nolog bookkeeping/init
// rules (severity "unknown"/empty, weight 0) filtered out — coraza-service
// includes them, filtering is the caller's job, same as the Python version.
func GetAnomalyScore(method, path, query string, headers map[string]string, body []byte, clientIP string) (int, []scoring.MatchedRule) {
	if !enabled {
		return 0, nil
	}
	reqBody := checkRequestBody{
		Method:   method,
		Path:     path,
		Query:    query,
		Headers:  headers,
		Body:     string(body),
		ClientIP: clientIP,
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		log.Printf("coraza: failed to marshal request: %v", err)
		return 0, nil
	}
	resp, err := httpClient.Post(corazaURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Printf("coraza scoring unavailable, continuing without it: %v", err)
		return 0, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("coraza scoring unavailable, continuing without it: status %d", resp.StatusCode)
		return 0, nil
	}
	var data checkResponseBody
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		log.Printf("coraza scoring unavailable, continuing without it: %v", err)
		return 0, nil
	}
	matched := make([]scoring.MatchedRule, 0, len(data.MatchedRules))
	for _, rule := range data.MatchedRules {
		if rule.Severity != "" && rule.Severity != "unknown" {
			matched = append(matched, rule)
		}
	}
	return data.AnomalyScore, matched
}

// Live connectivity state, updated by PollHealth below — see Status().
var (
	lastPollOK    atomic.Bool
	lastPollMu    sync.Mutex
	lastPollAt    string
	lastError     string
)

// PollHealth periodically pings coraza-service's /healthz, independent of
// real traffic — a fresh deployment with zero requests yet should still
// show a real status rather than "unknown until someone gets scored." Runs
// forever; a failed check just updates the status, never crashes the
// process. Intended to run in its own goroutine for the process lifetime.
func PollHealth() {
	if !enabled {
		return
	}
	healthClient := &http.Client{Timeout: timeout}
	for {
		resp, err := healthClient.Get(corazaHealthURL)
		if err == nil && resp.StatusCode < 300 {
			lastPollOK.Store(true)
			setLastError("")
		} else {
			lastPollOK.Store(false)
			if err != nil {
				setLastError(err.Error())
			} else {
				setLastError("status " + strconv.Itoa(resp.StatusCode))
			}
		}
		if resp != nil {
			resp.Body.Close()
		}
		setLastPollAt(time.Now().UTC().Format(time.RFC3339Nano))
		time.Sleep(pollInterval)
	}
}

func setLastError(s string) {
	lastPollMu.Lock()
	lastError = s
	lastPollMu.Unlock()
}

func setLastPollAt(s string) {
	lastPollMu.Lock()
	lastPollAt = s
	lastPollMu.Unlock()
}

// Status is a real connectivity check, not just whether coraza is enabled
// — reflects whether the last actual /healthz poll succeeded.
func Status() map[string]any {
	lastPollMu.Lock()
	at, errStr := lastPollAt, lastError
	lastPollMu.Unlock()

	var connected any
	if enabled {
		connected = lastPollOK.Load()
	}
	var lastErr any
	if errStr != "" {
		lastErr = errStr
	}
	var lastAt any
	if at != "" {
		lastAt = at
	}
	return map[string]any{
		"enabled":      enabled,
		"connected":    connected,
		"last_poll_at": lastAt,
		"last_error":   lastErr,
	}
}
