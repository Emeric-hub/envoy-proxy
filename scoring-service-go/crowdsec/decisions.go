// Package crowdsec is a 1:1 port of the original scoring-service's
// crowdsec_client.py: the LAPI decision-stream mirror (this file) and the
// two file-based log feeds (feed.go).
package crowdsec

import (
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
	crowdsecURL = envStr("CROWDSEC_URL", "http://crowdsec:8080")
	apiKey      = envStr("CROWDSEC_API_KEY", "")
	// Only bounds the background stream poll now (GetDecisions is a local
	// map read, no network call) — generous since nothing on the request
	// path waits on it.
	timeout      = envDuration("CROWDSEC_TIMEOUT", 2*time.Second)
	enabled      = envBool("ENABLE_CROWDSEC", true)
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

// Real CrowdSec bouncers don't query the LAPI per request — they poll
// /v1/decisions/stream on an interval and keep a local mirror, so the
// actual per-request lookup is a free map read instead of a network
// round-trip on every single request. This is that local mirror.
var (
	decisionsMu  sync.RWMutex
	decisionsByIP = map[string]map[string]scoring.CrowdsecDecision{}
)

var (
	lastPollOK atomic.Bool
	statusMu   sync.Mutex
	lastPollAt string
	lastError  string
)

type streamDecision struct {
	UUID     string `json:"uuid"`
	Value    string `json:"value"`
	Type     string `json:"type"`
	Scenario string `json:"scenario"`
}

type streamResponse struct {
	New     []streamDecision `json:"new"`
	Deleted []streamDecision `json:"deleted"`
}

// PollDecisionsStream keeps decisionsByIP in sync with CrowdSec's LAPI.
// First call uses startup=true and gets the full current decision set;
// every call after that gets only what changed (new/deleted) since the
// previous one. Runs forever; on failure, logs and retries next interval
// rather than crashing the process. Intended to run in its own goroutine
// for the process lifetime.
func PollDecisionsStream() {
	if !enabled {
		return
	}
	client := &http.Client{Timeout: timeout}
	first := true
	for {
		url := crowdsecURL + "/v1/decisions/stream"
		if first {
			url += "?startup=true"
		}
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		req.Header.Set("X-Api-Key", apiKey)

		resp, err := client.Do(req)
		ok := false
		if err != nil {
			setError(err.Error())
		} else {
			if resp.StatusCode >= 300 {
				setError("status " + strconv.Itoa(resp.StatusCode))
			} else {
				var data streamResponse
				if decodeErr := json.NewDecoder(resp.Body).Decode(&data); decodeErr != nil {
					setError(decodeErr.Error())
				} else {
					applyStreamUpdate(data)
					first = false
					ok = true
					setError("")
				}
			}
			resp.Body.Close()
		}
		lastPollOK.Store(ok)
		if !ok {
			log.Printf("crowdsec stream poll failed, will retry")
		}
		setLastPollAt(time.Now().UTC().Format(time.RFC3339Nano))
		time.Sleep(pollInterval)
	}
}

func applyStreamUpdate(data streamResponse) {
	decisionsMu.Lock()
	defer decisionsMu.Unlock()
	for _, d := range data.New {
		if decisionsByIP[d.Value] == nil {
			decisionsByIP[d.Value] = map[string]scoring.CrowdsecDecision{}
		}
		decisionsByIP[d.Value][d.UUID] = scoring.CrowdsecDecision{
			UUID: d.UUID, Value: d.Value, Type: d.Type, Scenario: d.Scenario,
		}
	}
	for _, d := range data.Deleted {
		if m, ok := decisionsByIP[d.Value]; ok {
			delete(m, d.UUID)
		}
	}
}

func setError(s string) {
	statusMu.Lock()
	lastError = s
	statusMu.Unlock()
}

func setLastPollAt(s string) {
	statusMu.Lock()
	lastPollAt = s
	statusMu.Unlock()
}

// Status is a real connectivity check, not just whether ENABLE_CROWDSEC is
// set — reflects whether the last actual poll of CrowdSec's LAPI succeeded.
func Status() map[string]any {
	statusMu.Lock()
	at, errStr := lastPollAt, lastError
	statusMu.Unlock()

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

// GetDecisions is advisory only — CrowdSec's agent never blocks anything
// itself here; it only accumulates decisions from the feed in feed.go.
// This reads the local mirror kept in sync by PollDecisionsStream, not a
// live LAPI call. Reflects prior requests, not necessarily this one:
// CrowdSec needs to see a pattern across multiple requests before it
// decides, so the exact request that first crosses a scenario's threshold
// can still slip through once — expected, not a bug.
func GetDecisions(ip string) []scoring.CrowdsecDecision {
	if !enabled || ip == "" || ip == "unknown" {
		return nil
	}
	decisionsMu.RLock()
	defer decisionsMu.RUnlock()
	m := decisionsByIP[ip]
	if len(m) == 0 {
		return nil
	}
	out := make([]scoring.CrowdsecDecision, 0, len(m))
	for _, d := range m {
		out = append(out, d)
	}
	return out
}
