// Package geoip is the HTTP client for geoip-service's /lookup endpoint —
// enriches a request's source IP with a real (approximate) location for
// the dashboard's attack globe. Advisory and cosmetic only: nothing in
// scoring/ ever reads a geoip result, so a slow or unreachable
// geoip-service can never affect an actual allow/deny decision, same
// posture as coraza/crowdsec being advisory to the composite score.
//
// Off by default (ENABLE_GEOIP=false) — unlike coraza/crowdsec, this
// depends on a third-party MaxMind account + license key
// (geoip-service/main.go), so it shouldn't turn on just because the
// container image happens to be present.
package geoip

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	geoipURL       = envStr("GEOIP_URL", "http://geoip-service:8092/lookup")
	geoipHealthURL = envStr("GEOIP_HEALTH_URL", "http://geoip-service:8092/health")
	timeout        = envDuration("GEOIP_TIMEOUT", 150*time.Millisecond)
	enabled        = envBool("ENABLE_GEOIP", false)
	// Same reuse-not-a-new-knob reasoning as coraza's own health poller.
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

// Result mirrors geoip-service's lookup response. Found is false whenever
// the IP isn't in the database (private/reserved ranges, most demo
// traffic) as well as whenever geoip-service itself is disabled,
// unreachable, or has no database loaded yet — callers can't tell those
// apart and don't need to: either way there's no real location to use.
type Result struct {
	Found       bool    `json:"found"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
}

// Lookup is advisory only — see the package doc comment. A short timeout
// (GEOIP_TIMEOUT, default 150ms) bounds how much latency this can ever add
// to a request; any failure just returns an empty (not found) Result
// rather than propagating an error the caller would have to handle.
func Lookup(ip string) Result {
	if !enabled {
		return Result{}
	}
	resp, err := httpClient.Get(geoipURL + "?ip=" + url.QueryEscape(ip))
	if err != nil {
		log.Printf("geoip lookup unavailable, continuing without it: %v", err)
		return Result{}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return Result{}
	}
	var out Result
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		log.Printf("geoip lookup unavailable, continuing without it: %v", err)
		return Result{}
	}
	return out
}

// Live connectivity state, updated by PollHealth below — see Status(),
// same pattern as coraza.Status()/crowdsec.Status().
var (
	lastPollOK atomic.Bool
	lastPollMu sync.Mutex
	lastPollAt string
	lastError  string
)

// PollHealth periodically pings geoip-service's /health, independent of
// real traffic, same reasoning as coraza.PollHealth(). Runs forever;
// intended to run in its own goroutine for the process lifetime.
func PollHealth() {
	if !enabled {
		return
	}
	healthClient := &http.Client{Timeout: timeout}
	for {
		resp, err := healthClient.Get(geoipHealthURL)
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

// Status is a real connectivity check, not just whether geoip is enabled —
// reflects whether the last actual /health poll succeeded.
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
