// coraza-service runs the Coraza WAF engine with the OWASP Core Rule Set in
// SecRuleEngine DetectionOnly mode: it never blocks a request itself. It only
// scores each request (summing matched-rule severities) and reports the
// score plus which rules fired, for the scoring-service to fold into its own
// allow/deny decision.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/fsnotify/fsnotify"
)

const baseDirectives = `
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecRequestBodyInMemoryLimit 131072
SecRequestBodyLimitAction ProcessPartial
SecDataDir /tmp/
`

type checkRequest struct {
	Method   string            `json:"method"`
	Path     string            `json:"path"`
	Query    string            `json:"query"`
	Headers  map[string]string `json:"headers"`
	Body     string            `json:"body"`
	ClientIP string            `json:"client_ip"`
}

type matchedRuleOut struct {
	ID       int      `json:"id"`
	Message  string   `json:"message"`
	Severity string   `json:"severity"`
	Tags     []string `json:"tags"`
}

type checkResponse struct {
	AnomalyScore int              `json:"anomaly_score"`
	MatchedRules []matchedRuleOut `json:"matched_rules"`
}

// severityWeight mirrors CRS's own severity-to-score convention
// (critical:5, error:4, warning:3, notice:2) so the number we hand back means
// the same thing CRS's own blocking-evaluation rule would have used.
func severityWeight(s types.RuleSeverity) int {
	switch s {
	case types.RuleSeverityEmergency, types.RuleSeverityAlert, types.RuleSeverityCritical:
		return 5
	case types.RuleSeverityError:
		return 4
	case types.RuleSeverityWarning:
		return 3
	case types.RuleSeverityNotice:
		return 2
	default:
		return 0
	}
}

// wafHolder lets us hot-swap the live WAF instance (see reloadWAF/watchExclusions)
// without a pointer-to-interface, which atomic.Pointer handles awkwardly.
type wafHolder struct {
	waf coraza.WAF
}

var current atomic.Pointer[wafHolder]

// buildWAF loads CRS itself, then — if present — the local exclusions file.
// Exclusions must load after CRS's own rules: SecRuleRemoveById and friends
// operate on already-registered rule IDs (see crs-exclusions/crs_exclusion.conf).
// Missing exclusions file is not an error — it's optional.
func buildWAF(crsDir, exclusionsPath string) (coraza.WAF, error) {
	config := coraza.NewWAFConfig().
		WithDirectives(baseDirectives).
		WithDirectivesFromFile(crsDir + "/main.conf")

	if _, err := os.Stat(exclusionsPath); err == nil {
		config = config.WithDirectivesFromFile(exclusionsPath)
	} else {
		log.Printf("no exclusions file at %s, skipping (%v)", exclusionsPath, err)
	}

	return coraza.NewWAF(config)
}

// reloadWAF rebuilds the WAF and swaps it in atomically. A failed reload (e.g.
// a syntax error just introduced in the exclusions file) logs and keeps
// serving the previous, still-valid instance rather than taking the service down.
func reloadWAF(crsDir, exclusionsPath string) {
	waf, err := buildWAF(crsDir, exclusionsPath)
	if err != nil {
		log.Printf("WAF reload failed, keeping previous instance: %v", err)
		return
	}
	current.Store(&wafHolder{waf: waf})
	log.Printf("WAF reloaded (exclusions: %s)", exclusionsPath)
}

// watchExclusions hot-reloads the WAF whenever the exclusions file changes —
// no restart needed. Watches the containing directory rather than the file
// itself: editors commonly save via a temp-file-then-rename, which can leave
// a direct file watch pointing at a now-detached inode.
func watchExclusions(crsDir, exclusionsPath string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("fsnotify unavailable, exclusions hot-reload disabled: %v", err)
		return
	}
	defer watcher.Close()

	dir := filepath.Dir(exclusionsPath)
	if err := watcher.Add(dir); err != nil {
		log.Printf("failed to watch %s, exclusions hot-reload disabled: %v", dir, err)
		return
	}

	var debounce *time.Timer
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if filepath.Clean(event.Name) != filepath.Clean(exclusionsPath) {
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			// debounce: editors/docker bind-mount syncs often fire several
			// events for what's conceptually a single save
			if debounce != nil {
				debounce.Stop()
			}
			debounce = time.AfterFunc(300*time.Millisecond, func() { reloadWAF(crsDir, exclusionsPath) })
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("fsnotify error: %v", err)
		}
	}
}

func newHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req checkRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		waf := current.Load().waf
		tx := waf.NewTransaction()
		defer func() {
			tx.ProcessLogging()
			_ = tx.Close()
		}()

		tx.ProcessConnection(req.ClientIP, 0, "", 0)
		uri := req.Path
		if req.Query != "" {
			uri += "?" + req.Query
		}
		tx.ProcessURI(uri, req.Method, "HTTP/1.1")
		// ProcessURI parses the URI but deliberately doesn't populate ARGS_GET;
		// that has to be fed in separately.
		if values, err := url.ParseQuery(req.Query); err == nil {
			for key, vals := range values {
				for _, v := range vals {
					tx.AddGetRequestArgument(key, v)
				}
			}
		}
		for k, v := range req.Headers {
			tx.AddRequestHeader(k, v)
		}
		tx.ProcessRequestHeaders()

		if req.Body != "" {
			if _, _, err := tx.WriteRequestBody([]byte(req.Body)); err != nil {
				log.Printf("write request body: %v", err)
			}
		}
		if _, err := tx.ProcessRequestBody(); err != nil {
			log.Printf("process request body: %v", err)
		}

		score := 0
		matched := make([]matchedRuleOut, 0)
		for _, mr := range tx.MatchedRules() {
			rule := mr.Rule()
			score += severityWeight(rule.Severity())
			matched = append(matched, matchedRuleOut{
				ID:       rule.ID(),
				Message:  mr.Message(),
				Severity: rule.Severity().String(),
				Tags:     rule.Tags(),
			})
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(checkResponse{AnomalyScore: score, MatchedRules: matched})
	}
}

func main() {
	crsDir := "/etc/coraza"
	if v := os.Getenv("CRS_DIR"); v != "" {
		crsDir = v
	}
	exclusionsPath := "/etc/coraza-exclusions/crs_exclusion.conf"
	if v := os.Getenv("EXCLUSIONS_FILE"); v != "" {
		exclusionsPath = v
	}
	crsVersion := os.Getenv("CRS_VERSION")
	if crsVersion == "" {
		crsVersion = "4.29.0"
	}
	paranoiaLevel := os.Getenv("CRS_PARANOIA_LEVEL")
	if paranoiaLevel == "" {
		paranoiaLevel = "1"
	}

	if err := ensureCRS(crsDir, crsVersion, paranoiaLevel); err != nil {
		log.Fatalf("failed to ensure CRS is available: %v", err)
	}

	// CRS's rules reference .data files (e.g. scanners-user-agents.data) by bare
	// relative name; Coraza resolves those against the directory of whichever
	// file WithDirectivesFromFile loaded, so that file (main.conf) and the .data
	// files must live side by side — see fetchCRS in crs_fetch.go.
	waf, err := buildWAF(crsDir, exclusionsPath)
	if err != nil {
		log.Fatalf("failed to initialize coraza WAF: %v", err)
	}
	current.Store(&wafHolder{waf: waf})

	go watchExclusions(crsDir, exclusionsPath)

	http.HandleFunc("/check", newHandler())
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	// Manual fallback alongside the file watcher: some bind-mount setups don't
	// propagate inotify events reliably, so this guarantees a way to pick up
	// exclusions changes without restarting the container.
	http.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		reloadWAF(crsDir, exclusionsPath)
		w.WriteHeader(http.StatusOK)
	})

	addr := ":8003"
	if v := os.Getenv("LISTEN_ADDR"); v != "" {
		addr = v
	}
	log.Printf("coraza-service listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
