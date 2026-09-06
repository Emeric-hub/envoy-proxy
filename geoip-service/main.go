// geoip-service resolves a source IP to an approximate real-world location
// (country, city, lat/lon) using a local MaxMind GeoLite2-City database —
// no per-lookup call to MaxMind, only a periodic database refresh. Every
// other service in this repo that enriches a request (coraza-service,
// crowdsec) is a local, self-contained check; this is the one exception,
// since accurate IP geolocation genuinely requires a maintained third-party
// dataset. That's a deliberate, opt-in trade-off (ENABLE_GEOIP defaults to
// off in scoring-service) — see README.md before enabling it.
//
// Requires a free MaxMind account + license key
// (https://www.maxmind.com/en/geolite2/signup) to actually download or
// refresh the database. Get sign-off from whoever owns third-party service
// approvals in your organization before wiring up real credentials here —
// this reaches out to MaxMind's servers on a schedule, not just once.
package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

func envOr(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

func envOrInt(name string, def int) int {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

var (
	accountID       = envOr("GEOIP_ACCOUNT_ID", "")
	licenseKey      = envOr("GEOIP_LICENSE_KEY", "")
	edition         = envOr("GEOIP_EDITION", "GeoLite2-City")
	dbPath          = envOr("GEOIP_DB_PATH", "/data/GeoLite2-City.mmdb")
	downloadURLBase = envOr("GEOIP_DOWNLOAD_URL", "https://download.maxmind.com/geoip/databases")
	refreshInterval = time.Duration(envOrInt("GEOIP_REFRESH_INTERVAL_H", 24)) * time.Hour
	listenAddr      = envOr("GEOIP_LISTEN_ADDR", ":8092")
)

// state is swapped as a whole unit under mu so a lookup never sees a
// half-updated reader/timestamp pair.
type state struct {
	reader    *geoip2.Reader
	loadedAt  time.Time
	lastError string
	lastCheck time.Time
}

var (
	mu      sync.RWMutex
	current state
)

func getState() state {
	mu.RLock()
	defer mu.RUnlock()
	return current
}

func setState(s state) {
	mu.Lock()
	current = s
	mu.Unlock()
}

// downloadDatabase fetches the current edition tarball via MaxMind's
// database-download API (HTTP Basic Auth: account ID + license key),
// extracts the single .mmdb entry from the tar.gz stream, and writes it to
// a temp file in the same directory before renaming over dbPath — the
// rename is atomic on the same filesystem, so a concurrent lookup never
// sees a partially-written database.
func downloadDatabase() error {
	if accountID == "" || licenseKey == "" {
		return fmt.Errorf("GEOIP_ACCOUNT_ID/GEOIP_LICENSE_KEY not set")
	}
	url := fmt.Sprintf("%s/%s/download?suffix=tar.gz", downloadURLBase, edition)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(accountID + ":" + licenseKey))
	req.Header.Set("Authorization", "Basic "+auth)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("download failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	tmpPath := dbPath + ".tmp"
	tmp, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}

	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			tmp.Close()
			os.Remove(tmpPath)
			return fmt.Errorf("tar read: %w", err)
		}
		if strings.HasSuffix(hdr.Name, ".mmdb") {
			if _, err := io.Copy(tmp, tr); err != nil {
				tmp.Close()
				os.Remove(tmpPath)
				return fmt.Errorf("extracting %s: %w", hdr.Name, err)
			}
			found = true
			break
		}
	}
	tmp.Close()
	if !found {
		os.Remove(tmpPath)
		return fmt.Errorf("no .mmdb file found in downloaded archive")
	}
	if err := os.Rename(tmpPath, dbPath); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}

// loadFromDisk opens whatever's currently at dbPath (without downloading
// anything) — used both at startup (serve a persisted database
// immediately, before any refresh check) and after a successful download.
func loadFromDisk() error {
	reader, err := geoip2.Open(dbPath)
	if err != nil {
		return err
	}
	old := getState()
	if old.reader != nil {
		old.reader.Close()
	}
	setState(state{reader: reader, loadedAt: time.Now(), lastCheck: old.lastCheck, lastError: old.lastError})
	return nil
}

// refreshLoop runs once at startup (download only if dbPath is missing —
// an existing persisted database is served as-is until the next scheduled
// refresh, not re-downloaded on every restart) and then on
// GEOIP_REFRESH_INTERVAL_H thereafter. Failures are logged and recorded in
// /health but never fatal: a stale-but-present database, or simply no
// database yet, are both states this service is expected to run in and
// report honestly rather than crash-loop over.
func refreshLoop() {
	if _, err := os.Stat(dbPath); err == nil {
		if err := loadFromDisk(); err != nil {
			log.Printf("geoip: found %s but failed to open it: %v", dbPath, err)
		} else {
			log.Printf("geoip: loaded existing database from %s", dbPath)
		}
	}

	for {
		err := downloadDatabase()
		now := time.Now()
		s := getState()
		s.lastCheck = now
		if err != nil {
			s.lastError = err.Error()
			setState(s)
			log.Printf("geoip: refresh failed: %v", err)
		} else {
			s.lastError = ""
			setState(s)
			if err := loadFromDisk(); err != nil {
				log.Printf("geoip: downloaded a new database but failed to open it: %v", err)
			} else {
				log.Printf("geoip: refreshed database (edition %s)", edition)
			}
		}
		time.Sleep(refreshInterval)
	}
}

type lookupResponse struct {
	IP          string  `json:"ip"`
	Found       bool    `json:"found"`
	CountryCode string  `json:"country_code,omitempty"`
	CountryName string  `json:"country_name,omitempty"`
	City        string  `json:"city,omitempty"`
	Lat         float64 `json:"lat,omitempty"`
	Lon         float64 `json:"lon,omitempty"`
}

func handleLookup(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	w.Header().Set("Content-Type", "application/json")
	if ip == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "missing ip query param"})
		return
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid ip"})
		return
	}
	s := getState()
	if s.reader == nil {
		json.NewEncoder(w).Encode(lookupResponse{IP: ip, Found: false})
		return
	}
	record, err := s.reader.City(parsed)
	// Private/reserved ranges, malformed IPs, and addresses genuinely
	// absent from the database all land here — GeoLite2-City simply has no
	// entry for RFC1918 space, so this is the normal, expected outcome for
	// most local/demo traffic, not an error worth logging per request.
	if err != nil || record.Country.IsoCode == "" {
		json.NewEncoder(w).Encode(lookupResponse{IP: ip, Found: false})
		return
	}
	json.NewEncoder(w).Encode(lookupResponse{
		IP:          ip,
		Found:       true,
		CountryCode: record.Country.IsoCode,
		CountryName: record.Country.Names["en"],
		City:        record.City.Names["en"],
		Lat:         record.Location.Latitude,
		Lon:         record.Location.Longitude,
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	s := getState()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"loaded":     s.reader != nil,
		"loaded_at":  formatTime(s.loadedAt),
		"last_check": formatTime(s.lastCheck),
		"last_error": s.lastError,
		"edition":    edition,
		"configured": accountID != "" && licenseKey != "",
	})
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func main() {
	go refreshLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("/lookup", handleLookup)
	mux.HandleFunc("/health", handleHealth)

	log.Printf("geoip-service listening on %s (db: %s, edition: %s, refresh every %s)", listenAddr, dbPath, edition, refreshInterval)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}
