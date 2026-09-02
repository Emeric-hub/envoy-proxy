// letsencrypt-sidecar issues and renews Let's Encrypt certificates for
// any routes.csv row with letsencrypt=true, dropping them into the same
// envoy/ssl/ directory envoy-control-plane already hot-reloads from.
//
// Real issuance needs a real, owned, publicly-resolvable domain with port
// 80 reachable from the internet — Let's Encrypt's HTTP-01 challenge has
// no way around that. Against this repo's own demo domains
// (*.example.com, IANA-reserved, not publicly resolvable, running on
// localhost with no public exposure), issuance will correctly fail at the
// DNS/connectivity step every time — that's expected, not a bug, and
// confirms the plumbing up to that boundary is correct.
package main

import (
	"encoding/csv"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"letsencrypt-sidecar/acme"
	"letsencrypt-sidecar/certstore"
	"letsencrypt-sidecar/challenge"
)

type routeRow struct {
	Domain      string
	LetsEncrypt bool
}

// loadRoutes is a small, self-contained CSV parse — not worth a shared Go
// package with envoy-control-plane (a separate module) for ~10 lines.
// Column 7 (0-indexed) is "letsencrypt", the 8th column added alongside
// envoy-control-plane's own route struct.
func loadRoutes(path string) ([]routeRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}

	var rows []routeRow
	for i, rec := range records[1:] { // skip header
		if len(rec) < 8 {
			log.Printf("routes.csv line %d: expected 8 columns, got %d, skipping", i+2, len(rec))
			continue
		}
		rows = append(rows, routeRow{
			Domain:      strings.TrimSpace(rec[1]),
			LetsEncrypt: strings.EqualFold(strings.TrimSpace(rec[7]), "true"),
		})
	}
	return rows, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("%s is required", key)
	}
	return v
}

func envBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
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

func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok {
		if i, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return i
		}
	}
	return def
}

func main() {
	email := mustEnv("LETSENCRYPT_EMAIL")
	staging := envBool("LETSENCRYPT_STAGING", true)
	sslDir := envOr("SSL_DIR", "/etc/envoy-cp/ssl")
	routesCSV := envOr("ROUTES_CSV", "/etc/envoy-cp/routes/routes.csv")
	accountDir := envOr("ACCOUNT_DIR", "/lego")
	challengeAddr := envOr("CHALLENGE_ADDR", ":8090")
	renewBefore := time.Duration(envInt("ACME_RENEW_DAYS_BEFORE", 30)) * 24 * time.Hour
	checkInterval := time.Duration(envInt("ACME_CHECK_INTERVAL_H", 12)) * time.Hour

	log.Printf("letsencrypt-sidecar: staging=%v renew_before=%s check_interval=%s", staging, renewBefore, checkInterval)

	store := acme.NewTokenStore()
	go func() {
		log.Fatalf("challenge server exited: %v", challenge.Serve(challengeAddr, store))
	}()

	client, err := acme.NewClient(acme.ClientConfig{
		Email:      email,
		Staging:    staging,
		AccountDir: accountDir,
		Provider:   store,
	})
	if err != nil {
		log.Fatalf("acme client setup: %v", err)
	}

	for {
		routes, err := loadRoutes(routesCSV)
		if err != nil {
			log.Printf("reading %s: %v", routesCSV, err)
		} else {
			managed := 0
			for _, r := range routes {
				if !r.LetsEncrypt {
					continue
				}
				managed++
				processDomain(client, sslDir, r.Domain, renewBefore)
			}
			log.Printf("checked %d letsencrypt=true domain(s)", managed)
		}
		time.Sleep(checkInterval)
	}
}

func processDomain(client *acme.Client, sslDir, domain string, renewBefore time.Duration) {
	expiry, err := certstore.ReadExpiry(sslDir, domain)
	if err != nil {
		log.Printf("%s: reading current cert: %v", domain, err)
	}
	if !expiry.IsZero() && time.Until(expiry) > renewBefore {
		return // still valid for a while, nothing to do
	}

	log.Printf("%s: issuing/renewing certificate", domain)
	certPEM, keyPEM, err := client.ObtainCertificate(domain)
	if err != nil {
		log.Printf("%s: issuance failed: %v", domain, err)
		if err := certstore.WriteStatus(sslDir, domain, "failed", err.Error()); err != nil {
			log.Printf("%s: also failed to record status: %v", domain, err)
		}
		return
	}
	if err := certstore.WriteCert(sslDir, domain, certPEM, keyPEM); err != nil {
		log.Printf("%s: writing cert: %v", domain, err)
		_ = certstore.WriteStatus(sslDir, domain, "failed", err.Error())
		return
	}
	log.Printf("%s: certificate issued/renewed successfully", domain)
}
