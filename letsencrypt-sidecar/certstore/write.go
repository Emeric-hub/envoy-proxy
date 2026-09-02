// Package certstore writes issued certificates into the same envoy/ssl/
// directory envoy-control-plane already watches (fsnotify) and hot-loads
// from — no new integration point needed on that side, this just has to
// match the existing flat <domain>.crt/<domain>.key naming exactly.
package certstore

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// WriteCert atomically writes <domain>.crt/.key (temp file + rename —
// these are fetched over the network, unlike the single-openssl-call
// self-signed flow in generate-cert.sh that never had to worry about a
// partial write), plus a flat plain-text <domain>.expiry file. Matches
// this repo's existing sidecar-metadata convention (coraza-service's
// VERSION/FETCHED_AT/PARANOIA_LEVEL — single value per file, not JSON)
// rather than inventing a new format.
func WriteCert(sslDir, domain string, certPEM, keyPEM []byte) error {
	if err := atomicWrite(filepath.Join(sslDir, domain+".crt"), certPEM, 0o644); err != nil {
		return fmt.Errorf("writing cert: %w", err)
	}
	// 0600, not generate-cert.sh's 0644 — that permissiveness was
	// explicitly justified there only for throwaway self-signed dev keys;
	// a real ACME-issued key is real credential material.
	if err := atomicWrite(filepath.Join(sslDir, domain+".key"), keyPEM, 0o600); err != nil {
		return fmt.Errorf("writing key: %w", err)
	}

	expiry, err := certExpiry(certPEM)
	if err != nil {
		return fmt.Errorf("parsing issued cert: %w", err)
	}
	if err := atomicWrite(filepath.Join(sslDir, domain+".expiry"), []byte(expiry.Format(time.RFC3339)+"\n"), 0o644); err != nil {
		return fmt.Errorf("writing expiry: %w", err)
	}
	return WriteStatus(sslDir, domain, "ok", "")
}

// WriteStatus is separate from WriteCert so a failed renewal attempt can
// record status=failed + the error without ever touching (let alone
// deleting) a still-valid existing cert — only ReadExpiry decides whether
// a new attempt is even needed.
func WriteStatus(sslDir, domain, status, lastError string) error {
	if err := atomicWrite(filepath.Join(sslDir, domain+".acme-status"), []byte(status+"\n"), 0o644); err != nil {
		return err
	}
	errPath := filepath.Join(sslDir, domain+".acme-error")
	if lastError == "" {
		_ = os.Remove(errPath) // clear a stale error once a later attempt succeeds
		return nil
	}
	return atomicWrite(errPath, []byte(lastError+"\n"), 0o644)
}

// ReadExpiry returns the current cert's NotAfter, or the zero time if no
// cert exists yet (treated as "needs issuance", not an error).
func ReadExpiry(sslDir, domain string) (time.Time, error) {
	data, err := os.ReadFile(filepath.Join(sslDir, domain+".crt"))
	if os.IsNotExist(err) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return certExpiry(data)
}

func certExpiry(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, fmt.Errorf("no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

func atomicWrite(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
