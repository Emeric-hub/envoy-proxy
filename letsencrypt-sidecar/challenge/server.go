// Package challenge serves HTTP-01 validation requests — Envoy's dedicated
// ACME-challenge listener (envoy-control-plane, built only when a route
// has letsencrypt=true) proxies everything to this.
package challenge

import (
	"net/http"
	"strings"

	"letsencrypt-sidecar/acme"
)

const wellKnownPrefix = "/.well-known/acme-challenge/"

// Serve blocks; call in a goroutine.
func Serve(addr string, store *acme.TokenStore) error {
	mux := http.NewServeMux()
	mux.HandleFunc(wellKnownPrefix, func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, wellKnownPrefix)
		keyAuth, ok := store.Get(token)
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(keyAuth))
	})
	return http.ListenAndServe(addr, mux)
}
