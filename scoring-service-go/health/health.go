// Package health serves the plain-HTTP /health endpoint the dashboard
// proxies (dashboard/app/main.py's api_status()) — unrelated to the
// ext_authz gRPC protocol, kept as a normal HTTP endpoint alongside it.
package health

import (
	"encoding/json"
	"net/http"

	"scoring-service-go/coraza"
	"scoring-service-go/crowdsec"
	"scoring-service-go/geoip"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"crowdsec": crowdsec.Status(),
		"coraza":   coraza.Status(),
		"geoip":    geoip.Status(),
	})
}
