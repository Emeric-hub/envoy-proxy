#!/usr/bin/env bash
# Runs testssl.sh (containerized, no local install needed) against every
# ssl=true domain in envoy-control-plane/routes/routes.csv, then scores the
# results for TLS hardening / best practices via score.py — deliberately
# ignoring the self-signed-certificate finding, since these are self-signed
# dev certs by design (see generate-cert.sh), not a real hardening gap.
#
# Usage: ./run-audit.sh [domain ...]
#   No args: audits every ssl=true row in routes.csv.
#   With args: audits only the given domain(s) (must still be routable
#   through envoy, e.g. present in routes.csv with ssl=true).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROUTES_CSV="$ROOT/envoy-control-plane/routes/routes.csv"
SSL_AUDIT_DIR="$ROOT/ssl-audit"
REPORTS_DIR="$SSL_AUDIT_DIR/reports"
mkdir -p "$REPORTS_DIR"

# shellcheck disable=SC1091
[[ -f "$ROOT/.env" ]] && source "$ROOT/.env"
HTTPS_PORT="${ENVOY_HTTPS_PORT:-10443}"

if [[ $# -gt 0 ]]; then
  DOMAINS=("$@")
else
  DOMAINS=()
  while IFS=',' read -r id domain target port ssl cert_check scoring; do
    [[ "$id" == "id" ]] && continue # header
    [[ -z "$id" ]] && continue
    if [[ "$(echo "$ssl" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')" == "true" ]]; then
      DOMAINS+=("$(echo "$domain" | tr -d '[:space:]')")
    fi
  done < "$ROUTES_CSV"
fi

if [[ ${#DOMAINS[@]} -eq 0 ]]; then
  echo "No ssl=true domains found in $ROUTES_CSV — nothing to audit." >&2
  exit 1
fi

ENVOY_CID="$(cd "$ROOT" && docker compose ps -q envoy)"
if [[ -z "$ENVOY_CID" ]]; then
  echo "envoy service isn't running (docker compose up -d envoy first)." >&2
  exit 1
fi
ENVOY_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$ENVOY_CID")"
NETWORK="$(cd "$ROOT" && docker compose ps --format '{{.Networks}}' envoy | head -1)"

echo "Auditing ${#DOMAINS[@]} domain(s) via envoy at $ENVOY_IP:$HTTPS_PORT (network: $NETWORK)"

REPORT_FILES=()
for domain in "${DOMAINS[@]}"; do
  echo
  echo "=== $domain ==="
  out="$REPORTS_DIR/${domain}.json"
  rm -f "$out" # testssl.sh refuses to overwrite an existing report file
  docker run --rm --network "$NETWORK" \
    -v "$REPORTS_DIR:/reports" \
    drwetter/testssl.sh:latest \
    --quiet --color 0 --jsonfile-pretty "/reports/${domain}.json" \
    --ip="$ENVOY_IP" "${domain}:${HTTPS_PORT}"
  REPORT_FILES+=("$out")
done

echo
echo "=== Scoring ==="
python3 "$SSL_AUDIT_DIR/score.py" "${REPORT_FILES[@]}" \
  --out "$REPORTS_DIR/summary.md" \
  --html-out "$REPORTS_DIR/summary.html"
