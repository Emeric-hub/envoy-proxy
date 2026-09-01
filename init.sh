#!/usr/bin/env bash
# One-time (but safe to re-run) local bootstrap for a fresh checkout:
#   1. Creates .env from .env.example if it doesn't exist yet.
#   2. Replaces the placeholder CrowdSec bouncer key with a random one.
#   3. Generates a self-signed cert/key for every ssl=true domain in
#      envoy-control-plane/routes/routes.csv, plus a "default" one backing
#      the HTTPS listener's fallback filter chain (unmatched/no SNI) —
#      skips any that already exist, see generate-cert.sh.
#   4. Touches crowdsec/feed/access.log and modsecurity.log — CrowdSec's file
#      datasource only globs for matches once at startup and never retries,
#      so both must exist before `docker compose up` runs crowdsec for the
#      first time.
#
# Usage: ./init.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env from .env.example"
else
  echo ".env already exists, leaving it alone"
fi

PLACEHOLDER="devbouncerkeychangeme"
if grep -q "^CROWDSEC_BOUNCER_KEY=${PLACEHOLDER}$" .env; then
  NEW_KEY="$(openssl rand -hex 32)"
  # Portable in-place sed: macOS/BSD sed requires an argument to -i, GNU
  # sed treats that argument as a suffix — the empty-string-as-next-arg
  # form works identically on both.
  sed -i.bak "s/^CROWDSEC_BOUNCER_KEY=${PLACEHOLDER}$/CROWDSEC_BOUNCER_KEY=${NEW_KEY}/" .env
  rm -f .env.bak
  echo "Replaced the default CrowdSec bouncer key with a random one"
else
  echo "CROWDSEC_BOUNCER_KEY already customized, leaving it alone"
fi

echo
echo "Generating TLS certificates for ssl=true domains in routes.csv..."
ROUTES_CSV="$ROOT/envoy-control-plane/routes/routes.csv"
while IFS=',' read -r id domain target port ssl cert_check scoring; do
  [[ "$id" == "id" || -z "$id" ]] && continue
  if [[ "$(echo "$ssl" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')" == "true" ]]; then
    "$ROOT/generate-cert.sh" "$(echo "$domain" | tr -d '[:space:]')"
  fi
done < "$ROUTES_CSV"

echo
echo "Generating the fallback cert for unmatched HTTPS SNI..."
"$ROOT/generate-cert.sh" default

mkdir -p "$ROOT/crowdsec/feed"
touch "$ROOT/crowdsec/feed/access.log" "$ROOT/crowdsec/feed/modsecurity.log"
echo
echo "crowdsec/feed/{access,modsecurity}.log ready"
echo
echo "Done. Next: docker compose up -d --build"
