#!/usr/bin/env bash
# Generates a self-signed cert/key pair for a domain into SSL_DIR (.env,
# default envoy/ssl) if one doesn't already exist there. Used for routes.csv
# rows with ssl=true — Envoy terminates TLS for that domain using whatever
# cert/key is named after it.
#
# Usage: ./generate-cert.sh <domain> [days]

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOMAIN="${1:?Usage: ./generate-cert.sh <domain> [days]}"
# 397, not a round number: the CA/Browser Forum baseline caps publicly
# trusted certs at 398 days: testssl.sh flags anything over that as a
# hardening finding (cert_extlifeSpan). These certs are self-signed and
# never leave this demo, but there's no reason not to match the real limit.
DAYS="${2:-397}"

# shellcheck disable=SC1091
[[ -f "$ROOT/.env" ]] && source "$ROOT/.env"
DIR="$ROOT/${SSL_DIR:-envoy/ssl}"
mkdir -p "$DIR"

CRT="$DIR/$DOMAIN.crt"
KEY="$DIR/$DOMAIN.key"

if [[ -f "$CRT" && -f "$KEY" ]]; then
  echo "Certificate for $DOMAIN already exists:"
  echo "  $CRT"
  echo "  $KEY"
  echo "Remove both files first to regenerate."
  exit 0
fi

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$KEY" -out "$CRT" -days "$DAYS" \
  -subj "/CN=$DOMAIN" \
  -addext "subjectAltName=DNS:$DOMAIN" \
  2>/dev/null

# openssl defaults the key to 600 (owner-only). The envoy container reads it
# as its own runtime UID (not the host user that ran this script), which
# doesn't have access at 600 — these are self-signed dev/demo certs, not real
# secrets, so world-readable is an acceptable tradeoff here.
chmod 644 "$KEY"

echo "Generated self-signed certificate for $DOMAIN (${DAYS}d):"
echo "  $CRT"
echo "  $KEY"
echo
echo "envoy-control-plane picks this up automatically (it watches ssl/) — no restart needed."
