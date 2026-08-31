#!/usr/bin/env bash
# Sends a mix of normal, bad-UA, and CRS-triggering requests through the envoy
# listener so you can watch the dashboard (http://localhost:8002) react live.
#
# "Malicious" traffic is split between two flavors: obviously bad User-Agents
# (caught by scoring-service's own heuristic) and CRS-style attack payloads
# (SQLi/XSS/LFI/RCE sent with a perfectly normal UA — these are the ones the
# UA heuristic alone would miss, and are exactly what coraza-service exists
# to catch).
#
# Usage:
#   ./generate-traffic.sh [count] [delay_seconds] [malicious_ratio_out_of_10]
#   ./generate-traffic.sh 50 0.1 3

set -euo pipefail

TARGET="${TARGET:-http://localhost:10000}"
COUNT="${1:-30}"
DELAY="${2:-0.3}"
MALICIOUS_RATIO="${3:-2}" # out of 10 requests; split between bad-UA and CRS payloads

NORMAL_UAS=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15)"
  "Mozilla/5.0 (X11; Linux x86_64)"
  "curl/8.1.0"
  "PostmanRuntime/7.36"
)

MALICIOUS_UAS=(
  "sqlmap/1.7.2"
  "nikto/2.5.0"
  "nmap scripting engine"
  "masscan/1.3"
)

PATHS=("/" "/api/users" "/login" "/search?q=test" "/products/42" "/checkout" "/health" "/admin")

# Synthetic source IPs (via X-Forwarded-For) so the dashboard's per-IP view has
# something to show against local test traffic, which otherwise all arrives from
# the same docker-bridge address.
FAKE_IPS=("203.0.113.10" "203.0.113.24" "198.51.100.7" "198.51.100.42" "192.0.2.15")

# Synthetic Host headers (envoy routes everything to the same backend regardless
# of domain today, but the scoring service records it, so this gives the
# per-domain donut something to show).
FAKE_DOMAINS=("shop.example.com" "api.example.com" "admin.example.com")

# CRS-triggering payloads: parallel arrays (method/path/query/body/label). Sent
# with a normal UA and no query/body content-type surprises beyond what's needed
# to trip a real CRS rule (SQLi, XSS, LFI, RCE, XXE-ish traversal).
CRS_METHODS=("GET" "POST" "GET" "GET" "GET")
CRS_PATHS=("/search" "/comment" "/files" "/ping" "/proxy")
CRS_QUERIES=(
  "id=1%27%20OR%20%271%27%3D%271"
  ""
  "path=..%2F..%2F..%2F..%2Fetc%2Fpasswd"
  "host=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd"
  "url=file%3A%2F%2F%2Fetc%2Fpasswd"
)
CRS_BODIES=("" "comment=<script>alert(document.cookie)</script>" "" "" "")
CRS_LABELS=("sqli" "xss" "lfi" "rce" "ssrf")

echo "Sending $COUNT requests to $TARGET (delay ${DELAY}s, ~${MALICIOUS_RATIO}/10 malicious: half bad-UA, half CRS payloads)"

for ((i = 1; i <= COUNT; i++)); do
  ip="${FAKE_IPS[$((RANDOM % ${#FAKE_IPS[@]}))]}"
  domain="${FAKE_DOMAINS[$((RANDOM % ${#FAKE_DOMAINS[@]}))]}"

  if ((RANDOM % 10 < MALICIOUS_RATIO)) && ((RANDOM % 2 == 0)); then
    # CRS payload: normal UA on purpose, the attack is in the query/body.
    idx=$((RANDOM % ${#CRS_PATHS[@]}))
    method="${CRS_METHODS[$idx]}"
    path="${CRS_PATHS[$idx]}"
    query="${CRS_QUERIES[$idx]}"
    body="${CRS_BODIES[$idx]}"
    label="${CRS_LABELS[$idx]}"
    ua="${NORMAL_UAS[$((RANDOM % ${#NORMAL_UAS[@]}))]}"
    url="$TARGET$path"
    [[ -n "$query" ]] && url="$url?$query"

    if [[ -n "$body" ]]; then
      code=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "$url" -A "$ua" \
        -H "X-Forwarded-For: $ip" -H "Host: $domain" \
        -H "Content-Type: application/x-www-form-urlencoded" --data-raw "$body")
    else
      code=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "$url" -A "$ua" \
        -H "X-Forwarded-For: $ip" -H "Host: $domain")
    fi
    printf "[%3d/%d] %-20s %-15s %-6s CRS:%-6s %-6s -> %s\n" "$i" "$COUNT" "$domain" "$ip" "$method" "$label" "$code" "$ua"
  else
    if ((RANDOM % 10 < MALICIOUS_RATIO)); then
      ua="${MALICIOUS_UAS[$((RANDOM % ${#MALICIOUS_UAS[@]}))]}"
    else
      ua="${NORMAL_UAS[$((RANDOM % ${#NORMAL_UAS[@]}))]}"
    fi
    path="${PATHS[$((RANDOM % ${#PATHS[@]}))]}"

    code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$path" -A "$ua" -H "X-Forwarded-For: $ip" -H "Host: $domain")
    printf "[%3d/%d] %-20s %-15s %-20s %-6s -> %s\n" "$i" "$COUNT" "$domain" "$ip" "$path" "$code" "$ua"
  fi

  sleep "$DELAY"
done
