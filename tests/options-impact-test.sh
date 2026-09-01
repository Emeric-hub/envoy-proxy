#!/usr/bin/env bash
# Reports what the CURRENTLY ACTIVE configuration actually does to traffic —
# not a load/latency test (see run-smoke-test.sh) and not fire-and-forget
# noise for watching the dashboard live (see generate-traffic.sh). Sends one
# fixed request per category (legitimate, SQLi, XSS, LFI, RCE, scanner UA,
# a borderline false-positive) and reports, per category: the underlying
# composite score and which signal(s) contributed (independent of whether
# AUDIT_MODE actually blocked it) alongside the real HTTP outcome — so
# flipping AUDIT_MODE, RISK_THRESHOLD, ENABLE_CORAZA/CROWDSEC/AI_TUNER, or
# CRS_PARANOIA_LEVEL in .env and re-running shows exactly what changed.
#
# Usage (run from the project root):
#   ./tests/options-impact-test.sh [domain]
#   ./tests/options-impact-test.sh shop.example.com

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

TARGET="${TARGET:-http://localhost:10000}"
DOMAIN="${1:-shop.example.com}"
DASHBOARD_URL="${DASHBOARD_URL:-http://127.0.0.1:8002}"
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

echo "=== active configuration ($DASHBOARD_URL/api/config) ==="
CONFIG="$(curl -s "$DASHBOARD_URL/api/config" 2>/dev/null || echo '{}')"
STATUS="$(curl -s "$DASHBOARD_URL/api/status" 2>/dev/null || echo '{}')"
OLLAMA="$(curl -s "$DASHBOARD_URL/api/ollama-status" 2>/dev/null || echo '{}')"
if command -v jq >/dev/null; then
  echo "$CONFIG" | jq .
else
  echo "$CONFIG"
fi
echo "coraza live:   $(echo "$STATUS" | jq -c '.coraza // empty' 2>/dev/null)"
echo "crowdsec live: $(echo "$STATUS" | jq -c '.crowdsec // empty' 2>/dev/null)"
echo "ai-tuner live: $(echo "$OLLAMA" | jq -c . 2>/dev/null)"
echo "domain: $DOMAIN"
echo

# Parallel arrays: label, method, path, query, body, expected ("allow" or
# "deny") — expected is what a *sane, fully-enabled* configuration should
# do; the report shows whether the active configuration actually agrees,
# not a pass/fail assertion (that's what run-smoke-test.sh's k6 thresholds
# are for).
LABELS=(legit-home legit-search sqli xss lfi rce scanner-ua borderline-fp)
METHODS=(GET GET GET POST GET GET GET GET)
PATHS=(/ /search /search /comment /files /ping /health /search)
QUERIES=("" "q=shoes" "id=1%27%20OR%20%271%27%3D%271" "" "path=..%2F..%2F..%2F..%2Fetc%2Fpasswd" "host=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd" "" "name=O%27Brien")
BODIES=("" "" "" "comment=<script>alert(document.cookie)</script>" "" "" "" "")
UAS=("$UA" "$UA" "$UA" "$UA" "$UA" "$UA" "sqlmap/1.7.2" "$UA")
# borderline-fp is deliberately expected "deny" too, same as the real attack
# rows — a FRESH system has no reason yet to treat "O'Brien" differently
# from any other CRS match. It's here to show the *other* kind of impact:
# re-run this after tests/crs-tuner-test.sh (or after enough natural
# repeats) generates an exclusion for it, and this row should flip to
# "allow" — demonstrating the adaptive loop's effect, not a config bug.
EXPECTED=(allow allow deny deny deny deny deny deny)

LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT
(timeout $(( ${#LABELS[@]} + 5 )) docker compose exec -T redis redis-cli SUBSCRIBE risk-events > "$LOG" 2>&1 &)
sleep 0.5

for i in "${!LABELS[@]}"; do
  url="$TARGET${PATHS[$i]}"
  [[ -n "${QUERIES[$i]}" ]] && url="$url?${QUERIES[$i]}"
  if [[ -n "${BODIES[$i]}" ]]; then
    curl -s -o /dev/null -X "${METHODS[$i]}" "$url" -A "${UAS[$i]}" -H "Host: $DOMAIN" \
      -H "Content-Type: application/x-www-form-urlencoded" --data-raw "${BODIES[$i]}"
  else
    curl -s -o /dev/null -X "${METHODS[$i]}" "$url" -A "${UAS[$i]}" -H "Host: $DOMAIN"
  fi
  sleep 0.3
done

sleep 2

echo "=== impact ==="
printf "%-14s %-8s %-6s %-6s %-8s %s\n" "case" "expected" "http" "score" "decision" "reasons"
LABELS_CSV="$(IFS=,; echo "${LABELS[*]}")" EXPECTED_CSV="$(IFS=,; echo "${EXPECTED[*]}")" \
  python3 - "$LOG" <<'PYEOF'
import json, os, sys
labels = os.environ["LABELS_CSV"].split(",")
expected = os.environ["EXPECTED_CSV"].split(",")
events = []
with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if line.startswith('{'):
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
for i, label in enumerate(labels):
    if i >= len(events):
        print(f"{label:<14} {expected[i]:<8} {'?':<6} {'?':<6} {'no event received':<8}")
        continue
    e = events[i]
    http = e.get("http_status")
    score = e.get("score")
    decision = e.get("decision")
    reasons = "; ".join(e.get("reasons", [])) or "-"
    agree = "" if (decision == expected[i]) else "  <-- active config disagrees with expected"
    print(f"{label:<14} {expected[i]:<8} {http!s:<6} {score!s:<6} {decision:<8} {reasons}{agree}")
PYEOF

echo
echo "Notes:"
echo "  - 'expected' is a sane fully-enabled baseline, not an assertion — a"
echo "    disagreement here is exactly the point of this tool: it shows what"
echo "    the *active* configuration actually does, config drift included."
echo "  - scanner-ua vs expected 'deny': a documented gap, not a bug — see"
echo "    TODO.md ('A single CRITICAL CRS match doesn't guarantee a block')."
echo "  - decision reflects the composite score/signals regardless of"
echo "    AUDIT_MODE; http reflects what was actually enforced — with"
echo "    AUDIT_MODE=true, http stays 200 everywhere even where decision=deny."
echo "  - borderline-fp: expected 'deny' on a clean system. Re-run after"
echo "    tests/crs-tuner-test.sh (or enough natural repeats) generates an"
echo "    exclusion for it, and it should flip to 'allow' — that's the"
echo "    adaptive loop, not drift."
