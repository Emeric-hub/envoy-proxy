#!/usr/bin/env bash
# Exercises the crs-tuner adaptive-exclusion loop end-to-end against a real
# false positive, not a real attack: an apostrophe in a name field
# ("O'Brien") trips CRS 920273 ("Invalid character in request") at the
# current paranoia level — a well-known, genuinely benign false-positive
# class, not a reused attack payload. Repeats it AI_TUNER_FP_THRESHOLD
# times, waits for crs-tuner to judge each one, then sends unrelated
# legitimate traffic to confirm nothing else is affected either way.
#
# crs-tuner's LLM judgment is non-deterministic — this can't guarantee an
# exclusion gets written, only exercise the pipeline and report what the
# model actually decided.
#
# Requires crs-tuner + an Ollama endpoint (local `ollama-local` profile, or
# a remote OLLAMA_URL) already running — this script doesn't start them,
# since ai-tuner/ollama-local are opt-in profiles (see README.md).
#
# Usage (run from the project root):
#   ./tests/crs-tuner-test.sh [domain] [repeats]
#   ./tests/crs-tuner-test.sh shop.example.com 5

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

TARGET="${TARGET:-http://localhost:10000}"
DOMAIN="${1:-shop.example.com}"
REPEATS="${2:-5}"
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
FP_PATH="/search"
FP_QUERY="name=O%27Brien"
RULE_ID="920273"
VARIABLE="ARGS"
KEY="name"

for svc in redis coraza-service scoring-service crs-tuner; do
  if ! docker compose ps "$svc" 2>/dev/null | grep -q "Up"; then
    echo "error: $svc is not running — start the stack with ai-tuner (and ollama-local, unless OLLAMA_URL points elsewhere) first:" >&2
    echo "  COMPOSE_PROFILES=coraza,crowdsec,ai-tuner,ollama-local docker compose up -d" >&2
    exit 1
  fi
done

safe_domain="$(printf '%s' "$DOMAIN" | tr -c 'a-zA-Z0-9.-' '_')"
combo="${DOMAIN}:${FP_PATH}:${RULE_ID}:${VARIABLE}:${KEY}"
analysis_file="crs-tuner/analysis/${safe_domain}.jsonl"
exclusion_file="coraza-service/crs-exclusions/auto-${safe_domain}.conf"

before_count=$(docker compose exec -T redis redis-cli GET "crs-tuner:fp-count:${combo}" 2>/dev/null | tr -d '\r')
before_count="${before_count:-0}"
[[ "$before_count" == "" ]] && before_count=0

echo "=== combo under test: $combo ==="
echo "=== fp-count before: $before_count (threshold: needs to reach ${AI_TUNER_FP_THRESHOLD:-3}) ==="

echo
echo "=== sending $REPEATS repeats of the O'Brien false positive to $DOMAIN$FP_PATH ==="
for ((i = 1; i <= REPEATS; i++)); do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$FP_PATH?$FP_QUERY" -A "$UA" -H "Host: $DOMAIN")
  echo "[$i/$REPEATS] -> $code"
  sleep 1
done

echo
echo -n "=== waiting for crs-tuner to drain the queue "
for _ in $(seq 1 30); do
  lag=$(docker compose exec -T redis redis-cli XINFO GROUPS crs-matches 2>/dev/null | grep -A1 "^lag$" | tail -1 | tr -d '\r')
  [[ "$lag" == "0" ]] && break
  echo -n "."
  sleep 1
done
echo " done (lag=$lag)"
sleep 1 # XACK happens right after the verdict/exclusion write completes, not before — a beat for the fs write + coraza's fsnotify reload to settle

after_count=$(docker compose exec -T redis redis-cli GET "crs-tuner:fp-count:${combo}" 2>/dev/null | tr -d '\r')
after_count="${after_count:-0}"
[[ "$after_count" == "" ]] && after_count=0

echo
echo "=== fp-count after: $after_count ==="
echo "=== last $REPEATS verdicts logged for $DOMAIN (rule $RULE_ID) ==="
if [[ -f "$analysis_file" ]]; then
  jq -c "select(.rule_id == \"$RULE_ID\")" "$analysis_file" | tail -n "$REPEATS"
else
  echo "  (no analysis file yet at $analysis_file)"
fi

echo
if [[ -f "$exclusion_file" ]] && grep -q "ruleRemoveTargetById=${RULE_ID}" "$exclusion_file" 2>/dev/null; then
  echo "=== exclusion generated: $exclusion_file ==="
  grep -B3 "ruleRemoveTargetById=${RULE_ID}" "$exclusion_file"
else
  echo "=== no exclusion generated for rule $RULE_ID yet ==="
  echo "  (model may not have judged false_positive $REPEATS times in a row at the required confidence — check $analysis_file)"
fi

echo
echo "=== unrelated legitimate traffic to $DOMAIN — should stay 200 regardless of the above ==="
for path in "/" "/health" "/products/42"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$path" -A "$UA" -H "Host: $DOMAIN")
  echo "  $path -> $code"
done

echo
echo "=== re-sending the O'Brien payload once more — 403 means still enforced, 200 means the exclusion took effect ==="
code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$FP_PATH?$FP_QUERY" -A "$UA" -H "Host: $DOMAIN")
echo "  $FP_PATH?$FP_QUERY -> $code"
