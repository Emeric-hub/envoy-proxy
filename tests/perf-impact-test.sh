#!/usr/bin/env bash
# Measures the actual latency cost of each opt-in security signal by
# running the exact same k6 load profile (tests/loadtest/smoke.js) with
# them progressively enabled, one at a time, and comparing latency across
# runs. Not a correctness test (see options-impact-test.sh — does the
# config change what gets *blocked*) and not a one-off load test (see
# run-smoke-test.sh — a single run against whatever's currently enabled):
# this is specifically about isolating the *performance* cost of turning
# each signal on, holding traffic/load identical across runs.
#
# Steps are cumulative by design — each adds exactly one more signal on top
# of the previous, so the delta between consecutive rows is that signal's
# own added cost, not a re-measurement of everything from scratch:
#   1. baseline        — every signal off (ENABLE_CORAZA/CROWDSEC/GEOIP/AI_TUNER=false)
#   2. +coraza          — adds the Coraza/CRS anomaly-score call
#   3. +crowdsec        — adds CrowdSec's local decision-cache read + log feed
#   4. +geoip           — adds the geoip-service lookup (cosmetic-only enrichment)
#   5. +ai-tuner        — adds the async crs-match publish (XAdd), only actually
#                         incurred on a matched rule NOT in AI_TUNER_INELIGIBLE_TAGS
#                         — smoke.js's CRS payloads are almost all in that
#                         default ineligible set (SQLi/XSS/LFI/RCE/scanner-UA
#                         are deliberately excluded, see .env.example), so this
#                         step commonly shows near-zero measured delta with the
#                         default traffic mix — that's a true finding about
#                         this traffic shape, not a broken test.
#
# A step whose container isn't actually running (its COMPOSE_PROFILES entry
# not enabled) is skipped with a warning rather than failing the whole run —
# only measures what's actually available in the current stack.
#
# Only ever changes scoring-service's environment for the duration of this
# script (via `env VAR=val docker compose up -d scoring-service`, never
# `export`, and never touches .env) — restores the real .env-driven config
# on exit regardless of how the script ends (trap below).
#
# Usage (run from the project root):
#   ./tests/perf-impact-test.sh [VUS] [RAMP] [HOLD]
#   ./tests/perf-impact-test.sh 30 10s 20s

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

VUS="${1:-20}"
RAMP="${2:-10s}"
HOLD="${3:-20s}"
DASHBOARD_URL="${DASHBOARD_URL:-http://127.0.0.1:8002}"
RESULTS_DIR="tests/loadtest/results"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"; echo; echo "Restoring scoring-service to its real .env configuration..."; docker compose up -d scoring-service >/dev/null 2>&1 || true' EXIT

echo "=== perf-impact-test: $VUS VUs, ${RAMP} ramp, ${HOLD} hold ==="
echo

# ---- Which steps are actually runnable right now? ----------------------
# coraza-service/crowdsec/geoip-service are all profile-gated — a step that
# needs one that isn't running gets its ENABLE_* forced to false and a
# warning, rather than measuring a timeout/unreachable cost that isn't the
# thing this test is trying to measure.
running_services() { docker compose ps --status running --services 2>/dev/null; }
RUNNING="$(running_services)"
has_service() { grep -qx "$1" <<<"$RUNNING"; }

CORAZA_OK=false; CROWDSEC_OK=false; GEOIP_OK=false
has_service coraza-service && CORAZA_OK=true || echo "warning: coraza-service not running — steps involving it will keep ENABLE_CORAZA=false"
has_service crowdsec && CROWDSEC_OK=true || echo "warning: crowdsec not running — steps involving it will keep ENABLE_CROWDSEC=false"
has_service geoip-service && GEOIP_OK=true || echo "warning: geoip-service not running — steps involving it will keep ENABLE_GEOIP=false"
echo

# Parallel arrays: label + the four ENABLE_* booleans for that step.
STEP_LABELS=("baseline (all signals off)" "+coraza" "+coraza+crowdsec" "+coraza+crowdsec+geoip" "+coraza+crowdsec+geoip+ai-tuner")
STEP_CORAZA=(false "$CORAZA_OK" "$CORAZA_OK" "$CORAZA_OK" "$CORAZA_OK")
STEP_CROWDSEC=(false false "$CROWDSEC_OK" "$CROWDSEC_OK" "$CROWDSEC_OK")
STEP_GEOIP=(false false false "$GEOIP_OK" "$GEOIP_OK")
STEP_AITUNER=(false false false false true)

wait_for_config() {
  local want_coraza="$1" want_crowdsec="$2" want_geoip="$3"
  for _ in $(seq 1 30); do
    local status
    status="$(curl -s "$DASHBOARD_URL/api/status" 2>/dev/null || echo '{}')"
    if python3 - "$status" "$want_coraza" "$want_crowdsec" "$want_geoip" <<'PYEOF'
import json, sys
status, wc, wd, wg = sys.argv[1:5]
try:
    data = json.loads(status)
except Exception:
    sys.exit(1)
def enabled(key): return bool((data.get(key) or {}).get("enabled"))
ok = (enabled("coraza") == (wc == "true") and
      enabled("crowdsec") == (wd == "true") and
      enabled("geoip") == (wg == "true"))
sys.exit(0 if ok else 1)
PYEOF
    then
      return 0
    fi
    sleep 1
  done
  echo "  (warning: scoring-service /health didn't reflect the expected config within 30s — proceeding anyway)"
}

RESULT_FILES=()
RESULT_LABELS=()

for i in "${!STEP_LABELS[@]}"; do
  label="${STEP_LABELS[$i]}"
  ec="${STEP_CORAZA[$i]}"; ed="${STEP_CROWDSEC[$i]}"; eg="${STEP_GEOIP[$i]}"; ea="${STEP_AITUNER[$i]}"

  echo "=== Step $((i + 1))/${#STEP_LABELS[@]}: $label ==="
  echo "  ENABLE_CORAZA=$ec ENABLE_CROWDSEC=$ed ENABLE_GEOIP=$eg ENABLE_AI_TUNER=$ea"

  env ENABLE_CORAZA="$ec" ENABLE_CROWDSEC="$ed" ENABLE_GEOIP="$eg" ENABLE_AI_TUNER="$ea" \
    docker compose up -d scoring-service >/dev/null
  wait_for_config "$ec" "$ed" "$eg"

  # Warm-up burst, discarded: the very first requests after a fresh
  # container recreate pay a one-time cost (new TCP connections to
  # coraza-service/crowdsec/redis, DNS resolution, connection-pool
  # spin-up) that has nothing to do with the signal being measured — left
  # unaddressed, whichever step happens to run first absorbs that cost and
  # looks artificially slower than every step after it.
  for _ in $(seq 1 15); do
    curl -s -o /dev/null "http://localhost:10000/health" -H "Host: shop.example.com" -A "Mozilla/5.0" || true
  done

  before_count=$(ls "$RESULTS_DIR"/smoke-*.json 2>/dev/null | wc -l)
  env ENABLE_CORAZA="$ec" ENABLE_CROWDSEC="$ed" ENABLE_GEOIP="$eg" ENABLE_AI_TUNER="$ea" \
    docker compose run --rm -e VUS="$VUS" -e RAMP_DURATION="$RAMP" -e HOLD_DURATION="$HOLD" loadtest \
    >"$WORKDIR/k6-step-$i.log" 2>&1 || echo "  (k6 reported a threshold failure — see $WORKDIR/k6-step-$i.log; still recording the numbers)"
  after_count=$(ls "$RESULTS_DIR"/smoke-*.json 2>/dev/null | wc -l)

  if [[ "$after_count" -le "$before_count" ]]; then
    echo "  no new result file written — skipping this step in the comparison"
    continue
  fi
  latest="$(ls -t "$RESULTS_DIR"/smoke-*.json | head -1)"
  cp "$latest" "$WORKDIR/step-$i.json"
  RESULT_FILES+=("$WORKDIR/step-$i.json")
  RESULT_LABELS+=("$label")
  echo "  -> $(basename "$latest")"
  echo
done

echo "=== Comparison (p95 / p99 http_req_duration, ms) ==="
COMBINED="$RESULTS_DIR/perf-impact-${STAMP}.json"
python3 - "$COMBINED" "${RESULT_LABELS[@]}" -- "${RESULT_FILES[@]}" <<'PYEOF'
import json, sys

args = sys.argv[1:]
combined_path = args[0]
sep = args.index("--")
labels = args[1:sep]
files = args[sep + 1:]

def metric(data, name, stat):
    try:
        return data["metrics"][name]["values"][stat]
    except Exception:
        return None

rows = []
for label, path in zip(labels, files):
    with open(path) as f:
        data = json.load(f)
    row = {
        "label": label,
        "requests": metric(data, "http_reqs", "count"),
        "p95_ms": metric(data, "http_req_duration", "p(95)"),
        "p99_ms": metric(data, "http_req_duration", "p(99)"),
        "avg_ms": metric(data, "http_req_duration", "avg"),
        "allowed_p95_ms": metric(data, "allowed_latency_ms", "p(95)"),
        "blocked_p95_ms": metric(data, "blocked_latency_ms", "p(95)"),
        "unexpected_5xx": metric(data, "unexpected_5xx", "count"),
    }
    rows.append(row)

baseline_p95 = rows[0]["p95_ms"] if rows and rows[0]["p95_ms"] else None

print(f"{'step':<34} {'p95':>8} {'p99':>8} {'avg':>8} {'+p95 vs baseline':>18}")
for row in rows:
    p95 = row["p95_ms"]
    delta = ""
    if baseline_p95 and p95 is not None:
        diff = p95 - baseline_p95
        pct = (diff / baseline_p95 * 100) if baseline_p95 else 0
        sign = "+" if diff >= 0 else ""
        delta = f"{sign}{diff:.1f}ms ({sign}{pct:.0f}%)"
    def fmt(v): return f"{v:.1f}" if isinstance(v, (int, float)) else "n/a"
    print(f"{row['label']:<34} {fmt(p95):>8} {fmt(row['p99_ms']):>8} {fmt(row['avg_ms']):>8} {delta:>18}")

print()
print(f"{'step':<34} {'allowed p95':>12} {'blocked p95':>12} {'5xx':>6}")
for row in rows:
    def fmt(v): return f"{v:.1f}" if isinstance(v, (int, float)) else "n/a"
    print(f"{row['label']:<34} {fmt(row['allowed_p95_ms']):>12} {fmt(row['blocked_p95_ms']):>12} {row['unexpected_5xx'] or 0:>6}")

with open(combined_path, "w") as f:
    json.dump({"baseline_p95_ms": baseline_p95, "steps": rows}, f, indent=2)
print()
print(f"Combined comparison written to {combined_path}")
PYEOF
