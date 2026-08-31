#!/usr/bin/env bash
# Runs the k6 load smoke test against the running stack. Standalone: doesn't
# require the full stack to already be started interactively — brings up
# whatever's missing, runs the test, leaves the rest as it found it.
#
# Usage:
#   ./run-smoke-test.sh                          # defaults: 20 VUs, 10s ramp, 20s hold
#   ./run-smoke-test.sh 50 20s 40s                # heavier run
#
# Results land in loadtest/results/ (.txt and .json, timestamped) in addition
# to the console summary.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

VUS="${1:-20}"
RAMP_DURATION="${2:-10s}"
HOLD_DURATION="${3:-20s}"

docker compose up -d envoy scoring-service coraza-service redis backend >/dev/null

docker compose run --rm \
  -e VUS="$VUS" \
  -e RAMP_DURATION="$RAMP_DURATION" \
  -e HOLD_DURATION="$HOLD_DURATION" \
  loadtest
