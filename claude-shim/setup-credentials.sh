#!/usr/bin/env bash
# One-time (re-run as needed) setup: copies the account/session-level files
# claude -p needs to authenticate into an ISOLATED Docker volume the
# claude-shim container reads from — never a live bind-mount of ~/.claude.
# The copy is one-way (host -> volume) and read-only from ~/.claude's side,
# so the shim container can never write back to or corrupt your actual
# local Claude Code session, no matter what runs inside it.
#
# Only copies auth/account-level files (.credentials.json, settings.json,
# policy-limits.json, remote-settings.json) — not interactive session
# history, IDE state, or project files (sessions/, ide/, projects/,
# shell-snapshots/, file-history/), which claude -p doesn't need and which
# would otherwise put your actual conversation history inside a less
# trusted container for no reason.
#
# Re-run this if the shim starts failing auth — e.g. your access token
# rotated locally in a way this copy hasn't picked up yet.
#
# Usage: ./claude-shim/setup-credentials.sh

set -euo pipefail

if [[ ! -f "$HOME/.claude/.credentials.json" ]]; then
  echo "No credentials found at ~/.claude/.credentials.json — log into Claude Code locally first (run 'claude' once interactively)." >&2
  exit 1
fi

docker volume create claude-shim-creds >/dev/null

docker run --rm \
  -v "$HOME/.claude:/src:ro" \
  -v claude-shim-creds:/dst \
  alpine sh -c '
    set -e
    for f in .credentials.json settings.json policy-limits.json remote-settings.json; do
      [ -f "/src/$f" ] && cp -a "/src/$f" "/dst/$f"
    done
    chmod 600 /dst/.credentials.json
  '

echo "Copied credentials into the claude-shim-creds Docker volume."
echo "Start the shim with: COMPOSE_PROFILES=coraza,crowdsec,ai-tuner,claude-shim docker compose up -d --build"
