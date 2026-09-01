# claude-shim

An Ollama-API-compatible shim for `crs-tuner`, backed by `claude -p`
(Claude Code's non-interactive mode) instead of a locally-run model. Lets
you use an existing Claude subscription's included usage as the judge
instead of a GPU or a metered `ANTHROPIC_API_KEY`.

Drop-in: exposes `POST /api/chat` and `GET /api/tags` matching Ollama's
shapes closely enough that `crs-tuner` needs zero code changes — just point
`OLLAMA_URL` at this service instead of `ollama`.

## Setup

```bash
./claude-shim/setup-credentials.sh
COMPOSE_PROFILES=coraza,crowdsec,ai-tuner,claude-shim docker compose up -d --build
```

Set `AI_TUNER_MODEL` in `.env` to a real Claude model alias (`haiku`,
`sonnet`, `opus`, ...) — not an Ollama tag like `llama3:8b`.

`setup-credentials.sh` copies the account/session-level files `claude -p`
needs (`.credentials.json`, `settings.json`, ...) into an isolated Docker
volume (`claude-shim-creds`) — **not** a live bind-mount of your real
`~/.claude`. The container only ever reads/writes that isolated copy, so
nothing it does can affect your actual local Claude Code session. Re-run
the script if the shim starts failing auth (token rotation your copy
hasn't picked up yet).

## Real cost and latency (measured against the actual container, not estimated)

Numbers below are from `--model haiku` calls through the actual running
shim (`docker compose logs claude-shim`, which logs real per-call
`total_cost_usd`/duration/cache stats — see `app/main.py`). A few things
that aren't obvious from the CLI's `--help`:

1. **Working directory matters enormously.** `claude -p` invoked from a
   real project directory (this repo, with its git history and file tree)
   auto-discovers and loads that context into the system prompt on *every*
   call — measured **~$0.11-0.12/call** in early testing outside this
   container, no cache reuse at all between calls. Invoked from an empty
   directory instead (what this shim actually does — `EMPTY_WORKDIR`,
   never bind-mounted to anything), steady-state measured **~$0.005-0.011
   per call**, ~8-9s latency, with cache reuse kicking in within a couple
   of calls (`cache_creation_input_tokens` dropping to 0,
   `cache_read_input_tokens` growing instead). This is why the Dockerfile
   builds a dedicated empty `/empty-workdir` and the app always runs
   `claude -p` with that as `cwd` — don't change that without re-measuring.
2. **No cache reuse across container restarts** (each fresh process/session
   starts cold again) but reuse **does** hold across sequential calls
   within one running container, since the CLI reuses the same account-level
   cache keyed off the (stable, empty-cwd) system prompt.
3. **Latency here (~8-9s) is higher than a bare CLI call outside a
   container (~2.2-2.9s in early testing)** — likely container/subprocess
   overhead, not something worth chasing further given this only ever runs
   off the request path (`crs-tuner`'s async queue), not in front of live
   traffic.
4. **`--model haiku` was less reliable about emitting bare JSON** — it
   sometimes wraps the answer in a ` ```json ` fence unprompted, where
   larger models tended not to. `_clean_json()` in `app/main.py` strips
   fences defensively regardless of model.

None of this is free tokens or a loophole — it's the same usage your
account meters for interactive Claude Code sessions, just not itemized as
a separate per-call API charge. A `crs-tuner` queue processing many CRS
matches will draw down the same quota you use for actual coding work.
Budget for that, and watch `crs-tuner/analysis/` volume if you enable this
against a busy site — see `dashboard`'s queue-depth chart to keep an eye
on throughput before it surprises you.

## Why tools are disabled

The "matched value" in every prompt comes directly from attacker-controlled
request data (that's the entire point — it's what tripped the CRS rule).
Every call passes `--disallowedTools Bash Write Edit NotebookEdit`, so a
value deliberately crafted to look like a tool-use instruction can't
actually get anything executed or written to disk. This is not
configurable/optional in `app/main.py` — it's a hard default regardless of
`AI_TUNER_MODEL`. (Newer Claude Code CLI versions have a single
`--restricted` flag for this; `--disallowedTools` is used instead here so
it works regardless of which CLI version `npm install` happens to pull.)
