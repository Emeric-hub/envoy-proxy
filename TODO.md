# TODO

## The original vision vs. where this stands

This project was framed at the start as an **"AI/ML augmented reverse
proxy"** — the initial question was where to even start building one, and
Envoy + a scoring microservice came out of that discussion.

Two earlier attempts at "the AI/ML part" — a UA-pattern heuristic, then an
in-process `IsolationForest` anomaly detector — were both removed. Both
scored individual requests in real time with no real ground truth: the
heuristic was trivially spoofed (regex on User-Agent), and the ML model
only knew "structurally unusual vs. a synthetic baseline," not "actually
malicious." Neither survived contact with "does this actually work well."

**What's built instead**: CRS (via Coraza) and CrowdSec remain the two
real-time signals — both well-established, both already have real
detection logic behind them. Rather than bolt on a third fragile real-time
signal, **`crs-tuner`** makes CRS itself more accurate over time,
asynchronously, off the request path entirely:

1. Every CRS match at or above `AI_TUNER_MIN_SEVERITY_CODE`, *and* whose CRS
   tag isn't one of `AI_TUNER_INELIGIBLE_TAGS` (the real attack-signature
   categories — SQLi, XSS, RCE, LFI/RFI, scanner detection, ... — see
   "Still a real risk" below for why this gate exists), gets queued
   (Redis Stream `crs-matches`) by `scoring-service`.
2. `crs-tuner` consumes the queue and asks a self-hosted LLM (Ollama,
   `AI_TUNER_MODEL`, local by default but `OLLAMA_URL` can point at a
   remote instance) to judge true-positive vs. false-positive from the
   actual matched rule + payload — not just the rule ID, the real
   `variable:key` and matched `value`.
3. Every verdict is logged (`crs-tuner/analysis/<domain>.jsonl`) — a full
   audit trail, and a dedicated `_errors.jsonl` for analysis failures
   specifically, kept separate from verdicts so "is analysis itself
   failing" is easy to check without wading through routine logs.
4. Only once the *same* (domain, path, rule, variable, key) combination is
   independently judged a false positive `AI_TUNER_FP_THRESHOLD` times —
   not on a single call — does `crs-tuner` generate and hot-load a
   narrowly-scoped exclusion (`coraza-service/crs-exclusions/auto-<domain>.conf`,
   `ctl:ruleRemoveTargetById` chained on Host *and* `REQUEST_FILENAME`, so
   it's scoped to that domain, that exact path, and that exact variable —
   a false positive seen on one endpoint doesn't get generalized to every
   endpoint on the domain).

**This is still a real risk, not a solved problem.** An auto-generated
exclusion is a self-modifying security surface: a wrong judgment (or a
probe deliberately crafted to look like a benign false positive) can
suppress real protection. Development surfaced this isn't hypothetical, at
two different scales:

- A single-rule test: a 3B model judged real SQLi-detection rules "false
  positive" against a textbook `' OR '1'='1` payload, and the threshold
  gate let it through once the verdict repeated `AI_TUNER_FP_THRESHOLD`
  times.
- A larger, realistic-traffic test: under sustained mixed attack traffic
  (the same shapes `tests/generate-traffic.sh` sends — repeated SQLi/XSS/LFI/RCE
  payloads and scanner User-Agents), the model judged real CRS
  attack-signature matches "false positive" *consistently* — not a fluke,
  the same wrong call repeated across many independent requests — enough to
  auto-generate dozens of exclusions across multiple domains within
  minutes, materially weakening real protection. Raising
  `AI_TUNER_CONFIDENCE_MIN` or `AI_TUNER_FP_THRESHOLD` doesn't fix this:
  the model was often confident and consistent about being wrong, so a
  higher bar just takes a little longer to clear.

What actually closes that gap: `AI_TUNER_INELIGIBLE_TAGS` (`.env`) gates
which CRS rule categories are ever eligible for auto-exclusion — by
CRS tag, checked in `scoring-service` before a match even reaches the
queue, so no LLM verdict can override it regardless of confidence or
repetition. Defaults to CRS's real attack-signature categories (SQLi, XSS,
RCE, LFI/RFI, scanner detection, PHP/Node injection, session fixation,
disclosure). This bounds the tuning loop to what it was actually designed
for — generic protocol/format anomaly rules that are legitimately noisy at
high paranoia levels (e.g. 920273 "Invalid character in request", 921180
"HTTP Parameter Pollution") — and makes it structurally impossible for a
wrong LLM judgment to suppress real SQLi/XSS/RCE/LFI detection, no matter
how the confidence/threshold knobs are tuned.

The threshold gate still bounds the blast radius of any *one* bad call
*within* the eligible categories, but doesn't eliminate the risk of a
sustained, deliberate attempt to game it there. `crs_exclusion.conf`'s own
documented ID range keeps human-written exclusions in a separate space from
auto-generated ones specifically so a human reviewing the file can tell
which is which — but nothing today alerts a human when a new
`auto-<domain>.conf` rule actually gets written. A follow-on worth doing:
surface newly-generated exclusions somewhere visible (the dashboard, or at
minimum a log line loud enough to notice) rather than only ever finding
out by reading the file.

Also worth revisiting eventually: real semantic/LLM-based judgment on the
request path itself (not just async WAF tuning) for payloads that don't
match any CRS rule at all — the original "catches *meaning*, not just
*shape or signature*" goal. `crs-tuner`'s async, non-blocking pattern
(queue now, benefit later — the same shape CrowdSec's own integration
already uses) is the template for how that would have to work without
adding LLM latency to the request path.

## Configuration

- **A `DASHBOARD_DOMAIN` (or similar) `.env` var** so the dashboard can be
  reached through Envoy itself at a real domain, if one is provided —
  currently it's only reachable directly via its own published port
  (`DASHBOARD_PORT`/`DASHBOARD_BIND_ADDR`), with no `routes.csv` entry or
  Envoy-side TLS of its own. If set, `envoy-control-plane` would need to
  add a route for that domain (proxying to `dashboard:8002`) and, if
  `ssl=true`-equivalent, a cert generated the same way `generate-cert.sh`
  already does for any other domain — same mechanism as the fallback
  `default` cert added for unmatched SNI. Optional/opt-in: unset by
  default, so the direct-port path keeps working unchanged for anyone not
  using it.

## Security follow-ups

Roughly in order of how much it'd matter if this were ever run somewhere
more real than a laptop demo:

- **Inter-service encryption with a shared internal CA.** Everything inside
  the Docker network is plaintext right now: `envoy` → `scoring-service`
  (ext_authz), `scoring-service` → `coraza-service`, `scoring-service` →
  `crowdsec` (LAPI), `scoring-service` → `redis`, and `envoy-control-plane`
  → `envoy` (gRPC/ADS). None of it leaves the Docker bridge network today,
  which is why this hasn't mattered yet, but a real deployment would want
  mTLS between all of these, backed by one internal CA generated at
  bootstrap (a natural extension of what `generate-cert.sh`/`init.sh`
  already do for the edge-facing certs).
- **No rate limiting or connection limits.** Envoy itself warns about this
  on startup ("no configured limit to the number of allowed active
  downstream connections") — there's no `envoy.resource_monitors` config
  and no per-IP rate limiting anywhere in the pipeline. A sufficiently fast
  attacker (or a misbehaving legitimate client) isn't constrained by
  anything but the scoring pipeline's own judgment.
- **Dashboard authentication.** The loopback bind + `DASHBOARD_ALLOWED_IPS`
  allowlist are network-level controls, not authentication — there's no
  login. Fine for local-only use; not fine the moment `DASHBOARD_BIND_ADDR`
  gets opened up for real.
- **Certificate revocation.** The demo's self-signed certs have no
  CRL/OCSP (this is exactly what `tests/run-audit.sh` flags as HIGH on every
  scan, and it's a real gap, not a false positive — it's just also
  inherent to a self-signed cert with no CA behind it).
- **Secrets in plaintext `.env`.** `CROWDSEC_BOUNCER_KEY` lives in a
  plaintext file on disk. `init.sh` randomizes it away from the checked-in
  placeholder, which is enough for a local demo, but it's not how a real
  deployment should manage this — a proper secrets manager or Docker
  secrets would be the next step.
- **Image pinning by tag, not digest.** `envoyproxy/envoy`,
  `crowdsecurity/crowdsec`, `drwetter/testssl.sh`, `nginx:alpine`,
  `mendhak/http-https-echo` are all pinned by tag. Tags can move; digest
  pinning would close that off for anything resembling supply-chain
  integrity.
- **No image/dependency vulnerability scanning** wired into the repo (e.g.
  Trivy or Grype as a CI step) — nothing currently checks the base images
  or Go/Python dependencies for known CVEs.
- **CRS paranoia level defaults to 1** (lowest coverage, fewest false
  positives). Worth tuning upward against real traffic once there's real
  traffic to tune against.
- **No log redaction.** Request paths, user agents, and IPs flow into
  stdout access logs and the dashboard verbatim. Fine for synthetic demo
  traffic; would need real PII handling before pointing this at anything
  with actual users.
- **CORS is entirely unset** — whatever each backend does on its own,
  unreviewed.

## Performance

- ~~Consider rewriting `scoring-service` in Go~~ — **done.** `scoring-service`
  is now Go (`scoring-service-go/`), and Envoy's `ext_authz` filter runs in
  gRPC mode instead of HTTP mode (`envoy-control-plane/main.go`'s
  `buildExtAuthzFilter`). Measured with `tests/run-smoke-test.sh` (k6, 50
  VUs, identical traffic mix, same run parameters) against this repo's own
  stack — Python/FastAPI + HTTP-mode ext_authz vs. the Go + gRPC-mode
  replacement:

  | metric | Python/HTTP | Go/gRPC | change |
  |---|---|---|---|
  | avg latency | 72.2ms | 7.0ms | ~10x lower |
  | median latency | 58.3ms | 6.3ms | ~9x lower |
  | p95 latency | 198.9ms | 13.3ms | ~15x lower |
  | p99 latency | 202.4ms | 18.4ms | ~11x lower |
  | throughput | 188 req/s | 262 req/s | ~1.4x higher |

  No interpreter overhead, no GIL contention, and protobuf-over-gRPC
  instead of JSON-over-HTTP for the ext_authz check itself. The gRPC
  switch also removed Envoy's config-level header allow-list
  (`AllowedHeaders`/`AllowedUpstreamHeaders`, HTTP-mode-only) — the Go
  service re-implements the same 6-header allow-list itself
  (`scoring-service-go/authz/headers.go`) rather than silently seeing
  everything now that gRPC hands it the full request.

## Known limitations / not fully verified

- **HTTP/3 (QUIC)** is wired up (UDP listener bound, `alt-svc` advertised,
  Envoy accepts the config) but hasn't been exercised with a real QUIC
  handshake — the `curl` available in dev here isn't built with HTTP/3
  support. Worth testing from a real HTTP/3 client (recent Chrome, or a
  `curl` built against `ngtcp2`/`quiche`) before trusting it fully.
- **`tests/generate-traffic.sh` and `tests/loadtest/smoke.js` share the same 5 fake
  source IPs** (via spoofed `X-Forwarded-For`). Repeated runs across both
  accumulate real CrowdSec bans against those IPs (`LePresidente/http-generic-403-bf`
  — CrowdSec correctly reacting to a real pattern of repeated 403s), which
  then makes *all* traffic from those IPs get blocked regardless of payload,
  skewing later runs. Not a bug — CrowdSec is doing exactly what it's
  supposed to — but if a smoke test run looks like 100% block rate for no
  obvious reason, check `cscli decisions list` before assuming something's
  broken. `cscli decisions delete --all` clears it for a fresh baseline.
- **A single CRITICAL CRS match doesn't guarantee a block on its own.**
  E.g. a bare `sqlmap/1.6` User-Agent against a route with no other attack
  payload matches CRS 913100 (critical, scanner UA) alone — anomaly score
  7/10 = 0.7, under the default `RISK_THRESHOLD=0.8`. The removed local
  heuristic used to catch this case specifically (a hardcoded UA regex
  forcing score 1.0); CRS's own anomaly scoring, combined via `max()` with
  CrowdSec, doesn't reproduce that guarantee for every single-rule match.
  Accepted trade-off of removing the heuristic, not a bug — tune
  `RISK_THRESHOLD` down or `CORAZA_SCORE_DIVISOR` if this class of request
  needs to be blocked outright.
- **CrowdSec bouncer key rotation on an existing deployment.** CrowdSec
  only auto-registers a bouncer from its `BOUNCER_KEY_<name>` env var if
  that bouncer doesn't already exist — changing `CROWDSEC_BOUNCER_KEY` in
  `.env` on a deployment that's already run once does *not* update the
  registered key. You'll see 403s from the LAPI until you also run
  `cscli bouncers delete scoring` (inside the `crowdsec` container) and
  restart it. Only matters after the first `docker compose up`; a fresh
  clone via `init.sh` + first startup is unaffected.
