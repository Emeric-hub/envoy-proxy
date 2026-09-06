# envoy-proxy

A self-contained, containerized reverse proxy demo built around
[Envoy](https://www.envoyproxy.io/), with a composite request-scoring
pipeline (OWASP CRS via Coraza + CrowdSec) sitting in front of dynamic,
CSV-driven multi-domain routing, a live dashboard, and an async AI-tuned
WAF exclusion loop.

This started as an exploration of "AI/ML augmented reverse proxy." Two
earlier real-time signals (a UA-pattern heuristic, then an ML anomaly
detector) were built and removed — both scored requests with no real
ground truth. See [TODO.md](TODO.md) for that history and what's here
instead: CRS and CrowdSec stay as the two real-time signals, and a
self-hosted LLM (`crs-tuner` + Ollama) makes CRS itself more accurate over
time, asynchronously, rather than adding a third fragile real-time one.

## Architecture

```
                         ┌─────────────────────────────────────────┐
                         │              envoy-control-plane          │
 routes.csv ────watch──▶│  Go xDS (ADS) server — turns routes.csv +  │
 envoy/ssl/  ───watch──▶│  ssl/ into listeners/routes/clusters,      │
                         │  pushed to Envoy live, no restarts        │
                         └───────────────┬─────────────────────────┘
                                         │ gRPC (ADS)
                                         ▼
  client ──HTTP/HTTPS/HTTP3──▶ envoy ──ext_authz──▶ scoring-service ──▶ decision
                                 │                        │  │
                                 │                        │  └──▶ crowdsec (reputation)
                                 │                        └─────▶ coraza-service (OWASP CRS)
                                 │
                                 ├──routes.csv target────▶ backend
                                 ├──unmatched, Host=raw IP▶ scored too (crs-extra rule 10002)
                                 └──unmatched domain─────▶ answered directly by Envoy
                                                            (DirectResponseAction, no upstream)

  scoring-service ──publish──▶ redis ──pub/sub──▶ dashboard (live WebSocket UI)
  coraza-service CRITICAL match ──▶ crowdsec (crowdsecurity/modsecurity) ──▶ immediate ban

  scoring-service ──CRS match──▶ redis stream ──▶ crs-tuner ──▶ ollama (LLM judgment)
                                                       │
                                                       ├──▶ analysis/<domain>.jsonl (audit trail)
                                                       └──▶ N false-positive verdicts for the
                                                            same (domain, path, rule, variable) ──▶
                                                            crs-exclusions/auto-<domain>.conf
                                                            ──▶ coraza-service hot-reloads it
```

Both real-time signals (CRS anomaly score, CrowdSec decision) are advisory
— neither Coraza nor CrowdSec ever blocks on its own. `scoring-service` is
the single place that combines them into an allow/deny decision. A single
CRITICAL-severity CRS match also feeds CrowdSec's own
`crowdsecurity/modsecurity` scenario directly, so one confirmed attack can
ban an IP outright rather than only via CrowdSec's usual repeated-403
pattern. Separately and asynchronously, `crs-tuner` never sits on the
request path at all — it only ever changes what CRS itself does for
*future* requests, and only after repeated, independent agreement.

Two directories extend CRS core, opposite directions: `crs-exclusions/`
*narrows* it (hand-written or `crs-tuner`-generated exceptions for known
false positives), `coraza-service/crs-extra/` *adds* to it — hand-authored
rules covering gaps CRS core doesn't (IDs 1-29999, see
`crs-extra/README.conf`). Both hot-reload the same way, no restart needed.

## Services

| Service               | Role                                                              |
|------------------------|--------------------------------------------------------------------|
| `envoy`                | Edge proxy — HTTP, HTTPS, and HTTP/3 (QUIC) listeners               |
| `envoy-control-plane`  | Go xDS server: routes.csv + ssl/ → live Envoy config, no restarts   |
| `scoring-service`      | Go: combines CRS + CrowdSec signals into allow/deny, ext_authz gRPC  |
| `coraza-service`       | Coraza WAF + OWASP CRS, `SecRuleEngine DetectionOnly` (advisory)    |
| `crowdsec`             | Log-based bot/attack detection, local decisions cache               |
| `crs-tuner`            | Async: LLM-judges CRS matches, auto-generates exclusions over time  |
| `ollama`               | Local LLM inference for `crs-tuner` (optional — can point elsewhere)|
| `claude-shim`          | Alternative to `ollama`: Ollama-API-compatible, backed by `claude -p` (see `claude-shim/README.md`) |
| `letsencrypt-sidecar`  | Opt-in: issues/renews real TLS certs for `routes.csv` domains flagged `letsencrypt=true` |
| `geoip-service`        | Opt-in: local MaxMind GeoLite2-City lookups, enriches events for the dashboard's attack map (needs a MaxMind account+key) |
| `dashboard`            | Live WebSocket dashboard — traffic, scores, topology, backend health|
| `redis`                | Pub/sub + stream transport (dashboard events, `crs-tuner`'s queue)  |
| `backend`              | Demo upstream (`mendhak/http-https-echo`) — echoes request details  |

There's no separate container for unmatched domains — Envoy answers those
directly (`DirectResponseAction`) from `envoy/default-site/index.html`,
mounted straight into `envoy-control-plane` and hot-reloaded the same way
`routes.csv` and `ssl/` are.

## Quick start

```bash
git clone git@github.com:Emeric-hub/envoy-proxy.git
cd envoy-proxy
./init.sh                     # creates .env, randomizes the CrowdSec bouncer
                               # key, generates self-signed certs
docker compose up -d --build
```

Then:

- Dashboard: http://localhost:8002
- Generate some traffic to watch it react: `./tests/generate-traffic.sh 60 0.1 3`
- Try the routed demo domains (`routes.csv`) directly:
  ```bash
  curl --resolve shop.example.com:10000:127.0.0.1 http://shop.example.com:10000/
  curl -k --resolve secure.example.com:10443:127.0.0.1 https://secure.example.com:10443/
  ```
- SSL/TLS hardening report: `./tests/run-audit.sh` (needs `secure.example.com` up)

`docker compose up` starts everything by default. To skip Coraza and/or
CrowdSec entirely (not just disable their scoring input — actually not
start those containers), set `COMPOSE_PROFILES` in `.env` — see the comment
there.

`crs-tuner` (the async AI WAF-tuning loop) is opt-in, not in the default
`COMPOSE_PROFILES` — add `ai-tuner`, and `ollama-local` too unless
`OLLAMA_URL` points at a remote instance:

```bash
COMPOSE_PROFILES=coraza,crowdsec,ai-tuner,ollama-local docker compose up -d --build
```

For GPU-accelerated local inference (NVIDIA + the
[Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html)),
add `-f docker-compose.gpu.yml`:

```bash
COMPOSE_PROFILES=coraza,crowdsec,ai-tuner,ollama-local \
  docker compose -f docker-compose.yml -f docker-compose.gpu.yml up -d --build
```

No GPU (or no interest in running a local model at all)? `claude-shim` is
an alternative to `ollama-local` — backed by `claude -p` against an
existing Claude subscription instead of local inference. Real cost/latency
numbers (it's not free) and setup are in `claude-shim/README.md`:

```bash
./claude-shim/setup-credentials.sh
COMPOSE_PROFILES=coraza,crowdsec,ai-tuner,claude-shim docker compose up -d --build
```

Want real TLS instead of self-signed? Flag a domain `letsencrypt=true` in
`routes.csv`, set `LETSENCRYPT_EMAIL` in `.env`, and enable the profile —
see `letsencrypt-sidecar/README.md` (needs a real, owned,
publicly-resolvable domain; this repo's own `*.example.com` domains can't
actually complete issuance, by design of how Let's Encrypt validates):

```bash
COMPOSE_PROFILES=coraza,crowdsec,letsencrypt docker compose up -d --build
```

## Dynamic routing (`envoy-control-plane/routes/routes.csv`)

```csv
id,domain,target,port,ssl,cert_check,scoring,letsencrypt
1,shop.example.com,backend,8443,false,false,true,false
4,secure.example.com,backend,8443,true,false,true,false
```

| Column        | Meaning                                                                 |
|---------------|--------------------------------------------------------------------------|
| `domain`      | Host header Envoy matches to route this row                             |
| `target`,`port` | Upstream — always connected to over HTTPS                             |
| `ssl`         | Terminate TLS for this domain (needs a cert — see `generate-cert.sh`). Plain HTTP for this domain redirects to HTTPS instead of serving directly. |
| `cert_check`  | Validate the upstream's own TLS cert (vs. accept self-signed/untrusted) |
| `scoring`     | Whether this domain goes through the scoring pipeline at all            |
| `letsencrypt` | Auto-issue/renew a real cert via `letsencrypt-sidecar` instead of a self-signed one (opt-in, `letsencrypt` Compose profile — see `letsencrypt-sidecar/README.md`; needs a real, owned, publicly-resolvable domain, which this repo's own `*.example.com` rows can never be) |

Edit the file and it's live within ~300ms — no Envoy restart, no reload
command. Same for dropping a new cert into `envoy/ssl/` — by hand
(`generate-cert.sh`) or automatically (`letsencrypt-sidecar`, same
directory, same file naming).

A `default` cert (`generate-cert.sh default`, already generated by
`init.sh`) backs the HTTPS listener's fallback filter chain — without it, a
client connecting with no SNI or an SNI that matches no `routes.csv` domain
gets the connection dropped outright rather than any response.

## Configuration

Everything is `.env`-driven and documented inline there — ports, TLS
versions/timeouts, risk threshold, per-tool enable flags, CRS paranoia
level, CrowdSec poll interval, dashboard bind address, and more. Start from
`.env.example` (`init.sh` does this for you).

## Observability

The dashboard (`http://localhost:8002` by default, loopback-only unless you
change `DASHBOARD_BIND_ADDR`) shows, live:

- Per-IP and per-domain request/block trends and donuts
- Requests-by-backend trend, deduplicated by `target:port` (not by fronting
  domain — several domains commonly share one backend)
- A backend topology graph (front domain → backend target, live up/down)
- Composite score breakdown per request, colored per signal source
- Live connectivity status for Coraza and CrowdSec (not just "enabled",
  actually reachable right now)
- CRS version, paranoia level, and fetch date
- Per-request protocol (HTTP/1.1, HTTP/2, HTTP/3) — resolved by Envoy
  itself before `ext_authz` runs, not something a client header could spoof
- `crs-tuner`'s analysis queue depth (length + in-flight/pending), live —
  only appears once something's actually been queued, so it stays out of
  the way if `ai-tuner` isn't enabled
- A running count of `crs-tuner`-generated exclusion rules (same
  appears-once-there's-data treatment) — full detail on **`/rules`**: every
  auto-generated rule, which domain/path/CRS rule it narrows, the model's
  confidence and reasoning, cross-referenced by ID with the actual
  `SecRule` line in `coraza-service/crs-exclusions/auto-<domain>.conf`
- A small "LE" badge per front domain once `letsencrypt-sidecar` is
  managing its certificate — green/red/grey for issued/failed/pending,
  expiry date on hover

## Security posture

This is a demo/learning project, not a hardened production deployment.
What it does do:

- Explicit TLS 1.2–1.3 floor, no implicit reliance on Envoy defaults
- Security response headers (HSTS, X-Content-Type-Options, X-Frame-Options,
  Referrer-Policy, Permissions-Policy), scoped correctly (HSTS HTTPS-only)
- `x-envoy-*` internals suppressed, no version-disclosing `Server` header
- Dashboard off the network by default (loopback bind + optional IP allowlist)
- Envoy admin API never published to the host
- Fail-closed `ext_authz` (a scoring-service outage denies, doesn't allow)

What it explicitly does **not** do yet, or does with a caveat — see
[TODO.md](TODO.md) for the full list:

- No inter-service encryption (everything inside the Docker network is
  plaintext today)
- `crs-tuner`'s auto-generated exclusions are a genuinely self-modifying
  security surface. The threshold gate (`AI_TUNER_FP_THRESHOLD`) bounds the
  blast radius of any *one* bad LLM judgment, but doesn't bound how *wrong*
  the model can be about what counts as a false positive. Verified directly
  during development — twice, at two different scales:
  - A single-rule test: a 3B model judged real SQLi-detection rules "false
    positive" against a textbook `' OR '1'='1` payload, and the threshold
    gate let that verdict through into a live exclusion once it repeated.
  - A much larger, realistic-traffic test: with `AI_TUNER_MIN_SEVERITY_CODE`
    gating only on severity, sustained mixed traffic (repeated SQLi/XSS/LFI/
    RCE payloads and scanner User-Agents, the same shapes `generate-traffic.sh`
    sends) got the model to judge core CRS attack-signature rules — real
    SQLi/XSS/LFI/RCE/scanner-detection matches, not just anomaly noise —
    "false positive" consistently enough to auto-generate dozens of
    exclusions across multiple domains within minutes, meaningfully
    weakening real protection.
  The fix isn't a higher confidence bar or a higher repeat threshold — the
  model was often *confident* and *consistent* about being wrong. What
  actually closes the gap is a hard, non-LLM gate: `scoring-service` only
  ever queues a match for `crs-tuner` at all if its CRS tag isn't in
  `AI_TUNER_INELIGIBLE_TAGS` (defaults to the real attack-signature
  categories — SQLi, XSS, RCE, LFI/RFI, scanner detection, PHP/Node
  injection, session fixation, disclosure). No LLM verdict, confidence, or
  repeat count can ever generate an exclusion for those categories — the
  tuning loop is structurally limited to the generic protocol/format anomaly
  categories it was actually designed for (CRS's own noisy-at-high-paranoia
  rules, e.g. 920273/921180). Still review `crs-tuner/analysis/` and
  `crs-exclusions/auto-*.conf` periodically rather than treating this as
  fire-and-forget — the category gate bounds *what* can be auto-excluded,
  not whether a bad call within that narrower category ever happens.

## Tools

Bootstrap utilities live at the project root; everything that exercises
traffic against the stack or verifies/scores an outcome lives in `tests/`.

- `generate-cert.sh <domain> [days]` — self-signed cert/key for a
  `routes.csv` domain with `ssl=true`.
- `tests/generate-traffic.sh [count] [delay] [malicious_ratio]` — sends a
  mix of normal/malicious traffic through Envoy so you can watch the
  dashboard react.
- `tests/run-audit.sh [domain...]` — runs `testssl.sh` (containerized)
  against every `ssl=true` domain and scores the result for hardening/best
  practices via `tests/ssl-audit/score.py` (ignores the expected
  self-signed finding, keeps everything else). Produces markdown + HTML
  reports.
- `tests/run-smoke-test.sh [vus] [ramp] [hold]` — standalone wrapper around
  the k6 smoke test (`tests/loadtest/smoke.js`); brings up whatever's
  missing, runs it, leaves the rest as it found it. Results land in
  `tests/loadtest/results/`.
- `tests/crs-tuner-test.sh [domain] [repeats]` — exercises `crs-tuner`'s
  adaptive-exclusion loop end-to-end against a real, non-attack false
  positive (an apostrophe in a name field), reports the model's verdicts
  and whether an exclusion got generated, and confirms unrelated
  legitimate traffic is unaffected either way. Needs `ai-tuner` (and an
  Ollama endpoint) already running.
- `tests/options-impact-test.sh [domain]` — sends one fixed request per
  category (legitimate, SQLi, XSS, LFI, RCE, scanner UA, a borderline false
  positive) and reports, per category, the *active* configuration's actual
  effect: composite score, which signals fired, the real HTTP outcome, and
  the underlying decision (independent of `AUDIT_MODE`) — flip
  `AUDIT_MODE`/`RISK_THRESHOLD`/`ENABLE_CORAZA`/`ENABLE_CROWDSEC`/
  `ENABLE_AI_TUNER`/`CRS_PARANOIA_LEVEL` in `.env`, restart the affected
  service, and re-run to see exactly what changed.
- `tests/perf-impact-test.sh [vus] [ramp] [hold]` — the *performance* cost
  version of the same idea: runs the k6 smoke test with every signal off,
  then re-runs it with Coraza, then +CrowdSec, then +GeoIP, then +ai-tuner
  each layered on top, holding load identical across runs, and prints a
  p95/p99 latency comparison table (the delta between consecutive rows is
  that signal's own added cost). Skips a step gracefully (with a warning)
  if its container isn't running; always restores `scoring-service` to the
  real `.env` configuration on exit, even if interrupted. Needs a decent
  VU count/duration to say anything meaningful — the defaults (20/10s/20s)
  are a reasonable floor; noisy/inconsistent-looking deltas usually just
  mean the run was too short, not a real regression.

All `tests/*.sh` scripts are run from the project root (`./tests/<script>.sh`),
not from inside `tests/`.

See [CHANGELOG.md](CHANGELOG.md) for what's been built and
[TODO.md](TODO.md) for what's left.
