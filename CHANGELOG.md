# Changelog

All notable changes to this project, grouped roughly by theme rather than
strictly by commit — this was built in one continuous session, so dates
compress a lot of iteration into each entry.

## [Unreleased]

### Added

- **`letsencrypt-sidecar`: opt-in automatic TLS via Let's Encrypt.** A new
  `routes.csv` column (`letsencrypt`) flags a domain for real
  issuance/renewal instead of `generate-cert.sh`'s self-signed flow —
  written into the exact same `envoy/ssl/<domain>.crt`/`.key` naming
  convention, so `envoy-control-plane`'s existing fsnotify hot-reload picks
  it up with zero changes on that side. HTTP-01 challenges are served by a
  dedicated Envoy listener (`buildAcmeChallengeListener`, port 80, built
  only when at least one route actually needs it) proxying to the
  sidecar's own tiny HTTP server. Real ACME account key persists in a new
  `letsencrypt-data` volume (never bind-mounted); private keys are written
  `0600` (real credential material, unlike the self-signed flow's
  throwaway `0644`). Verified against Let's Encrypt's real staging
  API — account registration succeeded, and issuance for `shop.example.com`
  correctly failed with `rejectedIdentifier: forbidden by policy`,
  confirming the entire plumbing chain works up to the one boundary that
  can't be crossed in this repo (a real, owned, publicly-resolvable
  domain). `/routes/health` gained a `letsencrypt` key (status + expiry +
  last error per domain); the dashboard shows it as a small badge per
  front domain in the topology view.
- **A dashboard page and chart for `crs-tuner`'s auto-generated
  exclusions.** Every rule `crs-tuner` writes now also logs a structured
  record (`crs-tuner/analysis/_generated-exclusions.jsonl`, mirroring the
  existing dedicated-log convention `_errors.jsonl` already established)
  with the rule's own auto-assigned ID, domain, path, CRS rule, target
  variable, confidence, and reasoning — cross-referenceable by ID with the
  actual generated `SecRule` line. A new **`/rules`** dashboard page lists
  every one, most recent first; the main dashboard gained a live chart of
  the running total (same rolling-sampled-gauge pattern as the existing
  queue-depth chart), appearing only once something's actually been
  generated.
- **`crs-tuner`'s prompt now judges the matched value on its own content,
  not just which rule category matched it.** Found and fixed a real gap:
  a generic protocol-enforcement rule (e.g. 920273, "invalid character")
  can still be tripped by a genuine attack payload, and the model would
  sometimes reason "it's just a protocol rule" without checking whether
  the actual matched *value* was a textbook attack string. The system
  prompt (`crs-tuner/app/ollama_client.py`, shared by both the Ollama and
  `claude-shim` backends since they take the same request shape) now
  explicitly lists recognizable attack patterns (SQL tautologies, script
  injection, path traversal, command injection, encoded variants) to
  classify true-positive regardless of rule category, alongside what a
  genuine false positive looks like, so it doesn't overcorrect into
  flagging everything. Verified live: the same textbook `' OR '1'='1`
  payload on rule 920273 now judges `true_positive` (confidence 1.0)
  consistently across repeated identical requests, while a genuinely
  benign match on a *different* variable of the same request (a numeric
  parameter counter) still correctly judges `false_positive` — the fix is
  value-content-aware, not a blanket change in either direction.
- **`claude-shim`: an Ollama-API-compatible alternative to `ollama-local`,
  backed by `claude -p`** (Claude Code's non-interactive mode) instead of a
  locally-run model — uses an existing Claude subscription's included usage
  instead of a GPU or a metered `ANTHROPIC_API_KEY`. Drop-in for
  `crs-tuner`: exposes `POST /api/chat` + `GET /api/tags` matching Ollama's
  shapes, zero changes needed on `crs-tuner`'s side, just point `OLLAMA_URL`
  at it. Credentials are never a live bind-mount of the host's real
  `~/.claude` — `setup-credentials.sh` copies only the account/session-level
  auth files into an isolated Docker volume the container reads/writes
  instead, so nothing the container does can affect the actual local Claude
  Code session. Every `Bash`/`Write`/`Edit`/`NotebookEdit` tool is denied on
  every call — the "matched value" being judged is attacker-controlled
  input, so a value crafted to look like a tool-use instruction can't
  actually get anything executed. Verified end-to-end through the real
  `crs-tuner` pipeline (`tests/crs-tuner-test.sh`), not just a standalone
  curl test. Real cost/latency measured, not estimated, and it's not
  free — see `claude-shim/README.md`; the single biggest factor found was
  running `claude -p` from an empty working directory instead of a real
  project directory (~$0.005-0.011/call steady-state vs. ~$0.11-0.12/call
  with CLAUDE.md/project auto-discovery bloating every call's context).
- **`crs-tuner`: async, LLM-tuned WAF exclusions.** Every CRS match at or
  above `AI_TUNER_MIN_SEVERITY_CODE` is queued (Redis Stream `crs-matches`)
  by `scoring-service` and analyzed off the request path by a self-hosted
  LLM (Ollama; local by default, `OLLAMA_URL` can point at a remote
  instance instead — separate `ollama-local`/`ai-tuner` Compose profiles so
  enabling the tuner doesn't require running a local model). Every verdict
  is logged (`crs-tuner/analysis/<domain>.jsonl`), with analysis failures
  specifically kept in their own `_errors.jsonl`. Only once the *same*
  (domain, path, rule, variable, key) is independently judged a false
  positive `AI_TUNER_FP_THRESHOLD` times does `crs-tuner` generate and
  hot-load a narrowly-scoped exclusion (`ctl:ruleRemoveTargetById`, chained
  on Host *and* `REQUEST_FILENAME` — domain-, path-, and variable-scoped,
  not domain-wide) into `coraza-service/crs-exclusions/auto-<domain>.conf`
  — verified the full loop end-to-end, including GPU-accelerated inference
  (0.15s warm vs. several seconds on CPU) and a live dashboard chart of
  queue depth (`/api/queue`, shown only once something's actually queued).
  Replaces two earlier real-time signals (a UA-pattern heuristic, then an
  ML anomaly detector) that were both built and then removed — see
  `TODO.md` for why.
- **`AI_TUNER_INELIGIBLE_TAGS`: a hard, non-LLM eligibility gate on
  `crs-tuner`.** Found empirically, not theoretically: under sustained
  mixed attack traffic, the local model judged real CRS attack-signature
  matches (SQLi, XSS, LFI, RCE, scanner detection) "false positive"
  consistently enough to auto-generate dozens of exclusions across
  multiple domains within minutes — raising the confidence bar or the
  repeat threshold doesn't fix this, since the model was often confident
  and consistent about being wrong. `scoring-service` now checks a match's
  CRS tags before it's ever queued (`events.py`'s `publish_crs_match`) and
  drops anything tagged as a real attack-signature category — no LLM
  verdict can override this regardless of confidence or repetition. The
  tuning loop is now structurally limited to the generic protocol/format
  anomaly categories it was designed for. See `TODO.md`/`README.md` for
  the full finding.
- **`crs-tuner-test.sh`**: exercises the adaptive-exclusion loop end-to-end
  against a real, non-attack false positive (an apostrophe in a name field
  — CRS's classic `O'Brien`, trips rule 920273 at higher paranoia levels)
  — repeats it, waits for `crs-tuner` to judge each one, reports the
  verdicts and whether an exclusion got generated, and confirms unrelated
  legitimate traffic is unaffected either way.
- **`tests/options-impact-test.sh`**: sends one fixed request per traffic
  category (legitimate, SQLi, XSS, LFI, RCE, scanner UA, a borderline false
  positive) and reports the *active* configuration's actual effect —
  composite score, contributing signals, real HTTP outcome, and the
  underlying decision independent of `AUDIT_MODE` — so changing `.env`
  options and re-running shows exactly what changed. Backed by a new
  `dashboard` `/api/config` JSON endpoint (previously only embedded in the
  HTML page as `window.__ACTIVE_CONFIG__`).
- **Default `AI_TUNER_MODEL` switched from `llama3.2:3b` to `llama3:8b`** —
  judges more reliably (see the `AI_TUNER_INELIGIBLE_TAGS` finding above,
  found against the 3B model); wants GPU acceleration to stay fast, drop to
  a smaller tag for CPU-only setups.
- **Per-site hand-written exclusion files.** `coraza-service/crs-exclusions/`
  already globs every `*.conf` in the directory, so a domain-scoped
  hand-written exclusion no longer has to live mixed into the single shared
  `crs_exclusion.conf` — it can go in its own `<domain>.conf` next to it
  (see the new `shop.example.com.conf` for a worked example). Cross-domain
  exclusions with no Host condition still belong in `crs_exclusion.conf`.
  IDs stay unique across the whole directory, not just within one file —
  coordinated by convention, same as before.
- **`crs-extra/`**: a second hot-reloaded directory alongside
  `crs-exclusions/`, for hand-authored new CRS-style rules rather than
  narrowing/removing existing ones — same fsnotify mechanism, generalized
  to watch both directories and glob-`Include` every `.conf` file in each
  (`coraza-service`'s `buildWAF`/`watchConfDirs`). A three-way rule-ID
  range convention (documented in both folders) keeps hand-written and
  `crs-tuner`-generated rules from ever colliding.
- **Direct Coraza/CRS → CrowdSec feedback loop**: a single CRITICAL-severity
  CRS match now feeds CrowdSec's `crowdsecurity/modsecurity` scenario
  immediately (originally `scoring-service/app/crowdsec_client.py`'s
  `log_modsec_matches_for_crowdsec`, now `scoring-service-go/crowdsec/feed.go`'s
  `LogModsecMatches` — see the Go rewrite entry below, writing ModSecurity-format error-log
  lines Coraza itself doesn't natively produce), rather than only
  indirectly via the generic repeated-403 pattern the access-log feed
  already covered. One confirmed CRS match can now ban an IP outright,
  even on a request whose own combined score doesn't cross
  `RISK_THRESHOLD` locally — verified end-to-end: a single SQLi request
  produced an immediate `crowdsecurity/modsecurity` ban, and the next
  (otherwise harmless) request from that IP was correctly denied via the
  `crowdsec` signal.
- **Envoy edge proxy** with an `ext_authz` (HTTP-mode) filter delegating
  every request to `scoring-service` before routing.
- **scoring-service**: combines Coraza/CRS's anomaly score and CrowdSec's
  decision into one composite score (`max()` of normalized signals), with
  per-source reasons surfaced to the dashboard. Audit mode
  (`AUDIT_MODE=true`) scores and logs identically but never actually blocks.
- **coraza-service**: Coraza WAF + OWASP CRS in `SecRuleEngine
  DetectionOnly` mode — advisory only, never blocks on its own. Fetches CRS
  itself on startup (`CRS_VERSION`, supports `latest` via GitHub tags API),
  hot-reloads local exclusions (`crs-exclusions/`) and hand-authored new
  rules (`crs-extra/`) via fsnotify with no restart, and supports a
  configurable `CRS_PARANOIA_LEVEL` (1–4) applied the same way, decoupled
  from CRS fetching so it takes effect even without a version bump.
- **CrowdSec integration**: real log-based detection (not just IP
  reputation lookup) via the `crowdsecurity/nginx` collection, fed by an
  nginx-combined-format log scoring-service writes. Decisions are polled
  into a local in-process cache (not queried per-request) to keep lookup
  latency near-zero.
- **Live dashboard**: WebSocket-fed, time-bucketed (not raw-buffer-capped)
  charts — requests/blocked per IP and per domain, requests-by-backend
  trend, IP/domain donuts with click-to-filter, a backend topology graph
  (front domain → deduplicated backend target, live up/down), composite
  score breakdown per request with per-source coloring, live connectivity
  dots for Coraza/CrowdSec (not just their enabled/disabled config state),
  and a plain on/off config bar (audit mode, risk threshold, per-tool
  flags, CRS version/paranoia level/fetch date).
- **Dynamic Envoy configuration**: a Go xDS (ADS) control plane
  (`envoy-control-plane/`) that turns `routes.csv` (id, domain, target,
  port, ssl, cert_check, scoring) plus a `ssl/` cert directory into live
  Envoy listeners/routes/clusters, pushed over gRPC — no static
  `envoy.yaml` edits, no restarts, changes apply within ~300ms of an
  fsnotify event. Supports:
  - Multiple domains routed to different (or shared) upstream targets
  - Per-domain TLS termination (SNI-based filter chain matching)
  - Per-domain upstream cert validation toggle (`cert_check`) — trust a
    self-signed/unknown upstream cert, or require it validate against the
    system CA bundle
  - Per-domain scoring pipeline toggle (`scoring` — skip `ext_authz`
    entirely for that route)
  - A static catch-all default site for unmatched domains
  - Live backend-target health (TCP reachability, deduplicated by
    `target:port`) exposed over an internal HTTP endpoint and surfaced on
    the dashboard
- **HTTP/3 (QUIC)**: a UDP listener sharing the HTTPS port, advertised via
  `alt-svc`, alongside the existing TCP HTTP/1.1+2 listener.
- **Security hardening**: explicit TLS 1.2–1.3 floor/ceiling (both
  downstream and upstream), security response headers (HSTS scoped to
  HTTPS only, X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
  Permissions-Policy), `x-envoy-*` header suppression, content-negotiated
  JSON/HTML error pages (403/5xx, based on `Accept`).
- **Configurable request-handling limits**: ext_authz body-buffer size and
  timeout, upstream connect timeout, overall request timeout, and stream
  idle timeout — all via `.env`, all previously hardcoded.
- **ssl-audit tool**: containerized `testssl.sh` run against every
  `ssl=true` domain, scored for hardening/best practices (`score.py`),
  deliberately ignoring the expected self-signed chain-of-trust finding
  while keeping every other real finding (cert lifetime, revocation,
  header presence, protocol/cipher support, known CVEs). Produces
  markdown and a styled HTML report.
- **k6 load/smoke test** (`tests/loadtest/smoke.js`) with a context banner and
  saved results, runnable standalone via a Compose profile.
- **Traffic generator** (`generate-traffic.sh`) — mixed normal/malicious
  synthetic traffic for exercising the dashboard and scoring pipeline.
- **`init.sh`**: bootstraps a fresh checkout — creates `.env` from
  `.env.example`, randomizes the CrowdSec bouncer key, generates certs for
  every `ssl=true` `routes.csv` domain, and prepares the CrowdSec log file
  CrowdSec needs to already exist before its first startup.
- **Compose profiles** for Coraza/CrowdSec (`COMPOSE_PROFILES` in `.env`)
  — run without either container entirely, not just with their scoring
  input disabled.
- Branded 403/5xx error pages (HTML and JSON variants).
- **Configurable request-handling limits** (continued): `.env`-driven ext_authz
  timeout/body size, upstream connect timeout, overall request timeout, and
  stream idle timeout (the last one matters for long-lived responses like SSE).
- **HTTP → HTTPS redirect**, but only for `routes.csv` domains with `ssl=true`
  — domains without a cert have no HTTPS listener to redirect to, so they
  keep being served over plain HTTP directly.
- **Per-request protocol tracking** (HTTP/1.1 / HTTP/2 / HTTP/3), resolved
  by Envoy itself via the `%PROTOCOL%` command operator in a `header_mutation`
  filter placed before `ext_authz`, forwarded through to scoring-service and
  shown as its own column on the dashboard.
- A default self-signed cert (`generate-cert.sh default`) backing the HTTPS
  listener's `DefaultFilterChain` — see Fixed.
- A favicon for the default site.

### Changed

- **`scoring-service` rewritten from Python/FastAPI to Go
  (`scoring-service-go/`), and Envoy's `ext_authz` filter switched from
  HTTP mode to gRPC mode** (`envoy-control-plane/main.go`'s
  `buildExtAuthzFilter` — `envoy.service.auth.v3.AuthorizationServer`
  instead of a JSON-over-HTTP `POST /check`). Every behavior was ported
  deliberately, not just translated: the composite scoring logic
  (`scoring/`), the CrowdSec LAPI decision-stream mirror and its two
  file-based log feeds including the exact ModSecurity grok-compatible
  format (`crowdsec/`), the coraza-service client and its
  `severity != "unknown"` filter (`coraza/`), and — critically —
  `events.PublishCRSMatch`'s `AI_TUNER_INELIGIBLE_TAGS` hard gate that
  keeps real attack-signature CRS matches out of `crs-tuner`'s queue no
  matter what any LLM judges (`events/redis.go`). Fixed one latent bug
  found while porting rather than carrying it forward: the original's
  denied-response body indexed `reasons[0]` unchecked; the Go version
  guards it. gRPC mode has no equivalent of HTTP mode's
  `AllowedHeaders`/`AllowedUpstreamHeaders` (Envoy hands the whole request
  to the authz server instead) — the same 6-header allow-list is now
  enforced in the Go service itself (`authz/headers.go`), a deliberate
  choice to not silently widen what scoring-service sees. Found one real
  bug via live testing that the port itself didn't anticipate: filtering
  headers to that old allow-list dropped a literal `host` header for
  HTTP/1.1 requests entirely (only `:authority` was allow-listed,
  HTTP/2-style), which meant CRS saw every request as missing its Host
  header — including breaking every domain-scoped `crs-tuner` exclusion,
  which key on `REQUEST_HEADERS:Host`. Fixed by synthesizing `host` from
  `AttributeContext_HttpRequest`'s dedicated `Host` field (which Envoy
  resolves correctly regardless of HTTP/1.1 vs. HTTP/2 vs. HTTP/3)
  directly into the header map handed to coraza-service, rather than
  relying on whichever header name the wire happened to use. Measured,
  not assumed: ~10x lower average latency, ~15x lower p95, ~1.4x higher
  throughput under identical k6 load — see `TODO.md`'s Performance
  section for the full numbers.
- **Moved everything traffic/verification-related into a new `tests/`
  folder**: `loadtest/` → `tests/loadtest/`, `ssl-audit/` →
  `tests/ssl-audit/`, `run-audit.sh` → `tests/run-audit.sh`,
  `run-smoke-test.sh` → `tests/run-smoke-test.sh`, `crs-tuner-test.sh` →
  `tests/crs-tuner-test.sh`, `generate-traffic.sh` →
  `tests/generate-traffic.sh` — keeps the project root to the actual demo
  stack plus pure bootstrap utilities (`generate-cert.sh`, `init.sh`). All
  `tests/*.sh` scripts still run from the project root
  (`./tests/<script>.sh`), not from inside `tests/`.
- Bumped the Envoy image from v1.31.2 to v1.39.1.
- Moved `envoy.yaml`, `error_pages/`, `default-site/`, and `ssl/` into a
  dedicated `envoy/` folder; moved `generate-cert.sh` and `run-audit.sh` to
  the project root.
- All cert/key material is embedded inline into the generated Envoy config
  (`DataSource_InlineBytes`) rather than referenced by filename — see Fixed.
- `SSL_DIR`, dashboard bind address/port, and Envoy HTTP/HTTPS ports are
  all `.env`-configurable rather than hardcoded paths/values.
- **Removed the `default-site` nginx container entirely.** Unmatched
  domains are now answered directly by Envoy (`DirectResponseAction`,
  `envoy/default-site/index.html` read fresh on every control-plane
  rebuild) — no upstream, no separate container, no nginx-specific
  version-leak surface to patch.
- `Server` response header suppressed entirely (`PASS_THROUGH` +
  `ResponseHeadersToRemove`) rather than left at Envoy's own generic
  `server: envoy` default.

### Fixed

- **Chart.js CDN version pin** that 404'd, silently breaking the whole
  dashboard's JS before it ever connected.
- **Dashboard render freeze under load**: per-event full table rebuilds
  blocked the main thread (5.7s for a 1500-event burst) — decoupled
  rendering onto a fixed 1s tick regardless of event arrival rate (down to
  ~3ms for the same burst).
- **Chart accuracy at high volume**: charts were derived from the
  event-count-capped raw buffer, silently showing less than the claimed
  60s window under load — replaced with a separate time-bucketed store
  pruned by wall-clock time, independent of buffer size.
- **Client IP always "unknown"**: `use_remote_address` defaults to false
  in Envoy's HCM; without it, no client IP was ever recorded.
- **CrowdSec never tailing its log**: its file datasource globs for
  matching files once at startup and never retries — fixed by bind-mounting
  a pre-created host file instead of a named volume that could still be
  empty at that point.
- **Coraza `Include` glob resolution**: glob includes resolve against the
  filesystem root, not the including file's directory (unlike single-file
  includes) — fixed by using absolute paths in the generated `main.conf`.
- **`os.RemoveAll` on a bind-mount point**: CRS's own directory *is* the
  mount point, so removing and recreating it (`os.RemoveAll`) failed with
  "device or resource busy" — fixed to clear contents only.
- **Dashboard's CRS metadata race**: version/fetch-date were cached once at
  Python import time; `depends_on` only guarantees start order, not
  completion, so a fast-starting dashboard could permanently cache
  "unknown" — fixed to read fresh per request.
- **routes.csv hot-reload silently stopped working** after being edited
  via a write-temp-then-rename pattern while mounted as a single file —
  fixed by mounting its parent directory instead (same class of fix
  already applied to the CrowdSec log file).
- **TLS private key permission mismatch**: `openssl`-generated keys
  defaulted to mode 600 owned by the host user; Envoy runs as a different
  UID inside the container and couldn't read them — fixed in
  `generate-cert.sh` (mode 644).
- **`Host: domain:port` routing miss**: Envoy's `VirtualHost.domains`
  requires an exact match including port; a client on a non-default port
  sends the port in its Host header — fixed with the `:*` wildcard suffix.
- **`cert_check=true` silently not enforcing anything**: upstream TLS
  verification was configured with `VERIFY_TRUST_CHAIN` but no
  `TrustedCa`, which has nothing to validate against — fixed by pointing it
  at the system CA bundle.
- **Cert rotation not actually rotating**: certs were referenced by
  filename (`DataSource_Filename`); replacing a cert's *content* in place
  produced a byte-identical Envoy config with nothing for the control
  plane to push differently, so Envoy kept serving the stale cert
  indefinitely — fixed by embedding cert bytes inline instead, so content
  changes are visible in the pushed config.
- **`DASHBOARD_ALLOWED_IPS=127.0.0.1` locking out the default (loopback)
  bind**: Docker's hairpin NAT rewrites same-host connections' source IP to
  the bridge gateway before the app ever sees them — fixed by skipping the
  allowlist check entirely whenever the bind address is loopback (already
  fully restricted at the socket level).
- **Dead admin-API port publish**: `9901:9901` was published to the host
  but Envoy's admin listener binds to `127.0.0.1` *inside* the container —
  the host mapping never actually worked. Removed; use `docker compose
  exec envoy` instead.
- **QUIC listener rejected** ("Non-HTTP/3 codec configured on QUIC
  listener") until the HTTP/3 listener's HCM was given an explicit
  `HTTP3` codec type — Envoy's default `AUTO` codec doesn't include it.
- **nginx version leak on `default-site`'s unmatched paths**: a genuine
  404 for a missing path passed straight through nginx's own default
  error page, which embeds its version in the body regardless of the
  `Server` header — moot now that `default-site` doesn't exist as a
  container at all (see Changed), but was fixed in place first
  (`server_tokens off` + routing 404s to the branded page) before the
  container was removed entirely.
- **Unmatched HTTPS SNI dropping the connection outright**
  (`PR_END_OF_FILE_ERROR` client-side, no TLS alert, no HTTP response):
  the HTTPS listener only had per-domain filter chains matched by SNI —
  nothing to fall back to for a client with no SNI or an SNI matching no
  `routes.csv` domain. Fixed with `Listener.DefaultFilterChain` backed by
  a dedicated `default` cert, routing through the same catch-all
  `RouteConfiguration` vhost the HTTP listener already had.

### Security

- Explicit TLS 1.2–1.3 floor on both downstream and upstream connections
  (previously implicit on Envoy's own defaults).
- Response security headers added proxy-wide (HSTS, X-Content-Type-Options,
  X-Frame-Options, Referrer-Policy, Permissions-Policy); `x-envoy-*`
  internals suppressed.
- Dashboard bound to loopback by default (`DASHBOARD_BIND_ADDR`), with an
  optional IP/CIDR allowlist (`DASHBOARD_ALLOWED_IPS`) for when it's opened
  further.
- Envoy admin API confirmed never reachable from the host.
- Demo cert lifetime brought under the CA/Browser Forum 398-day baseline
  (825 → 397 days default).
- `.env.example` replaces a committed `.env`; `init.sh` randomizes the
  CrowdSec bouncer key on first setup instead of shipping a fixed default
  into every deployment.
