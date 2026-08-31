# Changelog

All notable changes to this project, grouped roughly by theme rather than
strictly by commit — this was built in one continuous session, so dates
compress a lot of iteration into each entry.

## [Unreleased]

### Added

- **Envoy edge proxy** with an `ext_authz` (HTTP-mode) filter delegating
  every request to `scoring-service` before routing.
- **scoring-service**: combines a local UA/pattern heuristic, Coraza/CRS's
  anomaly score, and CrowdSec's decision into one composite score
  (`max()` of normalized signals), with per-source reasons surfaced to the
  dashboard. Audit mode (`AUDIT_MODE=true`) scores and logs identically but
  never actually blocks.
- **coraza-service**: Coraza WAF + OWASP CRS in `SecRuleEngine
  DetectionOnly` mode — advisory only, never blocks on its own. Fetches CRS
  itself on startup (`CRS_VERSION`, supports `latest` via GitHub tags API),
  hot-reloads a local exclusions file (`crs-exclusions/crs_exclusion.conf`)
  via fsnotify with no restart, and now supports a configurable
  `CRS_PARANOIA_LEVEL` (1–4) applied the same way, decoupled from CRS
  fetching so it takes effect even without a version bump.
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
- **k6 load/smoke test** (`loadtest/smoke.js`) with a context banner and
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

### Changed

- Bumped the Envoy image from v1.31.2 to v1.39.1.
- Moved `envoy.yaml`, `error_pages/`, `default-site/`, and `ssl/` into a
  dedicated `envoy/` folder; moved `generate-cert.sh` and `run-audit.sh` to
  the project root.
- All cert/key material is embedded inline into the generated Envoy config
  (`DataSource_InlineBytes`) rather than referenced by filename — see Fixed.
- `SSL_DIR`, dashboard bind address/port, and Envoy HTTP/HTTPS ports are
  all `.env`-configurable rather than hardcoded paths/values.

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
