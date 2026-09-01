# envoy-proxy

A self-contained, containerized reverse proxy demo built around
[Envoy](https://www.envoyproxy.io/), with a composite request-scoring
pipeline (heuristics + OWASP CRS via Coraza + CrowdSec) sitting in front of
dynamic, CSV-driven multi-domain routing and a live dashboard.

This started as an exploration of "AI/ML augmented reverse proxy" — see
[TODO.md](TODO.md) for how far the implementation actually got toward that
versus where it stands today (spoiler: rule-based/WAF/reputation scoring,
not machine learning yet).

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
                                 │                        │  │  │
                                 │                        │  │  └──▶ crowdsec (reputation)
                                 │                        │  └─────▶ coraza-service (OWASP CRS)
                                 │                        └────────▶ local heuristic
                                 │
                                 ├──routes.csv target────▶ backend
                                 └──unmatched domain─────▶ answered directly by Envoy
                                                            (DirectResponseAction, no upstream)

  scoring-service ──publish──▶ redis ──pub/sub──▶ dashboard (live WebSocket UI)
```

Every signal (heuristic, CRS anomaly score, CrowdSec decision) is advisory —
none of Coraza or CrowdSec ever blocks on their own. `scoring-service` is the
single place that combines them into an allow/deny decision, which keeps the
"why was this blocked" story in one place instead of three.

## Services

| Service               | Role                                                              |
|------------------------|--------------------------------------------------------------------|
| `envoy`                | Edge proxy — HTTP, HTTPS, and HTTP/3 (QUIC) listeners               |
| `envoy-control-plane`  | Go xDS server: routes.csv + ssl/ → live Envoy config, no restarts   |
| `scoring-service`      | Combines heuristic + CRS + CrowdSec signals into allow/deny         |
| `coraza-service`       | Coraza WAF + OWASP CRS, `SecRuleEngine DetectionOnly` (advisory)    |
| `crowdsec`             | Log-based bot/attack detection, local decisions cache               |
| `dashboard`            | Live WebSocket dashboard — traffic, scores, topology, backend health|
| `redis`                | Pub/sub transport for scoring-service → dashboard events            |
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
- Generate some traffic to watch it react: `./generate-traffic.sh 60 0.1 3`
- Try the routed demo domains (`routes.csv`) directly:
  ```bash
  curl --resolve shop.example.com:10000:127.0.0.1 http://shop.example.com:10000/
  curl -k --resolve secure.example.com:10443:127.0.0.1 https://secure.example.com:10443/
  ```
- SSL/TLS hardening report: `./run-audit.sh` (needs `secure.example.com` up)

`docker compose up` starts everything by default. To skip Coraza and/or
CrowdSec entirely (not just disable their scoring input — actually not
start those containers), set `COMPOSE_PROFILES` in `.env` — see the comment
there.

## Dynamic routing (`envoy-control-plane/routes/routes.csv`)

```csv
id,domain,target,port,ssl,cert_check,scoring
1,shop.example.com,backend,8443,false,false,true
4,secure.example.com,backend,8443,true,false,true
```

| Column        | Meaning                                                                 |
|---------------|--------------------------------------------------------------------------|
| `domain`      | Host header Envoy matches to route this row                             |
| `target`,`port` | Upstream — always connected to over HTTPS                             |
| `ssl`         | Terminate TLS for this domain (needs a cert — see `generate-cert.sh`). Plain HTTP for this domain redirects to HTTPS instead of serving directly. |
| `cert_check`  | Validate the upstream's own TLS cert (vs. accept self-signed/untrusted) |
| `scoring`     | Whether this domain goes through the scoring pipeline at all            |

Edit the file and it's live within ~300ms — no Envoy restart, no reload
command. Same for dropping a new cert into `envoy/ssl/`.

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

What it explicitly does **not** do yet — see [TODO.md](TODO.md) for the
full list, most importantly: no inter-service encryption (everything inside
the Docker network is plaintext today), and no real ML — the "AI/ML" in the
original framing is currently heuristic + WAF + reputation scoring.

## Tools

- `generate-traffic.sh` — sends a mix of normal/malicious traffic through
  Envoy so you can watch the dashboard react.
- `generate-cert.sh <domain> [days]` — self-signed cert/key for a
  `routes.csv` domain with `ssl=true`.
- `run-audit.sh [domain...]` — runs `testssl.sh` (containerized) against
  every `ssl=true` domain and scores the result for hardening/best
  practices via `ssl-audit/score.py` (ignores the expected self-signed
  finding, keeps everything else). Produces markdown + HTML reports.
- `run-smoke-test.sh [vus] [ramp] [hold]` — standalone wrapper around the k6
  smoke test (`loadtest/smoke.js`); brings up whatever's missing, runs it,
  leaves the rest as it found it. Results land in `loadtest/results/`.

See [CHANGELOG.md](CHANGELOG.md) for what's been built and
[TODO.md](TODO.md) for what's left.
