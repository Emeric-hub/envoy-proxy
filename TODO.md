# TODO

## The original vision vs. where this stands

This project was framed at the start as an **"AI/ML augmented reverse
proxy"** — the initial question was where to even start building one, and
Envoy + a scoring microservice came out of that discussion. What actually
got built is a **composite scoring pipeline**: a local UA/pattern
heuristic, OWASP CRS (via Coraza), and CrowdSec's reputation/behavior
detection, combined by `scoring-service` into one allow/deny decision. That
is genuinely useful and is how a lot of real WAF-adjacent systems work —
but none of it is machine learning. There's no model, nothing trained on
traffic, no anomaly detection beyond CRS's own rule-based anomaly scoring.

If the "AI/ML" part of the original goal gets picked back up, the natural
slot for it is a **fourth signal** into `scoring.py`'s `normalize_signals`/
`combine_scores` — e.g. an anomaly-detection model (isolation forest,
autoencoder, or similar) trained on request feature vectors (path entropy,
header set, timing, per-IP request-rate shape), or an LLM-based classifier
for payloads CRS's regex rules don't catch. Either would plug in the same
way Coraza and CrowdSec already do: a score in `[0, 1]`, folded into the
same `max()` combine step, with its own reasons surfaced in the dashboard.

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
  CRL/OCSP (this is exactly what `run-audit.sh` flags as HIGH on every
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

## Known limitations / not fully verified

- **HTTP/3 (QUIC)** is wired up (UDP listener bound, `alt-svc` advertised,
  Envoy accepts the config) but hasn't been exercised with a real QUIC
  handshake — the `curl` available in dev here isn't built with HTTP/3
  support. Worth testing from a real HTTP/3 client (recent Chrome, or a
  `curl` built against `ngtcp2`/`quiche`) before trusting it fully.
- **CrowdSec bouncer key rotation on an existing deployment.** CrowdSec
  only auto-registers a bouncer from its `BOUNCER_KEY_<name>` env var if
  that bouncer doesn't already exist — changing `CROWDSEC_BOUNCER_KEY` in
  `.env` on a deployment that's already run once does *not* update the
  registered key. You'll see 403s from the LAPI until you also run
  `cscli bouncers delete scoring` (inside the `crowdsec` container) and
  restart it. Only matters after the first `docker compose up`; a fresh
  clone via `init.sh` + first startup is unaffected.
