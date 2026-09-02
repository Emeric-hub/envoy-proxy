# letsencrypt-sidecar

Issues and renews real Let's Encrypt certificates for any `routes.csv` row
with `letsencrypt=true`, dropping them into the same `envoy/ssl/`
directory `envoy-control-plane` already hot-reloads from (`generate-cert.sh`'s
self-signed flow uses the exact same directory/naming — the two are
interchangeable as far as Envoy is concerned).

## The one thing that matters before you try this

**Real issuance needs a real, owned, publicly-resolvable domain, with port
80 reachable from the internet.** Let's Encrypt's HTTP-01 challenge has no
way around that — their validation server has to reach
`http://<your-domain>/.well-known/acme-challenge/<token>` on the real
internet. Against this repo's own demo domains (`*.example.com`,
IANA-reserved, not publicly resolvable, running on localhost with no
public exposure), issuance **cannot** succeed — verified directly: Let's
Encrypt's own staging API rejects `*.example.com` outright
(`rejectedIdentifier: forbidden by policy`), which is actually a clean
confirmation that everything up to that point (ACME account registration,
routes.csv parsing, order creation, error handling) is wired correctly.
This isn't a bug to fix, it's the actual, correct behavior for a domain
nobody can own.

## Setup (once you have a real domain)

1. Point the domain's real public DNS at the host running this stack.
2. Uncomment envoy's port 80 mapping in `docker-compose.yml`.
3. Set `LETSENCRYPT_EMAIL` in `.env`.
4. Flag the domain `letsencrypt=true` in `routes.csv`.
5. `COMPOSE_PROFILES=coraza,crowdsec,letsencrypt docker compose up -d --build`

Leave `LETSENCRYPT_STAGING=true` (the default) while testing — staging has
no meaningful rate limits and issues certs browsers won't trust. Only set
it to `false` once you're ready for a real, trusted certificate, subject
to Let's Encrypt's production rate limits.

## How it works

- A background loop (same shape as `crs-tuner`'s Redis-stream consumer or
  `scoring-service-go`'s CrowdSec poller — nothing new architecturally)
  checks every `letsencrypt=true` domain on `ACME_CHECK_INTERVAL_H`
  (default 12h), reads the current cert's expiry if one exists, and
  issues/renews if it's missing or within `ACME_RENEW_DAYS_BEFORE` (default
  30) of expiring.
- HTTP-01 challenges are served by this container's own tiny HTTP server
  (`challenge/server.go`), which `envoy-control-plane` routes to via a
  dedicated port-80 listener — built **only** when at least one route has
  `letsencrypt=true`, so it doesn't exist at all if you're not using this.
- Success writes `<domain>.crt`, `<domain>.key` (`0600` — this is real
  credential material, not `generate-cert.sh`'s throwaway `0644` self-signed
  dev keys), and a flat `<domain>.expiry` timestamp into `envoy/ssl/` —
  same naming convention as `generate-cert.sh`, same fsnotify hot-reload
  picks it up, no new integration point on that side.
- Every attempt (success or failure) also writes `<domain>.acme-status`
  (`ok`/`failed`/`pending`) and, on failure, `<domain>.acme-error` — a
  failed renewal never touches an existing valid cert, only these status
  files. `envoy-control-plane`'s `/routes/health` surfaces this
  (`letsencrypt` key), and the dashboard shows it as a small badge with an
  expiry-date tooltip on each front domain.
- The ACME account's private key persists in the `letsencrypt-data` Docker
  volume (never bind-mounted into the repo) — re-registering an existing
  account key is idempotent (Let's Encrypt just returns the existing
  account), so there's nothing else to persist across restarts.

## What's out of scope (for now)

DNS-01 challenges (would remove the port-80/public-reachability
requirement, at the cost of needing DNS provider API credentials — a
bigger secrets story than this demo needs) and wildcard certificates
(DNS-01 only, same reason).
