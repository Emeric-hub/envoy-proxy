import asyncio
import logging
import os
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("scoring-service.crowdsec")

CROWDSEC_URL = os.environ.get("CROWDSEC_URL", "http://crowdsec:8080")
CROWDSEC_API_KEY = os.environ.get("CROWDSEC_API_KEY", "")
# Only bounds the background stream poll now (get_decisions is a local dict
# read, no network call) — generous since nothing on the request path waits
# on it, and a spurious timeout just delays the next sync by one interval.
TIMEOUT = float(os.environ.get("CROWDSEC_TIMEOUT", "2.0"))
ENABLE_CROWDSEC = os.environ.get("ENABLE_CROWDSEC", "true").strip().lower() in ("1", "true", "yes", "on")
POLL_INTERVAL = float(os.environ.get("CROWDSEC_POLL_INTERVAL", "10"))

# Shared with the crowdsec container (see crowdsec/acquis.yaml, docker-compose.yml).
# nginx combined log format — reuses CrowdSec's own well-tested nginx-logs
# parser/scenarios rather than writing a custom one for a bespoke format.
FEED_PATH = os.environ.get("CROWDSEC_FEED_PATH", "/var/log/crowdsec-feed/access.log")

_client: httpx.AsyncClient | None = None

# Real CrowdSec bouncers don't query the LAPI per request — they poll
# /v1/decisions/stream on an interval and keep a local mirror, so the actual
# per-request lookup is a free dict read instead of a network round-trip on
# every single request. This is that local mirror.
_decisions_by_ip: dict[str, dict[str, dict]] = {}  # ip -> {uuid: decision}

# Live connectivity state, updated by poll_decisions_stream() below and
# surfaced via get_status() for a real "is CrowdSec actually reachable right
# now" check — not just whether ENABLE_CROWDSEC is set.
_last_poll_ok = False
_last_poll_at: str | None = None
_last_error: str | None = None


def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=TIMEOUT)
    return _client


def log_request_for_crowdsec(*, ip: str, method: str, path: str, status: int, user_agent: str) -> None:
    """Feed this request to CrowdSec's agent as an nginx-style access log line, so
    its scenarios (scanner UAs, probing, aggressive crawling, ...) can build up
    decisions from real traffic patterns over time — this is what lets
    get_decisions() below find anything. Best-effort: a logging failure must
    never affect the actual scoring decision."""
    if not ENABLE_CROWDSEC:
        return
    try:
        time_local = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
        ua = user_agent.replace('"', "") or "-"
        line = f'{ip} - - [{time_local}] "{method} {path} HTTP/1.1" {status} 0 "-" "{ua}"\n'
        with open(FEED_PATH, "a") as f:
            f.write(line)
    except Exception:
        logger.warning("failed to write crowdsec feed log", exc_info=True)


async def poll_decisions_stream() -> None:
    """Background task (start once at app startup): keeps _decisions_by_ip in
    sync with CrowdSec's LAPI. First call uses startup=true and gets the full
    current decision set; every call after that gets only what changed
    (new/deleted) since the previous one — cheap regardless of how many
    decisions exist in total. Runs forever; on failure, logs and retries next
    interval rather than crashing the app."""
    global _last_poll_ok, _last_poll_at, _last_error
    if not ENABLE_CROWDSEC:
        return
    first = True
    while True:
        try:
            response = await get_client().get(
                f"{CROWDSEC_URL}/v1/decisions/stream",
                params={"startup": "true"} if first else {},
                headers={"X-Api-Key": CROWDSEC_API_KEY},
            )
            response.raise_for_status()
            data = response.json()
            for d in data.get("new") or []:
                _decisions_by_ip.setdefault(d["value"], {})[d["uuid"]] = d
            for d in data.get("deleted") or []:
                _decisions_by_ip.get(d["value"], {}).pop(d["uuid"], None)
            first = False
            _last_poll_ok = True
            _last_error = None
        except Exception as exc:
            logger.warning("crowdsec stream poll failed, will retry", exc_info=True)
            _last_poll_ok = False
            _last_error = str(exc)
        _last_poll_at = datetime.now(timezone.utc).isoformat()
        await asyncio.sleep(POLL_INTERVAL)


def get_status() -> dict:
    """A real connectivity check, not just whether ENABLE_CROWDSEC is set —
    reflects whether the last actual poll of CrowdSec's LAPI succeeded."""
    return {
        "enabled": ENABLE_CROWDSEC,
        "connected": _last_poll_ok if ENABLE_CROWDSEC else None,
        "last_poll_at": _last_poll_at,
        "last_error": _last_error,
    }


async def get_decisions(ip: str) -> list[dict]:
    """Advisory signal only — CrowdSec's agent never blocks anything itself here;
    it only accumulates decisions from the feed above. This reads the local
    mirror kept in sync by poll_decisions_stream(), not a live LAPI call — see
    that function for why. Reflects prior requests, not necessarily this one:
    CrowdSec needs to see a pattern across multiple requests before it
    decides, so the exact request that first crosses a scenario's threshold
    can still slip through once — expected, not a bug. Async signature kept
    for a consistent call site even though this no longer awaits anything."""
    if not ENABLE_CROWDSEC or not ip or ip == "unknown":
        return []
    return list(_decisions_by_ip.get(ip, {}).values())
