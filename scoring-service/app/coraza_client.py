import asyncio
import logging
import os
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("scoring-service.coraza")

CORAZA_URL = os.environ.get("CORAZA_URL", "http://coraza-service:8003/check")
CORAZA_HEALTH_URL = os.environ.get("CORAZA_HEALTH_URL", "http://coraza-service:8003/healthz")
TIMEOUT = float(os.environ.get("CORAZA_TIMEOUT", "0.2"))
ENABLE_CORAZA = os.environ.get("ENABLE_CORAZA", "true").strip().lower() in ("1", "true", "yes", "on")
# Reuses the same poll cadence as the crowdsec stream poller — no need for a
# separate knob for what's conceptually the same kind of background check.
POLL_INTERVAL = float(os.environ.get("CROWDSEC_POLL_INTERVAL", "10"))

_client: httpx.AsyncClient | None = None

# Live connectivity state, updated by poll_coraza_health() below. Polled
# independently of real request traffic so the status is meaningful even
# before the first request comes in — see get_status().
_last_poll_ok = False
_last_poll_at: str | None = None
_last_error: str | None = None


def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=TIMEOUT)
    return _client


async def get_anomaly_score(
    *, method: str, path: str, query: str, headers: dict[str, str], body: bytes, client_ip: str
) -> tuple[int, list[dict]]:
    """Advisory signal only — Coraza runs in SecRuleEngine DetectionOnly and never
    blocks on its own. If it's slow or unreachable, contribute nothing rather
    than delay or fail the actual scoring decision.

    Returns (anomaly_score, matched_rules) where matched_rules excludes CRS's
    own nolog bookkeeping/init rules (severity "unknown", weight 0) so callers
    only see rules that actually contributed to the score."""
    if not ENABLE_CORAZA:
        return 0, []
    try:
        response = await get_client().post(
            CORAZA_URL,
            json={
                "method": method,
                "path": path,
                "query": query,
                "headers": headers,
                "body": body.decode("utf-8", errors="replace"),
                "client_ip": client_ip,
            },
        )
        response.raise_for_status()
        data = response.json()
        matched_rules = [
            rule for rule in data.get("matched_rules", []) if rule.get("severity") not in (None, "unknown")
        ]
        return data.get("anomaly_score", 0), matched_rules
    except Exception:
        logger.warning("coraza scoring unavailable, continuing without it", exc_info=True)
        return 0, []


async def poll_coraza_health() -> None:
    """Background task (start once at app startup): periodically pings
    coraza-service's /healthz, independent of real traffic — a fresh
    deployment with zero requests yet should still show a real status rather
    than 'unknown until someone gets scored'. Runs forever; a failed check
    just updates the status, it never crashes the app."""
    global _last_poll_ok, _last_poll_at, _last_error
    if not ENABLE_CORAZA:
        return
    while True:
        try:
            response = await get_client().get(CORAZA_HEALTH_URL)
            response.raise_for_status()
            _last_poll_ok = True
            _last_error = None
        except Exception as exc:
            _last_poll_ok = False
            _last_error = str(exc)
        _last_poll_at = datetime.now(timezone.utc).isoformat()
        await asyncio.sleep(POLL_INTERVAL)


def get_status() -> dict:
    """A real connectivity check, not just whether ENABLE_CORAZA is set —
    reflects whether the last actual /healthz poll succeeded."""
    return {
        "enabled": ENABLE_CORAZA,
        "connected": _last_poll_ok if ENABLE_CORAZA else None,
        "last_poll_at": _last_poll_at,
        "last_error": _last_error,
    }
