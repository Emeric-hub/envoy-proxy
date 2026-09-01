import json
import logging
import os
from datetime import datetime, timezone

import redis.asyncio as redis

logger = logging.getLogger("scoring-service.events")

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
CHANNEL = "risk-events"

_client: redis.Redis | None = None


def get_client() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.from_url(REDIS_URL, socket_connect_timeout=0.2, socket_timeout=0.2)
    return _client


async def publish_decision(
    *,
    method: str,
    path: str,
    user_agent: str,
    protocol: str,
    ip: str,
    domain: str,
    score: float,
    decision: str,
    http_status: int,
    audit_mode: bool,
    signals: dict[str, float],
    crowdsec_decisions: list[dict],
    reasons: list[str],
    duration_ms: float,
) -> None:
    """Fire-and-forget: a slow/unreachable Redis must never block or fail a scoring decision."""
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "method": method,
        "path": path,
        "user_agent": user_agent,
        "protocol": protocol,
        "ip": ip,
        "domain": domain,
        "score": score,
        "decision": decision,
        "http_status": http_status,
        "audit_mode": audit_mode,
        "signals": signals,
        "crowdsec_decisions": crowdsec_decisions,
        "reasons": reasons,
        "duration_ms": duration_ms,
    }
    try:
        await get_client().publish(CHANNEL, json.dumps(event))
    except Exception:
        logger.warning("failed to publish risk event", exc_info=True)
