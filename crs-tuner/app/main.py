import asyncio
import logging
import os

import redis.asyncio as redis

from app.analysis_log import write_error, write_verdict
from app.exclusion_writer import record_verdict
from app.ollama_client import analyze_match

logger = logging.getLogger("crs-tuner")
logging.basicConfig(level=logging.INFO)

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
STREAM = "crs-matches"
GROUP = "crs-tuner"
CONSUMER = "crs-tuner-1"

ENABLE_AI_TUNER = os.environ.get("ENABLE_AI_TUNER", "true").strip().lower() in ("1", "true", "yes", "on")


async def ensure_group(client: redis.Redis) -> None:
    try:
        # mkstream=True: the stream may not exist yet on a fresh deployment
        # (nothing's published to it until scoring-service sees a match).
        await client.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
    except redis.ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise


async def process_entry(fields: dict) -> None:
    domain = fields.get("domain", "unknown")
    path = fields.get("path", "")
    rule_id = fields.get("rule_id", "")
    variable = fields.get("variable", "")
    key = fields.get("key", "")

    verdict = await analyze_match(
        rule_id=rule_id,
        message=fields.get("message", ""),
        tags=fields.get("tags", ""),
        variable=variable,
        key=key,
        value=fields.get("value", ""),
    )
    if verdict is None:
        await write_error(stage="ollama", fields=fields, error="analysis returned no verdict")
        return

    await write_verdict(domain=domain, fields=fields, verdict=verdict)

    try:
        await record_verdict(domain=domain, path=path, rule_id=rule_id, variable=variable, key=key, verdict=verdict)
    except Exception as exc:
        await write_error(stage="exclusion_write", fields=fields, error=str(exc))
        raise


async def main() -> None:
    if not ENABLE_AI_TUNER:
        logger.info("ENABLE_AI_TUNER=false, crs-tuner idling")
        while True:
            await asyncio.sleep(3600)

    client = redis.from_url(REDIS_URL, decode_responses=True)
    await ensure_group(client)
    logger.info("crs-tuner consuming from %s (group=%s)", STREAM, GROUP)

    while True:
        try:
            resp = await client.xreadgroup(GROUP, CONSUMER, {STREAM: ">"}, count=10, block=5000)
        except Exception:
            logger.warning("stream read failed, retrying in 5s", exc_info=True)
            await asyncio.sleep(5)
            continue

        if not resp:
            continue
        for _stream_name, entries in resp:
            for entry_id, fields in entries:
                try:
                    await process_entry(fields)
                except Exception:
                    logger.warning("failed processing entry %s", entry_id, exc_info=True)
                finally:
                    # Ack regardless of outcome: a permanently-failing entry
                    # (e.g. a malformed field) would otherwise block the
                    # group forever via XREADGROUP's pending-entries list —
                    # write_error above is the durable record of the failure.
                    await client.xack(STREAM, GROUP, entry_id)


if __name__ == "__main__":
    asyncio.run(main())
