import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger("crs-tuner.analysis")

ANALYSIS_DIR = os.environ.get("ANALYSIS_DIR", "/var/lib/crs-tuner/analysis")


def _safe_domain(domain: str) -> str:
    """analysis/<domain>.jsonl filename — strip anything that isn't a sane
    hostname character, since domain comes from a client-controlled Host
    header (via scoring-service) and this becomes a filesystem path."""
    safe = "".join(c if c.isalnum() or c in ".-" else "_" for c in domain)
    return safe or "unknown"


def _append(path: str, record: dict) -> None:
    os.makedirs(ANALYSIS_DIR, exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(record) + "\n")


async def write_verdict(*, domain: str, fields: dict, verdict: dict) -> None:
    """One line per analyzed CRS match — the audit trail: what was analyzed,
    what the model concluded, when. Per-domain files, same layout ../crs-exclusions'
    auto-<domain>.conf uses, so the two are easy to cross-reference."""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "domain": domain,
        "path": fields.get("path"),
        "ip": fields.get("ip"),
        "rule_id": fields.get("rule_id"),
        "message": fields.get("message"),
        "variable": fields.get("variable"),
        "key": fields.get("key"),
        "value": fields.get("value"),
        "verdict": verdict.get("verdict"),
        "confidence": verdict.get("confidence"),
        "reasoning": verdict.get("reasoning"),
    }
    try:
        _append(os.path.join(ANALYSIS_DIR, f"{_safe_domain(domain)}.jsonl"), record)
    except Exception:
        logger.warning("failed to write analysis log", exc_info=True)


async def write_error(*, stage: str, fields: dict, error: str) -> None:
    """Failures get their own dedicated log (_errors.jsonl), separate from
    verdicts — "how often is analysis itself failing" is a different
    question from "what did the model conclude", and burying failures in
    container stdout alongside routine logs makes that question hard to
    answer later. stage identifies where it failed (e.g. "ollama",
    "exclusion_write") so failures cluster meaningfully when reviewed."""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "stage": stage,
        "domain": fields.get("domain"),
        "rule_id": fields.get("rule_id"),
        "error": error,
    }
    try:
        _append(os.path.join(ANALYSIS_DIR, "_errors.jsonl"), record)
    except Exception:
        logger.warning("failed to write error log", exc_info=True)
