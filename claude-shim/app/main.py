import asyncio
import json
import logging
import os
import re
import shutil
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("claude-shim")
logging.basicConfig(level=logging.INFO)

app = FastAPI()

CLAUDE_BIN = os.environ.get("CLAUDE_BIN", "claude")
EMPTY_WORKDIR = os.environ.get("EMPTY_WORKDIR", "/empty-workdir")
TIMEOUT_S = float(os.environ.get("SHIM_TIMEOUT_S", "60"))
DEFAULT_MODEL = os.environ.get("DEFAULT_MODEL", "haiku")

_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def _extract_messages(body: dict) -> tuple[str, str]:
    """Ollama /api/chat request shape: {"messages": [{"role", "content"}, ...]}.
    Only system + the last user message matter here — crs-tuner never sends
    multi-turn history, one classification per call."""
    system = ""
    user = ""
    for m in body.get("messages", []):
        if m.get("role") == "system":
            system = m.get("content", "")
        elif m.get("role") == "user":
            user = m.get("content", "")
    return system, user


def _clean_json(text: str) -> str:
    """Claude doesn't have Ollama's format:"json" forced-structured-output
    mode — it's asked to via the system prompt, and smaller/faster models in
    particular sometimes still wrap the answer in a markdown code fence.
    Strip that before handing it back, so crs-tuner's own json.loads() on
    the other end always sees clean JSON regardless of model quirks."""
    stripped = _FENCE_RE.sub("", text.strip()).strip()
    parsed = json.loads(stripped)  # raises if genuinely not JSON — caller handles
    return json.dumps(parsed)


@app.post("/api/chat")
async def chat(request: Request) -> JSONResponse:
    body = await request.json()
    system, user = _extract_messages(body)
    model = body.get("model") or DEFAULT_MODEL

    cmd = [
        CLAUDE_BIN, "-p",
        "--output-format", "json",
        # No code-exec/file-mutation tools — matched values are
        # attacker-controlled input (that's what tripped the CRS rule in
        # the first place), so a value deliberately crafted to look like a
        # tool-use instruction must not be able to get anything executed.
        # --restricted (a single flag for this) needs Claude Code >=2.1.2xx;
        # --disallowedTools works on older CLI versions too, so used here
        # for portability regardless of what version npm installs.
        "--disallowedTools", "Bash", "Write", "Edit", "NotebookEdit",
        "--model", model,
        "--system-prompt", system,
        user,
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=EMPTY_WORKDIR,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT_S)
    except asyncio.TimeoutError:
        proc.kill()
        logger.warning("claude -p timed out after %.0fs", TIMEOUT_S)
        return JSONResponse({"error": "claude -p timed out"}, status_code=504)
    except Exception:
        logger.warning("failed to invoke claude -p", exc_info=True)
        return JSONResponse({"error": "failed to invoke claude"}, status_code=502)

    if proc.returncode != 0:
        logger.warning("claude -p exited %d: %s", proc.returncode, stderr.decode(errors="replace")[:500])
        return JSONResponse({"error": "claude -p failed", "stderr": stderr.decode(errors="replace")[:500]}, status_code=502)

    try:
        envelope = json.loads(stdout)
        if envelope.get("is_error"):
            raise ValueError(f"claude reported an error: {envelope.get('result')}")
        content = _clean_json(envelope["result"])
    except Exception as exc:
        logger.warning("could not parse claude output: %s", exc)
        return JSONResponse({"error": f"could not parse claude output: {exc}"}, status_code=502)

    # Real per-call spend, not an estimate — this is the actual number that
    # matters for "how much of my subscription's usage is this eating."
    # Logged, not returned to the caller: crs-tuner doesn't need it, an
    # operator watching `docker compose logs claude-shim` does.
    usage = envelope.get("usage", {})
    logger.info(
        "claude -p: model=%s cost_usd=%.4f duration_ms=%s cache_read=%s cache_creation=%s",
        model, envelope.get("total_cost_usd", 0.0), envelope.get("duration_ms"),
        usage.get("cache_read_input_tokens"), usage.get("cache_creation_input_tokens"),
    )

    # Ollama /api/chat response shape — this is the only part crs-tuner's
    # ollama_client.py actually reads (response.json()["message"]["content"]).
    return JSONResponse({
        "model": model,
        "message": {"role": "assistant", "content": content},
        "done": True,
    })


@app.get("/api/tags")
async def tags() -> JSONResponse:
    """Cheap health check for the dashboard's live-connectivity poll (every
    5s) — must NOT invoke claude itself, that would burn a paid call every
    5 seconds for nothing. Just confirms the binary and credentials are
    actually there."""
    if shutil.which(CLAUDE_BIN) is None:
        return JSONResponse({"error": f"{CLAUDE_BIN} not found on PATH"}, status_code=503)
    creds_path = os.path.expanduser("~/.claude/.credentials.json")
    if not os.path.exists(creds_path):
        return JSONResponse({"error": "no credentials mounted at ~/.claude"}, status_code=503)
    return JSONResponse({"models": [{"name": DEFAULT_MODEL, "modified_at": int(time.time())}]})
