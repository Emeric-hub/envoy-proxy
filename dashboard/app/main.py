import asyncio
import ipaddress
import json
import logging
import os
from contextlib import asynccontextmanager

import httpx
import redis.asyncio as redis
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse

logger = logging.getLogger("dashboard")
logging.basicConfig(level=logging.INFO)

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
CHANNEL = "risk-events"
CRS_MATCH_STREAM = "crs-matches"
CRS_TUNER_GROUP = "crs-tuner"
SCORING_SERVICE_URL = os.environ.get("SCORING_SERVICE_URL", "http://scoring-service:8001")
CONTROL_PLANE_URL = os.environ.get("CONTROL_PLANE_URL", "http://envoy-control-plane:18001")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://ollama:11434")
# Server-side only — used to authenticate the live check below, never sent
# to the browser. STATIC_CONFIG exposes only whether it's set (bool).
OLLAMA_API_KEY = os.environ.get("OLLAMA_API_KEY", "").strip()

_redis_client: redis.Redis | None = None


def get_redis_client() -> redis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.from_url(REDIS_URL, socket_connect_timeout=0.5, socket_timeout=0.5)
    return _redis_client


def _bool_env(name: str, default: str) -> bool:
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


def _read_file(path: str) -> str:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return "unknown"


# Same env vars scoring-service reads, from the same .env — a read-only
# display of what's actually active, not a control surface from here.
STATIC_CONFIG = {
    "risk_threshold": float(os.environ.get("RISK_THRESHOLD", "0.8")),
    "audit_mode": _bool_env("AUDIT_MODE", "false"),
    "enable_coraza": _bool_env("ENABLE_CORAZA", "true"),
    "enable_crowdsec": _bool_env("ENABLE_CROWDSEC", "true"),
    "enable_ai_tuner": _bool_env("ENABLE_AI_TUNER", "true"),
    "ollama_auth_configured": bool(OLLAMA_API_KEY),
}


def active_config() -> dict:
    # crs_version/crs_fetched_at read fresh per request, not cached at import
    # time: coraza-service fetches CRS on its own startup (crs_fetch.go), and
    # depends_on only guarantees dashboard starts *after* that container
    # starts, not after it's finished fetching. Caching these once at import
    # risked permanently freezing on "unknown" if dashboard happened to win
    # that race on a fresh checkout.
    return {
        **STATIC_CONFIG,
        "crs_version": _read_file("/crs/VERSION"),
        "crs_fetched_at": _read_file("/crs/FETCHED_AT"),
        "crs_paranoia_level": _read_file("/crs/PARANOIA_LEVEL"),
    }

DASHBOARD_BIND_ADDR = os.environ.get("DASHBOARD_BIND_ADDR", "127.0.0.1").strip()


def _parse_allowed_networks(raw: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network] | None:
    """None means unrestricted. Loopback bind (the default) is already
    off-network entirely, and Docker's hairpin NAT rewrites same-host
    connections' source IP to the bridge gateway before this app ever sees
    them — an allowlist couldn't tell "us" apart from "the docker gateway" in
    that case anyway, so skip it. This only does something once
    DASHBOARD_BIND_ADDR is opened past loopback, where real client IPs (LAN,
    etc.) do reach here correctly."""
    if DASHBOARD_BIND_ADDR == "127.0.0.1":
        return None
    entries = [p.strip() for p in raw.split(",") if p.strip()]
    if not entries:
        return None
    return [ipaddress.ip_network(entry, strict=False) for entry in entries]


ALLOWED_NETWORKS = _parse_allowed_networks(os.environ.get("DASHBOARD_ALLOWED_IPS", ""))


class IPAllowlistMiddleware:
    """Raw ASGI (not BaseHTTPMiddleware) so it covers the /ws websocket scope
    too, not just regular HTTP requests."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if ALLOWED_NETWORKS is None or scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        client = scope.get("client")
        ip = ipaddress.ip_address(client[0]) if client else None
        if ip is not None and any(ip in net for net in ALLOWED_NETWORKS):
            await self.app(scope, receive, send)
            return

        logger.warning("blocked dashboard access from disallowed IP %s", client[0] if client else "unknown")
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
        else:
            await send({"type": "http.response.start", "status": 403, "headers": [(b"content-type", b"text/plain")]})
            await send({"type": "http.response.body", "body": b"Forbidden"})


connections: set[WebSocket] = set()


async def broadcast(message: str) -> None:
    for ws in list(connections):
        try:
            await ws.send_text(message)
        except Exception:
            connections.discard(ws)


async def redis_listener() -> None:
    """Single shared subscriber fanning out to all connected browsers, so we
    don't open one Redis pubsub connection per browser tab."""
    while True:
        try:
            client = redis.from_url(REDIS_URL)
            pubsub = client.pubsub()
            await pubsub.subscribe(CHANNEL)
            async for message in pubsub.listen():
                if message["type"] == "message":
                    await broadcast(message["data"].decode())
        except Exception:
            logger.warning("redis listener dropped, retrying in 1s", exc_info=True)
            await asyncio.sleep(1)


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(redis_listener())
    yield
    task.cancel()


app = FastAPI(lifespan=lifespan)
app.add_middleware(IPAllowlistMiddleware)


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    with open("app/static/index.html") as f:
        html = f.read()
    config_script = f"<script>window.__ACTIVE_CONFIG__ = {json.dumps(active_config())};</script>"
    return HTMLResponse(html.replace("<!--ACTIVE_CONFIG-->", config_script))


@app.get("/api/config")
async def api_config() -> JSONResponse:
    """Same data the HTML page embeds as window.__ACTIVE_CONFIG__, as plain
    JSON — for tooling (tests/options-impact-test.sh) that wants the active
    configuration without scraping the page."""
    return JSONResponse(active_config())


@app.get("/api/status")
async def api_status() -> JSONResponse:
    """Proxies scoring-service's own live health check — the browser can't
    reach scoring-service directly (not published to the host), so this is a
    thin relay. Fails soft: an unreachable scoring-service is itself a status
    worth showing, not a 500."""
    try:
        async with httpx.AsyncClient(timeout=1.5) as client:
            response = await client.get(f"{SCORING_SERVICE_URL}/health")
            response.raise_for_status()
            return JSONResponse(response.json())
    except Exception:
        logger.warning("scoring-service health check unreachable", exc_info=True)
        return JSONResponse(
            {"crowdsec": {"enabled": None, "connected": False, "last_poll_at": None, "last_error": "scoring-service unreachable"}}
        )


@app.get("/api/backends")
async def api_backends() -> JSONResponse:
    """Proxies envoy-control-plane's per-route TCP-reachability check — same
    reasoning as /api/status: the browser can't reach that internal service
    directly, and an unreachable control-plane is itself worth showing rather
    than a 500."""
    try:
        async with httpx.AsyncClient(timeout=1.5) as client:
            response = await client.get(f"{CONTROL_PLANE_URL}/routes/health")
            response.raise_for_status()
            return JSONResponse(response.json())
    except Exception:
        logger.warning("envoy-control-plane backend health check unreachable", exc_info=True)
        return JSONResponse({"backends": []})


@app.get("/api/ollama-status")
async def api_ollama_status() -> JSONResponse:
    """Live reachability check against Ollama itself (GET /api/tags — cheap,
    doesn't invoke the model), separate from ollama_auth_configured in
    STATIC_CONFIG which only says whether a key is *set*, not whether it
    actually works. Same fail-soft reasoning as /api/status and
    /api/backends: an unreachable or misauthenticated endpoint is itself a
    status worth showing, not a 500. Doesn't run at all if ai-tuner is
    disabled — nothing to check."""
    if not STATIC_CONFIG["enable_ai_tuner"]:
        return JSONResponse({"enabled": False})
    headers = {"Authorization": f"Bearer {OLLAMA_API_KEY}"} if OLLAMA_API_KEY else {}
    try:
        async with httpx.AsyncClient(timeout=1.5) as client:
            response = await client.get(f"{OLLAMA_URL}/api/tags", headers=headers)
            if response.status_code in (401, 403):
                return JSONResponse({"enabled": True, "connected": False, "last_error": f"auth rejected (HTTP {response.status_code})"})
            response.raise_for_status()
            return JSONResponse({"enabled": True, "connected": True})
    except Exception as exc:
        logger.warning("ollama connectivity check failed", exc_info=True)
        return JSONResponse({"enabled": True, "connected": False, "last_error": str(exc)})


@app.get("/api/queue")
async def api_queue() -> JSONResponse:
    """crs-tuner's analysis queue depth. length is the raw Redis Stream
    length; pending is how many entries crs-tuner's consumer group has
    claimed but not yet acked (i.e. actually mid-analysis / stuck). Fails
    soft: an empty/nonexistent stream or group (ai-tuner never enabled, or
    nothing queued yet) is a legitimate "queue is empty" state, not an error."""
    try:
        client = get_redis_client()
        length = await client.xlen(CRS_MATCH_STREAM)
        pending = 0
        try:
            summary = await client.xpending(CRS_MATCH_STREAM, CRS_TUNER_GROUP)
            pending = summary.get("pending", 0) if summary else 0
        except Exception:
            pending = 0  # consumer group doesn't exist yet — crs-tuner hasn't started
        return JSONResponse({"length": length, "pending": pending})
    except Exception:
        logger.warning("queue depth check failed", exc_info=True)
        return JSONResponse({"length": 0, "pending": 0})


@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket) -> None:
    await websocket.accept()
    connections.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        connections.discard(websocket)
