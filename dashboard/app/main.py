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
SCORING_SERVICE_URL = os.environ.get("SCORING_SERVICE_URL", "http://scoring-service:8001")
CONTROL_PLANE_URL = os.environ.get("CONTROL_PLANE_URL", "http://envoy-control-plane:18001")


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
    "enable_heuristic": _bool_env("ENABLE_HEURISTIC", "true"),
    "enable_crowdsec": _bool_env("ENABLE_CROWDSEC", "true"),
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


@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket) -> None:
    await websocket.accept()
    connections.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        connections.discard(websocket)
