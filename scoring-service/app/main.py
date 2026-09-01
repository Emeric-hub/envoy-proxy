import asyncio
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response

from app.coraza_client import get_anomaly_score
from app.coraza_client import get_status as get_coraza_status
from app.coraza_client import poll_coraza_health
from app.crowdsec_client import get_decisions, log_request_for_crowdsec, poll_decisions_stream
from app.crowdsec_client import get_status as get_crowdsec_status
from app.events import publish_decision
from app.scoring import AUDIT_MODE, RISK_THRESHOLD, build_reasons, combine_scores, normalize_signals, score_request


@asynccontextmanager
async def lifespan(app: FastAPI):
    tasks = [asyncio.create_task(poll_decisions_stream()), asyncio.create_task(poll_coraza_health())]
    yield
    for task in tasks:
        task.cancel()


app = FastAPI(lifespan=lifespan)


@app.get("/health")
async def health() -> dict:
    return {"crowdsec": get_crowdsec_status(), "coraza": get_coraza_status()}


def extract_client_ip(headers: dict[str, str]) -> str:
    """x-forwarded-for's leftmost entry is the original client per RFC 7239 convention;
    x-envoy-external-address is Envoy's own view of the downstream peer as a fallback."""
    forwarded_for = headers.get("x-forwarded-for", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return headers.get("x-envoy-external-address", "unknown")


@app.api_route(
    "/check/{full_path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def check(full_path: str, request: Request) -> Response:
    started_at = time.perf_counter()
    headers = {key.lower(): value for key, value in request.headers.items()}
    path = "/" + full_path
    body = await request.body()

    client_ip = extract_client_ip(headers)
    user_agent = headers.get("user-agent", "")
    protocol = headers.get("x-request-protocol", "unknown")

    rule_score, rule_reason, rule_triggered = score_request(headers, request.method, path)
    anomaly_score, matched_rules = await get_anomaly_score(
        method=request.method,
        path=path,
        query=str(request.url.query),
        headers=headers,
        body=body,
        client_ip=client_ip,
    )
    # Decisions reflect *prior* requests from this IP, not this one — CrowdSec
    # needs to see a pattern accumulate before it decides, so query before
    # feeding it this request.
    crowdsec_decisions = await get_decisions(client_ip)

    signals = normalize_signals(rule_score, anomaly_score, crowdsec_decisions)
    score = combine_scores(signals)
    decision = "deny" if score >= RISK_THRESHOLD else "allow"
    # decision is the logical verdict (what the dashboard shows and what
    # feeds stats/charts, so audit mode can be evaluated against real
    # traffic); blocked is whether it was actually enforced.
    blocked = decision == "deny" and not AUDIT_MODE
    http_status = 403 if blocked else 200
    reasons = build_reasons(signals, rule_reason, rule_triggered, matched_rules, crowdsec_decisions)
    duration_ms = (time.perf_counter() - started_at) * 1000

    log_request_for_crowdsec(
        ip=client_ip, method=request.method, path=path, status=http_status, user_agent=user_agent
    )

    await publish_decision(
        method=request.method,
        path=path,
        user_agent=user_agent,
        protocol=protocol,
        ip=client_ip,
        domain=headers.get("host", "unknown"),
        score=score,
        decision=decision,
        http_status=http_status,
        audit_mode=AUDIT_MODE,
        signals=signals,
        crowdsec_decisions=crowdsec_decisions,
        reasons=reasons,
        duration_ms=duration_ms,
    )

    if blocked:
        return Response(status_code=http_status, content=f"blocked (risk={score:.2f}): {reasons[0]}")
    if decision == "deny":
        # audit mode: would have blocked, but didn't
        return Response(
            status_code=http_status,
            headers={"x-risk-score": f"{score:.2f}", "x-audit-would-block": "true"},
        )
    return Response(status_code=http_status, headers={"x-risk-score": f"{score:.2f}"})
