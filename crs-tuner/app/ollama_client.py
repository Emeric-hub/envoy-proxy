import json
import logging
import os

import httpx

logger = logging.getLogger("crs-tuner.ollama")

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://ollama:11434")
# Only needed against a remote/hosted Ollama-compatible endpoint sitting
# behind auth (the bundled local ollama service doesn't require it). Empty
# by default — no header sent at all, not an empty Bearer token.
OLLAMA_API_KEY = os.environ.get("OLLAMA_API_KEY", "").strip()
MODEL = os.environ.get("AI_TUNER_MODEL", "llama3.2:3b")
TIMEOUT = float(os.environ.get("AI_TUNER_TIMEOUT", "30"))

SYSTEM_PROMPT = """You are a WAF (Web Application Firewall) tuning assistant. \
You are given one OWASP CRS rule that matched a real HTTP request, along \
with the specific value that triggered the match. Decide whether this is a \
TRUE POSITIVE (the matched value is genuinely part of an attack) or a \
FALSE POSITIVE (the matched value is legitimate data that happens to trip \
this rule's pattern).

Judge the matched VALUE itself, not just which rule category matched it. \
A generic/protocol-enforcement rule (e.g. "invalid character", "missing \
header", "parameter pollution") can still be tripped by a genuine attack \
payload — the rule category is not proof of a false positive. If the \
value contains a recognizable attack pattern, classify it true_positive \
with high confidence REGARDLESS of which rule matched, including:
- SQL tautologies/injection: ' OR '1'='1, ' OR 1=1--, UNION SELECT, ; DROP TABLE
- Script/markup injection: <script>, javascript:, onerror=, onload=
- Path traversal: ../, ..\\, sequences reaching /etc/passwd, win.ini, etc.
- Command injection: ; or | or backticks chained with shell commands (cat, whoami, nc, curl, wget, rm)
- Null bytes, or the same payloads URL/hex/unicode-encoded to look less obvious

Do not excuse one of these as "probably a test" or "unlikely to be a real \
attacker" — a textbook attack string is a true positive even if it looks \
like something copied from a tutorial or a scanner default payload; \
that's exactly what real attack traffic looks like too.

Genuine false positives look different: legitimate special characters in \
real data with no attack syntax around them (an apostrophe in a name like \
O'Brien, an ampersand in "Smith & Sons"), a numeric parameter counter, a \
legitimate URL or file path with no traversal sequence, business text that \
happens to contain a flagged word with no executable syntax.

Respond with ONLY a JSON object of this exact shape, nothing else:
{"verdict": "true_positive" or "false_positive", "confidence": a number from 0.0 to 1.0, "reasoning": "one sentence"}"""


async def analyze_match(
    *, rule_id: str, message: str, tags: str, variable: str, key: str, value: str
) -> dict | None:
    """Returns {"verdict", "confidence", "reasoning"} or None on any failure —
    a failed analysis just means this particular match doesn't contribute to
    the false-positive counter this time, not a crash. Structured output
    (format: json) rather than parsing free text out of a chat response."""
    prompt = (
        f"CRS rule {rule_id}: {message}\n"
        f"Tags: {tags}\n"
        f"Matched variable: {variable}:{key}\n"
        f"Matched value: {value!r}"
    )
    headers = {"Authorization": f"Bearer {OLLAMA_API_KEY}"} if OLLAMA_API_KEY else {}
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            response = await client.post(
                f"{OLLAMA_URL}/api/chat",
                headers=headers,
                json={
                    "model": MODEL,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    "format": "json",
                    "stream": False,
                },
            )
            response.raise_for_status()
            content = response.json()["message"]["content"]
            verdict = json.loads(content)
            if verdict.get("verdict") not in ("true_positive", "false_positive"):
                raise ValueError(f"unexpected verdict field: {verdict!r}")
            verdict["confidence"] = float(verdict.get("confidence", 0.0))
            return verdict
    except Exception:
        logger.warning("ollama analysis failed for rule %s", rule_id, exc_info=True)
        return None
