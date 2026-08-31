import os
import re

SUSPICIOUS_UA_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (r"sqlmap", r"nikto", r"nmap", r"masscan")
]

RISK_THRESHOLD = float(os.environ.get("RISK_THRESHOLD", "0.8"))
ENABLE_HEURISTIC = os.environ.get("ENABLE_HEURISTIC", "true").strip().lower() in ("1", "true", "yes", "on")
# When true, scoring/decisions/reasons are computed and published exactly as
# normal (so the dashboard shows what *would* happen) but nothing is actually
# enforced — every response is allowed regardless of decision. See main.py.
AUDIT_MODE = os.environ.get("AUDIT_MODE", "false").strip().lower() in ("1", "true", "yes", "on")

# A single CRS "critical" rule match (severity weight 5) shouldn't alone cross
# RISK_THRESHOLD; two matches, or one plus another signal, should.
CORAZA_SCORE_DIVISOR = 10.0


def score_request(headers: dict[str, str], method: str, path: str) -> tuple[float, str, bool]:
    """Return (risk score in [0, 1], human-readable reason, whether it actually
    found something). Rule-based placeholder for the eventual feature-extraction
    + model inference pipeline (request-rate/behavioral features will need
    shared state, e.g. Redis, that this function doesn't have yet)."""
    if not ENABLE_HEURISTIC:
        return 0.0, "heuristic disabled", False

    user_agent = headers.get("user-agent", "")

    if not user_agent:
        return 0.6, "empty User-Agent header", True
    for pattern in SUSPICIOUS_UA_PATTERNS:
        if pattern.search(user_agent):
            return 0.95, f"User-Agent matches known scanner pattern /{pattern.pattern}/", True

    return 0.05, "no local heuristic triggered", False


def normalize_signals(rule_score: float, coraza_anomaly_score: int, crowdsec_decisions: list[dict]) -> dict[str, float]:
    """Single source of truth for how each tool's raw output maps to a [0, 1]
    signal — combine_scores and build_reasons both read from this so they can
    never disagree about what each tool contributed. A CrowdSec decision is
    already the output of its own scenario thresholding (capacity/leakspeed),
    so it's treated as maximal rather than normalized like Coraza's raw score."""
    return {
        "heuristic": rule_score,
        "coraza": min(coraza_anomaly_score / CORAZA_SCORE_DIVISOR, 1.0),
        "crowdsec": 1.0 if crowdsec_decisions else 0.0,
    }


def combine_scores(signals: dict[str, float]) -> float:
    """Fuse the local heuristic with the advisory signals from Coraza/CRS and
    CrowdSec. Neither ever blocks on its own (Coraza runs SecRuleEngine
    DetectionOnly; CrowdSec's agent only ever accumulates decisions, nothing
    here enforces them directly) — they're just more signals folded into this
    one score_request-produced decision."""
    return max(signals.values())


def build_reasons(
    signals: dict[str, float],
    rule_reason: str,
    rule_triggered: bool,
    matched_rules: list[dict],
    crowdsec_decisions: list[dict],
) -> list[str]:
    """Human-readable breakdown of what produced the final score, ordered so the
    signal that actually drove combine_scores' max() reads first. A tool that
    found nothing contributes no line — a wall of "nothing happened" per tool
    isn't a reason, it's noise."""
    groups = [
        (signals["heuristic"], [f"heuristic ({signals['heuristic']:.2f}): {rule_reason}"] if rule_triggered else []),
        (
            signals["coraza"],
            [
                f"CRS {rule['id']} [{rule['severity']}]: {rule['message'] or ', '.join(rule.get('tags', []))}"
                for rule in matched_rules
            ],
        ),
        (
            signals["crowdsec"],
            [f"CrowdSec [{d['scenario']}]: active {d['type']} decision" for d in crowdsec_decisions],
        ),
    ]
    groups.sort(key=lambda g: g[0], reverse=True)
    return [line for _, lines in groups for line in lines]
