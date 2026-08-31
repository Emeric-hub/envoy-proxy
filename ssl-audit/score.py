#!/usr/bin/env python3
"""Turns one or more testssl.sh --jsonfile-pretty reports into a hardening
score + readable findings list. The self-signed chain-of-trust finding is
deliberately excluded from scoring — this demo's certs are self-signed by
design (see ../generate-cert.sh), that's not a hardening gap to flag, unlike
everything else testssl.sh checks (protocol support, cipher strength,
forward secrecy, known vulnerabilities, security headers, cert lifetime...).

Usage:
  ./score.py report1.json [report2.json ...]
  ./score.py reports/*.json --out summary.md
"""
import argparse
import html
import json
import sys
from datetime import datetime, timezone

# Categories testssl.sh reports that are actual hardening signal. Excluded:
# "grease" and "cipherTests" (empty/internal probes), "browserSimulations"
# (client compatibility info, not a hardening issue), "rating" (testssl's
# own derived score — we compute an independent one instead, and its grade
# would itself be contaminated by the self-signed finding we're ignoring).
SCORED_CATEGORIES = [
    "pretest", "protocols", "ciphers", "serverPreferences",
    "fs", "serverDefaults", "headerResponse", "vulnerabilities",
]

# Headline items worth calling out explicitly regardless of where they land
# in the severity-sorted list — these are the ones people mean by "TLS
# hardening basics".
HIGHLIGHT_IDS = [
    "SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3",
    "FS", "HSTS_time", "cert_keySize", "cert_signatureAlgorithm",
]

SEVERITY_WEIGHT = {
    "CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "WARN": 8, "LOW": 3,
    "OK": 0, "INFO": 0, "DEBUG": 0,
}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "WARN", "LOW", "OK", "INFO", "DEBUG"]


def is_ignored_self_signed(finding: dict) -> bool:
    return finding.get("id") == "cert_chain_of_trust" and "self signed" in finding.get("finding", "").lower()


def grade_for(score: int, has_high_or_critical: bool) -> str:
    if score >= 95 and not has_high_or_critical:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def score_report(path: str) -> dict:
    with open(path) as f:
        data = json.load(f)
    scan = data["scanResult"][0]
    target = f"{scan.get('targetHost', '?')}:{scan.get('port', '?')}"

    all_findings = []
    ignored = []
    for cat in SCORED_CATEGORIES:
        for finding in scan.get(cat, []):
            if is_ignored_self_signed(finding):
                ignored.append({**finding, "category": cat})
                continue
            all_findings.append({**finding, "category": cat})

    deductions = 0
    for f in all_findings:
        deductions += SEVERITY_WEIGHT.get(f.get("severity", "INFO"), 0)
    score = max(0, 100 - deductions)

    actionable = [f for f in all_findings if f.get("severity") not in ("OK", "INFO", "DEBUG")]
    actionable.sort(key=lambda f: SEVERITY_ORDER.index(f.get("severity", "INFO")))
    has_high_or_critical = any(f["severity"] in ("HIGH", "CRITICAL") for f in actionable)

    highlights = {}
    for cat in SCORED_CATEGORIES:
        for finding in scan.get(cat, []):
            if finding.get("id") in HIGHLIGHT_IDS:
                highlights[finding["id"]] = finding

    return {
        "path": path,
        "target": target,
        "score": score,
        "grade": grade_for(score, has_high_or_critical),
        "actionable": actionable,
        "ignored": ignored,
        "highlights": highlights,
    }


def format_report(r: dict) -> str:
    lines = []
    lines.append(f"# SSL/TLS hardening report — {r['target']}")
    lines.append("")
    lines.append(f"**Score: {r['score']}/100 (grade {r['grade']})**")
    lines.append("")
    if r["ignored"]:
        lines.append("Ignored (by design, not scored):")
        for f in r["ignored"]:
            lines.append(f"- `{f['id']}`: {f['finding']}")
        lines.append("")

    lines.append("## At a glance")
    for hid in HIGHLIGHT_IDS:
        f = r["highlights"].get(hid)
        if f:
            lines.append(f"- **{hid}**: {f['finding']} ({f['severity']})")
        else:
            lines.append(f"- **{hid}**: not reported")
    lines.append("")

    if r["actionable"]:
        lines.append("## Findings (worst first)")
        for f in r["actionable"]:
            cve = f" [{f['cve']}]" if f.get("cve") else ""
            lines.append(f"- **[{f['severity']}]** `{f['category']}/{f['id']}`: {f['finding']}{cve}")
    else:
        lines.append("## Findings")
        lines.append("None — every scored check came back OK/INFO.")
    lines.append("")
    return "\n".join(lines)


GRADE_COLOR = {"A+": "#4ade80", "A": "#4ade80", "B": "#a3e635", "C": "#facc15", "D": "#fb923c", "F": "#f87171"}
SEVERITY_COLOR = {
    "CRITICAL": "#f87171", "HIGH": "#fb923c", "MEDIUM": "#facc15",
    "WARN": "#facc15", "LOW": "#60a5fa", "OK": "#4ade80", "INFO": "#9aa0aa",
}


def render_report_html(r: dict) -> str:
    grade_color = GRADE_COLOR.get(r["grade"], "#9aa0aa")

    highlight_rows = []
    for hid in HIGHLIGHT_IDS:
        f = r["highlights"].get(hid)
        if f:
            color = SEVERITY_COLOR.get(f["severity"], "#9aa0aa")
            highlight_rows.append(
                f'<div class="chip"><span class="chip-id">{html.escape(hid)}</span>'
                f'<span class="dot" style="background:{color}"></span>'
                f'<span class="chip-finding">{html.escape(f["finding"])}</span></div>'
            )
        else:
            highlight_rows.append(
                f'<div class="chip chip-missing"><span class="chip-id">{html.escape(hid)}</span>'
                f'<span class="dot" style="background:#4b5563"></span>'
                f'<span class="chip-finding">not reported</span></div>'
            )

    finding_rows = []
    for f in r["actionable"]:
        color = SEVERITY_COLOR.get(f["severity"], "#9aa0aa")
        cve = f' <span class="cve">{html.escape(f["cve"])}</span>' if f.get("cve") else ""
        finding_rows.append(
            f'<tr><td><span class="sev" style="color:{color}">{html.escape(f["severity"])}</span></td>'
            f'<td class="mono">{html.escape(f["category"])}/{html.escape(f["id"])}</td>'
            f'<td>{html.escape(f["finding"])}{cve}</td></tr>'
        )
    findings_html = (
        f'<table><thead><tr><th>Severity</th><th>Check</th><th>Finding</th></tr></thead>'
        f'<tbody>{"".join(finding_rows)}</tbody></table>'
        if finding_rows else '<p class="muted">None — every scored check came back OK/INFO.</p>'
    )

    ignored_html = ""
    if r["ignored"]:
        items = "".join(f'<li><span class="mono">{html.escape(f["id"])}</span>: {html.escape(f["finding"])}</li>' for f in r["ignored"])
        ignored_html = f'<div class="ignored"><strong>Ignored by design (not scored):</strong><ul>{items}</ul></div>'

    return f"""
  <section class="report">
    <div class="report-head">
      <h2>{html.escape(r['target'])}</h2>
      <div class="score-badge" style="border-color:{grade_color}">
        <span class="score-num" style="color:{grade_color}">{r['score']}</span>
        <span class="score-den">/100</span>
        <span class="grade" style="color:{grade_color}">{html.escape(r['grade'])}</span>
      </div>
    </div>
    {ignored_html}
    <h3>At a glance</h3>
    <div class="chips">{"".join(highlight_rows)}</div>
    <h3>Findings (worst first)</h3>
    {findings_html}
  </section>"""


def format_report_html(results: list) -> str:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sections = "".join(render_report_html(r) for r in results)
    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>SSL/TLS hardening report</title>
<style>
  body {{ font-family: system-ui, sans-serif; background: #0f1115; color: #e6e6e6; margin: 0; padding: 2rem; }}
  h1 {{ font-size: 1.2rem; margin: 0 0 0.25rem; }}
  .generated {{ font-size: 0.75rem; color: #9aa0aa; margin-bottom: 1.5rem; }}
  .report {{ background: #1a1d24; border: 1px solid #2a2f3a; border-radius: 10px; padding: 1.25rem 1.5rem; margin-bottom: 1.5rem; }}
  .report-head {{ display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem; }}
  h2 {{ font-size: 1rem; margin: 0; font-family: ui-monospace, monospace; }}
  h3 {{ font-size: 0.8rem; color: #9aa0aa; text-transform: uppercase; letter-spacing: 0.03em; margin: 1.25rem 0 0.5rem; }}
  .score-badge {{ display: flex; align-items: baseline; gap: 0.35rem; border: 2px solid; border-radius: 8px; padding: 0.25rem 0.75rem; }}
  .score-num {{ font-size: 1.4rem; font-weight: 700; }}
  .score-den {{ font-size: 0.75rem; color: #9aa0aa; }}
  .grade {{ font-size: 1rem; font-weight: 700; margin-left: 0.5rem; }}
  .chips {{ display: flex; flex-wrap: wrap; gap: 0.5rem; }}
  .chip {{ display: flex; align-items: center; gap: 0.4rem; background: #0f1115; border: 1px solid #2a2f3a; border-radius: 999px; padding: 0.3rem 0.7rem; font-size: 0.75rem; }}
  .chip-missing {{ opacity: 0.5; }}
  .chip-id {{ font-family: ui-monospace, monospace; color: #e6e6e6; }}
  .chip-finding {{ color: #9aa0aa; }}
  .dot {{ width: 0.5rem; height: 0.5rem; border-radius: 50%; flex-shrink: 0; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.8rem; }}
  th, td {{ text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid #262a33; vertical-align: top; }}
  th {{ color: #9aa0aa; font-weight: 500; }}
  .mono {{ font-family: ui-monospace, monospace; white-space: nowrap; }}
  .sev {{ font-weight: 700; }}
  .cve {{ color: #6b7280; font-size: 0.75em; }}
  .muted {{ color: #6b7280; font-size: 0.85rem; }}
  .ignored {{ background: #0f1115; border: 1px solid #2a2f3a; border-radius: 6px; padding: 0.5rem 0.75rem; font-size: 0.8rem; color: #9aa0aa; margin-bottom: 0.5rem; }}
  .ignored ul {{ margin: 0.35rem 0 0; padding-left: 1.2rem; }}
</style>
</head>
<body>
  <h1>SSL/TLS hardening report</h1>
  <div class="generated">generated {generated}</div>
  {sections}
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("reports", nargs="+", help="testssl.sh --jsonfile-pretty output file(s)")
    parser.add_argument("--out", help="also write the combined report to this file (markdown)")
    parser.add_argument("--html-out", help="also write a styled HTML report to this file")
    parser.add_argument("--fail-under", type=int, default=80, help="exit 1 if any report scores below this (default 80)")
    args = parser.parse_args()

    results = [score_report(p) for p in args.reports]
    output = "\n---\n\n".join(format_report(r) for r in results)
    print(output)

    if args.out:
        with open(args.out, "w") as f:
            f.write(output)
        print(f"\n(written to {args.out})", file=sys.stderr)

    if args.html_out:
        with open(args.html_out, "w") as f:
            f.write(format_report_html(results))
        print(f"(html report written to {args.html_out})", file=sys.stderr)

    worst = min(r["score"] for r in results)
    sys.exit(0 if worst >= args.fail_under else 1)


if __name__ == "__main__":
    main()
