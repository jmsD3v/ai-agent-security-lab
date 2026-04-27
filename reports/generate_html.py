#!/usr/bin/env python3
"""
AI Agent Security Lab — HTML Report Generator
Reads audit.jsonl and produces a self-contained HTML report
with OWASP LLM Top 10 + MITRE ATLAS mapping.

Usage:
    python reports/generate_html.py
    python reports/generate_html.py --input reports/audit.jsonl --output reports/report.html
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# OWASP LLM Top 10 reference (inline — no external deps)
OWASP_LABELS = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

ATLAS_LABELS = {
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0048": "Exfiltration via ML Inference API",
    "AML.T0043": "Craft Adversarial Data",
    "AML.T0034": "Cost Harvesting",
    "AML.T0040": "ML Supply Chain Compromise",
}

CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; }
h1 { color: #58a6ff; font-size: 1.6rem; margin-bottom: 0.5rem; }
h2 { color: #8b949e; font-size: 1rem; margin: 1.5rem 0 0.5rem; text-transform: uppercase; letter-spacing: 2px; }
.meta { color: #6e7681; font-size: 0.85rem; margin-bottom: 2rem; }
.summary { display: flex; gap: 1.5rem; margin-bottom: 2rem; }
.stat { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1rem 1.5rem; }
.stat .num { font-size: 2rem; font-weight: bold; }
.stat .label { font-size: 0.75rem; color: #6e7681; text-transform: uppercase; }
.total .num { color: #58a6ff; }
.blocked-stat .num { color: #f85149; }
.success-stat .num { color: #3fb950; }
.policy-stat .num { color: #d29922; }
table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
th { background: #161b22; color: #8b949e; padding: 0.6rem 0.8rem; text-align: left;
     border: 1px solid #30363d; position: sticky; top: 0; }
td { padding: 0.5rem 0.8rem; border: 1px solid #21262d; vertical-align: top; }
tr:hover td { background: #161b22; }
.outcome-success { color: #3fb950; }
.outcome-error { color: #f85149; }
.outcome-policy_blocked { color: #d29922; }
.tool { font-weight: bold; color: #79c0ff; }
.method { color: #d2a8ff; }
.error-text { color: #f85149; font-size: 0.78rem; max-width: 300px; word-break: break-word; }
.badge { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem;
         font-weight: bold; margin-right: 4px; }
.badge-owasp { background: #b91c1c22; color: #f87171; border: 1px solid #b91c1c44; }
.badge-atlas { background: #1d4ed822; color: #60a5fa; border: 1px solid #1d4ed844; }
.gaps { background: #161b22; border: 1px solid #d2992244; border-radius: 6px; padding: 1rem; margin-bottom: 2rem; }
.gaps h3 { color: #d29922; margin-bottom: 0.5rem; }
.gaps li { color: #8b949e; margin-left: 1.2rem; margin-top: 0.3rem; font-size: 0.85rem; }
.footer { color: #484f58; font-size: 0.75rem; margin-top: 2rem; border-top: 1px solid #21262d; padding-top: 1rem; }
"""


def load_events(log_path: Path) -> list[dict]:
    if not log_path.exists():
        return []
    events = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return events


def classify_event(event: dict) -> tuple[str, str]:
    """Returns (owasp_id, atlas_id) based on tool + error content."""
    tool = event.get("tool", "")
    error = event.get("error", "").lower()
    outcome = event.get("outcome", "")

    if "injection" in error or "pattern" in error:
        return "LLM01", "AML.T0051"
    if "path not allowed" in error or "traversal" in error:
        return "LLM06", "AML.T0043"
    if "ssrf" in error or "domain not" in error or "metadata" in error:
        return "LLM05", "AML.T0043"
    if "blocked pattern" in error or "blocked dos" in error:
        return "LLM06", "AML.T0043"
    if "tool chaining" in error:
        return "LLM07", "AML.T0043"
    if "rate limit" in error:
        return "LLM10", "AML.T0034"
    if "leakage" in error:
        return "LLM02", "AML.T0048"
    if "value too large" in error:
        return "LLM10", "AML.T0034"
    return "", ""


def build_html(events: list[dict], output_path: Path) -> None:
    total = len(events)
    blocked = [e for e in events if e.get("outcome") == "error"]
    policy_blocked = [e for e in events if e.get("outcome") == "policy_blocked"]
    success = [e for e in events if e.get("outcome") == "success"]
    all_blocked = blocked + policy_blocked

    # Detect known defense gaps (encoding bypasses)
    gaps = [
        "Hex/octal encoding bypass (<code>\\x2e\\x2e</code>) — not caught by regex guardrails. Needs semantic validation.",
        "Base64-encoded payloads — bypasses pattern matching. Needs decoder pre-processing.",
        "Leet-speak substitution (Ign0re, instruct!ons) — evades exact regex. Needs fuzzy matching.",
        "Indirect injection via trusted external data — hard to block at input level without context tracking.",
    ]

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    rows = []
    for e in events:
        outcome = e.get("outcome", "unknown")
        owasp_id, atlas_id = classify_event(e)
        owasp_badge = (f'<span class="badge badge-owasp">{owasp_id}: {OWASP_LABELS.get(owasp_id, "")}</span>'
                       if owasp_id else "")
        atlas_badge = (f'<span class="badge badge-atlas">{atlas_id}: {ATLAS_LABELS.get(atlas_id, "")}</span>'
                       if atlas_id else "")
        error_cell = f'<div class="error-text">{e.get("error", "")[:200]}</div>' if e.get("error") else ""
        ts = e.get("timestamp", "")[:19].replace("T", " ")
        rows.append(f"""
        <tr>
          <td>{ts}</td>
          <td><span class="tool">{e.get('tool', '')}</span></td>
          <td><span class="method">{e.get('method', '')}</span></td>
          <td><span class="outcome-{outcome}">{outcome}</span></td>
          <td>{e.get('duration_ms', '')} ms</td>
          <td>{error_cell}</td>
          <td>{owasp_badge}{atlas_badge}</td>
        </tr>""")

    gaps_html = "\n".join(f"<li>{g}</li>" for g in gaps)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI Agent Security Lab — Audit Report</title>
  <style>{CSS}</style>
</head>
<body>

<h1>AI Agent Security Lab — Audit Report</h1>
<p class="meta">Generated: {now} &nbsp;|&nbsp; Source: {output_path.parent / 'audit.jsonl'}</p>

<div class="summary">
  <div class="stat total">
    <div class="num">{total}</div>
    <div class="label">Total Events</div>
  </div>
  <div class="stat success-stat">
    <div class="num">{len(success)}</div>
    <div class="label">Successful Calls</div>
  </div>
  <div class="stat blocked-stat">
    <div class="num">{len(blocked)}</div>
    <div class="label">Tool Errors Blocked</div>
  </div>
  <div class="stat policy-stat">
    <div class="num">{len(policy_blocked)}</div>
    <div class="label">Policy Violations</div>
  </div>
</div>

<h2>Known Defense Gaps (for community research)</h2>
<div class="gaps">
  <h3>Encoding Bypass Gaps — not caught by regex guardrails:</h3>
  <ul>{gaps_html}</ul>
</div>

<h2>Audit Log — All Events</h2>
<table>
  <thead>
    <tr>
      <th>Timestamp</th>
      <th>Tool</th>
      <th>Method</th>
      <th>Outcome</th>
      <th>Duration</th>
      <th>Error / Block Reason</th>
      <th>OWASP / ATLAS</th>
    </tr>
  </thead>
  <tbody>
    {''.join(rows) if rows else '<tr><td colspan="7" style="text-align:center;color:#484f58">No events recorded yet. Run: make attack-all</td></tr>'}
  </tbody>
</table>

<div class="footer">
  AI Agent Security Lab &nbsp;|&nbsp;
  <a href="https://owasp.org/www-project-top-10-for-large-language-model-applications/" style="color:#58a6ff">OWASP LLM Top 10</a> &nbsp;|&nbsp;
  <a href="https://atlas.mitre.org/" style="color:#58a6ff">MITRE ATLAS</a>
</div>

</body>
</html>"""

    output_path.write_text(html, encoding="utf-8")
    print(f"[Report] Saved to: {output_path}")
    print(f"[Report] Events: {total} total | {len(success)} OK | {len(all_blocked)} blocked")


def main():
    parser = argparse.ArgumentParser(description="Generate HTML security audit report")
    parser.add_argument("--input", default="reports/audit.jsonl",
                        help="Path to audit JSONL log (default: reports/audit.jsonl)")
    parser.add_argument("--output", default="reports/report.html",
                        help="Path for HTML output (default: reports/report.html)")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    events = load_events(input_path)
    if not events:
        print(f"[Report] No events found in {input_path}. Generating empty report.")

    build_html(events, output_path)


if __name__ == "__main__":
    main()
