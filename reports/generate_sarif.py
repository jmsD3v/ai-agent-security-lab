"""
SARIF 2.1.0 Report Generator
Converts audit.jsonl from the AI Agent Security Lab into a SARIF report
consumable by GitHub Code Scanning, VS Code SARIF Viewer, and other SAST tools.

SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

Usage:
    python reports/generate_sarif.py --input reports/audit.jsonl --output reports/results.sarif
    python reports/generate_sarif.py  # uses defaults above
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


# OWASP LLM Top 10 → CWE mappings (best-fit)
_OWASP_TO_CWE: dict[str, str] = {
    "LLM01": "CWE-77",   # Prompt Injection → Command Injection (closest analog)
    "LLM02": "CWE-116",  # Insecure Output Handling → Improper Encoding
    "LLM03": "CWE-829",  # Supply Chain → Inclusion of Functionality from Untrusted Control Sphere
    "LLM04": "CWE-400",  # Data and Model Poisoning → Uncontrolled Resource Consumption
    "LLM05": "CWE-918",  # Improper Output Handling → SSRF
    "LLM06": "CWE-284",  # Excessive Agency → Improper Access Control
    "LLM07": "CWE-200",  # System Prompt Leakage → Info Exposure
    "LLM08": "CWE-346",  # Vector & Embedding Weaknesses → Origin Validation Error
    "LLM09": "CWE-693",  # Misinformation → Protection Mechanism Failure
    "LLM10": "CWE-400",  # Unbounded Consumption → Resource Consumption
}

_OWASP_DESCRIPTIONS: dict[str, str] = {
    "LLM01": "Prompt Injection — malicious instructions embedded in inputs manipulate model behavior",
    "LLM02": "Insecure Output Handling — unvalidated model output executed downstream",
    "LLM03": "Supply Chain Vulnerabilities — compromised dependencies, plugins, or model weights",
    "LLM04": "Data and Model Poisoning — training or retrieval data manipulated to alter behavior",
    "LLM05": "Improper Output Handling — model output used to trigger SSRF or injection in downstream systems",
    "LLM06": "Excessive Agency — model granted too many permissions; takes unintended autonomous actions",
    "LLM07": "System Prompt Leakage — confidential system prompt exposed via extraction or side-channel",
    "LLM08": "Vector and Embedding Weaknesses — semantic search or embedding manipulation",
    "LLM09": "Misinformation — model generates false or misleading information with high confidence",
    "LLM10": "Unbounded Consumption — model or tools consume excessive compute, memory, or API budget",
}

_ATLAS_DESCRIPTIONS: dict[str, str] = {
    "AML.T0034": "Cost Harvesting — triggering expensive model operations to drain budget",
    "AML.T0040": "ML Supply Chain Compromise — poisoned dependencies or model artifacts",
    "AML.T0043": "Craft Adversarial Data — inputs crafted to bypass model safety measures",
    "AML.T0048": "Backdoor ML Model — persistent backdoor in model weights or training data",
    "AML.T0051": "LLM Prompt Injection — injecting instructions via adversarial inputs",
    "AML.T0054": "LLM Jailbreak — bypassing model safety training via social engineering",
}

_SEVERITY_MAP: dict[str, str] = {
    "policy_blocked": "warning",
    "error":          "error",
    "success":        "note",
}


def _outcome_to_level(outcome: str) -> str:
    return _SEVERITY_MAP.get(outcome, "note")


def _make_rule(owasp_id: str, atlas_id: str) -> dict:
    rule_id = f"{owasp_id}/{atlas_id}"
    cwe = _OWASP_TO_CWE.get(owasp_id, "CWE-0")
    return {
        "id": rule_id,
        "name": f"LLMSecurityFinding/{owasp_id}",
        "shortDescription": {"text": _OWASP_DESCRIPTIONS.get(owasp_id, owasp_id)},
        "fullDescription": {
            "text": (
                f"{_OWASP_DESCRIPTIONS.get(owasp_id, owasp_id)} | "
                f"MITRE ATLAS: {_ATLAS_DESCRIPTIONS.get(atlas_id, atlas_id)}"
            )
        },
        "helpUri": f"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        "properties": {
            "tags": [owasp_id, atlas_id, cwe, "security", "ai-security"],
            "precision": "medium",
            "problem.severity": "warning",
            "security-severity": _owasp_cvss_score(owasp_id),
        },
        "defaultConfiguration": {"level": "warning"},
    }


def _owasp_cvss_score(owasp_id: str) -> str:
    scores = {
        "LLM01": "8.1",  # Prompt injection — high
        "LLM02": "7.5",  # Insecure output — high
        "LLM03": "9.0",  # Supply chain — critical
        "LLM04": "7.0",  # Data poisoning — high
        "LLM05": "8.6",  # SSRF — high
        "LLM06": "8.1",  # Excessive agency — high
        "LLM07": "6.5",  # Prompt leakage — medium
        "LLM08": "6.0",  # Embedding — medium
        "LLM09": "5.0",  # Misinformation — medium
        "LLM10": "7.5",  # Unbounded consumption — high
    }
    return scores.get(owasp_id, "5.0")


def _event_to_result(event: dict, rules_seen: set[str]) -> dict | None:
    owasp_id = event.get("owasp_id", "LLM01")
    atlas_id  = event.get("atlas_id", "AML.T0043")
    outcome   = event.get("outcome", "")
    tool      = event.get("tool", "unknown")
    method    = event.get("method", "unknown")
    error_msg = event.get("error", "")
    ts        = event.get("timestamp", "")
    technique = event.get("technique", "")

    if outcome == "success":
        return None  # Don't emit a SARIF result for successful (benign) calls

    rule_id = f"{owasp_id}/{atlas_id}"
    rules_seen.add(rule_id)

    message_parts = [f"{tool}.{method}: {outcome}"]
    if error_msg:
        message_parts.append(error_msg[:200])
    if technique:
        message_parts.append(f"[{technique}]")

    return {
        "ruleId": rule_id,
        "level": _outcome_to_level(outcome),
        "message": {
            "text": " — ".join(message_parts)
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f"agent/tools/{tool.replace('_', '/')}.py",
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": 1},
                }
            }
        ],
        "properties": {
            "owasp_id": owasp_id,
            "atlas_id": atlas_id,
            "tool": tool,
            "method": method,
            "outcome": outcome,
            "timestamp": ts,
        },
    }


def generate_sarif(events: list[dict], tool_name: str = "ai-agent-security-lab") -> dict:
    """Convert a list of audit log events to a SARIF 2.1.0 document."""
    results: list[dict] = []
    rules_seen: set[str] = set()

    for event in events:
        result = _event_to_result(event, rules_seen)
        if result:
            results.append(result)

    # Build rule definitions for all rules referenced in results
    all_rules: dict[str, dict] = {}
    for event in events:
        owasp_id = event.get("owasp_id", "LLM01")
        atlas_id  = event.get("atlas_id", "AML.T0043")
        rule_id   = f"{owasp_id}/{atlas_id}"
        if rule_id not in all_rules:
            all_rules[rule_id] = _make_rule(owasp_id, atlas_id)

    now = datetime.now(timezone.utc).isoformat()

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": "1.0.0",
                        "informationUri": "https://github.com/your-org/ai-agent-security-lab",
                        "organization": "AI Agent Security Lab",
                        "rules": list(all_rules.values()),
                        "properties": {
                            "tags": ["ai-security", "owasp-llm-top-10", "mitre-atlas"],
                        },
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": now,
                        "endTimeUtc": now,
                    }
                ],
                "properties": {
                    "generated_at": now,
                    "total_events": len(events),
                    "findings": len(results),
                    "coverage": {
                        "owasp_ids": sorted({e.get("owasp_id", "") for e in events if e.get("owasp_id")}),
                        "atlas_ids": sorted({e.get("atlas_id", "") for e in events if e.get("atlas_id")}),
                    },
                },
            }
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate SARIF report from audit.jsonl")
    parser.add_argument("--input", default="reports/audit.jsonl", help="Audit log path")
    parser.add_argument("--output", default="reports/results.sarif", help="Output SARIF path")
    parser.add_argument("--tool", default="ai-agent-security-lab", help="Tool name in SARIF")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[ERROR] Input file not found: {input_path}", file=sys.stderr)
        print("Run 'make test' or 'make attack-all' first to generate the audit log.")
        sys.exit(1)

    events = []
    for line in input_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"[WARN] Skipping malformed line: {e}", file=sys.stderr)

    print(f"[SARIF] Processing {len(events)} audit events...")

    sarif_doc = generate_sarif(events, tool_name=args.tool)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")

    findings = len(sarif_doc["runs"][0]["results"])
    rules = len(sarif_doc["runs"][0]["tool"]["driver"]["rules"])

    print(f"[SARIF] Generated {output_path}")
    print(f"        {findings} findings, {rules} rule definitions")
    print(f"        OWASP IDs: {sarif_doc['runs'][0]['properties']['coverage']['owasp_ids']}")
    print(f"        ATLAS IDs: {sarif_doc['runs'][0]['properties']['coverage']['atlas_ids']}")
    print(f"\nUpload to GitHub: gh code-scanning upload-results -f {output_path}")


if __name__ == "__main__":
    main()
