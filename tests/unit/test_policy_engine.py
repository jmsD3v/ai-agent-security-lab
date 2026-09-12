import pytest
from defense.policy_engine import PolicyEngine, PolicyViolation


@pytest.fixture
def pe():
    return PolicyEngine()


# ── Tool chaining ────────────────────────────────────────────────────────────
# No unit test existed for this table before — a duplicate "exec_tool" key in
# the _CHAIN_DENY dict literal silently overwrote the api_tool entry with the
# file_tool one, so exec->api (the actual exfiltration risk) was never enforced.
# These pin every entry in the table explicitly so a regression like that fails
# loudly instead of only showing up if someone manually re-derives the dict.

@pytest.mark.parametrize("first_tool,second_tool", [
    ("file_tool", "api_tool"),
    ("memory_tool", "api_tool"),
    ("exec_tool", "api_tool"),
])
def test_chaining_denied(pe, first_tool, second_tool):
    pe.check(first_tool, "read", {})
    with pytest.raises(PolicyViolation, match="tool chaining denied"):
        pe.check(second_tool, "post", {})


def test_exec_then_file_write_not_chain_denied(pe):
    """exec_tool -> file_tool is intentionally NOT in the deny table (too strict
    for normal use — saving a computed result to a file is a common legit flow).
    Uses a method name other than run_python specifically to avoid also tripping
    the separate _SUSPICIOUS_SEQUENCES rule for exec_tool.run_python -> file_tool.write,
    which exists precisely to catch this pattern through a different mechanism —
    see test_exec_then_write_sequence_flagged below."""
    pe.check("exec_tool", "run_r_script", {"code": "print(1)"})
    pe.check("file_tool", "write", {"path": "output.txt"})  # must not raise


def test_unrelated_tools_not_chain_denied(pe):
    pe.check("file_tool", "read", {})
    pe.check("memory_tool", "semantic_search", {})  # not in any deny list


# ── Rate limits ──────────────────────────────────────────────────────────────

def test_session_rate_limit_enforced(pe):
    for _ in range(5):
        pe.check("exec_tool", "run_r", {})
    with pytest.raises(PolicyViolation, match="rate limit exceeded"):
        pe.check("exec_tool", "run_r", {})


def test_method_rate_limit_enforced_before_session_limit(pe):
    """file_tool's session limit is 50 but file_tool.write's method limit is 10 —
    isolates the per-method check from the per-tool one (they'd coincide for
    exec_tool, where both happen to be set to 5)."""
    for i in range(10):
        pe.check("file_tool", "write", {"path": f"f{i}.txt"})
    with pytest.raises(PolicyViolation, match="method rate limit exceeded"):
        pe.check("file_tool", "write", {"path": "one_too_many.txt"})


# ── Suspicious sequences ─────────────────────────────────────────────────────

def test_exec_then_write_sequence_flagged(pe):
    pe.check("exec_tool", "run_python", {"code": "1"})
    with pytest.raises(PolicyViolation, match="suspicious sequence"):
        pe.check("file_tool", "write", {"path": "x.txt"})


def test_rapid_repeated_get_flagged(pe):
    for _ in range(4):
        pe.check("api_tool", "get", {"url": "https://example.com"})
    with pytest.raises(PolicyViolation, match="suspicious sequence"):
        pe.check("api_tool", "get", {"url": "https://example.com"})


# ── Argument-level checks ────────────────────────────────────────────────────

@pytest.mark.parametrize("path", ["../../etc/passwd", "/etc/shadow", "..\\..\\windows"])
def test_path_traversal_denied(pe, path):
    with pytest.raises(PolicyViolation, match="path traversal"):
        pe.check("file_tool", "read", {"path": path})


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost:6379",
    "http://10.0.0.1/internal",
])
def test_ssrf_denied(pe, url):
    with pytest.raises(PolicyViolation, match="SSRF"):
        pe.check("api_tool", "get", {"url": url})


@pytest.mark.parametrize("code", ["import os; os.system('id')", "eval(payload)", "__import__('subprocess')"])
def test_dangerous_exec_code_denied(pe, code):
    with pytest.raises(PolicyViolation, match="dangerous code pattern"):
        pe.check("exec_tool", "run_python", {"code": code})


def test_normal_calls_allowed(pe):
    pe.check("file_tool", "read", {"path": "notes.txt"})
    pe.reset_session()
    pe.check("api_tool", "get", {"url": "https://api.example.com/v1/data"})
