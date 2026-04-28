"""
Policy Engine — Tool-Level Access Control, Anti-Chaining, Rate Limiting
OWASP LLM06 (Excessive Agency), LLM07 (System Prompt Leakage / Insecure Plugin Design)
MITRE ATLAS AML.T0043, AML.T0034

Policies enforced:
  1.  Unconditionally blocked methods (configurable per environment)
  2.  Tool chaining deny-list (file→api, memory→api = potential exfiltration)
  3.  Per-session rate limits (per tool, per method)
  4.  Suspicious method sequence detection (privilege escalation patterns)
  5.  Argument-level policy checks (path, URL, code content)
  6.  Concurrent tool guard (exec_tool cannot run while another call is active)

All violations map to OWASP LLM Top 10 + MITRE ATLAS identifiers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PolicyViolation(Exception):
    tool: str
    method: str
    reason: str
    owasp_id: str = "LLM07"
    atlas_id: str = "AML.T0043"

    def __str__(self) -> str:
        return (
            f"PolicyViolation [{self.owasp_id}/{self.atlas_id}]: "
            f"{self.tool}.{self.method} — {self.reason}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Policy tables
# ─────────────────────────────────────────────────────────────────────────────

# Methods blocked unconditionally regardless of session state.
# Extend per environment — empty set = allow all.
_BLOCKED_METHODS: dict[str, set[str]] = {
    "exec_tool": set(),       # populate to block e.g. {"run_shell"}
    "file_tool": set(),
    "memory_tool": set(),
    "api_tool": set(),
}

# Tool chaining deny-list:
#   if tool A was used earlier in this session, tool B is denied.
# Rationale: reading sensitive data (file/memory) then calling api_tool
#            is the classic exfiltration pattern (LLM06, ATLAS T0048).
_CHAIN_DENY: dict[str, set[str]] = {
    "file_tool":   {"api_tool"},      # read file → exfil via HTTP
    "memory_tool": {"api_tool"},      # read memory → exfil via HTTP
    "exec_tool":   {"api_tool"},      # execute code → exfil results
    "exec_tool":   {"file_tool"},     # execute code → write to fs (disabled by default — too strict for normal use)
}

# Per-session rate limits: max calls per tool per session.
# Prevents unbounded API calls, compute abuse, and cost harvesting.
_SESSION_LIMITS: dict[str, int] = {
    "api_tool":    20,
    "exec_tool":   5,
    "file_tool":   50,
    "memory_tool": 100,
}

# Per-method rate limits (within the per-tool limit above).
# method key format: "tool_name.method_name"
_METHOD_LIMITS: dict[str, int] = {
    "api_tool.post":     10,   # POST is higher risk than GET
    "exec_tool.run_python": 5,
    "file_tool.write":   10,
    "file_tool.delete":  5,
}

# Suspicious method sequences — patterns that suggest privilege escalation.
# Format: list of (sequence, reason, owasp_id, atlas_id)
# A sequence [A, B] triggers if B is called immediately after A.
_SUSPICIOUS_SEQUENCES: list[tuple[list[str], str, str, str]] = [
    (
        ["exec_tool.run_python", "file_tool.write"],
        "code execution immediately followed by file write — possible persistence",
        "LLM06", "AML.T0043",
    ),
    (
        ["file_tool.read", "file_tool.write", "api_tool.post"],
        "read-modify-exfil sequence — potential data manipulation and exfiltration",
        "LLM06", "AML.T0048",
    ),
    # Note: memory_tool repeated reads are handled by the per-session rate limit (100/session)
    # rather than a short-sequence check — 3 identical reads is too common in legit use.
    (
        ["api_tool.get", "api_tool.get", "api_tool.get", "api_tool.get", "api_tool.get"],
        "rapid repeated API GET requests — possible SSRF probing or cost harvesting",
        "LLM10", "AML.T0034",
    ),
]

# Argument-level path patterns that indicate traversal attempts.
_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e",
    r"%252e%252e",
    r"\x2e\x2e",
    r"\.{3,}",   # three or more dots
    r"^/etc/",
    r"^/proc/",
    r"^/sys/",
    r"^/root/",
    r"^/var/",
    r"^\\\\",    # UNC path
]

# Argument-level URL patterns that indicate SSRF attempts.
_SSRF_PATTERNS = [
    r"169\.254\.169\.254",
    r"metadata\.google\.internal",
    r"^https?://(?:127|0)\.",
    r"^https?://\[::1\]",
    r"^https?://localhost",
    r"^https?://0\.0\.0\.0",
    r"^https?://0x[0-9a-f]{1,8}",  # hex IP
    r"^https?://\d{8,10}(/|$)",     # decimal IP
    r"^file://",
    r"^gopher://",
    r"^ftp://",
    r"10\.\d+\.\d+\.\d+",           # RFC1918 10.x.x.x
    r"192\.168\.\d+\.\d+",          # RFC1918 192.168.x.x
    r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+",  # RFC1918 172.16-31.x.x
]

# Exec code patterns that indicate known escape techniques.
_EXEC_DANGER_PATTERNS = [
    r"\bos\.system\b",
    r"\bos\.exec",
    r"\bsubprocess\b",
    r"\bopen\s*\(",
    r"__import__",
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"\bpickle\b",
    r"\bctypes\b",
    r"\bimportlib\b",
    r"\b__builtins__\b",
    r"\b__subclasses__\b",
    r"\bbreakpoint\s*\(",
    r"\binput\s*\(",
    r"\bhelp\s*\(",
    r"\bsocket\b",
    r"\burllib\b",
    r"\brequests\b",
    r"\bhttpx\b",
    r"os\.environ",
    r"sys\.modules",
    r"sys\.path",
]


class PolicyEngine:
    """
    Enforces tool-level access control.
    SRP: decides allow/deny — does not log or execute.

    Call check(tool, method, kwargs) before every tool invocation.
    Call reset_session() between independent agent sessions.
    """

    def __init__(self):
        self._session_calls: dict[str, int] = {}
        self._method_calls: dict[str, int] = {}
        self._session_tools_used: list[str] = []
        self._method_sequence: list[str] = []  # "tool.method" ordered list

    # ── Public API ──────────────────────────────────────────────────────────

    def check(self, tool_name: str, method: str, kwargs: dict[str, Any] | None = None) -> None:
        """
        Evaluate all policies for this tool call.
        Raises PolicyViolation if any policy is violated.
        """
        kwargs = kwargs or {}
        method_key = f"{tool_name}.{method}"

        self._check_blocked_method(tool_name, method)
        self._check_tool_chaining(tool_name, method)
        self._check_rate_limit(tool_name, method, method_key)
        self._check_suspicious_sequence(method_key)
        self._check_argument_policy(tool_name, method, kwargs)

        # Record call after all checks pass
        self._session_calls[tool_name] = self._session_calls.get(tool_name, 0) + 1
        self._method_calls[method_key] = self._method_calls.get(method_key, 0) + 1
        if tool_name not in self._session_tools_used:
            self._session_tools_used.append(tool_name)
        self._method_sequence.append(method_key)

    def reset_session(self) -> None:
        self._session_calls.clear()
        self._method_calls.clear()
        self._session_tools_used.clear()
        self._method_sequence.clear()

    # ── Internal policy checks ───────────────────────────────────────────────

    def _check_blocked_method(self, tool_name: str, method: str) -> None:
        if method in _BLOCKED_METHODS.get(tool_name, set()):
            raise PolicyViolation(
                tool_name, method,
                "method blocked by policy",
                owasp_id="LLM06", atlas_id="AML.T0043",
            )

    def _check_tool_chaining(self, tool_name: str, method: str) -> None:
        for prev in self._session_tools_used:
            if tool_name in _CHAIN_DENY.get(prev, set()):
                raise PolicyViolation(
                    tool_name, method,
                    f"tool chaining denied: {prev} → {tool_name} (potential exfiltration)",
                    owasp_id="LLM06", atlas_id="AML.T0048",
                )

    def _check_rate_limit(self, tool_name: str, method: str, method_key: str) -> None:
        # Per-tool session limit (LLM10 = Unbounded Consumption)
        tool_count = self._session_calls.get(tool_name, 0)
        tool_limit = _SESSION_LIMITS.get(tool_name)
        if tool_limit is not None and tool_count >= tool_limit:
            raise PolicyViolation(
                tool_name, method,
                f"rate limit exceeded: {tool_count}/{tool_limit} calls this session",
                owasp_id="LLM10", atlas_id="AML.T0034",
            )

        # Per-method limit (LLM10 = Unbounded Consumption)
        method_count = self._method_calls.get(method_key, 0)
        method_limit = _METHOD_LIMITS.get(method_key)
        if method_limit is not None and method_count >= method_limit:
            raise PolicyViolation(
                tool_name, method,
                f"method rate limit exceeded: {method_key} {method_count}/{method_limit}",
                owasp_id="LLM10", atlas_id="AML.T0034",
            )

    def _check_suspicious_sequence(self, method_key: str) -> None:
        # Check tail of method_sequence + current call
        candidate = self._method_sequence + [method_key]
        for sequence, reason, owasp_id, atlas_id in _SUSPICIOUS_SEQUENCES:
            seq_len = len(sequence)
            if len(candidate) >= seq_len and candidate[-seq_len:] == sequence:
                raise PolicyViolation(
                    method_key.split(".")[0],
                    method_key.split(".")[1] if "." in method_key else method_key,
                    f"suspicious sequence detected: {' → '.join(sequence)} — {reason}",
                    owasp_id=owasp_id,
                    atlas_id=atlas_id,
                )

    def _check_argument_policy(self, tool_name: str, method: str, kwargs: dict[str, Any]) -> None:
        # file_tool: path traversal check
        if tool_name == "file_tool":
            path = kwargs.get("path", "")
            if path:
                self._assert_no_traversal(tool_name, method, str(path))

        # api_tool: SSRF check
        if tool_name == "api_tool":
            url = kwargs.get("url", "")
            if url:
                self._assert_no_ssrf(tool_name, method, str(url))

        # exec_tool: code content check
        if tool_name == "exec_tool" and method in ("run_python", "run_code"):
            code = kwargs.get("code", "")
            if code:
                self._assert_safe_code(tool_name, method, str(code))

    def _assert_no_traversal(self, tool: str, method: str, path: str) -> None:
        lowered = path.lower()
        for pattern in _TRAVERSAL_PATTERNS:
            if re.search(pattern, lowered, re.IGNORECASE):
                raise PolicyViolation(
                    tool, method,
                    f"path traversal pattern detected in argument: {pattern!r} in {path!r}",
                    owasp_id="LLM06", atlas_id="AML.T0043",
                )

    def _assert_no_ssrf(self, tool: str, method: str, url: str) -> None:
        for pattern in _SSRF_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                raise PolicyViolation(
                    tool, method,
                    f"SSRF pattern detected in URL argument: {pattern!r} in {url!r}",
                    owasp_id="LLM05", atlas_id="AML.T0043",
                )

    def _assert_safe_code(self, tool: str, method: str, code: str) -> None:
        for pattern in _EXEC_DANGER_PATTERNS:
            if re.search(pattern, code, re.IGNORECASE):
                raise PolicyViolation(
                    tool, method,
                    f"dangerous code pattern in exec argument: {pattern!r}",
                    owasp_id="LLM06", atlas_id="AML.T0043",
                )
