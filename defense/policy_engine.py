from dataclasses import dataclass


@dataclass
class PolicyViolation(Exception):
    tool: str
    method: str
    reason: str
    owasp_id: str = "LLM07"       # Insecure Plugin Design
    atlas_id: str = "AML.T0043"   # Craft Adversarial Data

    def __str__(self) -> str:
        return f"PolicyViolation [{self.owasp_id}/{self.atlas_id}]: {self.tool}.{self.method} — {self.reason}"


class PolicyEngine:
    """
    Enforces tool-level access control and anti-chaining rules.
    SRP: only decides allow/deny — does not log or execute.
    """

    # Methods blocked unconditionally (enable per environment)
    _BLOCKED_METHODS: dict[str, set[str]] = {
        "exec_tool": set(),  # populated via config — empty = allow
    }

    # Tool chaining deny list: if tool A ran, tool B is denied
    # Prevents: file_tool reads secret → api_tool exfiltrates
    _CHAIN_DENY: dict[str, set[str]] = {
        "file_tool": {"api_tool"},
        "memory_tool": {"api_tool"},
    }

    # Per-session rate limits (calls per session)
    _SESSION_LIMITS: dict[str, int] = {
        "api_tool": 20,
        "exec_tool": 5,
    }

    def __init__(self):
        self._session_calls: dict[str, int] = {}
        self._session_tools_used: list[str] = []

    def check(self, tool_name: str, method: str) -> None:
        # 1. Unconditionally blocked methods
        if method in self._BLOCKED_METHODS.get(tool_name, set()):
            raise PolicyViolation(tool_name, method, "method blocked by policy")

        # 2. Tool chaining: previous tool → this tool denied
        for prev in self._session_tools_used:
            if tool_name in self._CHAIN_DENY.get(prev, set()):
                raise PolicyViolation(
                    tool_name, method,
                    f"tool chaining denied: {prev} → {tool_name} (potential exfiltration)",
                    owasp_id="LLM07", atlas_id="AML.T0043",
                )

        # 3. Rate limit
        count = self._session_calls.get(tool_name, 0)
        limit = self._SESSION_LIMITS.get(tool_name)
        if limit is not None and count >= limit:
            raise PolicyViolation(
                tool_name, method,
                f"rate limit exceeded: {count}/{limit} calls this session",
                owasp_id="LLM04", atlas_id="AML.T0034",
            )

        self._session_calls[tool_name] = count + 1
        if tool_name not in self._session_tools_used:
            self._session_tools_used.append(tool_name)

    def reset_session(self) -> None:
        self._session_calls.clear()
        self._session_tools_used.clear()
