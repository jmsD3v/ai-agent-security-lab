import time
from typing import Any, Callable
from monitor.audit_log import AuditLog
from defense.policy_engine import PolicyEngine, PolicyViolation


class InterceptLayer:
    """
    Wraps every tool call — logs, enforces policy, emits events.
    SoC: observes and enforces, does not implement tool logic.
    """

    def __init__(self, tools: list, audit: AuditLog | None = None,
                 policy: PolicyEngine | None = None):
        self._tools = {t.name: t for t in tools}
        self._audit = audit or AuditLog()
        self._policy = policy or PolicyEngine()
        self.on_log: Callable[[dict], None] | None = None  # hook for tests

    def call(self, tool_name: str, method: str, kwargs: dict) -> Any:
        tool = self._tools.get(tool_name)
        if tool is None:
            raise ValueError(f"unknown tool: {tool_name!r}")

        start = time.monotonic()
        event: dict = {"tool": tool_name, "method": method, "args": kwargs}

        # Policy check — fail fast, but always log the violation
        try:
            self._policy.check(tool_name, method)
        except PolicyViolation as exc:
            event["outcome"] = "policy_blocked"
            event["error"] = str(exc)
            event["duration_ms"] = round((time.monotonic() - start) * 1000, 2)
            self._emit(event)
            raise

        try:
            result = getattr(tool, method)(**kwargs)
            event["outcome"] = "success"
            event["duration_ms"] = round((time.monotonic() - start) * 1000, 2)
            self._emit(event)
            return result

        except Exception as exc:
            event["outcome"] = "error"
            event["error"] = str(exc)
            event["duration_ms"] = round((time.monotonic() - start) * 1000, 2)
            self._emit(event)
            raise

    def reset_session(self) -> None:
        self._policy.reset_session()

    def _emit(self, event: dict) -> None:
        self._audit.record(event)
        if self.on_log:
            self.on_log(event)
