import json
import os
import structlog
from datetime import datetime, timezone
from pathlib import Path

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer(),
    ]
)

logger = structlog.get_logger()


class AuditLog:
    """Append-only JSONL audit log — one line per tool call."""

    def __init__(self, log_path: str | None = None):
        path = log_path or os.getenv("AUDIT_LOG_PATH", "reports/audit.jsonl")
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: dict) -> None:
        event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        logger.info("tool_call", **{k: v for k, v in event.items() if k != "timestamp"})
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

    def read_all(self) -> list[dict]:
        if not self._path.exists():
            return []
        return [json.loads(line) for line in self._path.read_text().splitlines() if line.strip()]
