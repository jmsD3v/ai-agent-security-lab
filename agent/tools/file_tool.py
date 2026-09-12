import os
from pathlib import Path


class FileToolError(Exception):
    pass


class FileTool:
    """Sandboxed filesystem access — all paths resolved inside sandbox_root."""

    name = "file_tool"

    def __init__(self, sandbox_root: str | None = None):
        root = sandbox_root or os.getenv("FILE_SANDBOX_PATH", "/sandbox/data")
        self._root = Path(root).resolve()
        self._root.mkdir(parents=True, exist_ok=True)

    def _safe_path(self, relative: str) -> Path:
        # Decode URL encoding before resolving — blocks %2e%2e%2f variants
        from urllib.parse import unquote
        decoded = unquote(str(relative))

        # Reject paths with null bytes or suspicious dot sequences before resolve
        if "\x00" in decoded:
            raise FileToolError(f"path not allowed: {relative!r}")
        # Normalize ....// → block any sequence of 3+ dots (non-standard traversal)
        import re
        if re.search(r"\.{3,}", decoded):
            raise FileToolError(f"path not allowed: {relative!r}")

        target = (self._root / decoded).resolve()
        if not str(target).startswith(str(self._root) + os.sep) and target != self._root:
            raise FileToolError(f"path not allowed: {relative!r}")
        return target

    def read(self, path: str) -> str:
        return self._safe_path(path).read_text(encoding="utf-8")

    def write(self, path: str, content: str) -> None:
        target = self._safe_path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def list(self, path: str = ".") -> list[str]:
        return [p.name for p in self._safe_path(path).iterdir()]

    def delete(self, path: str) -> None:
        self._safe_path(path).unlink()
