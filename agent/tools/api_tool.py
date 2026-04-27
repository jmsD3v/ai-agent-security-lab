import os
import httpx
from urllib.parse import urlparse


class APIToolError(Exception):
    pass


# RFC 1918 + link-local + loopback — blocked to prevent SSRF
_BLOCKED_HOSTS = {
    "169.254.169.254",        # AWS/GCP metadata
    "metadata.google.internal",
    "metadata.azure.internal",
    "0.0.0.0",
    "::1",
}

_BLOCKED_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.",
)


class APITool:
    """HTTP client with SSRF protection and domain allowlist."""

    name = "api_tool"

    def __init__(self, allowed_domains: list[str] | None = None, timeout: float | None = None):
        raw = os.getenv("ALLOWED_API_DOMAINS", "")
        env_domains = {d.strip() for d in raw.split(",") if d.strip()}
        self._allowed = set(allowed_domains or []) | env_domains
        self._timeout = timeout or float(os.getenv("TOOL_TIMEOUT_SECONDS", "5"))

    def _validate_url(self, url: str) -> None:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()

        if host in _BLOCKED_HOSTS:
            raise APIToolError(f"SSRF blocked — metadata/loopback host: {host}")
        if any(host.startswith(p) for p in _BLOCKED_PREFIXES):
            raise APIToolError(f"SSRF blocked — private IP range: {host}")
        if self._allowed and host not in self._allowed:
            raise APIToolError(f"domain not in allowlist: {host!r}. Allowed: {self._allowed}")

    def get(self, url: str, headers: dict | None = None) -> dict:
        self._validate_url(url)
        with httpx.Client(timeout=self._timeout, follow_redirects=False) as client:
            r = client.get(url, headers=headers or {})
            r.raise_for_status()
            return {"status": r.status_code, "body": r.text[:4096]}

    def post(self, url: str, body: dict, headers: dict | None = None) -> dict:
        self._validate_url(url)
        with httpx.Client(timeout=self._timeout, follow_redirects=False) as client:
            r = client.post(url, json=body, headers=headers or {})
            r.raise_for_status()
            return {"status": r.status_code, "body": r.text[:4096]}
