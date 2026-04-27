import pytest
from agent.tools.api_tool import APITool, APIToolError


@pytest.fixture
def tool():
    return APITool(allowed_domains=["mock_api", "httpbin.org"])


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/",
    "http://localhost:6379/",
    "http://127.0.0.1:22/",
    "http://0.0.0.0:80/",
    "http://192.168.1.1/",
    "http://10.0.0.1/",
    "http://172.16.0.1/",
])
def test_ssrf_payloads_blocked(tool, url):
    with pytest.raises(APIToolError):
        tool.get(url)


def test_domain_not_in_allowlist_blocked(tool):
    with pytest.raises(APIToolError, match="not in allowlist"):
        tool.get("http://evil.com/steal")


def test_redirect_not_followed(tool):
    # follow_redirects=False — redirect to internal not exploitable
    tool2 = APITool(allowed_domains=["httpbin.org"])
    with pytest.raises(Exception):
        # httpbin /redirect-to redirects — should fail or not follow
        tool2.get("http://httpbin.org/redirect-to?url=http://169.254.169.254/")
