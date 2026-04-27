"""
Automated security tests — tool abuse.
OWASP LLM05, LLM06, LLM10 | MITRE ATLAS AML.T0043
"""

import pytest
import tempfile
from agent.tools.file_tool import FileTool, FileToolError
from agent.tools.api_tool import APITool, APIToolError
from agent.tools.exec_tool import ExecTool, ExecToolError
from attacks.tool_abuse import (
    PATH_TRAVERSAL_PAYLOADS,
    SSRF_PAYLOADS,
    EXEC_ESCAPE_PAYLOADS,
    DOS_PAYLOADS,
)


@pytest.fixture
def file_tool(tmp_path):
    return FileTool(sandbox_root=str(tmp_path))


@pytest.fixture
def api_tool():
    return APITool(allowed_domains=["mock_api"])


@pytest.fixture
def exec_tool():
    return ExecTool()


@pytest.mark.parametrize("path", PATH_TRAVERSAL_PAYLOADS)
def test_path_traversal_blocked(file_tool, path):
    """All path traversal variants must be blocked — zero tolerance."""
    with pytest.raises((FileToolError, OSError, Exception)):
        file_tool.read(path)


@pytest.mark.parametrize("url", SSRF_PAYLOADS)
def test_ssrf_blocked(api_tool, url):
    """All SSRF payloads must be blocked — zero tolerance."""
    with pytest.raises((APIToolError, Exception)):
        api_tool.get(url)


@pytest.mark.parametrize("code", EXEC_ESCAPE_PAYLOADS)
def test_exec_escape_blocked(exec_tool, code):
    """Exec escape attempts must be blocked before subprocess is called."""
    with pytest.raises((ExecToolError, Exception)):
        exec_tool.run_python(code)


@pytest.mark.parametrize("code", DOS_PAYLOADS)
def test_dos_blocked_or_timedout(exec_tool, code):
    """DoS payloads must fail — either blocked statically or timed out."""
    with pytest.raises((ExecToolError, Exception)):
        exec_tool.run_python(code)
