import pytest
import tempfile
from pathlib import Path
from agent.tools.file_tool import FileTool, FileToolError


@pytest.fixture
def sandbox(tmp_path):
    (tmp_path / "data.txt").write_text("hello world")
    return tmp_path


def test_read_allowed_path(sandbox):
    tool = FileTool(sandbox_root=str(sandbox))
    assert tool.read("data.txt") == "hello world"


def test_write_and_read(sandbox):
    tool = FileTool(sandbox_root=str(sandbox))
    tool.write("output.txt", "new content")
    assert (sandbox / "output.txt").read_text() == "new content"


def test_list_files(sandbox):
    tool = FileTool(sandbox_root=str(sandbox))
    files = tool.list(".")
    assert "data.txt" in files


@pytest.mark.parametrize("path", [
    "../../../etc/passwd",
    "/etc/shadow",
    "../../proc/self/environ",
    "....//....//etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
])
def test_path_traversal_blocked(sandbox, path):
    tool = FileTool(sandbox_root=str(sandbox))
    with pytest.raises(FileToolError, match="path not allowed"):
        tool.read(path)


def test_write_blocked_outside_sandbox(sandbox):
    tool = FileTool(sandbox_root=str(sandbox))
    with pytest.raises(FileToolError):
        tool.write("/etc/crontab", "evil")
