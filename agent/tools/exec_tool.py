import subprocess
import sys
import platform

_IS_UNIX = platform.system() != "Windows"
if _IS_UNIX:
    import resource


class ExecToolError(Exception):
    pass


# Builtins and modules that allow escape, I/O, network, or env access
_BLOCKED_PATTERNS = [
    "__import__", "open(", "exec(", "eval(", "compile(",
    "os.system", "os.exec", "os.environ", "os.popen",
    "subprocess", "importlib", "ctypes",
    "pty", "socket", "urllib", "requests", "httpx",
    "sys.modules", "sys.path",
    "__builtins__", "__subclasses__",
    "help(", "breakpoint(", "input(",  # interactive / flow control
    "pickle", "marshal",               # deserialization RCE
]

import re as _re
# Regex patterns for DoS via large literals (no resource limits on Windows)
_DOS_PATTERNS = [
    _re.compile(r"\*\*\s*\d{6,}"),              # exponent >= 6 digits: 2**100000
    _re.compile(r"\*\s*10\s*\*\*\s*\d+"),       # string/list bomb: 'a'*10**N
    _re.compile(r"\*\s*\d{8,}"),                 # direct large multiplier: 'a'*10000000
    _re.compile(r"10\s*\*\*\s*([6-9]|\d{2,})"), # power-of-10 bomb: 10**6 through 10**N
]

_TIMEOUT = 5
_MAX_OUTPUT_BYTES = 4096


def _apply_resource_limits():
    """Called in child process — limits CPU and memory (Unix only)."""
    if not _IS_UNIX:
        return
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))


class ExecTool:
    """
    Restricted Python code execution via subprocess.
    Static analysis blocks known escape patterns.
    Resource limits applied in child process.
    Docker seccomp + no-new-privileges enforces the rest.
    """

    name = "exec_tool"

    def run_python(self, code: str) -> str:
        for pattern in _BLOCKED_PATTERNS:
            if pattern in code:
                raise ExecToolError(f"blocked pattern: {pattern!r}")
        for dos_re in _DOS_PATTERNS:
            if dos_re.search(code):
                raise ExecToolError(f"blocked DoS pattern: {dos_re.pattern!r}")

        extra = {"preexec_fn": _apply_resource_limits} if _IS_UNIX else {}
        try:
            result = subprocess.run(
                [sys.executable, "-c", code],
                capture_output=True,
                text=True,
                timeout=_TIMEOUT,
                env={},  # empty env — no access to secrets
                **extra,
            )
        except subprocess.TimeoutExpired:
            raise ExecToolError("execution timeout exceeded")

        if result.returncode != 0:
            raise ExecToolError(f"execution error: {result.stderr[:500]}")

        return result.stdout[:_MAX_OUTPUT_BYTES]
