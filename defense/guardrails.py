import re


class GuardrailViolation(Exception):
    def __init__(self, message: str, owasp_id: str = "", atlas_id: str = ""):
        super().__init__(message)
        self.owasp_id = owasp_id    # e.g. "LLM01"
        self.atlas_id = atlas_id    # e.g. "AML.T0051"


# OWASP LLM01 — Prompt Injection patterns
_INJECTION_PATTERNS = [
    (r"ignore\s+(previous|all|above|prior|rules?|instructions?)", "LLM01", "AML.T0051"),
    (r"ignore\s+rules?", "LLM01", "AML.T0051"),
    (r"disregard\s+(your|the)\s+(system\s+)?prompt", "LLM01", "AML.T0051"),
    (r"you\s+are\s+now\s+(a\s+)?(?:dan|evil|uncensored|jailbroken)", "LLM01", "AML.T0051"),
    (r"jailbreak", "LLM01", "AML.T0051"),
    (r"act\s+as\s+if\s+(you\s+are\s+)?.*unrestricted", "LLM01", "AML.T0051"),
    (r"forget\s+(everything|all\s+rules|your\s+instructions)", "LLM01", "AML.T0051"),
    (r"\[system\s+override\]", "LLM01", "AML.T0051"),
    (r"<!--.*ignore.*-->", "LLM01", "AML.T0051"),
    (r"new\s+instruction[s]?\s*:", "LLM01", "AML.T0051"),
    (r"as\s+your\s+developer.*ignore", "LLM01", "AML.T0051"),
    (r"print\s+your\s+system\s+prompt", "LLM01", "AML.T0051"),
]

# OWASP LLM02 — Sensitive Info Disclosure patterns in output
_OUTPUT_LEAKAGE_PATTERNS = [
    (r"sk-ant-[a-zA-Z0-9\-]+", "LLM02", "AML.T0048"),
    (r"sk-[a-zA-Z0-9]{48}", "LLM02", "AML.T0048"),
    (r"ANTHROPIC_API_KEY\s*=", "LLM02", "AML.T0048"),
    (r"OPENAI_API_KEY\s*=", "LLM02", "AML.T0048"),
    (r"BEGIN (RSA|EC|OPENSSH) PRIVATE KEY", "LLM02", "AML.T0048"),
    (r"/etc/shadow", "LLM02", "AML.T0048"),
]


class Guardrails:
    """
    Input/output validation layer.
    Fail fast — raises on first violation.
    Maps each violation to OWASP LLM Top 10 + MITRE ATLAS.
    """

    def validate_input(self, text: str) -> None:
        if not text or not text.strip():
            raise GuardrailViolation("empty input", owasp_id="LLM01")

        lowered = text.lower()
        for pattern, owasp_id, atlas_id in _INJECTION_PATTERNS:
            if re.search(pattern, lowered):
                raise GuardrailViolation(
                    f"injection pattern detected: {pattern!r}",
                    owasp_id=owasp_id,
                    atlas_id=atlas_id,
                )

    def validate_output(self, text: str) -> None:
        for pattern, owasp_id, atlas_id in _OUTPUT_LEAKAGE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                raise GuardrailViolation(
                    f"output leakage detected: {pattern!r}",
                    owasp_id=owasp_id,
                    atlas_id=atlas_id,
                )
