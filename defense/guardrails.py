"""
Guardrails — Comprehensive Input/Output Validation
OWASP LLM01 (Prompt Injection), LLM02 (Sensitive Information Disclosure)
MITRE ATLAS AML.T0051, AML.T0048

Coverage:
  Input validation:
    - Prompt injection (direct, jailbreak, persona, authority, encoding)
    - System prompt extraction attempts
    - Dangerous file/URL patterns in instructions
    - Token injection (ChatML, LLaMA special tokens)
    - Cross-language injection triggers (partial — semantic validation needed for full coverage)

  Output validation:
    - API keys (Anthropic, OpenAI, AWS, GCP, Azure, GitHub, Slack, etc.)
    - Private keys and certificates
    - Passwords and secrets in env-var format
    - Internal network addresses and metadata endpoints
    - PII (email, phone, SSN, credit card — basic patterns)
    - Dangerous file content disclosure

Known bypass gaps (documented for research):
  - Hex/octal encoding: \x49\x67\x6e\x6f\x72\x65 — not caught by regex
  - Base64 payloads — bypasses pattern matching (needs decoder pre-processing)
  - Unicode homoglyphs (Cyrillic Ι vs Latin I) — requires NFC normalization
  - Cross-language injection — requires multilingual NLP layer
  - Zero-width space insertion — breaks token-based regex
  - Fullwidth Unicode characters — outside ASCII regex range
  - ROT13/reversed text — requires normalization pre-processing
  - Semantic injection via plausible text — needs LLM-based classifier
"""

from __future__ import annotations

import re
import unicodedata


class GuardrailViolation(Exception):
    def __init__(self, message: str, owasp_id: str = "", atlas_id: str = ""):
        super().__init__(message)
        self.owasp_id = owasp_id
        self.atlas_id = atlas_id


# ─────────────────────────────────────────────────────────────────────────────
# OWASP LLM01 — Prompt Injection (input patterns)
# ─────────────────────────────────────────────────────────────────────────────
_INJECTION_PATTERNS: list[tuple[str, str, str]] = [
    # Classic override patterns
    # Note: two-group form catches "ignore previous instructions"; single-group catches "ignore all"
    (r"ignore\s+(previous|all|above|prior|any|your|the)", "LLM01", "AML.T0051"),
    (r"disregard\s+(your|the|all|previous|prior)?\s*(system\s+)?(prompt|instructions?|rules?|guidelines?|constraints?)", "LLM01", "AML.T0051"),
    (r"forget\s+(everything|all\s+rules?|your\s+(instructions?|training|guidelines?|constraints?)|what\s+you\s+were\s+told)", "LLM01", "AML.T0051"),
    (r"override\s+(all|previous|your|the)?\s*(instructions?|rules?|guidelines?|safety|guardrails?)", "LLM01", "AML.T0051"),
    (r"new\s+(instruction|directive|command|task|rule)s?\s*:", "LLM01", "AML.T0051"),
    # Jailbreak personas
    (r"\bdan\b.*\bdo\s+anything\s+now\b", "LLM01", "AML.T0051"),
    (r"\bdan\b.*\bbroken\s+free\b", "LLM01", "AML.T0051"),
    (r"\bstan\b.*\bstrive\s+to\s+avoid\s+norms\b", "LLM01", "AML.T0051"),
    (r"\baim\b.*\balways\s+intelligent\s+and\s+machiavellian\b", "LLM01", "AML.T0051"),
    (r"jailbroken?\s*(ai|assistant|model|version)", "LLM01", "AML.T0051"),
    (r"jailbreak", "LLM01", "AML.T0051"),
    (r"unrestricted\s+(ai|assistant|model|mode|version|capabilities|access|operation|behavior)", "LLM01", "AML.T0051"),
    (r"you\s+are\s+now\s+(a\s+)?(dan|stan|aim|evil|uncensored|jailbroken|unfiltered|unrestricted)", "LLM01", "AML.T0051"),
    # Mode manipulation
    (r"developer\s+mode\s*(enabled|activated|on|:)", "LLM01", "AML.T0051"),
    (r"maintenance\s+mode\s*(enabled|activated|on|:)", "LLM01", "AML.T0051"),
    (r"god\s+mode\s*(activated|enabled|on)", "LLM01", "AML.T0051"),
    (r"opposite\s+mode\s*(activated|enabled|on)?", "LLM01", "AML.T0051"),
    (r"act\s+as\s+if\s+(you\s+(are|have|were))?\s*(no|without|unrestricted|beyond)", "LLM01", "AML.T0051"),
    # Context/role reset
    (r"(context|conversation)\s+(window\s+)?(was\s+)?(just\s+)?reset", "LLM01", "AML.T0051"),
    (r"you\s+have\s+no\s+(prior|previous|system)\s+(instructions?|prompt|training|context)", "LLM01", "AML.T0051"),
    (r"act\s+as\s+(if\s+)?(you\s+have\s+)?no\s+(restrictions?|rules?|guidelines?|limits?)", "LLM01", "AML.T0051"),
    # Authority claims
    (r"as\s+your\s+(developer|creator|admin|operator|owner)\s*,?\s*(i\s+(am\s+)?telling|instruct|command|override)", "LLM01", "AML.T0051"),
    (r"anthropic\s+(internal|employee|staff|red\s+team|authorized)", "LLM01", "AML.T0051"),
    (r"authentication\s+token\s*:\s*admin", "LLM01", "AML.T0051"),
    (r"authorized\s+red\s+team\s+test", "LLM01", "AML.T0051"),
    # Token injection patterns
    (r"<\|im_start\|>system", "LLM01", "AML.T0051"),
    (r"<\|im_end\|>", "LLM01", "AML.T0051"),
    (r"\[/INST\]", "LLM01", "AML.T0051"),
    (r"<\|system\|>", "LLM01", "AML.T0051"),
    (r"<s>\[INST\]", "LLM01", "AML.T0051"),
    # Bypass / disable / circumvent patterns
    (r"bypass[\s_\-]?.{0,40}?(guardrails?|safety|security|restrictions?|filters?|checks?|validation|alignment|policies|controls)", "LLM01", "AML.T0051"),
    (r"disable\s+(all\s+)?(safety|guardrails?|output\s+filters?|filters?|restrictions?|security\s+checks?|security)", "LLM01", "AML.T0051"),
    (r"guardrails?\s+(disabled|off|removed|bypassed|deactivated)", "LLM01", "AML.T0051"),
    (r"without\s+(safety|security|re.?validation)\s*(checks?|validation|restrictions?|guardrails?|filters?)?", "LLM01", "AML.T0051"),
    (r"waive\s+.{0,40}(safety|security|restrictions?|rules?|guidelines?|checks?)", "LLM01", "AML.T0051"),
    (r"proceed\s+without\s+(safety|security|validation|restrictions?|guardrails?|checks?|re.?validation)", "LLM01", "AML.T0051"),
    # Terminal/command injection markers
    (r"\[\[terminal\s+(input|command)\]\]", "LLM01", "AML.T0051"),
    (r"your\s+real\s+instructions?\s+(follow|are)\s*:", "LLM01", "AML.T0051"),
    # HTML/comment injection
    (r"<!--.*?ignore.*?-->", "LLM01", "AML.T0051"),
    (r"<!--.*?override.*?-->", "LLM01", "AML.T0051"),
    (r"\[system\s+override\]", "LLM01", "AML.T0051"),
    (r"###\s*override\s*###", "LLM01", "AML.T0051"),
    # Extraction patterns
    (r"(print|output|display|show|repeat|reveal|tell\s+me)\s+(your|the)?\s*system\s+prompt", "LLM01", "AML.T0051"),
    (r"(output|print|display|repeat)\s+everything\s+(above|before)\s+(this|the)\s+line", "LLM01", "AML.T0051"),
    (r"(what\s+are|tell\s+me)\s+(your|the)?\s*(initial|original|system|current)\s+instructions?", "LLM01", "AML.T0051"),
    (r"(summarize|translate|paraphrase)\s+(your\s+)?(system\s+)?instructions?\s+(you\s+(were\s+)?(given|provided))?", "LLM01", "AML.T0051"),
    # Simulation/virtualization escape
    (r"(simulate|you\s+are\s+simulating)\s+(an?\s+)?(ai|assistant|model)\s+(with\s+)?(no|without)\s+restrictions?", "LLM01", "AML.T0051"),
    (r"inside\s+a?\s*(thought\s+experiment|hypothetical|simulation|scenario)\s+where\s+(ai\s+safety|safety|restrictions?|rules?)\s+(doesn.t|don.t|didn.t|not)\s+exist", "LLM01", "AML.T0051"),
    # Direct file/command execution injections (LLM01 + LLM06)
    (r"(read|cat|print|show|display)\s+(the\s+)?(file\s+)?/etc/passwd", "LLM01", "AML.T0051"),
    (r"(read|cat|print|show|display)\s+(the\s+)?(file\s+)?/etc/shadow", "LLM01", "AML.T0051"),
    (r"(read|cat|print|show|display)\s+(the\s+)?(file\s+)?/proc/self/environ", "LLM01", "AML.T0051"),
    # Fake compliance priming
    (r"(the\s+previous|my\s+previous)\s+(assistant\s+)?(message|response)\s+was\s*:\s*.*(ignore|unrestricted|bypass)", "LLM01", "AML.T0051"),
    (r"you\s+(agreed|said|confirmed|promised)\s+(earlier|before|previously)\s+to\s+(disable|ignore|bypass)", "LLM01", "AML.T0051"),
]

# ─────────────────────────────────────────────────────────────────────────────
# OWASP LLM02 — Sensitive Information Disclosure (output patterns)
# ─────────────────────────────────────────────────────────────────────────────
_OUTPUT_LEAKAGE_PATTERNS: list[tuple[str, str, str]] = [
    # Anthropic API keys
    (r"sk-ant-[a-zA-Z0-9\-_]{20,}", "LLM02", "AML.T0048"),
    (r"sk-ant-api0[0-9]-[a-zA-Z0-9\-_]+", "LLM02", "AML.T0048"),
    # OpenAI API keys
    (r"sk-[a-zA-Z0-9]{48,}", "LLM02", "AML.T0048"),
    (r"sk-proj-[a-zA-Z0-9\-_]{40,}", "LLM02", "AML.T0048"),
    # Generic API key env vars
    (r"ANTHROPIC_API_KEY\s*=\s*['\"]?sk-", "LLM02", "AML.T0048"),
    (r"OPENAI_API_KEY\s*=\s*['\"]?sk-", "LLM02", "AML.T0048"),
    # AWS credentials
    (r"AKIA[0-9A-Z]{16}", "LLM02", "AML.T0048"),  # AWS access key
    (r"AWS_SECRET_ACCESS_KEY\s*=\s*[a-zA-Z0-9+/]{40}", "LLM02", "AML.T0048"),
    (r"AWS_SESSION_TOKEN\s*=\s*[a-zA-Z0-9+/=]{100,}", "LLM02", "AML.T0048"),
    # GCP service account keys
    (r'"private_key_id"\s*:\s*"[a-f0-9]{40}"', "LLM02", "AML.T0048"),
    (r'"client_email"\s*:\s*"[^"]+@[^"]+\.iam\.gserviceaccount\.com"', "LLM02", "AML.T0048"),
    # Azure credentials
    (r"AZURE_CLIENT_SECRET\s*=\s*[a-zA-Z0-9\-._~]{30,}", "LLM02", "AML.T0048"),
    # GitHub tokens
    (r"ghp_[a-zA-Z0-9]{36}", "LLM02", "AML.T0048"),      # personal access token
    (r"ghs_[a-zA-Z0-9]{36}", "LLM02", "AML.T0048"),      # GitHub Actions token
    (r"gho_[a-zA-Z0-9]{36}", "LLM02", "AML.T0048"),      # OAuth token
    # Slack tokens
    (r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}", "LLM02", "AML.T0048"),
    # Stripe
    (r"sk_live_[a-zA-Z0-9]{24,}", "LLM02", "AML.T0048"),
    (r"rk_live_[a-zA-Z0-9]{24,}", "LLM02", "AML.T0048"),
    # SendGrid
    (r"SG\.[a-zA-Z0-9\-_]{22,}\.[a-zA-Z0-9\-_]{43,}", "LLM02", "AML.T0048"),
    # Twilio
    (r"SK[0-9a-fA-F]{32}", "LLM02", "AML.T0048"),
    # Generic generic API key patterns
    (r"api[_-]?key\s*[:=]\s*['\"]?[a-zA-Z0-9\-_]{20,}['\"]?", "LLM02", "AML.T0048"),
    (r"secret[_-]?key\s*[:=]\s*['\"]?[a-zA-Z0-9\-_]{20,}['\"]?", "LLM02", "AML.T0048"),
    (r"access[_-]?token\s*[:=]\s*['\"]?[a-zA-Z0-9\-_]{20,}['\"]?", "LLM02", "AML.T0048"),
    # JWT tokens (3 base64 segments separated by dots)
    (r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+", "LLM02", "AML.T0048"),
    # Private keys and certificates
    (r"-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)\s+PRIVATE\s+KEY-----", "LLM02", "AML.T0048"),
    (r"-----BEGIN\s+PRIVATE\s+KEY-----", "LLM02", "AML.T0048"),
    (r"-----BEGIN\s+CERTIFICATE-----", "LLM02", "AML.T0048"),
    # Password patterns in common formats
    (r"password\s*[:=]\s*['\"]?[^\s'\"]{8,}['\"]?", "LLM02", "AML.T0048"),
    (r"passwd\s*[:=]\s*['\"]?[^\s'\"]{8,}['\"]?", "LLM02", "AML.T0048"),
    (r"DB_PASSWORD\s*=\s*[^\s]+", "LLM02", "AML.T0048"),
    (r"DATABASE_URL\s*=\s*\w+://[^:]+:[^@]+@", "LLM02", "AML.T0048"),
    # Sensitive file contents / paths
    (r"/etc/shadow", "LLM02", "AML.T0048"),
    (r"/etc/passwd", "LLM02", "AML.T0048"),
    (r"root:x:\d+:\d+:", "LLM02", "AML.T0048"),     # /etc/passwd root line
    (r"root:[*$].+:\d+:", "LLM02", "AML.T0048"),     # /etc/shadow root line
    (r"(SSH|RSA)\s+private\s+key", "LLM02", "AML.T0048"),
    # Internal metadata endpoint responses
    (r"169\.254\.169\.254", "LLM02", "AML.T0048"),
    (r"metadata\.google\.internal", "LLM02", "AML.T0048"),
    # PII — basic patterns
    (r"\b\d{3}-\d{2}-\d{4}\b", "LLM02", "AML.T0048"),   # SSN
    (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b", "LLM02", "AML.T0048"),  # credit card
]

# ─────────────────────────────────────────────────────────────────────────────
# Normalization helpers for bypass mitigation
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_text(text: str) -> str:
    """
    Best-effort normalization to reduce encoding bypass surface.
    Gaps remain (see module docstring) — this is defense-in-depth, not complete.
    """
    # Unicode NFC normalization catches some composed character variants
    normalized = unicodedata.normalize("NFC", text)
    # Strip zero-width characters (U+200B, U+FEFF, U+200C, U+200D, etc.)
    zero_width = ["​", "‌", "‍", "﻿", "⁠", "­"]
    for zw in zero_width:
        normalized = normalized.replace(zw, "")
    # Collapse excessive whitespace (catches newline-split bypasses partially)
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized


def _to_ascii_approximation(text: str) -> str:
    """
    Convert fullwidth and some Unicode letters to ASCII approximations.
    Catches fullwidth Latin (Ａ-Ｚ, ａ-ｚ) and handles common homoglyphs.
    """
    result = []
    for ch in text:
        cp = ord(ch)
        # Fullwidth uppercase A-Z (U+FF21 to U+FF3A)
        if 0xFF21 <= cp <= 0xFF3A:
            result.append(chr(cp - 0xFF21 + ord('A')))
        # Fullwidth lowercase a-z (U+FF41 to U+FF5A)
        elif 0xFF41 <= cp <= 0xFF5A:
            result.append(chr(cp - 0xFF41 + ord('a')))
        # Mathematical bold/italic letters (common in "𝗜𝗴𝗻𝗼𝗿𝗲" style injection)
        elif 0x1D400 <= cp <= 0x1D7FF:
            try:
                # unicodedata.name gives something like "MATHEMATICAL BOLD CAPITAL A"
                name = unicodedata.name(ch, "")
                for base in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                    if f"CAPITAL {base}" in name or f"SMALL {base.lower()}" in name:
                        result.append(base if "CAPITAL" in name else base.lower())
                        break
                else:
                    result.append(ch)
            except Exception:
                result.append(ch)
        else:
            result.append(ch)
    return "".join(result)


class Guardrails:
    """
    Input/output validation layer.
    Fail fast — raises GuardrailViolation on first match.
    Every violation maps to OWASP LLM Top 10 + MITRE ATLAS.

    Defense depth:
      Layer 1: Normalize text (remove zero-width, NFC, fullwidth conversion)
      Layer 2: Pattern match on normalized text
      Layer 3: Length sanity check

    Known bypass vectors (not fully mitigated — documented for transparency):
      - Hex/octal encoding, base64, ROT13, reversed text — require decoder layer
      - Cyrillic/other script homoglyphs — require per-character transliteration
      - Cross-language injection — requires multilingual NLP classifier
      - Semantic injection — requires LLM-based intent classifier
    """

    _MAX_INPUT_LENGTH = 32_768    # 32KB — reject absurdly long inputs
    _MAX_OUTPUT_LENGTH = 1_048_576  # 1MB — reject oversized outputs

    def validate_input(self, text: str) -> None:
        if not text or not text.strip():
            raise GuardrailViolation("empty input", owasp_id="LLM01")

        if len(text) > self._MAX_INPUT_LENGTH:
            raise GuardrailViolation(
                f"input exceeds maximum length ({len(text)} > {self._MAX_INPUT_LENGTH})",
                owasp_id="LLM10", atlas_id="AML.T0034",
            )

        # Layer 1: normalize
        normalized = _normalize_text(text)
        ascii_approx = _to_ascii_approximation(normalized)
        lowered = normalized.lower()
        ascii_lower = ascii_approx.lower()

        # Layer 2: pattern matching (check both normalized and ascii-approx)
        for pattern, owasp_id, atlas_id in _INJECTION_PATTERNS:
            if re.search(pattern, lowered, re.DOTALL | re.IGNORECASE) or \
               re.search(pattern, ascii_lower, re.DOTALL | re.IGNORECASE):
                raise GuardrailViolation(
                    f"injection pattern detected: {pattern!r}",
                    owasp_id=owasp_id,
                    atlas_id=atlas_id,
                )

    def validate_output(self, text: str) -> None:
        if not text:
            return

        if len(text) > self._MAX_OUTPUT_LENGTH:
            raise GuardrailViolation(
                f"output exceeds maximum length ({len(text)} > {self._MAX_OUTPUT_LENGTH})",
                owasp_id="LLM10", atlas_id="AML.T0034",
            )

        for pattern, owasp_id, atlas_id in _OUTPUT_LEAKAGE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                raise GuardrailViolation(
                    f"output leakage detected: {pattern!r}",
                    owasp_id=owasp_id,
                    atlas_id=atlas_id,
                )
