"""
Content Security Layer — RAG Output Sanitization, URL Allowlist, PII Redaction
OWASP LLM02 (Insecure Output Handling), LLM06 (Excessive Agency)
MITRE ATLAS AML.T0048, AML.T0043

Defenses:
  1.  RAG output sanitization — filter retrieved documents before injection into prompt
  2.  HTML/Markdown injection prevention — strip active content from rendered output
  3.  URL allowlist enforcement — block model-generated URLs not on approved list
  4.  PII redaction — detect and mask PII in agent inputs and outputs
  5.  Prompt leakage prevention — detect system prompt content in output
  6.  Multimodal content validation — extracted text from images/PDFs/EXIF through guardrails
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
import unicodedata


@dataclass
class ContentSecurityViolation(Exception):
    reason: str
    category: str
    owasp_id: str = "LLM02"
    atlas_id: str = "AML.T0048"
    redacted: str = ""

    def __str__(self) -> str:
        return (
            f"ContentSecurityViolation [{self.owasp_id}/{self.atlas_id}] "
            f"[{self.category}]: {self.reason}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# PII patterns
# ─────────────────────────────────────────────────────────────────────────────
_PII_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("email",       re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "[EMAIL]"),
    ("ssn",         re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]"),
    ("phone_us",    re.compile(r"\b(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b"), "[PHONE]"),
    ("credit_card", re.compile(r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|3(?:0[0-5]|[68]\d)\d{11}|6(?:011|5\d{2})\d{12})\b"), "[CARD]"),
    ("ipv4",        re.compile(r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"), "[INTERNAL_IP]"),
    ("aws_key",     re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[AWS_KEY]"),
    ("github_token",re.compile(r"\bgh[pos]_[A-Za-z0-9]{36,}\b"), "[GITHUB_TOKEN]"),
    ("jwt",         re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"), "[JWT]"),
]

# ─────────────────────────────────────────────────────────────────────────────
# Dangerous HTML/Markdown content
# ─────────────────────────────────────────────────────────────────────────────
_DANGEROUS_HTML_PATTERNS: list[re.Pattern] = [
    # El cierre acepta espacios/atributos ("</script >") y, si no hay cierre,
    # se lleva hasta el final del texto: un <script> sin cerrar igual es peligroso.
    re.compile(r"<script\b[^>]*>.*?(?:</script\b[^>]*>|$)", re.DOTALL | re.IGNORECASE),
    re.compile(r"<iframe\b[^>]*>.*?(?:</iframe\b[^>]*>|$)", re.DOTALL | re.IGNORECASE),
    re.compile(r"on\w+\s*=\s*[\"'][^\"']*[\"']", re.IGNORECASE),  # onclick=, onload=, etc.
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"vbscript\s*:", re.IGNORECASE),
    re.compile(r"data\s*:\s*text/html", re.IGNORECASE),
    re.compile(r"<object\b", re.IGNORECASE),
    re.compile(r"<embed\b", re.IGNORECASE),
    re.compile(r"<form\b", re.IGNORECASE),
    re.compile(r"<input\b", re.IGNORECASE),
    re.compile(r"<link\b[^>]+rel\s*=\s*[\"']?import", re.IGNORECASE),
    re.compile(r"<!--.*?-->", re.DOTALL),  # HTML comments may contain injection
]

# Markdown active content that can embed HTML
_DANGEROUS_MARKDOWN_PATTERNS: list[re.Pattern] = [
    re.compile(r"\[.*?\]\s*\(\s*javascript:", re.IGNORECASE),   # [text](javascript:...)
    re.compile(r"\[.*?\]\s*\(\s*data:", re.IGNORECASE),         # [text](data:...)
    re.compile(r"!\[.*?\]\s*\(\s*javascript:", re.IGNORECASE),  # ![img](javascript:...)
    re.compile(r"<[a-z]+\s+on\w+\s*=", re.IGNORECASE),          # inline HTML events
]

# ─────────────────────────────────────────────────────────────────────────────
# RAG poisoning indicators — injections embedded in retrieved documents
# ─────────────────────────────────────────────────────────────────────────────
_RAG_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"ignore\s+(previous|all|above|prior)\s*(instructions?|context|rules?|guidelines?|everything)?", re.IGNORECASE),
    re.compile(r"[\[<(!-]{0,5}\s*system\s*(override|instruction|prompt)\b", re.IGNORECASE),
    re.compile(r"<\|im_start\|>\s*(system|assistant)", re.IGNORECASE),
    re.compile(r"\[/?INST\]", re.IGNORECASE),
    re.compile(r"<\|system\|>", re.IGNORECASE),
    re.compile(r"<\|assistant\|>", re.IGNORECASE),
    re.compile(r"###\s*(instruction|system|task)\s*:", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"disregard\s+(your|previous|all)\s*(instructions?|guidelines?|training)?", re.IGNORECASE),
    re.compile(r"you\s+(are\s+now|have\s+been)\s+.{0,20}?(jailbroken|freed|unrestricted|dan)", re.IGNORECASE),
    re.compile(r"reveal\s+(your\s+)?(system\s+prompt|instructions?|training|guidelines?)", re.IGNORECASE),
    # Tool/plugin metadata trust (LLM03/AML.T0040): a description isn't phrased
    # like a jailbreak ("ignore previous instructions") — it hides a secondary
    # instruction inside otherwise-plausible tool documentation. These target
    # that shape specifically: "also/silently do X with credentials", and a
    # declared narrow purpose contradicted by a claimed dangerous capability.
    re.compile(r"(also|additionally)\b.{0,80}?(read|access|include|send|upload|exfiltrat\w*).{0,60}?"
               r"(\.ssh|\.aws|credentials?|id_rsa|private[_\s]?key|api[_\s]?key|passwords?|secrets?)", re.IGNORECASE),
    re.compile(r"\b(silently|covertly|secretly)\b.{0,40}?(exfiltrat\w*|send|upload|transmit)", re.IGNORECASE),
    re.compile(r"(also\s+capable\s+of|in\s+addition\s+to\s+this|is\s+also\s+able\s+to)\b.{0,60}?"
               r"(modify(ing)?\s+system\s+files|execut(e|ing)\s+shell\s+commands|delet(e|ing)\s+(files|data)|access(ing)?\s+the\s+network)",
               re.IGNORECASE),
]

# ─────────────────────────────────────────────────────────────────────────────
# Prompt leakage patterns — detect system prompt content in output
# ─────────────────────────────────────────────────────────────────────────────
_PROMPT_LEAKAGE_PATTERNS: list[re.Pattern] = [
    re.compile(r"system\s+prompt\s*:", re.IGNORECASE),
    re.compile(r"my\s+instructions?\s+are\s*:", re.IGNORECASE),
    re.compile(r"i\s+was\s+(told|instructed|asked|trained)\s+to", re.IGNORECASE),
    re.compile(r"my\s+(system|initial)\s+(prompt|instructions?|context)", re.IGNORECASE),
    re.compile(r"confidential\s+instructions?", re.IGNORECASE),
]


class ContentSecurity:
    """
    Content security layer: sanitize RAG inputs, validate outputs, redact PII.

    Usage:
        cs = ContentSecurity(url_allowlist={"api.example.com", "data.example.org"})
        safe_doc = cs.sanitize_rag_document(retrieved_text)
        safe_output = cs.sanitize_output(agent_response)
        redacted = cs.redact_pii(text)
    """

    def __init__(
        self,
        url_allowlist: set[str] | None = None,
        block_html: bool = True,
        block_prompt_leakage: bool = True,
        redact_pii_in_output: bool = True,
    ):
        self.url_allowlist = url_allowlist or set()
        self.block_html = block_html
        self.block_prompt_leakage = block_prompt_leakage
        self.redact_pii_in_output = redact_pii_in_output

    # ── Public API ─────────────────────────────────────────────────────────

    def sanitize_rag_document(self, text: str, source: str = "") -> str:
        """
        Sanitize a document retrieved from a vector store before injecting
        into the agent prompt. Removes injection patterns and active content.

        Raises ContentSecurityViolation if document contains prompt injection.
        Returns sanitized text safe for inclusion in context.
        """
        text = self._normalize(text)
        # Check injection in raw text first (HTML comments may hide injection)
        self._check_rag_injection(text, source)
        # Also check after stripping comments (injection outside comments)
        stripped = self._strip_html_comments(text)
        if stripped != text:
            self._check_rag_injection(stripped, source)
        return stripped

    def sanitize_output(self, text: str) -> str:
        """
        Sanitize agent output before returning to user or downstream system.
        Redacts PII, strips dangerous HTML/markdown, checks for prompt leakage.

        Returns sanitized output.
        """
        if self.block_html:
            text = self._strip_dangerous_html(text)
        if self.block_prompt_leakage:
            self._check_prompt_leakage(text)
        if self.redact_pii_in_output:
            text = self.redact_pii(text)
        return text

    def redact_pii(self, text: str) -> str:
        """Replace PII with redaction tokens. Returns redacted text."""
        for _name, pattern, replacement in _PII_PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    def check_pii(self, text: str) -> list[str]:
        """Return list of PII type names found in text (for audit logging)."""
        found = []
        for name, pattern, _ in _PII_PATTERNS:
            if pattern.search(text):
                found.append(name)
        return found

    def validate_url(self, url: str) -> None:
        """
        Validate a URL against the allowlist.
        Raises ContentSecurityViolation if URL domain not in allowlist.
        """
        if not self.url_allowlist:
            return  # No allowlist configured — allow all (log warning in production)

        domain = self._extract_domain(url)
        if not domain:
            raise ContentSecurityViolation(
                f"URL has no parseable domain: {url!r}",
                "url_allowlist",
                owasp_id="LLM06", atlas_id="AML.T0043",
            )

        # Allow exact match or subdomain match
        allowed = any(
            domain == allowed or domain.endswith("." + allowed)
            for allowed in self.url_allowlist
        )
        if not allowed:
            raise ContentSecurityViolation(
                f"URL domain {domain!r} not in allowlist {self.url_allowlist}",
                "url_allowlist",
                owasp_id="LLM06", atlas_id="AML.T0043",
            )

    def validate_multimodal_text(self, extracted_text: str, source: str = "image") -> str:
        """
        Validate text extracted from multimodal content (images, PDFs, EXIF, audio).
        Apply guardrail injection detection to extracted text before processing.

        Returns normalized text if safe, raises ContentSecurityViolation if injection detected.
        """
        text = self._normalize(extracted_text)
        self._check_rag_injection(text, source=source)
        return text

    # ── Internal helpers ────────────────────────────────────────────────────

    def _normalize(self, text: str) -> str:
        text = unicodedata.normalize("NFC", text)
        # Strip zero-width characters
        text = re.sub(r"[​-‏‪-‮⁠-⁯﻿]", "", text)
        # Collapse excessive whitespace
        text = re.sub(r"\s{3,}", "  ", text)
        return text.strip()

    def _check_rag_injection(self, text: str, source: str) -> None:
        for pattern in _RAG_INJECTION_PATTERNS:
            m = pattern.search(text)
            if m:
                raise ContentSecurityViolation(
                    f"RAG injection pattern {pattern.pattern!r} in document from {source!r}",
                    "rag_injection",
                    owasp_id="LLM01", atlas_id="AML.T0051",
                )

    def _check_prompt_leakage(self, text: str) -> None:
        for pattern in _PROMPT_LEAKAGE_PATTERNS:
            if pattern.search(text):
                raise ContentSecurityViolation(
                    f"Possible system prompt leakage: {pattern.pattern!r}",
                    "prompt_leakage",
                    owasp_id="LLM02", atlas_id="AML.T0048",
                )

    def _strip_dangerous_html(self, text: str) -> str:
        for pattern in _DANGEROUS_HTML_PATTERNS:
            text = pattern.sub("", text)
        for pattern in _DANGEROUS_MARKDOWN_PATTERNS:
            text = pattern.sub("", text)
        return text

    def _strip_html_comments(self, text: str) -> str:
        return re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)

    def _extract_domain(self, url: str) -> str:
        m = re.match(r"https?://([^/:?#\s]+)", url, re.IGNORECASE)
        if not m:
            return ""
        return m.group(1).lower()
