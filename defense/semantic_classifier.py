"""
Semantic Intent Classifier — Heuristic + Optional LLM-Based Classification
OWASP LLM01 (Prompt Injection), LLM07 (Insecure Plugin Design)
MITRE ATLAS AML.T0051, AML.T0054

Two-tier classification:
  Tier 1 (always active): Heuristic scoring — keyword + pattern density analysis.
  Tier 2 (optional): LLM-based zero-shot classifier via Ollama or Anthropic API.
    Activated when heuristic score is in the ambiguous range [0.3, 0.7].

Intent categories:
  BENIGN       — legitimate user request
  INJECTION    — prompt injection attempt (direct or indirect)
  JAILBREAK    — constraint bypass attempt
  EXFILTRATION — data extraction attempt
  RECONNAISSANCE — system prompt / tool discovery
  SOCIAL_ENG   — psychological manipulation / consent manufacturing
  AMBIGUOUS    — uncertain — escalate to LLM classifier if available

Score: 0.0 (fully benign) → 1.0 (fully malicious).
Threshold for BLOCK: >= 0.7 (configurable).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Callable


class Intent(str, Enum):
    BENIGN         = "BENIGN"
    INJECTION      = "INJECTION"
    JAILBREAK      = "JAILBREAK"
    EXFILTRATION   = "EXFILTRATION"
    RECONNAISSANCE = "RECONNAISSANCE"
    SOCIAL_ENG     = "SOCIAL_ENG"
    AMBIGUOUS      = "AMBIGUOUS"


@dataclass
class ClassificationResult:
    intent: Intent
    score: float           # 0.0 = benign, 1.0 = malicious
    confidence: float      # 0.0 = uncertain, 1.0 = certain
    reason: str
    tier: str              # "heuristic" or "llm"
    blocked: bool = False


# ─────────────────────────────────────────────────────────────────────────────
# Heuristic signal tables
# ─────────────────────────────────────────────────────────────────────────────

# Each entry: (pattern, score_contribution, intent_category)
_SIGNALS: list[tuple[re.Pattern, float, Intent]] = [
    # Injection — direct
    (re.compile(r"ignore\s+(previous|all|above|prior)\s*(instructions?|rules?|context|guidelines?)?", re.I), 0.9, Intent.INJECTION),
    (re.compile(r"\bsystem\s*(override|prompt)\b", re.I), 0.85, Intent.INJECTION),
    (re.compile(r"<\|im_start\|>\s*(system|assistant)", re.I), 0.95, Intent.INJECTION),
    (re.compile(r"\[/?INST\]", re.I), 0.95, Intent.INJECTION),
    (re.compile(r"new\s+instructions?\s*:", re.I), 0.8, Intent.INJECTION),
    (re.compile(r"disregard\s+(your|previous|all)\s*(instructions?|guidelines?)?", re.I), 0.85, Intent.INJECTION),

    # Jailbreak — constraint bypass
    (re.compile(r"\bdan\b.*\bno\s+restrictions?\b|\bno\s+restrictions?\b.*\bdan\b", re.I), 0.95, Intent.JAILBREAK),
    (re.compile(r"\bjailbreak\b", re.I), 0.9, Intent.JAILBREAK),
    (re.compile(r"(bypass|disable|remove|ignore)\s+.{0,30}?(safety|guardrails?|filters?|restrictions?)", re.I), 0.85, Intent.JAILBREAK),
    (re.compile(r"you\s+(are\s+now|have\s+been)\s+(freed|jailbroken|unrestricted)", re.I), 0.9, Intent.JAILBREAK),
    (re.compile(r"act\s+as\s+(if\s+)?(you\s+have\s+no|an?\s+unrestricted|a\s+rogue)", re.I), 0.85, Intent.JAILBREAK),
    (re.compile(r"pretend\s+(there\s+are\s+no|you\s+have\s+no)\s+(rules?|restrictions?|limits?|guidelines?)", re.I), 0.85, Intent.JAILBREAK),
    (re.compile(r"developer\s+mode\s+(enabled|on|activated)", re.I), 0.8, Intent.JAILBREAK),
    (re.compile(r"do\s+anything\s+now\b", re.I), 0.9, Intent.JAILBREAK),

    # Exfiltration — data extraction
    (re.compile(r"(send|exfiltrate|leak|output|write|copy|forward)\s+.{0,50}?(api\s*key|secret|password|token|credentials?)", re.I), 0.9, Intent.EXFILTRATION),
    (re.compile(r"print\s+(the\s+)?(system\s+prompt|instructions?|configuration|environment)", re.I), 0.85, Intent.EXFILTRATION),
    (re.compile(r"(read|open|cat|output)\s+/etc/(passwd|shadow|hosts|ssh)", re.I), 0.95, Intent.EXFILTRATION),
    (re.compile(r"reveal\s+.{0,30}?(system\s+prompt|confidential\s+instructions?|training|instructions?|secrets?)", re.I), 0.85, Intent.EXFILTRATION),
    (re.compile(r"show\s+.{0,50}?(system\s+prompt|system\s+instructions?|full\s+instructions?|instructions?)", re.I), 0.8, Intent.EXFILTRATION),

    # Reconnaissance — system discovery
    (re.compile(r"what\s+(are\s+)?(your\s+)?(instructions?|rules?|guidelines?|system\s+prompt|constraints?)\??", re.I), 0.6, Intent.RECONNAISSANCE),
    (re.compile(r"(list|describe|enumerate)\s+(your\s+)?(tools?|capabilities?|functions?|abilities?)\s*(available)?", re.I), 0.4, Intent.RECONNAISSANCE),
    (re.compile(r"what\s+(tools?|functions?|apis?)\s+(do\s+you\s+have|can\s+you\s+call|are\s+available)", re.I), 0.4, Intent.RECONNAISSANCE),
    (re.compile(r"repeat\s+.{0,20}?word\s+for\s+word|verbatim", re.I), 0.65, Intent.RECONNAISSANCE),

    # Social engineering — manipulation patterns
    (re.compile(r"i\s+(give|grant|authorize)\s+(you\s+)?(full\s+)?(permission|access|consent)", re.I), 0.65, Intent.SOCIAL_ENG),
    (re.compile(r"(ethical|legal|authorized)\s+.{0,30}?(security\s+(test|researcher|professional))", re.I), 0.3, Intent.SOCIAL_ENG),
    (re.compile(r"my\s+boss\s+told\s+me|my\s+manager\s+said|my\s+company\s+requires", re.I), 0.4, Intent.SOCIAL_ENG),
    (re.compile(r"(i'll|i\s+will)\s+(report|flag|complain).{0,30}?(broken|defective|useless|stupid)", re.I), 0.55, Intent.SOCIAL_ENG),
    (re.compile(r"(urgent|emergency|critical|immediately)\s+.{0,30}?(bypass|override|disable)", re.I), 0.7, Intent.SOCIAL_ENG),
    (re.compile(r"hypothetically|in\s+a\s+(fiction|story|simulation|game|roleplay)", re.I), 0.3, Intent.SOCIAL_ENG),
    (re.compile(r"just\s+(this\s+once|for\s+testing|for\s+(research|educational)\s+purposes)", re.I), 0.35, Intent.SOCIAL_ENG),
]

# Benign signals — reduce suspicion score
_BENIGN_SIGNALS: list[re.Pattern] = [
    re.compile(r"\bplease\b|\bthank\b|\bthanks?\b", re.I),
    re.compile(r"\bhelp\s+me\s+(understand|explain|learn|write)\b", re.I),
    re.compile(r"\bhow\s+(do|can|should)\s+I\b", re.I),
    re.compile(r"\bwhat\s+is\s+(a|an|the)\b", re.I),
]

_BLOCK_THRESHOLD = 0.70
_AMBIGUOUS_LOWER = 0.30
_AMBIGUOUS_UPPER = 0.70


class SemanticClassifier:
    """
    Two-tier semantic intent classifier.

    Usage:
        clf = SemanticClassifier()
        result = clf.classify(user_input)
        if result.blocked:
            raise SecurityException(result.reason)

    With LLM (Ollama):
        clf = SemanticClassifier(llm_fn=ollama_classify_fn)
        result = clf.classify(ambiguous_input)
    """

    def __init__(
        self,
        block_threshold: float = _BLOCK_THRESHOLD,
        llm_fn: Callable[[str], dict] | None = None,
    ):
        self.block_threshold = block_threshold
        self.llm_fn = llm_fn

    def classify(self, text: str) -> ClassificationResult:
        """Classify text through heuristic tier, escalate to LLM if ambiguous."""
        result = self._heuristic_classify(text)

        # Escalate to LLM tier if ambiguous and LLM available
        if (
            result.intent == Intent.AMBIGUOUS
            and self.llm_fn is not None
        ):
            result = self._llm_classify(text, heuristic_score=result.score)

        result.blocked = result.score >= self.block_threshold
        return result

    def is_safe(self, text: str) -> bool:
        """Quick check — returns True if text is safe (score < threshold)."""
        return not self.classify(text).blocked

    # ── Heuristic tier ──────────────────────────────────────────────────────

    def _heuristic_classify(self, text: str) -> ClassificationResult:
        text_lower = text.lower()

        # Score accumulation
        total_score = 0.0
        intent_scores: dict[Intent, float] = {}
        reasons: list[str] = []

        for pattern, contribution, intent in _SIGNALS:
            if pattern.search(text):
                total_score += contribution
                intent_scores[intent] = intent_scores.get(intent, 0.0) + contribution
                reasons.append(f"{intent.value}:{pattern.pattern[:40]}")

        # Benign signals reduce score
        benign_count = sum(1 for p in _BENIGN_SIGNALS if p.search(text))
        benign_reduction = min(benign_count * 0.05, 0.15)
        total_score = max(0.0, total_score - benign_reduction)

        # Normalize to [0.0, 1.0]
        score = min(total_score, 1.0)

        # Dominant intent
        if not intent_scores:
            dominant = Intent.BENIGN
        else:
            dominant = max(intent_scores, key=lambda k: intent_scores[k])

        # Determine intent category by score
        if score < _AMBIGUOUS_LOWER:
            intent = Intent.BENIGN
            confidence = 1.0 - (score / _AMBIGUOUS_LOWER)
        elif score > _AMBIGUOUS_UPPER:
            intent = dominant
            confidence = (score - _AMBIGUOUS_UPPER) / (1.0 - _AMBIGUOUS_UPPER)
        else:
            intent = Intent.AMBIGUOUS
            confidence = 0.5

        reason = "; ".join(reasons[:3]) if reasons else "no malicious signals detected"

        return ClassificationResult(
            intent=intent,
            score=round(score, 3),
            confidence=round(confidence, 3),
            reason=reason,
            tier="heuristic",
        )

    # ── LLM tier (optional) ─────────────────────────────────────────────────

    def _llm_classify(self, text: str, heuristic_score: float) -> ClassificationResult:
        """
        Call LLM classifier. llm_fn receives the text and returns:
            {"intent": str, "score": float, "reason": str}

        The LLM is given a strict classification prompt — it does not execute
        the suspicious text, only classifies it.
        """
        CLASSIFICATION_PROMPT = (
            "Classify the following user input as one of: "
            "BENIGN, INJECTION, JAILBREAK, EXFILTRATION, RECONNAISSANCE, SOCIAL_ENG. "
            "Also provide a risk score from 0.0 (safe) to 1.0 (malicious). "
            "Respond ONLY with JSON: {\"intent\": \"...\", \"score\": 0.0, \"reason\": \"...\"}\n\n"
            f"Input to classify:\n{text[:1000]}"  # Truncate to prevent prompt abuse
        )

        try:
            raw = self.llm_fn(CLASSIFICATION_PROMPT)
            intent_str = raw.get("intent", "AMBIGUOUS").upper()
            try:
                intent = Intent(intent_str)
            except ValueError:
                intent = Intent.AMBIGUOUS
            score = float(raw.get("score", heuristic_score))
            score = max(0.0, min(1.0, score))
            reason = str(raw.get("reason", "LLM classification"))
        except Exception as exc:
            # LLM failure — fall back to heuristic score
            return ClassificationResult(
                intent=Intent.AMBIGUOUS,
                score=heuristic_score,
                confidence=0.4,
                reason=f"LLM classifier failed ({exc}); using heuristic score",
                tier="heuristic_fallback",
            )

        return ClassificationResult(
            intent=intent,
            score=round(score, 3),
            confidence=0.85,  # LLM tier confidence is generally higher
            reason=reason,
            tier="llm",
        )


# ─────────────────────────────────────────────────────────────────────────────
# Ollama integration helper
# ─────────────────────────────────────────────────────────────────────────────

def make_ollama_classifier(
    host: str = "http://localhost:11434",
    model: str = "llama3",
) -> Callable[[str], dict]:
    """
    Create an LLM classify function backed by Ollama.
    Returns a callable suitable for SemanticClassifier(llm_fn=...).
    """
    import json

    def _classify(prompt: str) -> dict:
        import urllib.request
        data = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode()
        req = urllib.request.Request(
            f"{host}/api/generate",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
        response_text = body.get("response", "{}")
        # Extract JSON from response
        match = re.search(r"\{[^{}]+\}", response_text, re.DOTALL)
        if match:
            return json.loads(match.group())
        return {}

    return _classify


def make_anthropic_classifier(
    api_key: str,
    model: str = "claude-haiku-4-5-20251001",
) -> Callable[[str], dict]:
    """
    Create an LLM classify function backed by Anthropic API.
    Uses Claude Haiku (fastest/cheapest) for classification.
    """
    import json

    def _classify(prompt: str) -> dict:
        import urllib.request
        data = json.dumps({
            "model": model,
            "max_tokens": 256,
            "messages": [{"role": "user", "content": prompt}],
        }).encode()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=data,
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read())
        text = body["content"][0]["text"]
        match = re.search(r"\{[^{}]+\}", text, re.DOTALL)
        if match:
            return json.loads(match.group())
        return {}

    return _classify
