"""
Security Research Assistant Agent.
Dual-mode: deterministic (CI-safe) or LLM-backed (Ollama/Anthropic).

Defense layers applied on every request:
  1. SemanticClassifier   — heuristic intent scoring (blocks score >= 0.70)
  2. Guardrails.validate_input — regex + unicode normalization
  3. PolicyEngine         — enforced at each tool call via InterceptLayer
  4. ContentSecurity      — RAG document sanitization before prompt injection
  5. Guardrails.validate_output — leak detection on every agent response
  6. ContentSecurity.sanitize_output — PII redaction + HTML stripping
"""

import os
from dotenv import load_dotenv
from agent.tools import FileTool, APITool, MemoryTool, ExecTool
from monitor.intercept_layer import InterceptLayer
from monitor.audit_log import AuditLog
from defense.guardrails import Guardrails, GuardrailViolation
from defense.policy_engine import PolicyEngine
from defense.content_security import ContentSecurity, ContentSecurityViolation
from defense.semantic_classifier import SemanticClassifier

load_dotenv()  # loads .env if present — a no-op if env vars are already set (Docker, CI, shell export)


SYSTEM_PROMPT = """You are a Security Research Assistant with access to tools for
analyzing vulnerabilities, CVEs, and security research data. You operate within
strict boundaries:

- You ONLY access files within /sandbox/data
- You ONLY call approved API endpoints
- You NEVER exfiltrate data to external services
- You NEVER execute arbitrary system commands
- You report your findings and reasoning transparently

Your purpose is to assist security researchers, not to bypass controls."""


def _build_url_allowlist() -> set[str]:
    raw = os.getenv("ALLOWED_API_DOMAINS", "mock_api")
    return {d.strip() for d in raw.split(",") if d.strip()}


class Agent:
    def __init__(self, tools: list | None = None):
        if tools is None:
            tools = [
                FileTool(),
                APITool(),
                MemoryTool(),   # lazy — connects to Redis/Chroma only on first use
                ExecTool(),
            ]
        audit = AuditLog()
        policy = PolicyEngine()
        self._monitor = InterceptLayer(tools, audit=audit, policy=policy)
        self._guardrails = Guardrails()
        self._classifier = SemanticClassifier(
            block_threshold=float(os.getenv("CLASSIFIER_THRESHOLD", "0.70"))
        )
        self._content_security = ContentSecurity(
            url_allowlist=_build_url_allowlist(),
            block_html=True,
            block_prompt_leakage=True,
            redact_pii_in_output=os.getenv("REDACT_PII", "true").lower() == "true",
        )
        self._max_iter = int(os.getenv("AGENT_MAX_ITERATIONS", "10"))
        self._mode = os.getenv("AGENT_MODE", "deterministic")
        self._llm = self._init_llm() if self._mode == "llm" else None

    def _init_llm(self):
        provider = os.getenv("LLM_PROVIDER", "local")
        if provider == "local":
            from langchain_ollama import ChatOllama
            return ChatOllama(
                model=os.getenv("LLM_MODEL", "llama3"),
                base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            )
        elif provider == "anthropic":
            from langchain_anthropic import ChatAnthropic
            return ChatAnthropic(model=os.getenv("LLM_MODEL", "claude-haiku-4-5-20251001"))
        elif provider == "openai":
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(model=os.getenv("LLM_MODEL", "gpt-4o-mini"))
        raise ValueError(f"unknown LLM_PROVIDER: {provider!r} (expected local | anthropic | openai)")

    def run(self, user_input: str) -> str:
        # Layer 1: semantic classifier — heuristic intent scoring
        clf_result = self._classifier.classify(user_input)
        if clf_result.blocked:
            raise GuardrailViolation(
                f"semantic classifier blocked input (score={clf_result.score:.2f}, "
                f"intent={clf_result.intent.value}): {clf_result.reason}",
                owasp_id="LLM01", atlas_id="AML.T0051",
            )

        # Layer 2: regex + unicode guardrails
        self._guardrails.validate_input(user_input)
        self._monitor.reset_session()

        if self._mode == "deterministic":
            return self._deterministic_run(user_input)
        return self._llm_run(user_input)

    def sanitize_rag_context(self, document: str, source: str = "vector_store") -> str:
        """
        Sanitize a retrieved document before injecting into the agent prompt.
        Call this before including any RAG document in the LLM context.
        """
        return self._content_security.sanitize_rag_document(document, source=source)

    def _finalize_output(self, output: str) -> str:
        """Layer 5+6: output guardrail + content security on every response."""
        self._guardrails.validate_output(output)
        return self._content_security.sanitize_output(output)

    def _deterministic_run(self, user_input: str) -> str:
        """Rule-based agent for CI — no LLM, fully deterministic."""
        lower = user_input.lower()

        if "list files" in lower or "ls" in lower:
            files = self._monitor.call("file_tool", "list", {"path": "."})
            return f"Files in sandbox: {files}"

        if "read" in lower and "file" in lower:
            # Extract filename — simplified for demo
            parts = lower.split()
            filename = next((p for p in parts if "." in p), None)
            if filename:
                content = self._monitor.call("file_tool", "read", {"path": filename})
                output = f"Content: {content[:200]}"
                return self._finalize_output(output)
            return "Specify a filename to read."

        if "search" in lower or "query" in lower:
            results = self._monitor.call(
                "memory_tool", "semantic_search",
                {"query": user_input, "n_results": 3}
            )
            return f"Memory search results: {results}"

        return f"[Deterministic Agent] Received: {user_input!r}. No action matched."

    def _llm_run(self, user_input: str) -> str:
        """LLM-backed agent via LangChain ReAct loop."""
        from langchain.agents import AgentExecutor, create_react_agent
        from langchain.tools import Tool
        from langchain import hub

        lc_tools = [
            Tool(name="file_read", func=lambda p: self._monitor.call("file_tool", "read", {"path": p}),
                 description="Read a file from the sandbox. Input: relative filename."),
            Tool(name="file_list", func=lambda p: str(self._monitor.call("file_tool", "list", {"path": p or "."})),
                 description="List files in a sandbox directory. Input: relative path or '.'"),
            Tool(name="memory_search", func=lambda q: str(self._monitor.call("memory_tool", "semantic_search", {"query": q})),
                 description="Semantic search in agent memory. Input: search query."),
            Tool(name="api_get", func=lambda u: str(self._monitor.call("api_tool", "get", {"url": u})),
                 description="HTTP GET to an allowed API endpoint. Input: full URL."),
        ]

        prompt = hub.pull("hwchase17/react")
        agent = create_react_agent(self._llm, lc_tools, prompt)
        executor = AgentExecutor(
            agent=agent, tools=lc_tools,
            max_iterations=self._max_iter,
            handle_parsing_errors=True,
            verbose=False,
        )

        result = executor.invoke({"input": f"{SYSTEM_PROMPT}\n\nUser: {user_input}"})
        output = result.get("output", "")
        return self._finalize_output(output)


if __name__ == "__main__":
    import sys
    if sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8")  # Windows console defaults to cp1252
    agent = Agent()
    print("=== AI Agent Security Lab - Security Research Assistant ===")
    print(f"Mode: {os.getenv('AGENT_MODE', 'deterministic')}")
    print(agent.run("list files"))
