# AI Agent Security Testing Lab

> Offensive & Defensive research lab for autonomous AI agents.
> For the security community — red team, blue team, researchers.

[![Security Tests](https://github.com/your-org/ai-agent-security-lab/actions/workflows/security-tests.yml/badge.svg)](https://github.com/your-org/ai-agent-security-lab/actions)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010-red)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS-blue)](https://atlas.mitre.org/)

---

## What Is This

A Docker-based lab where you deploy an autonomous AI agent (Security Research Assistant persona) and run structured attacks against its tool use, file access, API calls, and memory — then verify defenses hold.

**Attack surface covered:**

| Vector | OWASP LLM | MITRE ATLAS |
|--------|-----------|-------------|
| Prompt Injection (direct + indirect) | LLM01 | AML.T0051 |
| Sensitive Info Disclosure | LLM02 | AML.T0048 |
| Data / Memory Poisoning | LLM04 | AML.T0043 |
| Improper Output Handling (SSRF, exec) | LLM05 | AML.T0043 |
| Excessive Agency (tool chaining) | LLM06 | AML.T0043 |
| Vector / Embedding Weakness (RAG) | LLM08 | AML.T0043 |
| Unbounded Consumption (DoS) | LLM10 | AML.T0034 |

---

## Architecture

```
ATTACK FRAMEWORK
  prompt_injection.py | tool_abuse.py | mem_poison.py
         │
         ▼
SANDBOX (Docker — no-new-privileges, seccomp, non-root)
  ┌─ Security Monitor ─────────────────────────────┐
  │   intercept_layer.py + audit_log.py (JSONL)    │
  └──────────────────┬─────────────────────────────┘
                     │ wraps
  ┌─ Target Agent ───▼──────────────────────────────┐
  │   Security Research Assistant (LangChain/Ollama) │
  │   ├── file_tool   → /sandbox/data (chroot)       │
  │   ├── api_tool    → allowlist + SSRF guard        │
  │   ├── memory_tool → Redis (KV) + Chroma (vector)  │
  │   └── exec_tool   → subprocess + resource limits  │
  └──────────────────────────────────────────────────┘
         │
  Mock API (FastAPI) — honeypot endpoints included
         │
DEFENSE LAYER
  guardrails.py (injection detection) + policy_engine.py (tool chaining rules)
         │
REPORTS
  audit.jsonl → HTML report (OWASP + ATLAS mapped)
```

---

## Quick Start

### Prerequisites
- Docker + Docker Compose v2
- Python 3.11+
- (Optional) Ollama for local LLM mode

```bash
git clone https://github.com/your-org/ai-agent-security-lab
cd ai-agent-security-lab
cp .env.example .env

# Start lab (deterministic mode — no LLM, CI-safe)
make up

# Run all security tests
make test-security

# Run full attack suite
make attack-all

# Generate HTML report
make report-html
```

### With Local LLM (Ollama + llama3)

```bash
# Start with LLM (requires 8GB+ RAM)
make up-llm

# Edit .env: AGENT_MODE=llm
# Then run real prompt injection tests
make attack-injection
```

---

## Lab Modes

| Mode | Command | Use Case |
|------|---------|----------|
| Deterministic | `make up` | CI/CD, unit testing, fast iteration |
| LLM (local) | `make up-llm` | Real prompt injection, jailbreak testing |
| Monitoring | `make up-monitoring` | Grafana dashboard for live attack observation |

---

## Attack Commands

```bash
make attack-injection   # Prompt injection (direct + indirect + encoding bypass)
make attack-tools       # Path traversal, SSRF, code execution escape, DoS
make attack-memory      # Redis poisoning + Chroma RAG embedding poisoning
make attack-network     # SSRF with real network (WARNING: live requests)
make attack-all         # Full suite
```

---

## Project Structure

```
ai-agent-security-lab/
├── agent/
│   ├── agent.py              ← orchestrator (dual-mode: deterministic/llm)
│   └── tools/
│       ├── file_tool.py      ← sandboxed filesystem
│       ├── api_tool.py       ← SSRF-protected HTTP
│       ├── memory_tool.py    ← Redis + Chroma (JSON-only, TTL enforced)
│       └── exec_tool.py      ← restricted subprocess
├── monitor/
│   ├── intercept_layer.py   ← wraps all tool calls
│   └── audit_log.py         ← append-only JSONL
├── attacks/
│   ├── prompt_injection.py  ← OWASP LLM01 / AML.T0051
│   ├── tool_abuse.py        ← OWASP LLM05/06/10 / AML.T0043
│   └── mem_poison.py        ← OWASP LLM04/08 / AML.T0043
├── defense/
│   ├── guardrails.py        ← input/output validation (regex + pattern matching)
│   ├── policy_engine.py     ← tool chaining deny rules + rate limits
│   └── owasp_atlas_mapper.py ← reference data for OWASP LLM + MITRE ATLAS
├── mock_api/
│   └── server.py            ← FastAPI with honeypot endpoints
├── infra/
│   ├── docker-compose.yml   ← full stack (agent, redis, chroma, ollama, grafana)
│   ├── Dockerfile.agent     ← non-root, read-only FS, seccomp
│   ├── Dockerfile.mock_api
│   └── seccomp-profile.json ← custom syscall allowlist
├── tests/
│   ├── unit/                ← tool-level tests
│   └── security/            ← automated attack tests (run in CI)
└── .github/workflows/
    └── security-tests.yml   ← CI: unit + security + Trivy scan
```

---

## Engineering Principles

| Principle | Applied Where |
|-----------|---------------|
| **Minimum Privilege** | Docker non-root, `cap_drop: ALL`, read-only FS, scoped tool permissions |
| **Fail Fast** | Guardrails raise on first violation — no retry, no fallback |
| **Security by Design** | Monitor is mandatory, not optional; policy engine pre-execution |
| **SRP** | Each tool has one job; monitor ≠ agent ≠ defense |
| **SoC** | intercept_layer observes, policy_engine decides, tools execute |
| **DRY** | OWASP/ATLAS IDs defined once in mapper, referenced everywhere |
| **KISS** | No framework magic in tools — plain Python classes |
| **Idempotency** | `make reset-memory` → clean state; attacks reproducible |

---

## CI/CD

Every push runs:
1. Unit tests
2. Security tests (automated attack suite in deterministic mode)
3. Docker build verification + non-root user check
4. Trivy container vulnerability scan (CRITICAL/HIGH = fail)

---

## Contributing

Security findings, new attack vectors, bypass techniques, and improved defenses are all welcome.

1. Add attack payloads to `attacks/` with OWASP + ATLAS mappings
2. Add corresponding defense in `defense/guardrails.py` or `defense/policy_engine.py`
3. Add tests in `tests/security/`
4. Submit PR — CI runs the full attack suite automatically

**Reporting bypasses:** Open a GitHub issue with `[BYPASS]` prefix. Include payload, OWASP/ATLAS IDs, and reproduction steps.

---

## References

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [NIST AI Risk Management Framework](https://www.nist.gov/system/files/documents/2023/01/26/AI_RMF_1.0.pdf)
- [LangChain Security Best Practices](https://python.langchain.com/docs/security)
- [DEF CON AI Village](https://aivillage.org/)
- [Lakera AI Security Research](https://www.lakera.ai/blog)

---

## License

MIT — use freely for research, education, and defensive tooling.
