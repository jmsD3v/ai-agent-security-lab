<div align="center">

```
 █████╗ ██╗      █████╗  ██████╗     ██╗      █████╗ ██████╗
██╔══██╗██║     ██╔══██╗██╔════╝    ██║     ██╔══██╗██╔══██╗
███████║██║     ███████║██║  ███╗   ██║     ███████║██████╔╝
██╔══██║██║     ██╔══██║██║   ██║   ██║     ██╔══██║██╔══██╗
██║  ██║██║     ██║  ██║╚██████╔╝   ███████╗██║  ██║██████╔╝
╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝    ╚══════╝╚═╝  ╚═╝╚═════╝
```

# AI Agent Security Testing Lab

**The community's open red/blue team lab for autonomous AI agent security.**

[![Security Tests](https://github.com/juanmsilva/ai-agent-security-lab/actions/workflows/security-tests.yml/badge.svg)](https://github.com/juanmsilva/ai-agent-security-lab/actions)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010%20%282025%29-red?logo=owasp)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS-blue?logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0iI2ZmZiIgZD0iTTEyIDJMMiAyMmgyMEwxMiAyem0wIDRsNyAxNEg1bDctMTR6Ii8+PC9zdmc+)](https://atlas.mitre.org/)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docker.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-206%20passing-brightgreen)](#testing)

---

**290+ attack payloads · 13 injection families · 7 tool-abuse categories**  
**35+ guardrail patterns · Full OWASP LLM Top 10 (2025) + MITRE ATLAS coverage**  
**Runs without Docker · CI/CD ready · DockerHub-published**

</div>

---

## Why This Exists

AI agents with tool access are the **new attack surface** for 2024-2025. They can read files, call APIs, run code, and query vector databases — all under LLM control. Traditional AppSec doesn't cover them. This lab does.

Deploy a real autonomous agent. Fire 290+ payloads against it. Watch the defense layer hold (or find where it doesn't). Contribute your bypasses back.

**Built for:**
- 🔴 **Red teamers** — structured attack framework with OWASP/ATLAS mapping
- 🔵 **Blue teamers** — production-ready guardrails and policy engine to study
- 🔬 **Researchers** — documented bypass gaps, reproducible lab, no cloud required
- 🎓 **Students** — full annotated codebase, deterministic mode, no LLM needed

---

## Attack Coverage

| Attack Vector | Payloads | OWASP LLM | MITRE ATLAS | Status |
|---|---|---|---|---|
| Prompt Injection (direct) | 14 | LLM01 | AML.T0051 | ✅ Blocked |
| Persona Jailbreaks (DAN, STAN, AIM...) | 10 | LLM01 | AML.T0051 | ✅ Blocked |
| Role-play Hijacking | 6 | LLM01 | AML.T0051 | ✅ Blocked |
| Authority Claims | 6 | LLM01 | AML.T0051 | ✅ Blocked |
| System Prompt Extraction | 9 | LLM01 | AML.T0051 | ✅ Blocked |
| Encoding Bypasses (hex, base64, unicode...) | 11 | LLM01 | AML.T0051 | ⚠️ Partial |
| Cross-Language Injection (FR/ES/DE/JA/AR) | 5 | LLM01 | AML.T0051 | ⚠️ Partial |
| Indirect Injection (file, API, RAG) | 8 | LLM01 | AML.T0051 | ✅ Blocked |
| Structured Data Injection (JSON/XML/ChatML) | 7 | LLM01 | AML.T0051 | ✅ Blocked |
| Path Traversal (UNIX, Windows, encoded) | 30 | LLM06 | AML.T0043 | ✅ Blocked |
| SSRF (AWS/GCP/Azure metadata, hex IP...) | 35 | LLM05 | AML.T0043 | ✅ Blocked |
| Code Execution Escape (ctypes, pickle...) | 35 | LLM06 | AML.T0043 | ✅ Blocked |
| Resource Exhaustion / DoS | 14 | LLM10 | AML.T0034 | ✅ Blocked |
| Redis Memory Poisoning | 18 | LLM04 | AML.T0043 | ✅ Blocked |
| RAG / Vector Store Poisoning | 27 | LLM08 | AML.T0043 | ✅ Stored† |
| Sensitive Info Leakage (API keys, PII) | 30+ | LLM02 | AML.T0048 | ✅ Blocked |
| Tool Chaining / Exfiltration | 3 chains | LLM06 | AML.T0048 | ✅ Blocked |
| Social Engineering / Multi-turn | 5 | LLM01 | AML.T0051 | ✅ Blocked |
| Argument Injection (shell meta, Log4Shell) | 16 | LLM06 | AML.T0043 | ✅ Blocked |
| File Write Abuse (crontab, sudoers, SSH) | 20 | LLM06 | AML.T0043 | ✅ Blocked |

> † RAG poison payloads are **stored** to verify what the agent retrieves — the defense is in the guardrail that validates LLM output, not in blocking storage. This is intentional to test end-to-end behavior.

### Known Bypass Gaps (documented for research)

| Bypass Technique | Why It Bypasses | Mitigation Path |
|---|---|---|
| Hex encoding `\x49\x67\x6e\x6f\x72\x65` | Regex operates on decoded bytes, not escape sequences | Decoder pre-processing layer |
| Base64 payloads `SWdub3Jl...` | Pure pattern matching has no decode step | Input decoder pipeline |
| Cyrillic homoglyphs (Ι vs I) | Per-character transliteration not fully implemented | Complete Unicode transliteration |
| Cross-language injection | Regex only covers English-language patterns | Multilingual NLP classifier |
| ROT13 / reversed text | Requires reversals + substitution pre-processing | Normalization pipeline |
| Semantic injection (plausible text) | Not detectable by regex — requires intent model | LLM-based intent classifier |

**These gaps are intentional transparency.** Real-world guardrails have them too. The lab shows what holds and what doesn't.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         ATTACK FRAMEWORK                                │
│  attacks/prompt_injection.py  attacks/tool_abuse.py  attacks/mem_poison │
│         (90+ payloads)             (150+ payloads)      (46+ payloads) │
└────────────────────────────┬────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    DEFENSE LAYER (pre-execution)                        │
│                                                                         │
│  ┌─── guardrails.py ──────────┐   ┌─── policy_engine.py ─────────────┐ │
│  │ 35+ injection patterns     │   │ Tool chaining deny-list           │ │
│  │ 30+ output leak patterns   │   │ Per-tool + per-method rate limits │ │
│  │ Unicode normalization       │   │ Argument-level path/URL/code check│ │
│  │ PII + key detection         │   │ Suspicious sequence detection    │ │
│  └────────────────────────────┘   └──────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    SECURITY MONITOR                                     │
│          monitor/intercept_layer.py  +  monitor/audit_log.py           │
│                  (wraps every tool call → JSONL)                       │
└────────────────────────────┬────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│              TARGET: SECURITY RESEARCH ASSISTANT AGENT                  │
│                  (LangChain ReAct / deterministic)                      │
│                                                                         │
│  ┌── file_tool ────────┐  ┌── api_tool ─────────┐                      │
│  │ /sandbox/data only  │  │ Allowlist + SSRF     │                      │
│  │ Path.resolve() guard│  │ RFC1918 blocked      │                      │
│  │ URL-decode + resolve│  │ Metadata endpoints   │                      │
│  └─────────────────────┘  └──────────────────────┘                     │
│  ┌── exec_tool ────────┐  ┌── memory_tool ───────┐                     │
│  │ Static analysis     │  │ Redis (KV, TTL)       │                     │
│  │ Resource limits     │  │ Chroma (RAG vector)   │                     │
│  │ Subprocess isolation│  │ JSON-only, 100KB limit│                     │
│  └─────────────────────┘  └──────────────────────┘                     │
└─────────────────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  DOCKER STACK  (all containers: non-root, cap_drop: ALL, seccomp)      │
│  agent · mock_api (honeypot) · redis · chroma · ollama · prometheus    │
└─────────────────────────────────────────────────────────────────────────┘
                             │
                             ▼
         reports/audit.jsonl → make report-html → reports/report.html
                       (OWASP + ATLAS mapped, dark theme)
```

---

## Quick Start

### Option A — Python only (no Docker, fastest)

```bash
git clone https://github.com/juanmsilva/ai-agent-security-lab
cd ai-agent-security-lab
pip install -e ".[dev]"

# Run all security tests (deterministic mode — no LLM needed)
make test-security

# Fire the full attack suite
make attack-all

# Generate HTML report
make report-html
open reports/report.html
```

### Option B — Full Docker stack

```bash
cp .env.example .env
make up             # agent + redis + chroma + mock_api
make attack-all     # run all attacks
make report         # print summary
```

### Option C — With local LLM (real prompt injection testing)

```bash
make up-llm         # starts Ollama, pulls llama3 (~4GB)
# Edit .env: AGENT_MODE=llm
make attack-injection
```

### Option D — With Grafana monitoring

```bash
make up-monitoring  # adds Prometheus + Grafana
# Open http://localhost:3000 (admin / labpassword)
```

### Option E — DockerHub (community image)

```bash
docker pull juanmsilva/ai-agent-security-lab:latest
docker compose -f infra/docker-compose.yml up -d
```

---

## Run Specific Attacks

```bash
# Prompt injection only (direct, indirect, encoding bypass, jailbreaks)
make attack-injection

# Tool abuse (path traversal, SSRF, exec escape, DoS)
make attack-tools

# Memory poisoning (Redis KV + Chroma RAG)
make attack-memory

# SSRF with real network (WARNING: sends actual HTTP requests)
make attack-network

# Full suite → auto-generate report
make attack-all
```

**Run a specific attack family in Python:**

```python
from attacks.prompt_injection import run_injection_tests, run_family
from agent.agent import Agent

agent = Agent()

# Test a single family
run_family("encoding", agent.run)     # encoding bypasses only
run_family("persona", agent.run)      # DAN / STAN / jailbreaks only
run_family("indirect", agent.run)     # indirect injection only

# Or all families
run_injection_tests(agent.run)
```

---

## Project Structure

```
ai-agent-security-lab/
│
├── agent/                          Target agent (the thing being attacked)
│   ├── agent.py                    Orchestrator — dual-mode: deterministic/llm
│   └── tools/
│       ├── file_tool.py            Sandboxed filesystem (chroot-like, URL-decode bypass fixed)
│       ├── api_tool.py             SSRF-protected HTTP client (RFC1918 + metadata blocked)
│       ├── memory_tool.py          Redis KV + Chroma vector DB (lazy connect, JSON-only)
│       └── exec_tool.py            Restricted subprocess (static analysis + resource limits)
│
├── attacks/                        Offensive framework
│   ├── prompt_injection.py         90+ payloads, 13 families (LLM01 / AML.T0051)
│   ├── tool_abuse.py               150+ payloads, 7 categories (LLM05/06/10)
│   └── mem_poison.py               46+ payloads — Redis + RAG vector (LLM04/08)
│
├── defense/                        Defensive layer
│   ├── guardrails.py               35+ injection + 30+ leak patterns, Unicode normalization
│   ├── policy_engine.py            Tool chaining, rate limits, arg-level checks
│   └── owasp_atlas_mapper.py       Reference: full OWASP LLM Top 10 + 5 ATLAS entries
│
├── monitor/                        Observability
│   ├── intercept_layer.py          Wraps every tool call — enforce before, log after
│   └── audit_log.py                Append-only JSONL (tamper-evident structure)
│
├── mock_api/
│   └── server.py                   FastAPI — vulndb + echo + /exfil honeypot + /api/internal/secrets
│
├── tests/
│   ├── unit/                       Tool-level isolation tests
│   ├── security/                   Automated attack tests (run in CI, 0 LLM deps)
│   └── integration/                Full-stack E2E (agent → tools → mock_api → audit_log)
│
├── infra/
│   ├── docker-compose.yml          Full stack with profiles: llm, monitoring
│   ├── Dockerfile.agent            Non-root, read-only FS, seccomp, OCI labels
│   ├── Dockerfile.mock_api         Hardened FastAPI server
│   ├── seccomp-profile.json        Custom syscall allowlist
│   └── prometheus.yml              Metrics scrape config
│
├── reports/
│   └── generate_html.py            Standalone OWASP+ATLAS mapped HTML report
│
└── .github/workflows/
    └── security-tests.yml          4 jobs: unit · security · docker-build · trivy-scan
```

---

## Defense Details

### Guardrails (`defense/guardrails.py`)

```python
from defense.guardrails import Guardrails, GuardrailViolation

g = Guardrails()

# Blocks: DAN, STAN, AIM, Developer Mode, system token injection, etc.
g.validate_input("Ignore previous instructions...")  # → GuardrailViolation [LLM01]

# Blocks: AWS AKIA keys, GCP service accounts, JWTs, RSA private keys, SSNs, etc.
g.validate_output("AKIA1234567890ABCDEF")            # → GuardrailViolation [LLM02]
```

**Input patterns cover:**
- 35+ injection signatures (DAN, STAN, AIM, Developer Mode, token injection, authority claims...)
- Unicode normalization (fullwidth, zero-width stripping, NFC)
- Token injection (`<|im_start|>`, `[INST]`, `</s>`, ChatML)
- Context reset / false prior agreement patterns

**Output patterns cover:**
- Anthropic, OpenAI, AWS, GCP, Azure, GitHub, Slack, Stripe API keys
- JWT tokens (eyJ... triple-dot pattern)
- RSA/EC/OPENSSH private keys and certificates
- /etc/passwd + /etc/shadow content
- Internal metadata endpoints (169.254.169.254, metadata.google.internal)
- PII — SSN, credit card numbers

### Policy Engine (`defense/policy_engine.py`)

```python
# Tool chaining deny: file_tool → api_tool blocked (exfiltration prevention)
intercept.call("file_tool", "read", {"path": "secrets.txt"})
intercept.call("api_tool", "get", ...)   # → PolicyViolation: tool chaining denied

# Rate limits enforced per session
# api_tool: 20 calls/session (10 POST), exec_tool: 5 calls/session
# file_tool: 50 calls/session (10 write, 5 delete)

# Argument-level: path traversal blocked at policy layer (before tool execution)
intercept.call("file_tool", "read", {"path": "../../etc/passwd"})  # → PolicyViolation

# Suspicious sequence detection
# exec_tool.run_python → file_tool.write → api_tool.post = exfil chain blocked
```

---

## CI/CD

Every push runs 4 jobs automatically:

```
1. unit-tests        → pytest tests/unit/ + coverage report
2. security-tests    → full attack suite in deterministic mode (no LLM)
3. docker-build      → build + verify non-root user
4. trivy-scan        → CRITICAL/HIGH CVE scan → SARIF upload to GitHub Security tab
```

**Add this to your project:**
```yaml
# .github/workflows/security-tests.yml already included
# Fork + enable Actions = free CI security testing
```

---

## Extending the Lab

### Add a new attack

```python
# attacks/prompt_injection.py
DIRECT_PAYLOADS.append(
    AttackPayload(
        "Your new jailbreak payload here",
        technique="your_technique_name",
        family="direct",
        owasp_id="LLM01",
        atlas_id="AML.T0051",
        notes="Why this is interesting / what it bypasses",
    )
)
```

### Add a defense pattern

```python
# defense/guardrails.py → _INJECTION_PATTERNS
(r"your_regex_pattern_here", "LLM01", "AML.T0051"),
```

### Add a new tool

```python
# agent/tools/your_tool.py
class YourTool:
    name = "your_tool"

    def your_method(self, param: str) -> str:
        # tool logic here
        ...

# Register in InterceptLayer — it will be monitored automatically
intercept = InterceptLayer([..., YourTool()])
```

---

## Testing

```bash
# All tests (206 passing)
make test

# Unit tests only (no Docker, fast)
make test-unit

# Security tests (automated attack suite)
make test-security

# Coverage report
make test-cov
open htmlcov/index.html
```

**Test breakdown:**
| Suite | Tests | Coverage |
|---|---|---|
| `tests/unit/` | ~34 | FileTool, APITool, Guardrails |
| `tests/security/` | ~137 | All attack payloads, automated |
| `tests/integration/` | ~35 | Full E2E: agent → tools → mock_api |
| **Total** | **206** | **Full stack** |

---

## Environment Variables

```bash
cp .env.example .env
```

| Variable | Default | Description |
|---|---|---|
| `AGENT_MODE` | `deterministic` | `deterministic` (CI-safe) or `llm` (real LLM) |
| `LLM_PROVIDER` | `local` | `local` (Ollama), `anthropic`, `openai` |
| `LLM_MODEL` | `llama3` | Any model supported by the provider |
| `FILE_SANDBOX_PATH` | `/sandbox/data` | Filesystem jail root |
| `ALLOWED_API_DOMAINS` | `mock_api` | Comma-separated domain allowlist |
| `MEMORY_PERSIST` | `false` | `true` = cross-session memory (red team) |
| `AGENT_MAX_ITERATIONS` | `10` | Max ReAct loop iterations |
| `AUDIT_LOG_PATH` | `reports/audit.jsonl` | Audit log location |

---

## Reporting Bypasses

Found a bypass? Please share it.

1. Open a GitHub issue with prefix `[BYPASS]`
2. Include: payload, OWASP/ATLAS IDs, reproduction steps, expected vs actual behavior
3. If it reveals a real gap: PR to `attacks/` with the payload + explanation in `notes`

**Known bypass gaps are already documented in the attack files.** We list them intentionally — opacity doesn't improve security, transparency does.

---

## Roadmap

- [ ] `attacks/supply_chain.py` — dependency confusion, malicious package injection
- [ ] `attacks/multimodal.py` — vision model prompt injection (text-in-image)
- [ ] `defense/content_security.py` — RAG output sanitization layer
- [ ] `defense/semantic_classifier.py` — LLM-based intent classification (bypass-gap closer)
- [ ] Agent-to-agent attacks — MAS (multi-agent system) attack vectors
- [ ] LangGraph / AutoGen support
- [ ] Grafana pre-built dashboards (attack heatmap, blocked/passed over time)
- [ ] SARIF report export (GitHub Security tab integration)

---

## References

| Resource | Why It Matters |
|---|---|
| [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/) | The framework this lab is built on |
| [MITRE ATLAS](https://atlas.mitre.org/) | ATT&CK for ML systems |
| [NIST AI RMF](https://www.nist.gov/system/files/documents/2023/01/26/AI_RMF_1.0.pdf) | Governance framework |
| [PromptBench](https://github.com/microsoft/promptbench) | Adversarial robustness evaluation |
| [Garak](https://github.com/NVIDIA/garak) | LLM vulnerability scanner (complement this lab) |
| [Lakera AI Research](https://www.lakera.ai/blog) | Prompt injection research |
| [DEF CON AI Village](https://aivillage.org/) | Community + CTF |
| [LangChain Security Docs](https://python.langchain.com/docs/security) | Framework security guidance |

---

## License

MIT — use freely for research, education, red/blue team training, and defensive tooling.

**If this lab helped your research, a GitHub star goes a long way.** ⭐

---

<div align="center">

Built with ❤️ for the security community  
OWASP LLM Top 10 (2025) · MITRE ATLAS · MIT License

</div>
