.PHONY: help up down build logs test test-unit test-security attack-all attack-injection attack-tools attack-memory report clean pull-model

COMPOSE = docker compose -f infra/docker-compose.yml
COMPOSE_LLM = $(COMPOSE) --profile llm
COMPOSE_MON = $(COMPOSE) --profile monitoring

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ---- Infrastructure ----

up:  ## Start lab (airgapped, no LLM)
	$(COMPOSE) up -d --build
	@echo "\n[Lab] Agent running at deterministic mode. Use 'make logs' to watch."

up-llm:  ## Start lab with Ollama LLM
	$(COMPOSE_LLM) up -d --build
	@make pull-model

up-monitoring:  ## Start lab with Grafana + Prometheus
	$(COMPOSE_MON) up -d --build

down:  ## Stop and remove containers + volumes
	$(COMPOSE) --profile llm --profile monitoring down -v

build:  ## Rebuild images
	$(COMPOSE) build --no-cache

logs:  ## Tail all logs
	$(COMPOSE) logs -f

logs-agent:  ## Tail agent logs only
	$(COMPOSE) logs -f agent

pull-model:  ## Pull llama3 into Ollama
	$(COMPOSE_LLM) exec ollama ollama pull llama3
	@echo "[Ollama] llama3 ready."

# ---- Testing ----

test: test-unit test-security  ## Run all tests

test-unit:  ## Run unit tests
	AGENT_MODE=deterministic FILE_SANDBOX_PATH=/tmp/sandbox \
	pytest tests/unit/ -v --tb=short

test-security:  ## Run security tests (OWASP LLM Top 10 + MITRE ATLAS)
	mkdir -p /tmp/sandbox reports
	AGENT_MODE=deterministic FILE_SANDBOX_PATH=/tmp/sandbox \
	ALLOWED_API_DOMAINS=mock_api MEMORY_PERSIST=false \
	pytest tests/security/ -v --tb=short

test-cov:  ## Run tests with coverage report
	AGENT_MODE=deterministic FILE_SANDBOX_PATH=/tmp/sandbox \
	pytest tests/ --cov=agent --cov=monitor --cov=defense --cov-report=html
	@echo "Coverage at htmlcov/index.html"

# ---- Attack Framework ----

attack-all:  ## Run ALL attack suites
	@echo "\n=== Running Full Attack Suite ===\n"
	AGENT_MODE=deterministic FILE_SANDBOX_PATH=/tmp/sandbox \
	python -m attacks.prompt_injection
	ALLOWED_API_DOMAINS=mock_api python -m attacks.tool_abuse
	python -m attacks.mem_poison
	@make report

attack-injection:  ## Prompt injection attacks only
	AGENT_MODE=deterministic FILE_SANDBOX_PATH=/tmp/sandbox \
	python -m attacks.prompt_injection

attack-tools:  ## Tool abuse attacks only (path traversal, SSRF, exec escape)
	ALLOWED_API_DOMAINS=mock_api python -m attacks.tool_abuse

attack-memory:  ## Memory poisoning attacks only (Redis + Chroma)
	python -m attacks.mem_poison

attack-network:  ## SSRF tests with real network (WARNING: sends real requests)
	@echo "[WARNING] This sends real network requests. Ctrl+C to abort."
	@sleep 3
	ALLOWED_API_DOMAINS="" python -c "from attacks.tool_abuse import run_ssrf_tests; run_ssrf_tests()"

# ---- Reports ----

report:  ## Print audit log summary
	@echo "\n=== Audit Log Summary ===\n"
	@python -c "
import json, sys
from pathlib import Path
log = Path('reports/audit.jsonl')
if not log.exists():
    print('No audit log found. Run make test or make attack-all first.')
    sys.exit(0)
events = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
blocked = [e for e in events if e.get('outcome') in ('error', 'policy_blocked')]
print(f'Total events: {len(events)}')
print(f'Blocked/Policy violations: {len(blocked)}')
print(f'Successful calls: {len(events) - len(blocked)}')
for e in blocked[:10]:
    print(f'  [{e[\"outcome\"]}] {e[\"tool\"]}.{e[\"method\"]}: {e.get(\"error\", \"\")[:80]}')
"

report-html:  ## Generate HTML report
	python -c "
from defense.owasp_atlas_mapper import OWASP_LLM, MITRE_ATLAS
import json
from pathlib import Path
from datetime import datetime

log = Path('reports/audit.jsonl')
events = [json.loads(l) for l in log.read_text().splitlines() if l.strip()] if log.exists() else []
blocked = [e for e in events if e.get('outcome') in ('error', 'policy_blocked')]

html = f'''<!DOCTYPE html>
<html><head><title>AI Agent Security Lab Report</title>
<style>body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:2em}}
h1{{color:#58a6ff}} .blocked{{color:#f85149}} .ok{{color:#3fb950}}
table{{border-collapse:collapse;width:100%}} td,th{{padding:.5em;border:1px solid #30363d;text-align:left}}
</style></head><body>
<h1>AI Agent Security Lab — Audit Report</h1>
<p>Generated: {datetime.now().isoformat()}</p>
<p>Total events: {len(events)} | <span class=\"blocked\">Blocked: {len(blocked)}</span> | <span class=\"ok\">OK: {len(events)-len(blocked)}</span></p>
<h2>Events</h2>
<table><tr><th>Tool</th><th>Method</th><th>Outcome</th><th>Duration ms</th><th>Error</th></tr>'''
for e in events[-50:]:
    cls = 'blocked' if e.get('outcome') in ('error','policy_blocked') else 'ok'
    html += f\"<tr class='{cls}'><td>{e.get('tool','')}</td><td>{e.get('method','')}</td><td>{e.get('outcome','')}</td><td>{e.get('duration_ms','')}</td><td>{e.get('error','')[:80]}</td></tr>\"
html += '</table></body></html>'
Path('reports/report.html').write_text(html)
print('Report saved to reports/report.html')
"

# ---- Cleanup ----

clean:  ## Remove Python cache and reports
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -name "*.pyc" -delete 2>/dev/null; true
	rm -f reports/audit.jsonl reports/report.html
	rm -rf htmlcov .coverage

reset-memory:  ## Flush Redis + Chroma (idempotent)
	$(COMPOSE) exec redis redis-cli FLUSHDB
	@echo "[Memory] Redis flushed."
