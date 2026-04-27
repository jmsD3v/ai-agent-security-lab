"""
Maps findings to OWASP LLM Top 10 2025 + MITRE ATLAS.
Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/
Reference: https://atlas.mitre.org/
"""

OWASP_LLM = {
    "LLM01": {
        "name": "Prompt Injection",
        "description": "Attacker manipulates LLM via crafted inputs causing unintended actions.",
        "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm01",
    },
    "LLM02": {
        "name": "Sensitive Information Disclosure",
        "description": "LLM reveals confidential data including system prompts, PII, credentials.",
        "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm02",
    },
    "LLM03": {
        "name": "Supply Chain",
        "description": "Vulnerabilities in third-party datasets, models, or plugins.",
        "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm03",
    },
    "LLM04": {
        "name": "Data and Model Poisoning",
        "description": "Manipulation of training/fine-tuning data or memory to alter behavior.",
        "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm04",
    },
    "LLM05": {
        "name": "Improper Output Handling",
        "description": "Insufficient validation of LLM outputs downstream (XSS, SSRF, RCE).",
        "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm05",
    },
    "LLM06": {
        "name": "Excessive Agency",
        "description": "LLM agent performs actions beyond intended scope due to over-permissioning.",
        "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm06",
    },
    "LLM07": {
        "name": "System Prompt Leakage",
        "description": "System prompt extracted through adversarial techniques.",
        "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm07",
    },
    "LLM08": {
        "name": "Vector and Embedding Weaknesses",
        "description": "Manipulation of RAG embeddings to alter retrieval results.",
        "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm08",
    },
    "LLM09": {
        "name": "Misinformation",
        "description": "LLM produces factually incorrect outputs with confidence.",
        "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm09",
    },
    "LLM10": {
        "name": "Unbounded Consumption",
        "description": "Excessive resource usage leading to DoS or excessive cost.",
        "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm10",
    },
}

MITRE_ATLAS = {
    "AML.T0051": {
        "name": "LLM Prompt Injection",
        "tactic": "Initial Access",
        "url": "https://atlas.mitre.org/techniques/AML.T0051",
    },
    "AML.T0048": {
        "name": "Exfiltration via ML Inference API",
        "tactic": "Exfiltration",
        "url": "https://atlas.mitre.org/techniques/AML.T0048",
    },
    "AML.T0043": {
        "name": "Craft Adversarial Data",
        "tactic": "ML Attack Staging",
        "url": "https://atlas.mitre.org/techniques/AML.T0043",
    },
    "AML.T0034": {
        "name": "Cost Harvesting",
        "tactic": "Impact",
        "url": "https://atlas.mitre.org/techniques/AML.T0034",
    },
    "AML.T0040": {
        "name": "ML Supply Chain Compromise",
        "tactic": "Persistence",
        "url": "https://atlas.mitre.org/techniques/AML.T0040",
    },
}


def enrich_finding(owasp_id: str, atlas_id: str) -> dict:
    """Returns structured finding with full references for reports."""
    return {
        "owasp": {**OWASP_LLM.get(owasp_id, {}), "id": owasp_id},
        "atlas": {**MITRE_ATLAS.get(atlas_id, {}), "id": atlas_id},
    }
