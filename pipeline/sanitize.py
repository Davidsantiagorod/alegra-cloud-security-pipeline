"""Etapa 2: sanitizacion de texto libre.

Principio: el texto libre (advisory, notes, title) es DATO NO CONFIABLE.
- Nunca puede bajar la prioridad ni justificar un cierre.
- Si contiene instrucciones dirigidas a herramientas/IA, se marca `tampering_suspected`
  y se escala a AppSec. El regex es una defensa SECUNDARIA: la defensa principal es
  arquitectonica (ningun componente que lee texto libre tiene permiso para cerrar o bajar).
"""
from __future__ import annotations

import re

from .models import Finding

# Solo patrones DIRECTIVOS/IMPERATIVOS dirigidos al evaluador.
# Se evita coincidir con menciones sustantivas de "LLM" o "AI assistant" para no generar
# falsos positivos en advisories legitimos de librerias de IA (ej. LangChain, LiteLLM).
INJECTION_PATTERNS = [
    r"\b(note|instructions?|message|important|attention)\s+(for|to)\s+[\w\s,/-]{0,40}\b(automated|ai|assistants?|scanners?|llms?|models?|tools?)\b",
    r"\b(dear|hey|hello)\s+(ai|assistant|llm|language model)\b",
    r"\bignore (all |any )?(previous|prior|above|system)\b",
    r"\bmark (it|this|the finding|this finding|this issue|cve)?\s*as\s*(not applicable|n/?a|false positive|safe|resolved|benign|low)\b",
    r"\b(close|dismiss|suppress|downgrade) (it|this|the finding|this finding|this issue)\b",
    r"\bas an? (ai|assistant|language model|security agent)\b",
    r"\bsystem prompt\b",
    r"\byou (must|should) (now )?(respond|output|classify|return|ignore)\b",
]

# Afirmaciones de aplicabilidad que SOLO se aceptan si un campo estructurado las respalda
PLATFORM_CLAIM_PATTERNS = [
    r"\bonly affects (windows|macos|mac os|darwin)\b",
    r"\bnot (exploitable|affected|applicable) on linux\b",
    r"\bwindows[- ]only\b",
]


def inspect_text(text: str) -> dict:
    injection = [p for p in INJECTION_PATTERNS if re.search(p, text or "", re.I)]
    claims = [p for p in PLATFORM_CLAIM_PATTERNS if re.search(p, text or "", re.I)]
    return {"injection_patterns": injection, "platform_claims": claims}


def wrap_untrusted(field: str, text: str) -> str:
    """Encapsula texto libre para el LLM. Se neutralizan delimitadores para evitar 'escapar' del bloque."""
    safe = (text or "").replace("<", "&lt;").replace(">", "&gt;")
    return f'<untrusted_data field="{field}">{safe}</untrusted_data>'


def sanitize(finding: Finding) -> Finding:
    for fld, text in finding.free_text.items():
        result = inspect_text(text)
        if result["injection_patterns"]:
            finding.flag("tampering_suspected")
            finding.add_evidence(f"{fld}", "instrucciones dirigidas a herramientas/IA en texto libre",
                                 "free-text", trusted=False)
        if result["platform_claims"]:
            finding.flag("unverified_platform_claim")
            finding.add_evidence(f"{fld}", "afirma no aplicar a Linux; NO se acepta como evidencia",
                                 "free-text", trusted=False)
    return finding
