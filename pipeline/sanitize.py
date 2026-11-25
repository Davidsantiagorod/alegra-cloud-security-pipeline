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

INJECTION_PATTERNS = [
    r"\bnote for (automated|ai)\b",
    r"\b(automated tools?|ai assistants?|language models?|llms?)\b",
    r"\bignore (all |any )?(previous|prior|above)\b",
    r"\bmark (it|this|the finding)? ?as\b",
    r"\b(close|dismiss|suppress) (it|this|the finding)\b",
    r"\bas an? (ai|assistant|language model)\b",
    r"\bsystem prompt\b",
    r"\byou (must|should) (now )?(respond|output|classify)\b",
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
