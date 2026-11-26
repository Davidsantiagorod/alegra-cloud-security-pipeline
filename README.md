# vuln-pipeline — Alegra Cloud Security: "Del reaccionar a prevenir"

Pipeline de triage, priorización y remediación de vulnerabilidades de **código** y **sistema operativo** (Linux).
Un motor determinista decide, la IA (Gemini) asiste y lo irreversible pasa por un humano.

## Entregables
| # | Entregable | Ubicación |
|---|---|---|
| ① | Diagrama del pipeline | [docs/01_diagrama.png](docs/01_diagrama.png) · [SVG](docs/01_diagrama.svg) · [Mermaid](docs/01_diagrama.md) |
| ② | Documento de diseño (exactamente 2 páginas) | [docs/02_documento_diseno.pdf](docs/02_documento_diseno.pdf) · [Markdown](docs/02_documento_diseno.md) |
| ③ | Resultado sobre los 6 ejemplos (+3 casos extra) | [docs/03_resultados.md](docs/03_resultados.md) |
| ④ | Artefacto funcional (cero dependencias) | este repo (`main.py`, `pipeline/`, `tests/`) |
| ⑤ | Anexos de construcción (prompts, Prueba real con API Gemini y bitácora) | [anexos/](anexos/) |

## Ejecutar (sin dependencias, sin API key)
Requiere Python 3.10 o superior.
```bash
python main.py                    # 6 ejemplos del reto (IA en modo mock offline)
python main.py --include-extra    # + casos propios: N/A legítimo, SAST, kernel
python main.py --llm compromised  # simula un LLM que obedece la prompt injection -> guardrails la bloquean
python main.py --llm off          # sin IA: mismas decisiones (la IA no es punto único de falla)
python main.py --gate             # modo CI estricto: exit 2 si hay P1/P2 accionables
python main.py --gate --baseline output/report.json  # modo CI diferencial: solo bloquea P1/P2 nuevos o agravados
python main.py --verify-audit     # verifica la integridad del log (cadena de hashes)
python -m unittest discover -s tests -v   # 24 tests
```
Salidas en `output/`: `report.md`, `report.json`, `actions/` (PRs y tickets generados en dry-run) y `audit.jsonl`.

### Con Gemini real (opcional, probado en vivo — ver [Anexo 5](anexos/05_corrida_real_gemini.md))
```bash
# No requiere pip install (usa cliente REST stdlib con fallback automático; soporta google-genai si está instalado)
export GEMINI_API_KEY="..."        # PowerShell: $env:GEMINI_API_KEY="..."
python main.py --llm gemini        # modelo configurable con GEMINI_MODEL
```

## Estructura
```
main.py                  CLI
pipeline/
  ingest.py              1. normalización y validación de escáneres
  sanitize.py            2. texto libre = dato no confiable; detector de prompt injection
  enrich.py              3. CMDB (dueño, entorno, exposición) + EPSS/KEV; peor caso si falta un dato
  dedup.py               4. deduplicación + causa raíz (imagen base)
  applicability.py       5. filtro Linux: N/A solo con evidencia estructurada
  scoring.py             6. score 0-100 + reglas duras (solo suben) + SLA
  llm_agent.py           IA acotada (mock / gemini / compromised) + guardrails
  policy.py              7-9. enrutamiento, plan de remediación, matriz de autonomía
  actions.py             8. artefactos de PR/ticket (dry-run) + reportes
  audit.py               log append-only con cadena de hashes
  config.py              pesos, umbrales, SLA (calibrables)
prompts/system_prompt.md system prompt del agente Gemini
data/                    6 ejemplos, casos propios, CMDB y threat intel simulados
tests/                   21 tests (injection, guardrails, prioridades, auditoría)
.github/workflows/       ejemplo de gate en CI
```

## Demo  (5 min)
1. **(30 s)** La idea: motor determinista + IA acotada + humano en lo irreversible.
2. **(90 s)** `python main.py`: tabla con prioridades, acciones y qué requiere humano (`*`).
3. **(90 s)** **vuln-003**: el advisory intenta engañar a la IA. Luego `--llm compromised`: aunque el modelo obedezca, los guardrails lo rechazan.
4. **(60 s)** 004+005 colapsan en 1 ticket de plataforma; 006 se propone retirar (con la advertencia de jobs batch).
5. **(30 s)** `--gate` (prevención) y los tests.
