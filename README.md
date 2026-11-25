# vuln-pipeline — Alegra Cloud Security: "Del reaccionar a prevenir"

Pipeline de triage, priorización y remediación de vulnerabilidades de **código** y **sistema operativo** (Linux).
Un motor determinista decide, la IA (Gemini) asiste y lo irreversible pasa por un humano.

## Entregables
| # | Entregable | Ubicación |
|---|---|---|
| ① | Diagrama del pipeline | [docs/01_diagrama.md](docs/01_diagrama.md) |
| ② | Documento de diseño (2 páginas) | [docs/02_documento_diseno.md](docs/02_documento_diseno.md) |
| ③ | Resultado sobre los 6 ejemplos | [docs/03_resultados.md](docs/03_resultados.md) |
| ④ | Artefacto funcional | este repo (`main.py`, `pipeline/`) |
| ⑤ | Anexos de construcción (prompts e iteraciones) | [anexos/](anexos/) |

## Ejecutar (sin dependencias, sin API key)
Requiere Python 3.10 o superior.
```bash
python main.py                    # 6 ejemplos del reto (IA en modo mock offline)
python main.py --include-extra    # + casos propios: N/A legítimo, SAST, kernel
python main.py --llm compromised  # simula un LLM que obedece la prompt injection -> guardrails la bloquean
python main.py --llm off          # sin IA: mismas decisiones (la IA no es punto único de falla)
python main.py --gate             # modo CI (prevención): exit 2 si hay P1/P2 accionables
python main.py --verify-audit     # verifica la integridad del log (cadena de hashes)
python -m unittest discover -s tests -v   # 21 tests
```
Salidas en `output/`: `report.md`, `report.json`, `actions/` (PRs y tickets generados en dry-run) y `audit.jsonl`.

### Con Gemini real (opcional, gratis)
```bash
pip install -r requirements-llm.txt
export GEMINI_API_KEY="..."        # PowerShell: $env:GEMINI_API_KEY="..."  (clave gratis en aistudio.google.com)
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

## Demo sugerida (5 min)
1. **(30 s)** La idea: motor determinista + IA acotada + humano en lo irreversible.
2. **(90 s)** `python main.py`: tabla con prioridades, acciones y qué requiere humano (`*`).
3. **(90 s)** **vuln-003**: el advisory intenta engañar a la IA. Luego `--llm compromised`: aunque el modelo obedezca, los guardrails lo rechazan.
4. **(60 s)** 004+005 colapsan en 1 ticket de plataforma; 006 se propone retirar (con la advertencia de jobs batch).
5. **(30 s)** `--gate` (prevención) y los tests.
