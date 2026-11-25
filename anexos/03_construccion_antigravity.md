# Anexo 3 — Construcción del artefacto en Google Antigravity

Resumen de decisiones de ingeniería, fallos reales encontrados durante el desarrollo e iteraciones aplicadas. La transcripción literal turno por turno de la sesión está adjunta en [06_conversacion_cruda_antigravity.md](06_conversacion_cruda_antigravity.md).

## Decisiones clave de arquitectura
- **Núcleo 100% libre de dependencias** (solo librería estándar de Python, incluso para `--llm gemini` vía `urllib.request`, con soporte opcional de `google-genai`) y suite de pruebas en `unittest`. Cualquier evaluador lo clona y ejecuta sin `pip install`.
- **Proveedores de IA intercambiables:** `mock` (offline determinista por defecto), `gemini` (API real con esquema JSON forzado, `temperature=0`, *backoff* ante `503` y cadena de *fallback* de modelos), `compromised` (simula un LLM que obedeció el *prompt injection* para demostrar en vivo que los *guardrails* lo bloquean) y `off`.
- **Gate diferencial en CI (`--gate --baseline`):** evita bloquear PRs de equipos por deuda histórica preexistente; en modo diferencial solo rompe el build si entra un `P1/P2` nuevo o si uno existente empeora de prioridad.
- **Casos propios adicionales (`data/extra_findings.json`):** `vuln-101` (N/A legítimo de Windows respaldado por campo estructurado `package.platforms`, contraste directo con `vuln-003`), `vuln-102` (SQL Injection por SAST) y `vuln-103` (CVE de kernel Linux en servidores).
- **Auditoría inmutable (`audit.jsonl`):** cadena criptográfica de hashes SHA-256 verificable con `--verify-audit`.

## Iteraciones y fallos reales corregidos
1. **Falso flag de imagen base en hallazgos de código:** en la primera corrida `vuln-001` (`npm`) heredaba `assumption_base_image_lineage` desde la CMDB de `billing-api`. Se restringió la herencia de `baseImage` exclusivamente a `category == "os"`.
2. **Test de adulteración del log que dio falso negativo:** el test sobrescribía `priority = "P4"` sobre el último registro del log, que casualmente ya era `P4`, por lo que el hash no cambiaba y el test falló (`1/21`). Se corrigió forzando una mutación real.
3. **Ruido potencial del detector de inyección en librerías de IA:** una revisión detectó que buscar sustantivos sueltos como `LLM` o `AI assistant` marcaría `tampering_suspected` en CVEs legítimos de paquetes como `langchain`. Se refinó `sanitize.py` para exigir estructura directiva/imperativa dirigida al evaluador y se validó con `test_legitimate_ai_library_advisory_not_flagged`.
4. **Prueba real contra Gemini API (`Anexo 5`):** al probar con una API key real de Free Tier descubrimos modelos retirados (`404` en `gemini-2.5-flash`), cuotas en cero (`429` en `gemini-4-carbon`) y picos `503`. Se añadió envío de credencial por header `x-goog-api-key`, cadena de *fallback* hacia `gemini-3.5-flash-lite` y reintentos con *backoff*, logrando `5/5` análisis reales exitosos.
5. **Resultado final:** `24/24` tests unitarios pasando en `<0.1s`, documento de diseño exportado en exactamente 2 páginas PDF y corrida real de Gemini archivada en `anexos/05_corrida_real_gemini.json`.
