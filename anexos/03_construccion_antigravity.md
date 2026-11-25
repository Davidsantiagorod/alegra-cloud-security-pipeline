# Anexo 3 — Construcción del artefacto en Google Antigravity

**Decisiones de diseño tomadas durante la construcción**
- **Núcleo sin dependencias** (solo la librería estándar de Python) y tests con `unittest`. Cualquier evaluador lo ejecuta con `python main.py`, sin `pip install` ni API key.
- **Proveedores de IA intercambiables:** `mock` (offline, determinista, default), `gemini` (API real con JSON por esquema y temperature 0), `compromised` (simula un modelo que cayó en la inyección, para *demostrar* los guardrails en vez de solo afirmarlos) y `off`.
- **Casos propios** para cubrir flujos que el reto menciona pero que no están en los 6 ejemplos: N/A legítimo con evidencia estructurada (vuln-101, el contraste con vuln-003), inyección SQL por SAST (vuln-102) y kernel en hosts (vuln-103).
- **Log de auditoría con cadena de hashes:** trazabilidad que además detecta si alguien edita una decisión después.

## Iteraciones y fallos
1. **Primera ejecución:** vuln-001 (un hallazgo de *código*) aparecía con el flag `assumption_base_image_lineage`, que solo aplica a SO. Causa: el enriquecimiento copiaba la imagen base de la CMDB a cualquier hallazgo del servicio. Arreglo: solo se aplica en la categoría `os`.
2. **Razones duplicadas** en el grupo 004+005 (una por instancia). Arreglo: deduplicación de razones.
3. **Test de manipulación del log que falló**: el test cambiaba la prioridad a "P4" en un registro que ya era P4, así que no había alteración real. El bug era del test, no del log. Arreglo: el test garantiza un cambio real.
4. **Guardrail de versiones:** el regex que detecta versiones inventadas habría marcado el CVSS ("7.5") o el EPSS como una versión alucinada. Arreglo: esos valores también se permiten.
5. **Resultado final:** 21/21 tests; prioridades P1, P1, P2 (agrupado), P4, P4 sobre los 6 ejemplos.

## Prompts usados en Antigravity (resumen)
1. "Este archivo es de lo más importante, te paso el prompt que le pasé a Claude… revísalo y me dices" (con el PDF adjunto) → revisión crítica (anexo 2).
2. "¿Qué modelo me recomiendas para hacerlo?" → seguir con Claude Opus por continuidad y usar Gemini como revisor cruzado.
3. "¿Sí o sí se necesita una Gemini API?" → diseño offline-first, con Gemini opcional en su capa gratuita.
4. "Inicia y me vas contando" → construcción iterativa: datos → etapas → scoring/policy → IA + guardrails → CLI → tests → documentación.
