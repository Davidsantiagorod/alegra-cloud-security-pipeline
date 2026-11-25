# ⑤ Anexos de construcción

Cómo usé la IA para resolver el reto, incluidos los intentos que no funcionaron.

| Archivo | Contenido |
|---|---|
| [01_prompt_claude_web.md](01_prompt_claude_web.md) | Prompt inicial a Claude (web) y su respuesta (diseño base) |
| [02_revision_critica.md](02_revision_critica.md) | Revisión de esa respuesta contra el PDF del reto: errores encontrados |
| [03_construccion_antigravity.md](03_construccion_antigravity.md) | Construcción del artefacto en Google Antigravity: iteraciones y fallos |
| [../prompts/system_prompt.md](../prompts/system_prompt.md) | System prompt del agente Gemini que usa el pipeline |

**Herramientas:** Claude (web) para el diseño inicial; Google Antigravity (agente con Claude Opus) para la revisión crítica y la construcción; Gemini como el LLM que usa el pipeline en ejecución.

**Lección principal:** la IA aceleró mucho el trabajo, pero varias de sus salidas tenían errores sutiles: una fórmula que no producía las prioridades que afirmaba, un control de seguridad con la comparación invertida y datos desactualizados sobre la API. Revisar cada salida contra la fuente (el PDF) y convertir cada afirmación en un test fue lo que más valor aportó.
