# ⑤ Anexos de construcción

Cómo usé la IA para resolver el reto, incluidos los prompts originales, las conversaciones crudas, los intentos fallidos y la evidencia de ejecución real con Gemini.

| Archivo | Contenido |
|---|---|
| [01_prompt_claude_web.md](01_prompt_claude_web.md) | Prompt inicial a Claude (web), autocrítica del sesgo en el prompt y respuesta íntegra original |
| [02_revision_critica.md](02_revision_critica.md) | Auditoría contra el PDF del reto: bugs matemáticos y de seguridad detectados antes de codificar |
| [03_construccion_antigravity.md](03_construccion_antigravity.md) | Bitácora de ingeniería en Google Antigravity: decisiones, fallos reales y cómo se resolvieron |
| [05_corrida_real_gemini.md](05_corrida_real_gemini.md) | Evidencia y análisis de la ejecución en vivo con `--llm gemini` ([JSON completo](05_corrida_real_gemini.json)) |
| [06_conversacion_cruda_antigravity.md](06_conversacion_cruda_antigravity.md) | Transcripción literal turno a turno exportada de Antigravity (con credenciales redactadas) |
| [../prompts/system_prompt.md](../prompts/system_prompt.md) | System prompt del agente Gemini (`triage-agent/v1.0`) |

**Herramientas:** Claude (web) para el borrador inicial; Google Antigravity (Claude Opus y Gemini) para la auditoría crítica, desarrollo iterativo y pruebas; Google Gemini API (`gemini-3.5-flash-lite`) en ejecución real.

**Lección principal:** la IA multiplicó la velocidad de diseño e implementación, pero cada etapa requirió verificación ingenieril: el borrador inicial tenía una fórmula que clasificaba mal `vuln-002` y un bug que dejaba pasar *downgrades*, el regex inicial habría generado ruido en librerías de IA, y la prueba en vivo contra la API de Gemini destapó cuotas y errores `503` reales que resolvimos con *fallback* y *backoff*. Convertir cada hallazgo en código y tests (`24/24`) fue la diferencia entre una propuesta teórica y un sistema listo para producción.
