# Anexo 1 — Prompt inicial a Claude (web)

## Prompt usado

> Actúa como un Principal Cloud Security Architect y Lead AI Engineer.
>
> Tengo que resolver el desafío técnico de Cloud Security para Alegra ("Del reaccionar a prevenir"). Mi objetivo es diseñar y construir un pipeline inteligente y funcional para la priorización, tratamiento y remediación de vulnerabilidades (Código y OS Linux), utilizando IA para automatizar la mayor parte del flujo con mínima intervención humana y alta trazabilidad.
>
> ### Stack Tecnológico y Contexto de Ejecución:
> - Stack de desarrollo / IA: Voy a utilizar Google Anti-Gravity junto con modelos de Google AI Pro para construir la lógica y el artefacto funcional (scripts, agentes o automatización ejecutable).
> - Alcance del reto: Exclusivamente Linux.
> - Datos de prueba: Se nos entregan 6 vulnerabilidades de ejemplo en formato JSON (incluyendo dependencias npm/pypi, imágenes base Debian, falsos positivos por SO como CVE en Windows, etc.).
>
> ### Lo que necesito que me entregues:
> 1. Arquitectura y Diseño Estratégico del Pipeline: flujo paso a paso desde la ingesta de escáneres (dependency, container, host) hasta el cierre o decisión documentada; matriz de priorización inteligente (CVSS, exploitability EPSS/público, entorno, internetFacing, deduplicación/filtrado de ruido); diferenciación de tratamiento CÓDIGO vs. SISTEMA OPERATIVO.
> 2. Definición del Límite de Automatización vs. Intervención Humana: criterios de auto-remediación vs. aprobación manual (AppSec, DevOps, Team Lead); análisis de riesgos del pipeline (inyección de prompts desde advisories, falsos negativos críticos, auto-merge defectuoso) y controles.
> 3. Análisis y Resolución de los 6 Ejemplos del Reto (vuln-001 a vuln-006): prioridad, acción automatizada sugerida y justificación técnica.
> 4. Diseño del Artefacto Funcional con Google Anti-Gravity + Google AI Pro: estructura de código Python, system prompts para los agentes, flujo de ejecución y cómo presentarlo en la entrevista.
>
> Por favor, estructura tu respuesta de manera clara, profesional y lista para ser utilizada como base de mi documento de diseño (máximo 2 páginas) y desarrollo.

## Lo que no funcionó del prompt (autocrítica)
- **Sesgo en la descripción de los datos:** escribí "falsos positivos por SO como CVE en Windows". Esa frase da por hecho que vuln-003 es un falso positivo real, cuando en realidad es una **prompt injection**. Claude no cayó, pero un modelo menos cuidadoso podría haber cerrado la vulnerabilidad más peligrosa del set. Es justamente el riesgo que el pipeline debe controlar: el contexto que se le da a una IA puede sesgarla.
- **No pedí** el diagrama (entregable ①), la justificación de tecnologías ni el enfoque de *prevención* que da título al reto.
- "Google AI Pro" es una suscripción, no una API. El artefacto usa la **Gemini API** (con capa gratuita en AI Studio).

## Respuesta de Claude
<!-- Pegar aquí la respuesta completa (o exportar la conversación como PDF y enlazarla). -->
Resumen de los aportes que se conservaron: el principio "motor determinista + IA acotada", la detección de vuln-003 como inyección, las cuatro condiciones para automatizar (reversible, acotado, verificable, entradas confiables), la matriz de autonomía y el modo sin LLM para la demo.
