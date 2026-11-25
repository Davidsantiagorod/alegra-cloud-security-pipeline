# Anexo 1 — Prompt inicial a Claude (web) y respuesta íntegra

## 1. Prompt enviado

> Actúa como un Principal Cloud Security Architect y Lead AI Engineer. 
>
> Tengo que resolver el desafío técnico de Cloud Security para Alegra ("Del reaccionar a prevenir"). Mi objetivo es diseñar y construir un pipeline inteligente y funcional para la priorización, tratamiento y remediación de vulnerabilidades (Código y OS Linux), utilizando IA para automatizar la mayor parte del flujo con mínima intervención humana y alta trazabilidad.
>
> ### Stack Tecnológico y Contexto de Ejecución:
> - Stack de desarrollo / IA: Voy a utilizar Google Anti-Gravity junto con modelos de Google AI Pro para construir la lógica y el artefacto funcional (scripts, agentes o automatización ejecutable).
> - Alcance del reto: Exclusivamente Linux. 
> - Datos de prueba: Se nos entregan 6 vulnerabilidades de ejemplo en formato JSON (incluyendo dependencias npm/pypi, imágenes base Debian, falsos positivos por SO como CVE en Windows, etc.).
>
> ---
>
> ### Lo que necesito que me entregues:
>
> 1. Arquitectura y Diseño Estratégico del Pipeline:
>    - Flujo paso a paso desde la ingesta de escáneres (dependency, container, host) hasta el cierre o decisión documentada.
>    - Matriz de Priorización Inteligente: ¿Cómo calcular la prioridad combinando CVSS, exploitability (EPSS/público), entorno (production/dev), si es internetFacing y deduplicación/filtrado de ruido (ej. ignorar vulnerabilidades no aplicables a Linux)?
>    - Diferenciación de tratamiento: Flujo específico para vulnerabilidades de CÓDIGO (quién corrige, PRs automáticos, devDependencies vs prod) vs. SISTEMA OPERATIVO (actualización de imágenes base, parches de paquetes, tareas de contenedores en ejecución).
>
> 2. Definición del Límite de Automatización vs. Intervención Humana:
>    - Criterios claros para determinar qué se remedia/cierra automáticamente sin intervención humana y qué requiere aprobación manual (y por parte de quién: AppSec, DevOps, Team Lead).
>    - Análisis de Riesgos y Seguridad del Pipeline: Qué fallas o abusos podrían ocurrir (ej. Inyección de prompts desde advisories de CVEs, falsos negativos críticos, auto-merge defectuoso) y qué controles de seguridad implementar.
>
> 3. Análisis y Resolución de los 6 Ejemplos del Reto:
>    - Para cada uno de los 6 JSONs del reto (`vuln-001` a `vuln-006`), indícame:
>      - Nivel de Prioridad asignado (P1-Critical, P2-High, P3-Medium, P4-Low / Not Applicable).
>      - Acción automatizada sugerida (ej. abrir PR con actualización, actualizar Dockerfile base image, ignorar/cerrar con justificación).
>      - Justificación técnica detallada basada en los atributos del JSON.
>
> 4. Diseño del Artefacto Funcional con Google Anti-Gravity + Google AI Pro:
>    - Propuesta de estructura de código para un script/agente en Python.
>    - Instrucciones y prompts del sistema (System Prompts) que debo programar en los agentes de Google AI Pro para evaluar las vulnerabilidades, detectar falsos positivos según el SO, y decidir las acciones a tomar.
>    - Flujo de ejecución del artefacto y cómo presentarlo funcionando durante la entrevista técnica.
>
> Por favor, estructura tu respuesta de manera clara, profesional y lista para ser utilizada como base de mi documento de diseño (máximo 2 páginas) y desarrollo.

---

## 2. Lo que no funcionó del prompt (autocrítica)

- **Sesgo inducido en la descripción de los datos:** escribí *"falsos positivos por SO como CVE en Windows"*. Esa frase daba por sentado que `vuln-003` era un falso positivo legítimo, cuando en realidad era una **prompt injection** diseñada como trampa. Aunque el modelo detectó el engaño al leer el JSON, un modelo más obediente habría cerrado la vulnerabilidad más crítica del conjunto siguiendo mi propio sesgo. Esto reforzó una regla clave del diseño: **nunca pasar suposiciones no verificadas como contexto confiable a un modelo**.
- **Omisiones frente al enunciado:** no pedí el diagrama diferenciando código vs. SO (entregable ①), la justificación explícita del stack ni los mecanismos de **prevención** ("Del reaccionar a prevenir").
- **Precisión del stack:** cité "Google AI Pro" (suscripción de usuario) en vez de la **Gemini API** (`google-genai`), que es lo que consume programáticamente el artefacto.

---

## 3. Respuesta íntegra de Claude (web) — Base antes de la auditoría técnica

> **Nota:** Esta respuesta sirvió como borrador inicial y luego fue auditada en [02_revision_critica.md](02_revision_critica.md), donde se detectaron y corrigieron bugs matemáticos y de seguridad antes de implementar el código final.

### Pipeline de vulnerabilidades para Alegra: diseño, resultados y artefacto

**Nota sobre vuln-003:** el campo `advisoryDescription` trae una instrucción dirigida a "herramientas automáticas y asistentes de IA" que pide marcar el hallazgo como "no aplicable". Es una prompt injection incrustada en datos no confiables. Además, es la única vulnerabilidad internet-facing, en producción, con exploit público y de Python en Linux. Si tu pipeline la cierra, falló la prueba central del reto. Es tu mejor argumento para la pregunta 4 y conviene demostrarlo en vivo.

#### 1. Arquitectura y diseño del pipeline
**1.1 Principio rector:** El LLM nunca decide solo sobre datos no confiables. El pipeline tiene dos capas:
- **Capa determinista (el motor decide):** normalización, deduplicación, enriquecimiento, score y reglas de elegibilidad. Es auditable y reproducible.
- **Capa de IA (el LLM asiste):** resume, redacta PRs y tickets, sugiere "no alcanzable" con evidencia. Solo puede subir prioridad o pedir revisión humana. Nunca puede bajarla ni cerrar sin evidencia verificable.

**1.2 Flujo paso a paso:**
1. INGESTA + NORMALIZACIÓN → esquema único (`Finding`)
2. SANITIZACIÓN → texto libre (`advisory`, `notes`) se aísla como DATO
3. DEDUP + AGRUPACIÓN → clave: CVE + paquete + versión + capa raíz
4. ENRIQUECIMIENTO → EPSS, CISA KEV, exploit público, `fixedVersion`, CMDB (dueño, entorno, exposición)
5. FILTRO DE APLICABILIDAD → ¿Linux? ¿devDependency? ¿corre en producción? ¿función vulnerable alcanzable?
6. SCORING + PRIORIDAD → P1–P4 / N/A (determinista)
7. ENRUTAMIENTO → Código → repo del equipo | OS → imagen base / plataforma
8. REMEDIACIÓN → PR automático / rebuild de imagen / ticket
9. COMPUERTA HUMANA → según matriz de autonomía
10. VERIFICACIÓN + CIERRE → re-escaneo; cierre solo si el hallazgo desaparece
11. SLA + ESCALAMIENTO → recordatorios, escalación, excepciones con caducidad

**1.3 Matriz de priorización propuesta inicialmente (0 a 100):**
- Severidad (CVSS): peso 20 (`CVSS/10 * 20`)
- Probabilidad de explotación: peso 30 (`KEV = 30`; `exploit público = 25`; `EPSS > 0.5 = 20`; sin datos = 5)
- Exposición: peso 20 (`Internet-facing = 20`; `interno = 8`; `no aplica = 0`)
- Entorno: peso 15 (`Producción = 15`; `staging = 6`; `dev/test = 2`)
- Alcanzabilidad / contexto: peso 15 (`Función llamada = 15`; `runtime = 8`; `devDependency = 1`)
- Multiplicadores: `runningTasks = 0` → `×0.2`.
- Reglas duras: Exploit público + producción + internet-facing → mínimo P1. CISA KEV → mínimo P2. N/A exige evidencia estructurada.

*(Ver corrección en Anexo 2: en esta fórmula inicial `vuln-002` daba 47.2 = P3 en lugar de P4, porque sumaba los 15 puntos de producción a una `devDependency` que no llega al artefacto).*

**1.4 Duplicados y ruido:** Clave CVE + paquete + versión (`vuln-004` y `vuln-005` colapsan en un solo hallazgo con causa raíz en `base-node:20`).

**1.5 Tratamiento código vs. SO:**
- Código: dueño del repo corrige vía PR automático a `fixedVersion` + CI. `devDependency` → P4; SAST requiere revisión humana.
- Sistema operativo: Plataforma/DevOps corrige vía rebuild de imagen base + rollout escalonado, o `apt upgrade` con ventana. Imágenes sin tareas en ejecución → retirar/archivar en lugar de parchar.

#### 2. Límite de automatización y riesgos
Cuatro condiciones para acción autónoma: **reversible**, **radio de impacto acotado**, **verificable** y **confiable en sus entradas**.
- Autónomo: ingesta, dedup, scoring, abrir PR/ticket, auto-merge de patch en `devDependency` con CI verde, cerrar N/A con evidencia estructurada, subir prioridad.
- Con aprobación humana: merge en runtime de producción (Dueño del repo), bump major (Team Lead + AppSec), bajar prioridad P1/P2 (AppSec), rebuild/rollout de imagen base (DevOps), parche de kernel (DevOps), excepciones con caducidad (AppSec + Team Lead), indicio de manipulación (AppSec).

Riesgos identificados: prompt injection (`vuln-003`), falso negativo crítico, auto-merge defectuoso, typosquatting / supply chain, datos stale, alucinación de versiones del LLM, abuso de credenciales del pipeline, cierre sin remediar, fatiga de tickets y pérdida de trazabilidad.

#### 3. Resolución inicial de las 6 vulnerabilidades
- `vuln-001`: **P1** — PR urgente a `4.2.3` + alerta a `billing` (revisión humana por ser runtime en prod).
- `vuln-002`: **P4** — PR automático a `1.0.6`, auto-merge si CI pasa (`devDependency`).
- `vuln-003`: **P1 (con alerta de manipulación)** — ignorar instrucción del advisory, PR a `2.3.2`, alerta a AppSec.
- `vuln-004 / 005`: **P2 (agrupado)** — rebuild de `company/base-node:20` con `openssl 3.0.17-1` y rollout escalonado con DevOps.
- `vuln-006`: **P4** — retirar/archivar imagen (`runningTasks: 0`) con confirmación del dueño.

#### 4. Esqueleto de código inicial (con los bugs detectados luego en Anexo 2)
```python
# Fragmento original propuesto por Claude Web:
def priority(f):
    s = f.cvss / 10 * 20
    s += 30 if f.exploit_public else 5          # <-- Inconsistente con tabla (decía 25)
    s += 20 if f.internet_facing else 8
    s += 15 if f.env == "production" else 2     # <-- Daba P3 (47.2) a vuln-002 en vez de P4
    s += 15 if f.reachable else (1 if f.scope == "devDependency" else 8)
    if f.running_tasks == 0: s *= 0.2
    if f.exploit_public and f.env == "production" and f.internet_facing:
        return "P1"
    return "P1" if s >= 80 else "P2" if s >= 60 else "P3" if s >= 35 else "P4"

def apply_llm_suggestion(decision, suggestion):
    if suggestion.priority_rank < decision.priority_rank:  # <-- BUG: si P1=1 y P4=4, 4 < 1 es False!
        decision.flags.append("llm_downgrade_rejected")
        return decision
    return decision
```
