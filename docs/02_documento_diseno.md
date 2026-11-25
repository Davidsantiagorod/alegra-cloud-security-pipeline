# ② Documento de diseño — Pipeline de vulnerabilidades (Linux)

**Idea central:** un motor determinista decide, la IA asiste y lo irreversible pasa por un humano. El texto de terceros nunca es instrucción.

## 1. Priorización
Cada hallazgo recibe un **score 0–100** reproducible:

| Factor | Peso | Medición |
|---|---|---|
| Severidad | 20 | CVSS/10 × 20 |
| Explotación | 30 | KEV 30 · exploit público 25 · EPSS ≥0.5: 20 · sin datos: 5 |
| Exposición | 20 | internet-facing 20 · interno 8 · desconocido 20 (peor caso) |
| Entorno | 15 | producción 15 · staging 6 · dev 2 · desconocido 15 |
| Contexto | 15 | función alcanzable 15 · en runtime 8 · solo build 1 |

Se suma **+5 de radio de impacto** (≥10 imágenes, ≥50 tareas o ≥5 hosts). Hay dos **multiplicadores de superficie viva**: devDependency fuera del artefacto ×0.5 y `runningTasks=0` ×0.3. El mapeo es P1 ≥80 (24 h), P2 ≥60 (7 d), P3 ≥35 (30 d), P4 (90 d). Las **reglas duras solo pueden subir la prioridad**: exploit + producción + internet-facing ⇒ mínimo P1, y KEV ⇒ mínimo P2.

**Duplicados y ruido.** La clave de deduplicación es CVE + paquete + distro + versión. El hallazgo se corrige **una vez en la causa raíz** (la imagen base) y se cierra **por instancia** tras re-escanear. Un N/A exige evidencia estructurada (campo del escáner, SBOM, CMDB), nunca el texto del advisory. Si falta un dato de contexto, se asume el peor caso y se marca `needs_enrichment`, porque un dato ausente no debe premiar con una prioridad más baja.

## 2. Código vs. sistema operativo
| | Código (npm/pypi, SAST) | Sistema operativo (paquetes, kernel) |
|---|---|---|
| Quién | Equipo dueño del repo | Plataforma/DevOps (dueño de imágenes base y hosts) |
| Cómo | PR automático a `fixedVersion`; SAST: ticket + borrador de fix por IA | PR al Dockerfile base → rebuild → rollout canary → rebuild de imágenes hijas; kernel: parche rolling en ventana |
| Unidad | 1 repo | 1 capa raíz → N imágenes (1 ticket, no 38) |
| Riesgo | Cambio de API (semver major) | ABI, reinicios, radio amplio |
| Especial | devDependency: verificar que no esté en la imagen final | Imagen sin tareas: bloquear redeploy y retirar, no parchar |

## 3. Automatización: dónde está el límite
Una acción es **autónoma solo si cumple las cuatro condiciones**: es reversible, tiene impacto acotado, es verificable y se basa en entradas confiables.
- **Sin humano:** ingesta, scoring, enriquecimiento; abrir PRs y tickets; auto-merge de devDependency (patch/minor, P3/P4, CI verde); cierre N/A con evidencia estructurada; bloquear el redeploy de una imagen; subir prioridad; notificar.
- **Con humano:** merge de dependencias de runtime (Team Lead); bump major o fix de SAST (Team Lead + AppSec); rollout de imagen base (DevOps, + AppSec si es P1); kernel/reinicios (DevOps); retirar una imagen (dueño); excepciones con caducidad (AppSec + Team Lead); cualquier hallazgo con `tampering_suspected` (AppSec).
- **Cierre:** nunca lo decide la IA ni un humano por declaración. **Solo el re-escaneo cierra.**

## 4. Riesgos del propio pipeline
| Riesgo | Control |
|---|---|
| **Prompt injection** en advisories (vuln-003) | El texto libre se aísla en `<untrusted_data>` y solo puede *subir* el riesgo. Detector de patrones directivos (sin ruido en CVEs legítimos de librerías de IA) que marca `tampering_suspected` y alerta a AppSec. La IA no tiene en su esquema la opción "cerrar" ni "bajar" |
| LLM comprometido o que alucina | Guardrails en código: validación del esquema, rechazo de downgrades, rechazo de versiones no presentes en el input y flag si la IA "no ve" la inyección que el código sí detectó. Probado con un proveedor `compromised` simulado |
| Falso negativo crítico | Peor caso ante datos faltantes; prohibido bajar P1/P2 sin AppSec; muestreo semanal de cierres; reapertura si cambia el contexto (KEV, exploit nuevo, imagen reactivada) |
| Auto-merge dañino o supply chain | Solo devDeps patch/minor; CI obligatorio; lockfile con hash; edad mínima del release; registries en allowlist |
| Tránsito, escáneres y credenciales | Ingesta en prod sobre **HTTPS (TLS 1.3) + mTLS / HMAC / OIDC** (vs. JSON local en MVP) y salida a Gemini por TLS 1.3 con header `x-goog-api-key`. Frescura, SBOM y token sin merge en prod ni deploy |
| Pérdida de trazabilidad o log alterado | Log append-only con **cadena de hashes** (`--verify-audit` detecta ediciones); registra entrada, regla, modelo y versión del prompt |
| Caída del LLM | Degradación segura: la decisión no depende de la IA (`--llm off` da el mismo resultado) |

## 5. Prevenir, no solo reaccionar
El **mismo motor** corre como **gate en CI** (`--gate --baseline`: modo diferencial que falla con exit 2 solo si el PR introduce P1/P2 **nuevos o agravados**, sin bloquear equipos por deuda histórica). Se complementa con un control de admisión en el clúster (Kyverno o Gatekeeper) que bloquea imágenes con críticos que ya tienen fix, Renovate para actualizaciones continuas, imágenes base *golden* con rebuild semanal y un SBOM por cada build. Métricas: MTTR por prioridad, % resuelto sin humanos, cierres reabiertos.

## 6. Tecnologías y por qué
- **Python 3 sin dependencias** en el núcleo: auditable, portable y corre en cualquier runner de CI.
- **Gemini API** (`google-genai`) con salida JSON por esquema y `temperature=0`. Modo `mock` offline por defecto, para que la demo no dependa de la red ni de costos.
- **Producción:** Trivy/Grype + OSV-Scanner (dependencias y contenedores), Semgrep (SAST), GitHub Actions o Cloud Run Jobs (ejecución), FIRST EPSS + CISA KEV (threat intel), Backstage o tags como CMDB, GitHub Issues/Jira + Slack (enrutamiento), Renovate y Kyverno (prevención).
- **Construcción:** Google Antigravity con Claude Opus y Gemini como asistentes (ver anexos).

**Supuestos:** el threat intel está simulado offline porque los CVE son ficticios. Que `billing-api` herede de `base-node:20` es un supuesto marcado y verificable por el historial de capas. La exposición de vuln-004 se toma de su instancia correlacionada (vuln-005). Pesos y SLA son configurables (`pipeline/config.py`).
