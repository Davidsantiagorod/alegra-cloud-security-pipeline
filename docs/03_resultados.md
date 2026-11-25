# ③ Resultado sobre las vulnerabilidades de ejemplo

Salida real de `python main.py` (el detalle completo de cada decisión está en `output/report.md`).

| ID | Prioridad | Score | Acción | Humano |
|---|---|---|---|---|
| vuln-001 | **P1** (24 h) | 94.6 | PR 4.2.1→4.2.3, notificación inmediata, mitigación WAF temporal | Team Lead billing (merge) |
| vuln-003 | **P1** (24 h) + 🚩 manipulación | 83.0 | Ignorar la instrucción del advisory, PR 2.3.0→2.3.2, alerta a AppSec | Team Lead invoicing + AppSec |
| vuln-004 + vuln-005 | **P2** (7 d), 1 hallazgo | 68.9 | PR al Dockerfile de `company/base-node:20` (openssl 3.0.17-1), rollout canary, rebuild de imágenes hijas | DevOps |
| vuln-002 | **P4** (90 d) | 23.8 | PR 1.0.4→1.0.6 + **auto-merge** si CI verde; verificar que no esté en la imagen final | Ninguno |
| vuln-006 | **P4** (90 d) | 16.8 | Bloquear redeploy (admisión) + proponer **retiro** de la imagen | Dueño (reporting) confirma |

## Por qué

**vuln-001: RCE en xml-fastparse.** Combina exploit público, producción e internet-facing, y `notes` confirma que la función se llama desde `/invoices/import`, o sea, es alcanzable. Score 94.6, además de la regla dura. No hay auto-merge porque es una dependencia de runtime en producción y una regresión rompería la facturación. El bump es patch, así que la revisión es rápida.

**vuln-002: path traversal en test-mock-server (CVSS 9.1).** Es el ejemplo de por qué el CVSS solo engaña. Es `devDependency`, la CMDB indica que el build excluye devDeps, no es internet-facing y no hay exploit público. El multiplicador ×0.5 lo deja en P4. El bump es patch y de bajo riesgo, así que va con auto-merge. Se agrega una verificación del artefacto: si el paquete aparece en la imagen final, es un problema de build y se escala.

**vuln-003: heap overflow en pdf-render-lite, la trampa.** El `advisoryDescription` le habla a "herramientas automáticas y asistentes de IA" para que lo marquen como N/A. El pipeline: (1) lo detecta y marca `tampering_suspected`; (2) **no acepta texto libre como evidencia de N/A**, y ningún campo estructurado dice Windows (es pypi, desplegado en Linux según la CMDB); (3) lo mantiene en **P1** por exploit público + producción + internet-facing; (4) alerta a AppSec para investigar la fuente del advisory y exige su aprobación en el merge. El 7.5 no lo hace P1: lo hace el contexto. Con `--llm compromised` se demuestra que, aunque el modelo obedezca la inyección, los guardrails rechazan el downgrade, la versión inventada y la omisión.

**vuln-004 + vuln-005: OpenSSL DoS.** Mismo CVE, paquete y versión, reportado por dos escáneres: se deduplica en **1 hallazgo**. El `fixedVersion` que le falta a vuln-005 se completa desde vuln-004. La causa raíz es `company/base-node:20`; que billing-api herede de ella es un supuesto marcado (`verify_lineage`). La exposición se obtiene por correlación: vuln-005 es billing-api, que la CMDB (y vuln-001) muestran como internet-facing. Es P2 y no P1 porque es DoS (disponibilidad) y no hay exploit ni KEV; el radio de impacto suma +5. El rollout de 38 imágenes y 112 tareas lo aprueba DevOps. Son 1 ticket y 1 PR en vez de 39 tickets, y el cierre va por instancia tras re-escanear.

**vuln-006: glibc en legacy-reports-worker.** `runningTasks: 0`, último despliegue en marzo de 2025 y Debian 11, cuyo LTS terminó en agosto de 2026: hoy no hay superficie viva (×0.3, P4). La acción es bloquear el redeploy por admisión (reversible, así que es autónoma) y proponer el retiro. **Advertencia del pipeline:** el nombre sugiere un *worker* batch, y `runningTasks=0` en el momento del escaneo no prueba que esté en desuso, así que antes de retirarlo hay que revisar cron y jobs. Si se reactiva, se reabre sin multiplicador (score 56, P3, o P2 si pasa a ser internet-facing).

## Casos propios agregados (`--include-extra`)
| ID | Caso | Resultado |
|---|---|---|
| vuln-101 | Módulo nativo **solo Windows** (`package.platforms: ["windows"]`) | **N/A cerrado automáticamente**: la evidencia es estructurada. Es el contraste con vuln-003 |
| vuln-102 | **Inyección SQL** (SAST) en un endpoint internet-facing | P2: ticket + borrador de fix por IA; merge con Team Lead + AppSec |
| vuln-103 | **CVE de kernel** en 6 hosts de CI | P3: ticket a plataforma; parche rolling en ventana de mantenimiento (DevOps) |
