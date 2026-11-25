# Anexo 2 — Revisión crítica de la propuesta inicial

Hecha en Google Antigravity: le pasé el PDF del reto y la respuesta de Claude con la instrucción "revísalo y dime".

## Errores encontrados en la propuesta
| # | Problema | Cómo se resolvió en el artefacto |
|---|---|---|
| 1 | **La fórmula no daba las prioridades que afirmaba**: vuln-002 sumaba 47.2 (P3) aunque decía P4, porque una devDependency sumaba el peso completo de "producción". La tabla decía exploit = 25 y el código sumaba 30 | Multiplicador de presencia en runtime (devDependency ×0.5 → 23.8, P4). Pesos únicos en `config.py`. Test `test_priorities` |
| 2 | **Bug en el control anti-downgrade**: `suggestion.rank < decision.rank` con P1=1 no detecta bajar de P1 a P4 | `is_downgrade()` con la semántica explícita. Test de regresión `test_downgrade_direction` |
| 3 | Afirmaba que billing-api hereda de `base-node:20` sin respaldo en los datos | Supuesto marcado (`baseImageSource: assumed`) más la acción `verify_lineage` |
| 4 | "Se corrige una vez y se propaga": las imágenes hijas no se reconstruyen solas | Acción de rebuild de imágenes hijas y cierre **por instancia** tras re-escanear |
| 5 | No correlacionaba que billing-api es internet-facing (dato de vuln-001) para el hallazgo de OpenSSL | Enriquecimiento con la CMDB + agregación de peor caso en el grupo |
| 6 | vuln-006: `runningTasks=0` no prueba desuso en un *worker* batch. Debian 11 ya está fuera de LTS (agosto de 2026) | Flag `verify_scheduled_jobs` + `block_redeploy` (control de admisión) |
| 7 | El sanitizador reemplazaba todo el advisory por `[UNTRUSTED]`, perdiendo la información legítima | Se marca y se encapsula en `<untrusted_data>` sin borrar nada |
| 8 | Faltaba **prevención** (gate en CI, control de admisión, Renovate, SBOM) | Modo `--gate` + workflow de ejemplo en `.github/workflows/` |
| 9 | La IA tenía un papel muy chico para un reto "con IA en el centro" | La IA resume, redacta PRs, sugiere subir o revisar y detecta inyecciones; los guardrails la validan |
| 10 | ~6 páginas para un documento de máximo 2 | Documento recortado; el detalle va al reporte y a los anexos |

## Otro error de IA durante el proceso
En una respuesta intermedia, un modelo citó cuotas de la capa gratuita de "Gemini 1.5" y el SDK `google-generativeai`: ambos datos están desactualizados. Se corrigió usando el SDK actual `google-genai`, con el modelo configurable por la variable `GEMINI_MODEL`, sin depender de cifras de cuota.
