"""Etapas 7-9: enrutamiento, plan de remediacion y matriz de autonomia.

Una accion es AUTONOMA solo si es: reversible, de impacto acotado, verificable
y basada en entradas confiables. Todo lo demas requiere aprobacion humana.
"""
from __future__ import annotations

import json
from pathlib import Path
import re

from . import config as C
from .dedup import Group
from .models import Action, Decision


def bump_type(old: str | None, new: str | None) -> str:
    """Clasifica el salto de version (semver). Para versiones de distro devuelve 'distro'."""
    if not old or not new:
        return "unknown"
    po = re.match(r"^(\d+)\.(\d+)\.(\d+)$", old)
    pn = re.match(r"^(\d+)\.(\d+)\.(\d+)$", new)
    if not (po and pn):
        return "distro"
    o, n = [int(x) for x in po.groups()], [int(x) for x in pn.groups()]
    if n[0] != o[0]:
        return "major"
    if n[1] != o[1]:
        return "minor"
    return "patch"


def owner_and_route(g: Group) -> tuple[str, str]:
    f = g.lead
    if f.category == "code":
        return f.team or "appsec-triage", f"repo:{f.asset_name}"
    if g.root_cause:
        return "platform", f"base-image:{g.root_cause}"
    if f.asset.get("host"):
        return f.team or "platform", f"hosts:{f.asset_name}"
    return f.team or "platform", f"image:{f.asset.get('image', f.asset_name)}"


def plan(g: Group, priority: str, applicable: bool, na_reasons: list[str]) -> list[Action]:
    f = g.lead
    acts: list[Action] = []
    flags = g.flags
    tampering = "tampering_suspected" in flags
    team = f.team or "owner"

    if tampering:
        acts.append(Action("alert_appsec",
                           "Alerta de posible manipulacion: el texto libre contiene instrucciones para "
                           "herramientas/IA. Se ignoran y se investiga la fuente del advisory.",
                           autonomous=True))

    # ---------- N/A ----------
    if not applicable:
        trusted_evidence = not tampering
        acts.append(Action("close_not_applicable",
                           "Cerrar como N/A con evidencia estructurada: " + "; ".join(na_reasons),
                           autonomous=trusted_evidence,
                           approvers=[] if trusted_evidence else ["AppSec"]))
        acts.append(Action("schedule_review", "Revalidar en 180 dias o si cambia el contexto", True))
        return acts

    # ---------- CODIGO: dependencia ----------
    if f.category == "code" and f.package_name and f.fixed_version:
        bt = bump_type(f.version, f.fixed_version)
        acts.append(Action("open_pr",
                           f"PR en {f.asset_name}: {f.package_name} {f.version} -> {f.fixed_version} "
                           f"({bt}); CI obligatorio + re-escaneo",
                           autonomous=True))
        if g.runtime_presence == "build-only":
            if bt in ("patch", "minor") and priority in ("P3", "P4"):
                acts.append(Action("auto_merge", "Auto-merge si CI verde (devDependency, bump "
                                   f"{bt}, sin impacto en runtime)", autonomous=True))
            else:
                acts.append(Action("merge", "Merge con revision", False, [f"Team Lead ({team})"]))
            acts.append(Action("verify_build",
                               "Verificar que la devDependency NO esta en la imagen final (multi-stage / "
                               "npm ci --omit=dev). Si esta, escalar como problema de build.", True))
        else:
            approvers = [f"Team Lead ({team})"]
            if bt == "major":
                approvers.append("AppSec")
            if tampering:
                approvers.append("AppSec")
            acts.append(Action("merge", "Merge de dependencia de runtime en produccion: requiere revision "
                               "humana (posible regresion)", False, sorted(set(approvers))))
        if priority == "P1":
            acts.append(Action("notify", f"Notificacion inmediata a {team} + AppSec (SLA {C.SLA['P1']})", True))
            if g.internet_facing:
                acts.append(Action("temp_mitigation", "Mitigacion temporal (regla WAF / feature flag) "
                                   "mientras se despliega el fix", False, [f"Team Lead ({team})"]))

    # ---------- CODIGO: SAST (codigo propio) ----------
    elif f.category == "code":
        acts.append(Action("open_ticket", f"Ticket a {team} con ubicacion y CWE; la IA redacta un "
                           "borrador de fix (draft PR)", True))
        acts.append(Action("merge", "Fix de codigo propio: revision obligatoria", False,
                           [f"Team Lead ({team})", "AppSec"]))

    # ---------- SO: sin superficie viva ----------
    elif g.running_tasks == 0:
        acts.append(Action("block_redeploy", "Politica de admision: bloquear despliegue de esta imagen "
                           "hasta re-escaneo limpio (reversible)", True))
        msg = "Proponer RETIRO de la imagen en lugar de parchar"
        if "verify_scheduled_jobs" in flags:
            msg += " (verificar antes cron/batch: runningTasks=0 en el escaneo no prueba desuso)"
        acts.append(Action("retire_image", msg, False, [f"Team Lead ({team})"]))
        acts.append(Action("reopen_rule", "Si se reactiva: reabrir y re-priorizar sin multiplicador", True))

    # ---------- SO: imagen base (causa raiz) ----------
    elif g.root_cause:
        acts.append(Action("open_pr", f"PR al Dockerfile de {g.root_cause}: {f.package_name} -> "
                           f"{f.fixed_version} y rebuild", True))
        acts.append(Action("rollout", f"Rollout escalonado (canary -> resto) de {g.root_cause} y rebuild de "
                           f"~{g.images_affected or '?'} imagenes hijas", False,
                           ["DevOps/Platform"] + (["AppSec"] if priority == "P1" else [])))
        acts.append(Action("open_ticket", "Un ticket de plataforma (no " + str(len(g.findings) +
                           (g.images_affected or 0)) + " tickets); instancias enlazadas", True))

    # ---------- SO: hosts / kernel ----------
    elif f.asset.get("host"):
        acts.append(Action("open_ticket", f"Ticket a {team}: actualizar {f.package_name} a {f.fixed_version}", True))
        acts.append(Action("patch_hosts", "Parche + reinicio rolling en ventana de mantenimiento", False,
                           ["DevOps/Platform"]))
    else:
        acts.append(Action("open_ticket", f"Ticket a {team} para actualizar {f.package_name}", True))
        acts.append(Action("patch_image", "Rebuild/redeploy de la imagen", False, ["DevOps/Platform"]))

    if "needs_enrichment" in flags:
        acts.append(Action("request_enrichment", "Pedir al dueno completar CMDB (entorno/exposicion)", True))
    if "assumption_base_image_lineage" in flags:
        acts.append(Action("verify_lineage", "Confirmar herencia de imagen base via historial de capas/SBOM "
                           "(hoy es un supuesto)", True))
    acts.append(Action("verify_and_close", "Cerrar SOLO cuando el re-escaneo confirme que desaparecio "
                       "(por instancia)", True))
    return acts


def evaluate_gate(decisions: list[Decision], baseline_path: Path | None = None) -> tuple[list[Decision], int]:
    """Evalua el gate de CI.

    - Sin `baseline_path`: bloquea ante cualquier P1/P2 accionable.
    - Con `baseline_path` (report.json previo): modo diferencial; solo bloquea si un P1/P2 es NUEVO
      o si su prioridad EMPEORO respecto al baseline (evita frenar PRs ajenos por deuda historica).
    Devuelve (decisiones_bloqueantes, cantidad_suprimida_por_baseline).
    """
    candidates = [d for d in decisions if d.priority in ("P1", "P2")]
    if not baseline_path:
        return candidates, 0

    data = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    known: dict[str, str] = {}
    for item in data.get("decisions", data if isinstance(data, list) else []):
        prio = item.get("priority")
        if not prio:
            continue
        if item.get("group_id"):
            known[item["group_id"]] = prio
        for fid in item.get("finding_ids", []):
            known[fid] = prio

    blocking: list[Decision] = []
    suppressed = 0
    for d in candidates:
        prev_prios = [known[fid] for fid in d.finding_ids if fid in known]
        if not prev_prios and d.group_id in known:
            prev_prios = [known[d.group_id]]
        if not prev_prios or len(prev_prios) < len(d.finding_ids):
            blocking.append(d)  # hallazgo nuevo no registrado en el baseline
        elif any(C.PRIORITY_ORDER[d.priority] < C.PRIORITY_ORDER[p] for p in prev_prios):
            blocking.append(d)  # se agravo (ej. era P3 y salio exploit publico -> P1)
        else:
            suppressed += 1
    return blocking, suppressed

