"""Etapa 8 (dry-run): materializa las acciones como artefactos revisables y genera el reporte.

En produccion estas funciones llamarian a la API de GitHub/Jira/Slack con un token de
minimo privilegio (puede abrir PRs y tickets; NO puede hacer merge en ramas protegidas ni desplegar).
"""
from __future__ import annotations

import json
from pathlib import Path

from .models import Decision


def write_action_artifacts(decisions: list[Decision], out_dir: Path) -> None:
    base = Path(out_dir) / "actions"
    base.mkdir(parents=True, exist_ok=True)
    for d in decisions:
        llm = (d.llm or {}).get("accepted") or {}
        for i, a in enumerate(d.actions, 1):
            if a.type not in ("open_pr", "open_ticket", "alert_appsec", "close_not_applicable", "retire_image"):
                continue
            path = base / f"{d.group_id}__{i:02d}_{a.type}.md"
            title = llm.get("pr_title") if a.type == "open_pr" and llm.get("pr_title") else \
                f"[{d.priority}] {d.title}"
            body = [f"# {title}", "",
                    f"- **Hallazgos:** {', '.join(d.finding_ids)}",
                    f"- **Prioridad:** {d.priority} (score {d.score}) · **SLA:** {d.sla}",
                    f"- **Dueno:** {d.owner} · **Destino:** {d.route}",
                    f"- **Accion:** {a.description}",
                    f"- **Autonoma:** {'si' if a.autonomous else 'no — aprueba: ' + ', '.join(a.approvers)}",
                    "", "## Por que", *[f"- {r}" for r in d.rationale]]
            if llm.get("summary"):
                body += ["", "## Resumen (IA, validado por guardrails)", llm["summary"]]
            if d.flags:
                body += ["", "## Flags", *[f"- `{x}`" for x in d.flags]]
            body += ["", "> Generado por vuln-pipeline (dry-run). El cierre solo ocurre tras re-escaneo limpio."]
            path.write_text("\n".join(body), encoding="utf-8")
            a.artifact = str(path.relative_to(Path(out_dir)))


def _actions_short(d: Decision) -> str:
    parts = []
    for a in d.actions:
        if a.type in ("verify_and_close", "schedule_review", "reopen_rule", "request_enrichment",
                      "verify_lineage", "verify_build"):
            continue
        parts.append(a.type + ("" if a.autonomous else "*"))
    return ", ".join(parts)


def console_table(decisions: list[Decision]) -> str:
    rows = [("GRUPO", "PRIO", "SCORE", "SLA", "DUENO", "ACCIONES (*=requiere humano)", "FLAGS")]
    for d in decisions:
        key_flags = [f for f in d.flags if f in ("tampering_suspected", "llm_downgrade_rejected",
                                                 "llm_missed_injection", "llm_hallucinated_version",
                                                 "needs_enrichment", "verify_scheduled_jobs",
                                                 "assumption_base_image_lineage")]
        rows.append((d.group_id, d.priority, f"{d.score:.1f}", d.sla.split(" ")[0], d.owner,
                     _actions_short(d), ",".join(key_flags) or "-"))
    widths = [min(max(len(str(r[i])) for r in rows), 60) for i in range(len(rows[0]))]
    line = "-+-".join("-" * w for w in widths)
    out = []
    for n, r in enumerate(rows):
        out.append(" | ".join(str(c)[:widths[i]].ljust(widths[i]) for i, c in enumerate(r)))
        if n == 0:
            out.append(line)
    return "\n".join(out)


def write_reports(result: dict, out_dir: Path) -> None:
    out_dir = Path(out_dir)
    decisions = result["decisions"]
    (out_dir / "report.json").write_text(json.dumps(
        {"run_id": result["run_id"], "errors": result["errors"],
         "decisions": [d.to_dict() for d in decisions]}, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8")

    md = [f"# Reporte de triage — run `{result['run_id']}`", "",
          "| Grupo | Prioridad | Score | SLA | Dueno | Acciones |", "|---|---|---|---|---|---|"]
    for d in decisions:
        md.append(f"| {d.group_id} | **{d.priority}** | {d.score} | {d.sla} | {d.owner} | {_actions_short(d)} |")
    md.append("\n`*` = requiere aprobacion humana\n")
    for d in decisions:
        md += [f"## {d.group_id} — {d.priority}: {d.title}", "",
               f"**Destino:** {d.route} · **Dueno:** {d.owner} · **SLA:** {d.sla}", "", "**Por que:**",
               *[f"- {r}" for r in d.rationale], "", "**Acciones:**"]
        for a in d.actions:
            who = "autonoma" if a.autonomous else "aprueba " + ", ".join(a.approvers)
            md.append(f"- `{a.type}` ({who}): {a.description}")
        if d.score_breakdown:
            b = d.score_breakdown
            md += ["", f"**Score:** severidad {b['severity']} + explotacion {b['exploitability']} "
                       f"({b['exploitability_reason']}) + exposicion {b['exposure']} + entorno {b['environment']} "
                       f"+ contexto {b['context']} ({b['context_reason']}) + radio {b['blast_radius_bonus']} "
                       f"= {b['base']} × {b['multiplier']} = **{b['total']}**"]
        if d.flags:
            md += ["", "**Flags:** " + ", ".join(f"`{x}`" for x in d.flags)]
        md.append("")
    (out_dir / "report.md").write_text("\n".join(md), encoding="utf-8")
