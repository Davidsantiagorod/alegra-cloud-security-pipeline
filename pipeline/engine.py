"""Orquestador: ejecuta las etapas en orden y registra cada decision en el log de auditoria."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from . import config as C
from .applicability import assess
from .audit import AuditLog
from .dedup import group_findings
from .enrich import Context, enrich
from .ingest import load
from .llm_agent import apply_guardrails, build_context, get_provider
from .models import Decision
from .policy import owner_and_route, plan
from .sanitize import sanitize
from .scoring import prioritize


def run(inputs: list[Path], inventory: Path, intel: Path, out_dir: Path, llm: str = "mock") -> dict:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    audit = AuditLog(out_dir / "audit.jsonl")
    provider = get_provider(llm)
    ctx = Context(inventory, intel)

    # 1. Ingesta + normalizacion
    findings, errors = load(inputs)
    for f in findings:
        audit.write("ingest", f.id, {"source": f.source, "input_sha256": hashlib.sha256(
            json.dumps(f.raw, sort_keys=True).encode()).hexdigest()})
    for e in errors:
        audit.write("ingest_error", "-", {"error": e})

    # 2-4. Sanitizacion + enriquecimiento
    for f in findings:
        sanitize(f)
        enrich(f, ctx)
        audit.write("sanitize_enrich", f.id, {"flags": f.flags})

    # 3. Dedup / causa raiz
    groups = group_findings(findings)
    for g in groups:
        if len(g.findings) > 1:
            audit.write("dedup", g.id, {"notes": g.notes, "root_cause": g.root_cause})

    decisions: list[Decision] = []
    for g in groups:
        # 5. Aplicabilidad (evidencia estructurada por instancia)
        results = [assess(f) for f in g.findings]
        applicable = any(r[0] for r in results)
        reasons = list(dict.fromkeys(r for res in results for r in res[1]))

        # 6. Scoring
        if applicable:
            priority, score, breakdown, notes = prioritize(g)
        else:
            priority, score, breakdown, notes = "N/A", 0.0, {}, []

        # IA acotada: sugiere, los guardrails validan
        llm_result, llm_flags = None, []
        if provider is not None:
            lctx = build_context(g, priority)
            try:
                raw = provider.analyze(lctx)
            except Exception as exc:  # degradacion segura: la decision no depende del LLM
                raw, llm_flags = None, ["llm_unavailable"]
                llm_result = {"provider": provider.name, "error": str(exc)}
            if raw is not None:
                clean, new_prio, llm_flags = apply_guardrails(raw, lctx, priority)
                if applicable and new_prio != priority:
                    notes.append(f"IA sugirio subir {priority} -> {new_prio} (pendiente de revision)")
                    priority = new_prio
                llm_result = {"provider": provider.name, "prompt_version": C.PROMPT_VERSION,
                              "raw": raw, "accepted": clean}
            for fl in llm_flags:
                for f in g.findings:
                    f.flag(fl)

        owner, route = owner_and_route(g)
        actions = plan(g, priority, applicable, reasons)
        d = Decision(
            group_id=g.id, finding_ids=[f.id for f in g.findings], category=g.lead.category,
            title=g.lead.title, priority=priority, score=score, score_breakdown=breakdown,
            sla=C.SLA[priority], applicable=applicable, owner=owner, route=route,
            rationale=g.notes + reasons + notes, actions=actions, flags=g.flags,
            evidence=[asdict(e) | {"finding": f.id} for f in g.findings for e in f.evidence],
            llm=llm_result,
        )
        decisions.append(d)
        audit.write("decision", g.id, {
            "priority": priority, "score": score, "breakdown": breakdown, "flags": d.flags,
            "actions": [{"type": a.type, "autonomous": a.autonomous, "approvers": a.approvers}
                        for a in actions],
            "llm_provider": getattr(provider, "name", None), "prompt_version": C.PROMPT_VERSION,
        })

    decisions.sort(key=lambda d: (C.PRIORITY_ORDER[d.priority], -d.score))
    return {"run_id": audit.run_id, "decisions": decisions, "errors": errors,
            "audit_path": str(audit.path)}
