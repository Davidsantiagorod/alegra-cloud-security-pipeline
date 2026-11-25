"""Etapa 6: scoring determinista + reglas duras (suelos) + SLA."""
from __future__ import annotations

from . import config as C
from .dedup import Group


def exploit_points(g: Group) -> tuple[float, str]:
    options = [(C.W_EXPLOIT_FLOOR, "sin datos de explotacion")]
    if g.kev:
        options.append((C.W_EXPLOIT_KEV, "en CISA KEV"))
    if g.exploit_public:
        options.append((C.W_EXPLOIT_PUBLIC, "exploit publico"))
    if g.epss is not None:
        pts = C.W_EXPLOIT_EPSS_HIGH if g.epss >= 0.5 else C.W_EXPLOIT_FLOOR + 15 * (g.epss / 0.5)
        options.append((pts, f"EPSS={g.epss}"))
    return max(options, key=lambda o: o[0])


def score_group(g: Group) -> tuple[float, dict, list[str]]:
    notes: list[str] = []
    severity = g.cvss / 10 * C.W_SEVERITY
    exploit, exploit_reason = exploit_points(g)
    exposure = C.EXPOSURE[g.internet_facing]
    if g.internet_facing is None:
        notes.append("exposicion desconocida: se asume internet-facing (peor caso)")
    env = C.ENVIRONMENT.get(g.environment, C.ENVIRONMENT[None])
    if g.environment is None:
        notes.append("entorno desconocido: se asume production (peor caso)")

    if g.runtime_presence == "build-only":
        ctx_key = "build-only"
    elif g.reachable:
        ctx_key = "reachable"
    else:
        ctx_key = "runtime"
    context = C.CONTEXT[ctx_key]

    blast = 0
    if (g.images_affected or 0) >= 10 or (g.running_tasks or 0) >= 50 or (g.hosts_affected or 0) >= 5:
        blast = C.BLAST_RADIUS_BONUS

    base = severity + exploit + exposure + env + context + blast
    mult = 1.0
    if g.runtime_presence == "build-only":
        mult *= C.MULT_BUILD_ONLY
        notes.append("devDependency: no llega al artefacto de produccion (x0.5)")
    if g.running_tasks == 0:
        mult *= C.MULT_NOT_RUNNING
        notes.append("runningTasks=0: sin superficie viva hoy (x0.3)")
    total = min(100.0, round(base * mult, 1))

    breakdown = {
        "severity": round(severity, 1),
        "exploitability": round(exploit, 1), "exploitability_reason": exploit_reason,
        "exposure": exposure, "environment": env,
        "context": context, "context_reason": ctx_key,
        "blast_radius_bonus": blast, "multiplier": mult,
        "base": round(base, 1), "total": total,
    }
    return total, breakdown, notes


def priority_from_score(score: float) -> str:
    for threshold, prio in C.THRESHOLDS:
        if score >= threshold:
            return prio
    return "P4"


def stricter(a: str, b: str) -> str:
    return a if C.PRIORITY_ORDER[a] <= C.PRIORITY_ORDER[b] else b


def apply_floors(g: Group, prio: str) -> tuple[str, list[str]]:
    """Reglas duras: SOLO pueden subir la prioridad."""
    notes = []
    live = g.running_tasks != 0
    if ((g.kev or g.exploit_public) and g.environment == "production" and g.internet_facing is True
            and g.runtime_presence == "runtime" and live):
        new = stricter(prio, "P1")
        if new != prio:
            notes.append("regla dura: exploit + produccion + internet-facing => minimo P1")
        prio = new
    if g.kev:
        new = stricter(prio, "P2")
        if new != prio:
            notes.append("regla dura: CISA KEV => minimo P2")
        prio = new
    return prio, notes


def prioritize(g: Group) -> tuple[str, float, dict, list[str]]:
    score, breakdown, notes = score_group(g)
    prio = priority_from_score(score)
    prio, floor_notes = apply_floors(g, prio)
    return prio, score, breakdown, notes + floor_notes
