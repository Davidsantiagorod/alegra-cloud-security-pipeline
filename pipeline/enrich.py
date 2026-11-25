"""Etapa 4: enriquecimiento con CMDB (dueno, entorno, exposicion) y threat intel (EPSS/KEV).

Regla: si un dato de contexto falta en el escaner y en la CMDB, se asume el PEOR CASO
y se marca `needs_enrichment` para que el dueno complete el inventario.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Finding

REACHABILITY_PATTERNS = [r"\bis called from\b", r"\bcalled from\b", r"\breachable\b",
                         r"\binvoked (from|by)\b", r"\buser[- ]controlled\b", r"\bconcatenated into\b"]


class Context:
    def __init__(self, inventory_path: Path, intel_path: Path):
        inv = json.loads(Path(inventory_path).read_text(encoding="utf-8"))
        self.services = inv.get("services", {})
        self.base_images = inv.get("baseImages", {})
        intel = json.loads(Path(intel_path).read_text(encoding="utf-8"))
        self.kev = set(intel.get("kev", []))
        self.epss = intel.get("epss", {})
        self.intel_date = intel.get("snapshotDate")


def _asset_name(asset: dict) -> str | None:
    for key in ("repo", "service", "host"):
        if asset.get(key):
            return asset[key]
    if asset.get("image"):
        return asset["image"].split(":")[0]
    if asset.get("baseImage"):
        return asset["baseImage"]
    return None


def enrich(f: Finding, ctx: Context) -> Finding:
    a = f.asset
    f.asset_name = _asset_name(a)
    cmdb = ctx.services.get(f.asset_name or "", {})
    is_base_image = bool(a.get("baseImage"))
    base_meta = ctx.base_images.get(a.get("baseImage", ""), {})

    # Dueno
    f.team = a.get("team") or cmdb.get("team") or base_meta.get("owner")
    f.add_evidence("team", f.team, "scanner" if a.get("team") else "cmdb")

    # Entorno
    if a.get("environment"):
        f.environment = a["environment"]
        f.add_evidence("environment", f.environment, "scanner")
    elif cmdb.get("environment"):
        f.environment = cmdb["environment"]
        f.add_evidence("environment", f.environment, "cmdb")
    else:
        f.flag("needs_enrichment")

    # Exposicion
    if "internetFacing" in a:
        f.internet_facing = bool(a["internetFacing"])
        f.add_evidence("internetFacing", f.internet_facing, "scanner")
    elif "internetFacing" in cmdb:
        f.internet_facing = bool(cmdb["internetFacing"])
        f.add_evidence("internetFacing", f.internet_facing, "cmdb")
    elif is_base_image:
        f.flag("exposure_from_downstream")  # se resuelve al correlacionar con instancias
    else:
        f.flag("needs_enrichment")

    # Superficie viva / radio de impacto
    f.running_tasks = a.get("runningTasks")
    f.images_affected = a.get("imagesAffected")
    f.hosts_affected = a.get("hostsAffected")
    # La herencia de imagen base solo es relevante para hallazgos de SO
    f.base_image = a.get("baseImage") or (cmdb.get("baseImage") if f.category == "os" else None)
    if f.category == "os" and cmdb.get("baseImage") and not a.get("baseImage"):
        f.add_evidence("baseImage", cmdb["baseImage"], "cmdb",
                       trusted=cmdb.get("baseImageSource") != "assumed")
        if cmdb.get("baseImageSource") == "assumed":
            f.flag("assumption_base_image_lineage")
    if cmdb.get("workloadType") == "batch-worker":
        f.flag("verify_scheduled_jobs")
    f.runtime_os = cmdb.get("runtimeOs") or base_meta.get("runtimeOs")

    # Presencia en runtime: devDependency + build que excluye devDeps => build-only
    if f.scope == "devDependency":
        f.runtime_presence = "build-only"
        f.add_evidence("package.scope", "devDependency", "scanner")
        if cmdb.get("buildExcludesDevDependencies"):
            f.add_evidence("buildExcludesDevDependencies", True, "cmdb")
        else:
            f.flag("verify_devdep_not_in_runtime_artifact")

    # Alcanzabilidad: el texto libre SOLO puede subir el riesgo (nunca bajarlo)
    notes = f.free_text.get("notes", "")
    if any(re.search(p, notes, re.I) for p in REACHABILITY_PATTERNS):
        f.reachable = True
        f.add_evidence("notes", "funcion vulnerable alcanzable (solo puede subir riesgo)",
                       "free-text", trusted=False)

    # Threat intel
    if f.cve:
        f.kev = f.cve in ctx.kev
        f.epss = ctx.epss.get(f.cve)
        if f.epss is not None:
            f.add_evidence("epss", f.epss, f"threat-intel@{ctx.intel_date}")
        if f.kev:
            f.add_evidence("kev", True, f"threat-intel@{ctx.intel_date}")
    if f.exploit_public:
        f.add_evidence("exploitPublic", True, "scanner")
    return f
