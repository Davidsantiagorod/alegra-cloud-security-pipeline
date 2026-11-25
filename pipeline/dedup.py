"""Etapa 3: deduplicacion y agrupacion por causa raiz.

- Clave OS:   CVE + paquete + distro + version  (mismo paquete vulnerable en distintos activos)
- Clave code: CVE/CWE + paquete/ubicacion + version + repo
Un grupo se corrige UNA vez (en la causa raiz) pero se cierra POR INSTANCIA tras re-escaneo.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import Finding


@dataclass
class Group:
    key: tuple
    findings: list = field(default_factory=list)
    root_cause: str | None = None
    notes: list = field(default_factory=list)

    @property
    def id(self) -> str:
        return "+".join(f.id for f in self.findings)

    @property
    def lead(self) -> Finding:
        return self.findings[0]

    # ---- atributos agregados (peor caso entre instancias) ----
    @property
    def cvss(self) -> float:
        return max(f.cvss for f in self.findings)

    @property
    def exploit_public(self) -> bool:
        return any(f.exploit_public for f in self.findings)

    @property
    def kev(self) -> bool:
        return any(f.kev for f in self.findings)

    @property
    def epss(self):
        vals = [f.epss for f in self.findings if f.epss is not None]
        return max(vals) if vals else None

    @property
    def internet_facing(self):
        vals = [f.internet_facing for f in self.findings]
        if any(v is True for v in vals):
            return True
        if all(v is False for v in vals):
            return False
        return None

    @property
    def environment(self):
        envs = [f.environment for f in self.findings if f.environment]
        if "production" in envs:
            return "production"
        return envs[0] if envs else None

    @property
    def reachable(self) -> bool:
        return any(f.reachable for f in self.findings)

    @property
    def runtime_presence(self) -> str:
        return "runtime" if any(f.runtime_presence == "runtime" for f in self.findings) else "build-only"

    @property
    def running_tasks(self):
        vals = [f.running_tasks for f in self.findings if f.running_tasks is not None]
        if not vals:
            return None
        # Si alguna instancia sin dato es un servicio vivo detectado por host-scanner, hay superficie viva
        return max(vals)

    @property
    def images_affected(self):
        vals = [f.images_affected for f in self.findings if f.images_affected is not None]
        return max(vals) if vals else None

    @property
    def hosts_affected(self):
        vals = [f.hosts_affected for f in self.findings if f.hosts_affected is not None]
        return max(vals) if vals else None

    @property
    def flags(self) -> list:
        out = []
        for f in self.findings:
            for fl in f.flags:
                if fl not in out:
                    out.append(fl)
        if self.internet_facing is not None and "exposure_from_downstream" in out:
            out.remove("exposure_from_downstream")
        return out


def dedup_key(f: Finding) -> tuple:
    if f.category == "os":
        return ("os", f.cve, f.package_name, f.distro, f.version)
    loc = f.package_name or (f.raw.get("location") or {}).get("file")
    return ("code", f.cve or f.cwe, loc, f.version, f.asset_name)


def group_findings(findings: list[Finding]) -> list[Group]:
    groups: dict[tuple, Group] = {}
    for f in findings:
        k = dedup_key(f)
        groups.setdefault(k, Group(key=k)).findings.append(f)

    for g in groups.values():
        if len(g.findings) > 1:
            # Completar fixedVersion faltante desde otra instancia del mismo paquete/version
            fixed = next((f.fixed_version for f in g.findings if f.fixed_version), None)
            for f in g.findings:
                if not f.fixed_version and fixed:
                    f.fixed_version = fixed
                    f.add_evidence("fixedVersion", fixed, "correlation")
            g.notes.append(f"{len(g.findings)} reportes de {len({f.source for f in g.findings})} "
                           f"escaneres colapsados en 1 hallazgo")
        # Causa raiz: imagen base si alguna instancia la declara o la CMDB la vincula
        bases = {f.base_image for f in g.findings if f.base_image}
        if g.lead.category == "os" and len(bases) == 1:
            g.root_cause = bases.pop()
            g.notes.append(f"causa raiz: imagen base {g.root_cause}")
        # Ordenar: el reporte con imagen base primero (es la unidad de correccion)
        g.findings.sort(key=lambda f: (0 if f.asset.get("baseImage") else 1, f.id))
    return list(groups.values())
