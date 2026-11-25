"""Etapa 5: filtro de aplicabilidad (alcance: solo Linux).

Un hallazgo solo se declara N/A con EVIDENCIA ESTRUCTURADA (campo del escaner, SBOM, CMDB).
El texto libre del advisory nunca es evidencia suficiente.
"""
from __future__ import annotations

from .config import CROSS_PLATFORM_ECOSYSTEMS, LINUX_DISTROS
from .models import Finding


def assess(f: Finding) -> tuple[bool, list[str]]:
    """Devuelve (aplicable, razones)."""
    reasons: list[str] = []

    # 1) Campo estructurado de plataformas del paquete
    if f.platforms:
        plats = [p.lower() for p in f.platforms]
        if "linux" not in plats:
            reasons.append(f"package.platforms={f.platforms} (estructurado) excluye Linux")
            return False, reasons
        reasons.append(f"package.platforms incluye linux")

    # 2) Runtime del activo segun CMDB
    if f.runtime_os and f.runtime_os.lower() != "linux":
        reasons.append(f"CMDB runtimeOs={f.runtime_os}: fuera de alcance (solo Linux)")
        return False, reasons

    # 3) Paquete de distro Linux o ecosistema multiplataforma
    if f.distro and f.distro.lower().startswith(LINUX_DISTROS):
        reasons.append(f"paquete de distro Linux ({f.distro})")
    elif f.ecosystem and f.ecosystem.lower() in CROSS_PLATFORM_ECOSYSTEMS:
        reasons.append(f"ecosistema multiplataforma ({f.ecosystem}) desplegado en runtime "
                       f"{f.runtime_os or 'desconocido (se asume linux)'}")
    elif f.category == "code" and not f.package_name:
        reasons.append("hallazgo SAST en codigo propio desplegado en Linux")
    else:
        reasons.append("plataforma indeterminada: se asume aplicable (peor caso)")
        f.flag("needs_enrichment")

    if "unverified_platform_claim" in f.flags:
        reasons.append("el advisory afirma 'no aplica a Linux' pero NINGUN campo estructurado lo respalda: se ignora")
    return True, reasons
