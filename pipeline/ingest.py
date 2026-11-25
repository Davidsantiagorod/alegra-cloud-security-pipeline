"""Etapa 1: ingesta y normalizacion de escaneres heterogeneos a un esquema unico."""
from __future__ import annotations

import json
from pathlib import Path

from .models import Finding

FREE_TEXT_FIELDS = ("title", "notes", "advisoryDescription", "description")
VALID_CATEGORIES = ("code", "os")


class IngestError(ValueError):
    pass


def _validate(raw: dict) -> None:
    if not isinstance(raw, dict):
        raise IngestError("finding no es un objeto JSON")
    for key in ("id", "source", "category", "cvss"):
        if key not in raw:
            raise IngestError(f"{raw.get('id', '?')}: falta el campo obligatorio '{key}'")
    if raw["category"] not in VALID_CATEGORIES:
        raise IngestError(f"{raw['id']}: category invalida '{raw['category']}'")
    cvss = raw["cvss"]
    if not isinstance(cvss, (int, float)) or not 0 <= cvss <= 10:
        raise IngestError(f"{raw['id']}: cvss fuera de rango")


def normalize(raw: dict) -> Finding:
    _validate(raw)
    pkg = raw.get("package") or {}
    return Finding(
        id=raw["id"],
        source=raw["source"],
        category=raw["category"],
        cve=raw.get("cve"),
        cwe=raw.get("cwe"),
        cvss=float(raw["cvss"]),
        title=raw.get("title", ""),
        package_name=pkg.get("name"),
        ecosystem=pkg.get("ecosystem"),
        distro=pkg.get("distro"),
        version=pkg.get("version"),
        fixed_version=pkg.get("fixedVersion"),
        scope=pkg.get("scope"),
        platforms=pkg.get("platforms"),
        exploit_public=bool(raw.get("exploitPublic", False)),
        asset=raw.get("asset") or {},
        free_text={k: raw[k] for k in FREE_TEXT_FIELDS if isinstance(raw.get(k), str)},
        raw=raw,
    )


def load(paths: list[Path]) -> tuple[list[Finding], list[str]]:
    """Carga uno o mas archivos. Devuelve (findings validos, errores). Un registro invalido no tumba el lote."""
    findings, errors = [], []
    for path in paths:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        for raw in data:
            try:
                findings.append(normalize(raw))
            except IngestError as exc:
                errors.append(str(exc))
    return findings, errors
