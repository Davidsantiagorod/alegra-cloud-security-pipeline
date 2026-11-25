"""Modelos de datos del pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional


@dataclass
class Evidence:
    """Un hecho usado para decidir. `trusted` = viene de un campo estructurado o fuente autenticada."""
    field: str
    value: Any
    source: str          # scanner | cmdb | threat-intel | correlation | free-text
    trusted: bool = True


@dataclass
class Finding:
    id: str
    source: str
    category: str                    # code | os
    cve: Optional[str]
    cwe: Optional[str]
    cvss: float
    title: str
    package_name: Optional[str]
    ecosystem: Optional[str]
    distro: Optional[str]
    version: Optional[str]
    fixed_version: Optional[str]
    scope: Optional[str]             # devDependency | None
    platforms: Optional[list]
    exploit_public: bool
    asset: dict
    free_text: dict                  # campos de texto libre NO confiables
    raw: dict

    # --- enriquecimiento ---
    asset_name: Optional[str] = None
    team: Optional[str] = None
    environment: Optional[str] = None
    internet_facing: Optional[bool] = None
    running_tasks: Optional[int] = None
    images_affected: Optional[int] = None
    hosts_affected: Optional[int] = None
    base_image: Optional[str] = None
    runtime_os: Optional[str] = None
    runtime_presence: str = "runtime"  # runtime | build-only
    reachable: bool = False
    epss: Optional[float] = None
    kev: bool = False
    flags: list = field(default_factory=list)
    evidence: list = field(default_factory=list)

    def flag(self, name: str) -> None:
        if name not in self.flags:
            self.flags.append(name)

    def add_evidence(self, field_: str, value: Any, source: str, trusted: bool = True) -> None:
        self.evidence.append(Evidence(field_, value, source, trusted))


@dataclass
class Action:
    type: str
    description: str
    autonomous: bool
    approvers: list = field(default_factory=list)
    artifact: Optional[str] = None


@dataclass
class Decision:
    group_id: str
    finding_ids: list
    category: str
    title: str
    priority: str
    score: float
    score_breakdown: dict
    sla: str
    applicable: bool
    owner: str
    route: str
    rationale: list = field(default_factory=list)
    actions: list = field(default_factory=list)
    flags: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    llm: Optional[dict] = None

    def to_dict(self) -> dict:
        return asdict(self)
