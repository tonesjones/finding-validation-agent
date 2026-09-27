"""Reconcile SCA findings against what is actually resolved/installed.

The scanner's component version is what IT saw (often the floor of a declared
range when there is no lockfile). The inventory is what the tested runtime uses.

Status -> evidence stance:
  scanned_version_present   neutral  (present is not the same as exploitable)
  version_drift             refutes  (name installed, scanned version is not)
  not_installed             refutes
  unresolved_name           neutral  (can't map the scanner's component name)
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from fva.langpacks.base import InstalledPackage
from fva.schemas import EvidenceRecord, EvidenceType, Finding, Stance

_NS = uuid.UUID("7c2d9a41-5e3b-4f8a-9b61-0e4c3d2a1f77")

# Scanner component names that differ from the ecosystem package name.
# Keyed by (source_tool, component name). Extend as new ones appear; never guess.
NAME_ALIASES: dict[tuple[str, str], str] = {
    ("polaris", "Auth0_node-jsonwebtoken"): "jsonwebtoken",
    ("polaris", "expressjsmorgan"): "morgan",
    ("polaris", "node-glob"): "glob",
}


@dataclass(frozen=True)
class DependencyResult:
    finding_id: str
    status: str
    package: str | None
    scanned_version: str | None
    installed_versions: tuple[str, ...]
    dev_only: bool | None


def reconcile(f: Finding, inventory: list[InstalledPackage]) -> DependencyResult:
    if f.package is None:
        return DependencyResult(f.finding_id, "unresolved_name", None, None, (), None)
    by_name: dict[str, list[InstalledPackage]] = {}
    for p in inventory:
        by_name.setdefault(p.name, []).append(p)
    name = NAME_ALIASES.get((f.source_tool, f.package.name), f.package.name)
    if name not in by_name:
        # Absence is only trusted when the name is known to be an ecosystem name (aliased, or the
        # scanner declared an ecosystem). A raw vendor spelling we can't map stays unresolved.
        trusted = name != f.package.name or f.package.ecosystem is not None
        return DependencyResult(f.finding_id, "not_installed" if trusted else "unresolved_name",
                                name, f.package.version, (), None)
    inst = by_name[name]
    versions = tuple(sorted({p.version for p in inst}))
    matching = [p for p in inst if p.version == f.package.version]
    status = "scanned_version_present" if matching else "version_drift"
    dev_only = all(p.dev for p in (matching or inst))
    return DependencyResult(f.finding_id, status, name, f.package.version, versions, dev_only)


_STANCE = {"scanned_version_present": Stance.neutral, "version_drift": Stance.refutes,
           "not_installed": Stance.refutes, "unresolved_name": Stance.neutral}


def to_evidence(r: DependencyResult, *, inventory_ref: str, profile_id: str | None = None) -> EvidenceRecord:
    msg = {
        "scanned_version_present": f"{r.package} {r.scanned_version} is present in the resolved inventory",
        "version_drift": f"{r.package}: scanner saw {r.scanned_version}; resolved inventory has {', '.join(r.installed_versions)}",
        "not_installed": f"{r.package} is not in the resolved inventory",
        "unresolved_name": f"Cannot map scanner component name to an installed package ({r.package})",
    }[r.status]
    if r.dev_only:
        msg += " (dev dependency only)"
    return EvidenceRecord(
        evidence_id=str(uuid.uuid5(_NS, f"{r.finding_id}:{inventory_ref}")), finding_ids=(r.finding_id,),
        evidence_type=EvidenceType.dependency_resolution, method=f"inventory:{r.status}",
        stance=_STANCE[r.status], summary=msg, detail_ref=inventory_ref, deployment_profile_id=profile_id,
        collected_at=datetime.now(timezone.utc))
