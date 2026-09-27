"""Rule-based static reachability. Output is ALWAYS `reachability` evidence, kept separate
from runtime evidence, and never strong enough to confirm a finding on its own.

SAST: is the finding's file in the import graph rooted at the profile's entrypoints?
SCA:  is the package imported by shipped code, only by tests/tooling, or not at all?
"""
from __future__ import annotations

import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from fva.correlation.dependency import package_name
from fva.langpacks import REGISTRY
from fva.schemas import (DeploymentProfile, EvidenceRecord, EvidenceType, Finding, FindingType, Stance)
from fva.surface import classify_path, is_deployed

_NS = uuid.UUID("3f9b2c11-8d4e-4a67-a2b5-6c7d8e9f0a12")


@dataclass
class CodeGraph:
    files: set[str]
    edges: dict[str, set[str]] = field(default_factory=dict)  # file -> local files it imports
    package_uses: dict[str, list[tuple[str, int]]] = field(default_factory=dict)  # pkg -> [(file, line)]
    reachable: set[str] = field(default_factory=set)
    parents: dict[str, str] = field(default_factory=dict)  # BFS tree for explaining a path

    def path_to(self, f: str, limit: int = 8) -> list[str]:
        chain = [f]
        while chain[-1] in self.parents and len(chain) < limit:
            chain.append(self.parents[chain[-1]])
        return list(reversed(chain))


def build_graph(root: Path, files: list[str], profile: DeploymentProfile) -> CodeGraph:
    packs = [REGISTRY[n] for n in profile.language_packs]
    fset = set(files)
    g = CodeGraph(files=fset)
    for rel in files:
        pack = next((p for p in packs if rel.endswith(p.source_suffixes)), None)
        if pack is None:
            continue
        try:
            text = (Path(root) / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        deps = set()
        for spec, line in pack.imports(text):
            local = pack.resolve_local(spec, rel, fset)
            if local:
                deps.add(local)
                continue
            pkg = pack.package_of(spec)
            if pkg:
                g.package_uses.setdefault(pkg, []).append((rel, line))
        g.edges[rel] = deps
    queue = deque(e for e in profile.entrypoints if e in fset)
    g.reachable.update(queue)
    while queue:
        cur = queue.popleft()
        for nxt in g.edges.get(cur, ()):
            if nxt not in g.reachable:
                g.reachable.add(nxt)
                g.parents[nxt] = cur
                queue.append(nxt)
    return g


@dataclass(frozen=True)
class ReachResult:
    finding_id: str
    status: str
    detail: str
    sites: tuple[str, ...] = ()


def assess(f: Finding, g: CodeGraph, profile: DeploymentProfile, *, declared_direct: set[str] | None = None) -> ReachResult:
    if f.finding_type is FindingType.sast:
        if f.location is None:
            return ReachResult(f.finding_id, "unknown", "no source location")
        p = f.location.path
        if p in g.reachable:
            return ReachResult(f.finding_id, "in_entrypoint_graph", " -> ".join(g.path_to(p)))
        if p not in g.edges:
            return ReachResult(f.finding_id, "not_code", "file is not source code the import graph covers")
        return ReachResult(f.finding_id, "not_in_entrypoint_graph",
                           "no static import path from entrypoints (may still be loaded dynamically)")
    if f.package is None:
        return ReachResult(f.finding_id, "unknown", "no package")
    name = package_name(f)
    uses = g.package_uses.get(name, [])
    shipped = [(fl, ln) for fl, ln in uses if is_deployed(classify_path(fl, profile), profile)]
    sites = tuple(f"{fl}:{ln}" for fl, ln in (shipped or uses)[:10])
    if shipped:
        in_graph = [s for s in shipped if s[0] in g.reachable]
        st = "imported_by_reachable_code" if in_graph else "imported_by_shipped_code"
        return ReachResult(f.finding_id, st, f"{len(shipped)} import site(s) in shipped code", sites)
    if uses:
        return ReachResult(f.finding_id, "imported_only_outside_deployment",
                           "imported only by tests/tooling/fixtures", sites)
    direct = declared_direct is not None and name in declared_direct
    return ReachResult(f.finding_id, "declared_not_imported" if direct else "not_imported_directly",
                       "declared directly but never imported" if direct else
                       "no direct import (may be a transitive dependency)")


# Stance mapping. Static reachability never `supports` - that would let a guess look like proof.
_STANCE = {
    "imported_only_outside_deployment": Stance.refutes,
}


def to_evidence(r: ReachResult, *, source_content_sha256: str, profile_id: str) -> EvidenceRecord:
    summary = f"{r.status}: {r.detail}"
    if r.sites:
        summary += "\nsites: " + ", ".join(r.sites)
    return EvidenceRecord(
        evidence_id=str(uuid.uuid5(_NS, f"{r.finding_id}:{source_content_sha256}:{profile_id}")),
        finding_ids=(r.finding_id,), evidence_type=EvidenceType.reachability,
        method=f"static_import_graph:{r.status}", stance=_STANCE.get(r.status, Stance.neutral),
        summary=summary, deployment_profile_id=profile_id, collected_at=datetime.now(timezone.utc),
        tool_versions={"source_content_sha256": source_content_sha256})
