"""SCA <-> SAST linking: a vulnerable package used in the same shipped file as a SAST finding.

The link says "these two findings may be one flaw", never "the advisory is exploitable".
Import sites come from the static import graph, so the basis is file-level, not call-level:

  high    same shipped file imports the package AND the SAST CWE matches an advisory CWE
          AND the SAST line is at or after the import line
  medium  same shipped file imports the package AND CWEs overlap
  low     same shipped file imports the package, CWEs unknown or different
  (none)  package imported only by tests/tooling, or not in the SAST finding's file
"""
from __future__ import annotations

import uuid

from fva.correlation.dependency import package_name
from fva.correlation.reachability import CodeGraph
from fva.schemas import DeploymentProfile, Finding, FindingLink, FindingType, LinkKind
from fva.surface import classify_path, is_deployed

METHOD = "fva.correlation.package_link@0.1.0"
_NS = uuid.UUID("7b1e4c90-2f3a-4d5e-9a8b-1c2d3e4f5a6b")


def link(sca: Finding, sast: Finding, g: CodeGraph, profile: DeploymentProfile) -> FindingLink | None:
    if sca.finding_type is not FindingType.sca or sast.finding_type is not FindingType.sast:
        return None
    if sca.package is None or sast.location is None:
        return None
    path = sast.location.path
    if not is_deployed(classify_path(path, profile), profile):
        return None
    lines = [ln for fl, ln in g.package_uses.get(package_name(sca), []) if fl == path]
    if not lines:
        return None
    basis = ["shipped_import_same_file"]
    cwe_match = bool(set(sca.cwe) & set(sast.cwe))
    if cwe_match:
        basis.append("cwe")
    after_import = sast.location.start_line is not None and sast.location.start_line >= min(lines)
    if cwe_match and after_import:
        basis.append("sink_after_import")
        conf = "high"
    else:
        conf = "medium" if cwe_match else "low"
    return FindingLink(
        link_id=str(uuid.uuid5(_NS, f"{sca.finding_id}:{sast.finding_id}")), kind=LinkKind.sca_sast,
        from_finding_id=sca.finding_id, to_finding_id=sast.finding_id, confidence=conf,
        basis=tuple(basis), method=METHOD)


def link_all(sca: list[Finding], sast: list[Finding], g: CodeGraph, profile: DeploymentProfile) -> list[FindingLink]:
    out = [l for a in sca for b in sast if (l := link(a, b, g, profile))]
    return sorted(out, key=lambda l: l.link_id)
