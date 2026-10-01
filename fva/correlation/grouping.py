"""Group linked findings into issues: connected components over FindingLinks.

Every finding lands in exactly one GroupedIssue (unlinked ones become singletons). The primary finding is the
one a developer fixes: SAST sink, else SCA, else DAST. Output is independent of input ordering.
"""
from __future__ import annotations

import uuid
from typing import Literal

from fva.schemas import Finding, FindingLink, FindingType, GroupedIssue

_NS = uuid.UUID("3c9d5a1e-6b7f-4e28-8d41-a5f0c2b97e13")
_RANK = {"low": 0, "medium": 1, "high": 2}


def group(findings: list[Finding], links: list[FindingLink],
          min_confidence: Literal["low", "medium", "high"] = "low") -> list[GroupedIssue]:
    by_id = {f.finding_id: f for f in findings}
    parent = {i: i for i in by_id}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    used = []
    for l in links:
        if l.from_finding_id not in by_id or l.to_finding_id not in by_id:
            raise ValueError(f"link {l.link_id} references a finding not in findings")
        if _RANK[l.confidence] >= _RANK[min_confidence]:
            used.append(l)
            ra, rb = find(l.from_finding_id), find(l.to_finding_id)
            if ra != rb:
                parent[max(ra, rb)] = min(ra, rb)

    members: dict[str, list[str]] = {}
    for i in by_id:
        members.setdefault(find(i), []).append(i)
    comp_links: dict[str, set[str]] = {r: set() for r in members}
    degree: dict[str, int] = {}
    for l in {l.link_id: l for l in used}.values():
        comp_links[find(l.from_finding_id)].add(l.link_id)
        for e in (l.from_finding_id, l.to_finding_id):
            degree[e] = degree.get(e, 0) + 1

    out = []
    for root, ids in members.items():
        ids = sorted(ids)
        primary = ids[0]
        for kind in (FindingType.sast, FindingType.sca, FindingType.dast):
            cands = [i for i in ids if by_id[i].finding_type == kind]
            if cands:
                primary = min(cands, key=lambda i: (-degree.get(i, 0), i))
                break
        out.append(GroupedIssue(issue_id=str(uuid.uuid5(_NS, "|".join(ids))), finding_ids=tuple(ids),
                                link_ids=tuple(sorted(comp_links[root])), primary_finding_id=primary))
    return sorted(out, key=lambda g: g.issue_id)
