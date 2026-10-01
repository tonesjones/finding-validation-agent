"""SAST <-> DAST linking: a static sink and a DAST observation that look like one flaw.

A CWE overlap is required; without it there is never a link. Then:

  high    the route maps to the SAST file AND the DAST parameter name appears near the sink
  medium  the route maps to the SAST file (from the Express route table)
  low     no route table entry, but the last route segment names the SAST file (e.g.
          /rest/products/search -> routes/search.ts)

A link is a claim of identity. Whether it becomes runtime evidence is decided later,
and only a high-confidence link may ever `support` a finding.
"""
from __future__ import annotations

import re
import uuid
from pathlib import Path, PurePosixPath

from fva.langpacks import REGISTRY
from fva.schemas import Finding, FindingLink, FindingType, LinkKind

METHOD = "fva.correlation.runtime_link@0.1.0"
_NS = uuid.UUID("5c2a8e71-9d3b-4f60-b1a4-2e3f4a5b6c7d")
PARAM_WINDOW = 15  # lines either side of the sink to look for the parameter name

# app.get('/rest/x', handlerModule.fn(...)) / router.post("/x", mod.fn)
_ROUTE_RE = re.compile(r"\b\w+\.(get|post|put|patch|delete|all|use)\(\s*(['\"`])(/[^'\"`]*)\2\s*,[^\n]*?\b(\w+)\.\w+")
_BINDING_RE = re.compile(r"(?:import\s+\*\s+as\s+(\w+)\s+from\s+|import\s+(\w+)\s+from\s+|"
                         r"(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*)(['\"])([^'\"]+)\4")

RouteMap = dict[tuple[str, str], set[str]]  # (METHOD|ALL, path) -> handler files


def build_route_map(root: Path, files: list[str], entrypoints: tuple[str, ...]) -> RouteMap:
    """Express-style route table from entrypoint files: route path -> files of the handler module."""
    node = REGISTRY["node"]
    fset, out = set(files), {}
    for ep in entrypoints:
        try:
            text = (Path(root) / ep).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        bindings = {}
        for m in _BINDING_RE.finditer(text):
            name = m.group(1) or m.group(2) or m.group(3)
            local = node.resolve_local(m.group(5), ep, fset)
            if local:
                bindings[name] = local
        for m in _ROUTE_RE.finditer(text):
            verb, path, mod = m.group(1).upper(), m.group(3), m.group(4)
            if mod in bindings:
                key = ("ALL" if verb in ("ALL", "USE") else verb, path)
                out.setdefault(key, set()).add(bindings[mod])
    return out


def _route_files(dast: Finding, routes: RouteMap) -> set[str]:
    ep = dast.endpoint
    return routes.get((ep.method, ep.path), set()) | routes.get(("ALL", ep.path), set())


def _param_near_sink(sast: Finding, param: str | None, source: dict[str, list[str]]) -> bool:
    lines = source.get(sast.location.path)
    if not param or not lines or sast.location.start_line is None:
        return False
    i = sast.location.start_line - 1
    window = "\n".join(lines[max(0, i - PARAM_WINDOW): i + PARAM_WINDOW + 1])
    return re.search(rf"\b{re.escape(param)}\b", window) is not None


def link(sast: Finding, dast: Finding, routes: RouteMap, source: dict[str, list[str]] | None = None
         ) -> FindingLink | None:
    if sast.finding_type is not FindingType.sast or dast.finding_type is not FindingType.dast:
        return None
    if sast.location is None or dast.endpoint is None or not set(sast.cwe) & set(dast.cwe):
        return None
    path = sast.location.path
    if path in _route_files(dast, routes):
        if _param_near_sink(sast, dast.endpoint.parameter, source or {}):
            conf, basis = "high", ("cwe", "route", "parameter")
        else:
            conf, basis = "medium", ("cwe", "route")
    else:
        segment = PurePosixPath(dast.endpoint.path).name.lower()
        if not segment or PurePosixPath(path).stem.lower() != segment:
            return None
        conf, basis = "low", ("cwe", "route_name")
    return FindingLink(
        link_id=str(uuid.uuid5(_NS, f"{sast.finding_id}:{dast.finding_id}")), kind=LinkKind.sast_dast,
        from_finding_id=sast.finding_id, to_finding_id=dast.finding_id, confidence=conf, basis=basis,
        method=METHOD)


def link_all(sast: list[Finding], dast: list[Finding], routes: RouteMap,
             source: dict[str, list[str]] | None = None) -> list[FindingLink]:
    out = [l for a in sast for b in dast if (l := link(a, b, routes, source))]
    return sorted(out, key=lambda l: l.link_id)
