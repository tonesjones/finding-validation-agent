"""Polaris (Black Duck) SAST + SCA findings -> Finding[].

Input: the flat per-issue record shape the PoC collected through the Polaris MCP
server (one JSON object per issue, JSON array / JSONL / CSV). Columns:

  candidate_id  issue id (== instance_key in the PoC)      -> source_finding_id
  tool          "SAST" | "SCA"                             -> finding_type
  checker       e.g. SIGMA.hardcoded_secret                -> rule_id
  issue_type, severity, cwe, location, line, function
  component, component_version, vulnerability_id (CVE), linked_vulnerability_id (BDSA)
  reachability, reachability_evidence_count, scanner_triage, scanner_link

Extra columns (e.g. a PoC's disposition fields) are ignored by this adapter.

TODO(real MCP sample): the raw MCP tool responses were never saved. When one is,
add a fixture and confirm the column names above against it; only this preset
should need to change.
"""
from __future__ import annotations

from pathlib import Path

from fva.adapters.mapping import FieldMap, load as _load
from fva.schemas import FindingType

POLARIS = FieldMap(
    source_tool="polaris",
    id="candidate_id",
    rule_id="checker",
    title="issue_type",
    severity="severity",
    finding_type=lambda r: FindingType.sca if str(r.get("tool", "")).upper() == "SCA" else FindingType.sast,
    cwe="cwe",
    path="location",
    line="line",
    function="function",
    package_name="component",
    package_version="component_version",
    advisory_id="vulnerability_id",
    linked_advisory_id="linked_vulnerability_id",
    metadata=("instance_key", "reachability", "reachability_evidence_count", "scanner_triage", "scanner_link",
              "ledger_row_id"),
)


def load(path: Path, *, source_commit: str | None = None):
    return _load(path, POLARIS, source_commit=source_commit)


# --------------------------------------------------------------------------------------------
# Raw Polaris MCP / REST issue objects (get_issue, list_issues)
# --------------------------------------------------------------------------------------------
import json as _json
import uuid as _uuid
from datetime import datetime as _dt, timezone as _tz

from fva import severity as _sev
from fva.provenance import raw_ref as _raw_ref, sha256_file as _sha
from fva.schemas import Finding as _Finding, FindingLocation as _Loc, FindingType as _FT, \
    IngestionRun as _Run, PackageRef as _Pkg

_NS_MCP = _uuid.UUID("0d6f6a52-3c1e-4b8a-b1f7-6b0f5d1c9e21")  # same namespace as mapping adapter
# Polaris component-origin-external-namespace -> ecosystem
NAMESPACE_ECOSYSTEM = {"npmjs": "npm", "pypi": "pypi", "maven": "maven", "nuget": "nuget",
                       "golang": "golang", "rubygems": "gem", "crates": "cargo", "packagist": "composer"}
# Only these context keys are kept; _links and tenantId are internal and never persisted.
_SAFE_CONTEXT = ("toolType", "toolId", "scanMode", "date")


def _unwrap(doc):
    """Accept an MCP tools/call result, its text payload, a {'data': ...} envelope, or a bare issue/list."""
    if isinstance(doc, dict) and "content" in doc:
        doc = _json.loads(doc["content"][0]["text"])
    if isinstance(doc, dict) and "data" in doc:
        doc = doc["data"]
    if isinstance(doc, dict) and "_items" in doc:
        return doc["_items"]
    return doc if isinstance(doc, list) else [doc]


# TODO(real DAST sample): Polaris DAST MCP responses have never been sampled. ASSUMED: the same envelope
# as SAST/SCA (`occurrenceProperties` key/value list, `context`, `type.altName`, `id`) with occurrence keys
# `url`, `http-method`, `parameter-name`, `parameter-location`, `cwe`, `severity`, `title`, `request`,
# `response-snippet`. Confirm against a real sample; only `from_dast_issue` should need to change.
_SNIPPET_MAX = 500
_PARAM_LOCS = {"query", "body", "header", "cookie", "path"}


def _app_path(url: str) -> str:
    """App-relative path only: no scheme, host, port, query, or fragment."""
    from urllib.parse import urlsplit
    path = urlsplit(url.strip()).path or "/"
    return path if path.startswith("/") else "/" + path


def _snippet(text, url: str) -> str | None:
    """Scrub host, redact secrets, THEN truncate (so a cut never leaves a partial secret)."""
    if not text:
        return None
    import re
    from urllib.parse import urlsplit
    from fva.redact import redact
    t = str(text)
    host = urlsplit(url.strip()).netloc
    if host:
        t = re.sub(re.escape(host), "[HOST]", t, flags=re.I)
        t = re.sub(re.escape(host.rsplit("@", 1)[-1].split(":")[0]), "[HOST]", t, flags=re.I)
    t = re.sub(r"(?im)^\s*host\s*:.*$", "Host: [HOST]", t)
    return redact(t)[:_SNIPPET_MAX]


def from_dast_issue(issue: dict, *, run_id: str, raw_digest: str, pointer: str) -> _Finding:
    from fva.schemas import EndpointRef
    op = {p["key"]: p["value"] for p in issue.get("occurrenceProperties", [])}
    ctx = issue.get("context") or {}
    typ = issue.get("type") or {}
    iid = issue["id"]
    url = str(op.get("url") or "")
    ploc = str(op.get("parameter-location") or "").lower()
    ep = EndpointRef(method=str(op.get("http-method") or "GET"), path=_app_path(url),
                     parameter=op.get("parameter-name") or None,
                     parameter_location=ploc if ploc in _PARAM_LOCS else None)
    alt = typ.get("altName") or ""
    localized = typ.get("_localized") or {}
    details = {d["key"]: d["value"] for d in localized.get("otherDetails") or []}
    meta = {
        "request_snippet": _snippet(op.get("request"), url),
        "response_snippet": _snippet(op.get("response-snippet"), url),
        "context": {k: ctx[k] for k in _SAFE_CONTEXT if k in ctx} or None,
    }
    return _Finding(
        finding_id=str(_uuid.uuid5(_NS_MCP, f"finding:polaris:{iid}")), run_id=run_id,
        source_tool="polaris", source_finding_id=iid,
        rule_id=(alt.split(":")[0] if alt else None) or "unknown",
        cwe=tuple(c.strip() for c in str(op.get("cwe", "")).split(",") if c.strip().startswith("CWE-")),
        title=op.get("title") or localized.get("name") or "Untitled issue",
        description=op.get("description") or details.get("description", ""),
        severity=_sev.from_vendor(str(op.get("severity", "info"))),
        finding_type=_FT.dast, endpoint=ep,
        scanner_metadata={k: v for k, v in meta.items() if v not in (None, "", [])},
        raw_evidence_ref=_raw_ref(raw_digest, pointer),
    )


def from_issue(issue: dict, *, run_id: str, raw_digest: str, pointer: str) -> _Finding:
    if (issue.get("context") or {}).get("toolType") == "dast":
        return from_dast_issue(issue, run_id=run_id, raw_digest=raw_digest, pointer=pointer)
    op = {p["key"]: p["value"] for p in issue.get("occurrenceProperties", [])}
    ctx = issue.get("context") or {}
    typ = issue.get("type") or {}
    is_sca = (ctx.get("toolType") == "sca") or ("component-name" in op)
    iid = issue["id"]
    pkg = None
    if is_sca:
        origin = op.get("component-origin-external-id")  # e.g. "jsonwebtoken/0.4.0", "@types/x/1.2.3"
        name = origin.rsplit("/", 1)[0] if origin and "/" in origin else op.get("component-name", "unknown")
        pkg = _Pkg(name=name, version=str(op.get("component-version-name", "unknown")),
                   ecosystem=NAMESPACE_ECOSYSTEM.get(op.get("component-origin-external-namespace", "")),
                   advisory_id=op.get("vulnerability-id"))
    loc = None
    if not is_sca and op.get("location"):
        fn = op.get("function-name")
        loc = _Loc(path=op["location"], start_line=op.get("line-number"),
                   function=fn if fn and fn != "unknown" else None)
    alt = typ.get("altName") or ""
    meta = {
        "checker": op.get("checker"),
        "language": op.get("language"),
        "reachability": issue.get("reachability"),
        "reachability_evidence_count": issue.get("reachabilityEvidenceCount"),
        "vendor_component_name": op.get("component-name") if is_sca else None,
        "vulnerability_source": op.get("vulnerability-source"),
        "cvss_base_score": op.get("base-score"),
        "fix_guidance": op.get("solution"),
        "upgrade_minor": op.get("minor-version-upgrade-guidance-version-name"),
        "upgrade_major": op.get("major-version-upgrade-guidance-version-name"),
        "coverity_events_ref": op.get("coverity-events"),
        "declared_at": [f"{c['filePath']}:{l['lineNumber']}" for c in issue.get("componentLocations") or []
                        for l in c.get("lineLocations") or []] or None,
        "triage_status": next((t["value"] for t in issue.get("triageProperties") or [] if t["key"] == "status"), None),
        "context": {k: ctx[k] for k in _SAFE_CONTEXT if k in ctx} or None,
    }
    localized = typ.get("_localized") or {}
    details = {d["key"]: d["value"] for d in localized.get("otherDetails") or []}
    return _Finding(
        finding_id=str(_uuid.uuid5(_NS_MCP, f"finding:polaris:{iid}")), run_id=run_id,
        source_tool="polaris", source_finding_id=iid,
        rule_id=(alt.split(":")[0] if alt else None) or op.get("checker") or op.get("vulnerability-id") or "unknown",
        cwe=tuple(c.strip() for c in str(op.get("cwe", "")).split(",") if c.strip().startswith("CWE-")),
        title=op.get("title") or localized.get("name")
        or (f"{op.get('vulnerability-id', 'Vulnerability')} in {pkg.name} {pkg.version}" if pkg else "Untitled issue"),
        description=op.get("description") or details.get("description", ""),
        severity=_sev.from_vendor(str(op.get("severity", "info"))),
        finding_type=_FT.sca if is_sca else _FT.sast, location=loc, package=pkg,
        scanner_metadata={k: v for k, v in meta.items() if v not in (None, "", [])},
        raw_evidence_ref=_raw_ref(raw_digest, pointer),
    )


def load_mcp(paths, *, source_commit: str | None = None):
    """Load saved get_issue / list_issues responses (one or many files). Returns (run, findings)."""
    paths = [Path(p) for p in ([paths] if isinstance(paths, (str, Path)) else paths)]
    import hashlib
    h = hashlib.sha256()
    for p in sorted(paths):
        h.update(bytes.fromhex(_sha(p)))
    run = _Run(run_id=str(_uuid.uuid5(_NS_MCP, f"run:polaris-mcp:{h.hexdigest()}")), source_tool="polaris",
               adapter="fva.adapters.polaris:mcp@0.2.0", raw_artifact_sha256=h.hexdigest(),
               raw_artifact_name=",".join(p.name for p in sorted(paths)), source_commit=source_commit,
               ingested_at=_dt.now(_tz.utc))
    out = []
    for p in sorted(paths):
        digest = _sha(p)
        for i, issue in enumerate(_unwrap(_json.loads(p.read_text(encoding="utf-8")))):
            out.append(from_issue(issue, run_id=run.run_id, raw_digest=digest, pointer=f"/issues/{i}"))
    return run, out


def load_dast(paths, *, source_commit: str | None = None):
    """Explicit alias of load_mcp for DAST responses (same run/hashing behaviour)."""
    return load_mcp(paths, source_commit=source_commit)
