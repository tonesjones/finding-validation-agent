"""SARIF 2.1.0 -> Finding[].

Identifier precedence for source_finding_id (never regenerated when present):
  result.guid > result.correlationGuid > fingerprints (first, sorted by key)
  > partialFingerprints (first, sorted by key) > synthesized "<run>:<result>" (flagged).
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fva import severity as sev
from fva.provenance import raw_ref, sha256_file
from fva.schemas import Finding, FindingLocation, FindingType, IngestionRun, PackageRef

ADAPTER = "fva.adapters.sarif@0.2.0"
_CWE_RE = re.compile(r"cwe[-_/:]?0*(\d+)", re.I)
_MANIFESTS = {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt",
              "poetry.lock", "Pipfile.lock", "pom.xml", "build.gradle", "go.mod", "go.sum",
              "Gemfile.lock", "Cargo.lock", "composer.lock", "packages.lock.json"}


def _source_id(result: dict, ri: int, xi: int) -> tuple[str, bool]:
    for key in ("guid", "correlationGuid"):
        if result.get(key):
            return str(result[key]), False
    for key in ("fingerprints", "partialFingerprints"):
        fp = result.get(key) or {}
        if fp:
            k = sorted(fp)[0]
            return f"{k}={fp[k]}", False
    return f"{ri}:{xi}", True


def _rule(run: dict, result: dict) -> dict:
    rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
    idx = result.get("ruleIndex")
    if isinstance(idx, int) and 0 <= idx < len(rules):
        return rules[idx]
    rid = result.get("ruleId")
    return next((r for r in rules if r.get("id") == rid), {})


def _cwes(rule: dict, result: dict) -> tuple[str, ...]:
    tags = list((rule.get("properties") or {}).get("tags") or []) + list((result.get("properties") or {}).get("tags") or [])
    for rel in rule.get("relationships") or []:
        tags.append(((rel.get("target") or {}).get("id")) or "")
    found = []
    for t in tags:
        m = _CWE_RE.search(str(t))
        if m and f"CWE-{m.group(1)}" not in found:
            found.append(f"CWE-{m.group(1)}")
    return tuple(found)


def _severity(rule: dict, result: dict):
    for props in (result.get("properties") or {}, rule.get("properties") or {}):
        s = props.get("security-severity")
        if s is not None:
            try:
                return sev.from_cvss(float(s))
            except ValueError:
                pass
    level = result.get("level") or ((rule.get("defaultConfiguration") or {}).get("level")) or "warning"
    return sev.SARIF_LEVEL[level]


def _location(result: dict) -> FindingLocation | None:
    locs = result.get("locations") or []
    if not locs:
        return None
    pl = locs[0].get("physicalLocation") or {}
    uri = (pl.get("artifactLocation") or {}).get("uri")
    if not uri:
        return None
    region = pl.get("region") or {}
    logical = (locs[0].get("logicalLocations") or [{}])[0]
    return FindingLocation(
        path=re.sub(r"^file://", "", uri),
        start_line=region.get("startLine"),
        end_line=region.get("endLine"),
        function=logical.get("fullyQualifiedName") or logical.get("name"),
    )


def _package(result: dict, loc: FindingLocation | None) -> PackageRef | None:
    p = result.get("properties") or {}
    name = p.get("packageName") or p.get("package") or p.get("component")
    version = p.get("packageVersion") or p.get("installedVersion") or p.get("componentVersion")
    if not name or not version:
        return None
    return PackageRef(name=name, version=str(version), ecosystem=p.get("ecosystem"),
                      purl=p.get("purl"), advisory_id=p.get("advisoryId") or p.get("cve"))


def parse(path: Path, *, source_commit: str | None = None, source_repo: str | None = None,
          finding_type: FindingType | None = None) -> tuple[IngestionRun, list[Finding]]:
    digest = sha256_file(path)
    doc: dict[str, Any] = json.loads(path.read_bytes())
    if doc.get("version") != "2.1.0":
        raise ValueError(f"unsupported SARIF version {doc.get('version')!r}")
    run_rec = IngestionRun(
        run_id=str(uuid.uuid4()), source_tool="sarif", adapter=ADAPTER,
        raw_artifact_sha256=digest, raw_artifact_name=path.name,
        source_repo=source_repo, source_commit=source_commit,
        ingested_at=datetime.now(timezone.utc),
    )
    findings = []
    for ri, run in enumerate(doc.get("runs") or []):
        driver = ((run.get("tool") or {}).get("driver") or {})
        tool_name = driver.get("name") or "unknown"
        commit = source_commit or ((run.get("versionControlProvenance") or [{}])[0].get("revisionId"))
        for xi, result in enumerate(run.get("results") or []):
            rule = _rule(run, result)
            sid, synth = _source_id(result, ri, xi)
            loc = _location(result)
            pkg = _package(result, loc)
            ftype = finding_type or (
                FindingType.sca if pkg or (loc and Path(loc.path).name in _MANIFESTS) else FindingType.sast)
            msg = (result.get("message") or {}).get("text") or ""
            title = ((rule.get("shortDescription") or {}).get("text")) or rule.get("name") or result.get("ruleId") or msg[:80]
            findings.append(Finding(
                finding_id=str(uuid.uuid4()), run_id=run_rec.run_id,
                source_tool=f"sarif:{tool_name}", source_finding_id=sid,
                source_finding_id_synthesized=synth,
                rule_id=result.get("ruleId") or rule.get("id") or "unknown",
                cwe=_cwes(rule, result), title=title, description=msg,
                severity=_severity(rule, result), finding_type=ftype,
                location=loc, package=pkg,
                fingerprint=next(iter((result.get("partialFingerprints") or {}).values()), None),
                scanner_metadata={k: v for k, v in {
                    "tool_version": driver.get("semanticVersion") or driver.get("version"),
                    "source_commit": commit,
                    "suppressed": bool(result.get("suppressions")) or None,
                    "baseline_state": result.get("baselineState"),
                }.items() if v is not None},
                raw_evidence_ref=raw_ref(digest, f"/runs/{ri}/results/{xi}"),
            ))
    return run_rec, findings
