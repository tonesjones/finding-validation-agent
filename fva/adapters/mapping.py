"""Declarative field-mapping adapter for flat records (JSON array, JSONL, or CSV).

A FieldMap names which source column feeds each Finding field. Vendor adapters
(e.g. Polaris) are just FieldMap presets plus small hooks, so a new tool's flat
export usually needs a mapping, not new code.
"""
from __future__ import annotations

import csv
import io
import json
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fva import severity as sev
from fva.provenance import raw_ref, sha256_file
from fva.schemas import Finding, FindingLocation, FindingType, IngestionRun, PackageRef

_NS = uuid.UUID("0d6f6a52-3c1e-4b8a-b1f7-6b0f5d1c9e21")


@dataclass(frozen=True)
class FieldMap:
    source_tool: str
    id: str  # required: the scanner's own identifier column
    rule_id: str
    title: str
    severity: str
    # finding_type: column name, or a callable(row) -> FindingType
    finding_type: str | Callable[[dict], FindingType]
    description: str | None = None
    cwe: str | None = None
    path: str | None = None
    line: str | None = None
    function: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    ecosystem: str | None = None
    advisory_id: str | None = None
    linked_advisory_id: str | None = None
    fingerprint: str | None = None
    metadata: tuple[str, ...] = ()  # extra columns copied into scanner_metadata
    null_values: tuple[str, ...] = ("", "unknown", "null", "None", "N/A")
    severity_map: dict[str, Any] = field(default_factory=dict)  # vendor string -> Severity override


def _rows(path: Path) -> Iterator[tuple[str, dict]]:
    """Yield (pointer, row). Pointer is 'L<n>' for JSONL/CSV lines, '/<i>' for JSON arrays."""
    text = path.read_text(encoding="utf-8-sig")
    suffix = path.suffix.lower()
    if suffix == ".csv":
        for i, row in enumerate(csv.DictReader(io.StringIO(text)), start=2):
            yield f"L{i}", row
    elif suffix in (".jsonl", ".ndjson"):
        for i, line in enumerate(text.splitlines(), 1):
            if line.strip():
                yield f"L{i}", json.loads(line)
    else:
        data = json.loads(text)
        if isinstance(data, dict):  # common wrappers: {"items": [...]} / {"_items": [...]}
            data = next((v for v in data.values() if isinstance(v, list)), [])
        for i, row in enumerate(data):
            yield f"/{i}", row


def load(path: Path, fm: FieldMap, *, source_commit: str | None = None,
         deterministic_ids: bool = True) -> tuple[IngestionRun, list[Finding]]:
    digest = sha256_file(path)
    run = IngestionRun(run_id=str(uuid.uuid5(_NS, f"run:{fm.source_tool}:{digest}")) if deterministic_ids
                       else str(uuid.uuid4()),
                       source_tool=fm.source_tool, adapter=f"fva.adapters.mapping:{fm.source_tool}@0.2.0",
                       raw_artifact_sha256=digest, raw_artifact_name=path.name,
                       source_commit=source_commit, ingested_at=datetime.now(timezone.utc))
    out = []
    for ptr, row in _rows(path):
        def g(col):
            if col is None:
                return None
            v = row.get(col)
            if v is None or (isinstance(v, str) and v.strip() in fm.null_values):
                return None
            return v

        sid = row.get(fm.id)
        if sid in (None, ""):
            raise ValueError(f"{path.name}{ptr}: missing required id column {fm.id!r}")
        sid = str(sid)  # preserved as-is; no stripping or case change
        ftype = fm.finding_type(row) if callable(fm.finding_type) else FindingType(str(row[fm.finding_type]).lower())
        raw_sev = str(g(fm.severity) or "info")
        severity = fm.severity_map.get(raw_sev) or sev.from_vendor(raw_sev)
        loc = None
        if g(fm.path):
            line = g(fm.line)
            loc = FindingLocation(path=str(g(fm.path)), start_line=int(line) if line is not None else None,
                                  function=g(fm.function))
        pkg = None
        if ftype is FindingType.sca and g(fm.package_name):
            linked = g(fm.linked_advisory_id)
            pkg = PackageRef(name=str(g(fm.package_name)), version=str(g(fm.package_version) or "unknown"),
                             ecosystem=g(fm.ecosystem), advisory_id=g(fm.advisory_id),
                             linked_advisory_ids=(str(linked),) if linked else ())
            loc = None  # SCA "location" columns are usually "name version", not a file
        cwe = g(fm.cwe)
        out.append(Finding(
            finding_id=str(uuid.uuid5(_NS, f"finding:{fm.source_tool}:{sid}")) if deterministic_ids else str(uuid.uuid4()),
            run_id=run.run_id, source_tool=fm.source_tool, source_finding_id=sid,
            rule_id=str(g(fm.rule_id) or g(fm.advisory_id) or "unknown"),
            cwe=tuple(c.strip() for c in str(cwe).split(",") if c.strip()) if cwe else (),
            title=str(g(fm.title) or ""), description=str(g(fm.description) or ""),
            severity=severity, finding_type=ftype, location=loc, package=pkg,
            fingerprint=g(fm.fingerprint),
            scanner_metadata={c: row[c] for c in fm.metadata if g(c) is not None},
            raw_evidence_ref=raw_ref(digest, ptr),
        ))
    return run, out
