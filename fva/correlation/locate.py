"""Map Finding.location onto a pinned checkout and emit static_source evidence.

Statuses:
  exact            path exists and line is in range
  line_out_of_range path exists, line beyond EOF (scan/source drift)
  relocated        path missing, but exactly one file with the same repo-relative
                   suffix exists (e.g. scanner root differs by a prefix)
  path_missing     cannot find the file
  no_location      finding has no file location (e.g. SCA)
Evidence stance is always neutral: finding the line proves the code exists, not
that the issue is real.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from fva.redact import CREDENTIAL_CWES, redact
from fva.schemas import EvidenceRecord, EvidenceType, Finding, Stance

_NS = uuid.UUID("a3e1c7d2-1f0b-4c55-8d6e-2b7a9e4f1c30")
CONTEXT = 2


@dataclass(frozen=True)
class LocateResult:
    finding_id: str
    status: str
    resolved_path: str | None
    line: int | None
    snippet: str | None  # redacted


class SourceIndex:
    def __init__(self, root: Path, files: list[str]):
        self.root = Path(root)
        self.files = set(files)
        self._by_name: dict[str, list[str]] = {}
        for f in files:
            self._by_name.setdefault(f.rsplit("/", 1)[-1], []).append(f)
        self._cache: dict[str, list[str]] = {}

    @classmethod
    def build(cls, root: Path, excludes=None):
        from fva.correlation.source_pin import DEFAULT_EXCLUDES, iter_files
        return cls(root, [rel for rel, _ in iter_files(Path(root), excludes or DEFAULT_EXCLUDES)])

    def lines(self, rel: str) -> list[str]:
        if rel not in self._cache:
            raw = (self.root / rel).read_bytes().replace(b"\r\n", b"\n")
            self._cache[rel] = raw.decode("utf-8", errors="replace").split("\n")
        return self._cache[rel]

    def resolve(self, path: str) -> tuple[str | None, str]:
        if path in self.files:
            return path, "exact"
        cands = [f for f in self._by_name.get(path.rsplit("/", 1)[-1], [])
                 if f.endswith("/" + path) or path.endswith("/" + f)]
        return (cands[0], "relocated") if len(cands) == 1 else (None, "path_missing")


def locate(f: Finding, idx: SourceIndex) -> LocateResult:
    if f.location is None:
        return LocateResult(f.finding_id, "no_location", None, None, None)
    rel, status = idx.resolve(f.location.path)
    if rel is None:
        return LocateResult(f.finding_id, status, None, None, None)
    line = f.location.start_line
    if line is None:
        return LocateResult(f.finding_id, status, rel, None, None)
    lines = idx.lines(rel)
    if line > len(lines):
        return LocateResult(f.finding_id, "line_out_of_range", rel, line, None)
    lo, hi = max(1, line - CONTEXT), min(len(lines), line + CONTEXT)
    all_strings = bool(set(f.cwe) & CREDENTIAL_CWES)
    snippet = "\n".join(f"{'>' if n == line else ' '}{n:5d}| {redact(lines[n - 1].rstrip(), all_strings=all_strings)}"
                        for n in range(lo, hi + 1))
    return LocateResult(f.finding_id, status, rel, line, snippet)


def to_evidence(r: LocateResult, *, source_content_sha256: str) -> EvidenceRecord:
    summary = {
        "exact": f"Located {r.resolved_path}:{r.line}",
        "relocated": f"Path differs from scanner; located as {r.resolved_path}:{r.line}",
        "line_out_of_range": f"{r.resolved_path} exists but has fewer than {r.line} lines (scan/source drift)",
        "path_missing": "Reported file not present in pinned source",
        "no_location": "Finding has no source location",
    }[r.status]
    if r.snippet:
        summary += "\n" + r.snippet
    return EvidenceRecord(
        evidence_id=str(uuid.uuid5(_NS, f"{r.finding_id}:{source_content_sha256}")),
        finding_ids=(r.finding_id,), evidence_type=EvidenceType.static_source, method=f"locate:{r.status}",
        stance=Stance.neutral, summary=summary, collected_at=datetime.now(timezone.utc),
        tool_versions={"source_content_sha256": source_content_sha256})
