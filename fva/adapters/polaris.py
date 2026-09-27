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
