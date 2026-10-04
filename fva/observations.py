"""Passive runtime observation receipts and the evidence they produce.

A receipt records what a collector saw while the app ran normally (startup, its own test
suite): loaded packages, executed lines, registered routes, config state. No attack
traffic is sent. Observations are context: they never confirm and never supply the
`supports` a `likely` verdict needs. The one decisive stance is a package that was not
loaded, which refutes. Receipts stay in ignored `data/`; the format is in docs/operations.md.
"""
from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from fva.runtime import digest, file_digest, read_rows, write_json
from fva.schemas import EvidenceRecord, EvidenceType, ObservationKind, Stance

FORMAT = "fva.runtime_observation/1"

SUBJECT_KEYS = {
    ObservationKind.loaded_package: {"name", "version"},
    ObservationKind.line_executed: {"path", "line"},
    ObservationKind.route_registered: {"method", "path"},
    ObservationKind.config_state: {"key", "value"},
}
# Finding types each kind may describe. A not-loaded package can only argue against SCA.
FINDING_TYPES = {
    ObservationKind.loaded_package: {"sca"},
    ObservationKind.line_executed: {"sast"},
    ObservationKind.route_registered: {"sast", "dast"},
    ObservationKind.config_state: {"sast", "sca", "dast"},
}


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Collector(_Model):
    name: str = Field(min_length=1, max_length=100)
    version: str = Field(min_length=1, max_length=50)


class RawFile(_Model):
    name: str = Field(min_length=1, max_length=200)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class Observation(_Model):
    kind: ObservationKind
    finding_ids: tuple[str, ...] = Field(min_length=1)
    observed: bool
    subject: dict[str, str | int]

    @model_validator(mode="after")
    def _subject(self):
        if set(self.subject) != SUBJECT_KEYS[self.kind]:
            raise ValueError(f"{self.kind.value} subject needs keys {sorted(SUBJECT_KEYS[self.kind])}")
        if any(isinstance(v, str) and not 0 < len(v) <= 300 for v in self.subject.values()):
            raise ValueError("subject values must be 1-300 characters")
        return self


class Receipt(_Model):
    format: Literal["fva.runtime_observation/1"]
    profile_id: str = Field(min_length=1)
    source_content_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    findings_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    collector: Collector
    exercise: str = Field(min_length=1, max_length=200)  # e.g. "npm test", "startup only"
    raw_file: RawFile
    collected_at: AwareDatetime
    observations: tuple[Observation, ...] = Field(min_length=1)


def stance(obs: Observation) -> Stance:
    if obs.kind is ObservationKind.loaded_package and not obs.observed:
        return Stance.refutes
    return Stance.neutral


def bind_run(receipt: Receipt, run: Path) -> None:
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    findings_path = run / "findings.jsonl"
    if (summary.get("profile") != receipt.profile_id
            or summary.get("source_content_sha256") != receipt.source_content_sha256
            or file_digest(findings_path) != receipt.findings_sha256):
        raise ValueError("receipt does not match the run's profile, source and findings")
    types = {r["finding_id"]: r.get("finding_type") for r in read_rows(findings_path)}
    for obs in receipt.observations:
        for fid in obs.finding_ids:
            if fid not in types:
                raise ValueError(f"receipt names unknown finding {fid}")
            if types[fid] not in FINDING_TYPES[obs.kind]:
                raise ValueError(f"{obs.kind.value} cannot describe a {types[fid]} finding")


def _summary(obs: Observation, exercise: str) -> str:
    s = obs.subject
    if obs.kind is ObservationKind.loaded_package:
        what = f"package {s['name']}@{s['version']}"
    elif obs.kind is ObservationKind.line_executed:
        what = f"line {s['path']}:{s['line']}"
    elif obs.kind is ObservationKind.route_registered:
        what = f"route {s['method']} {s['path']}"
    else:
        what = f"config {s['key']}"  # config values can be sensitive; name the key only
    return f"{what} {'observed' if obs.observed else 'not observed'} under {exercise!r}"


def evidence_from_receipt(data: dict, run: Path) -> list[EvidenceRecord]:
    receipt = Receipt.model_validate(data)
    bind_run(receipt, run)
    receipt_hash = digest(data)
    method = f"observation:{receipt.collector.name}@{receipt.collector.version}"
    return [EvidenceRecord(
        evidence_id=f"observation:{receipt_hash}:{n}", finding_ids=obs.finding_ids,
        evidence_type=EvidenceType.runtime_observation, method=method, stance=stance(obs),
        summary=_summary(obs, receipt.exercise), detail_ref=f"raw:sha256:{receipt_hash}#/observations/{n}",
        deployment_profile_id=receipt.profile_id, collected_at=receipt.collected_at,
        tool_versions={"kind": obs.kind.value, "observed": str(obs.observed).lower(),
                       "collector": f"{receipt.collector.name}@{receipt.collector.version}",
                       "exercise": receipt.exercise, "receipt_sha256": receipt_hash,
                       "raw_sha256": receipt.raw_file.sha256,
                       "source_content_sha256": receipt.source_content_sha256})
        for n, obs in enumerate(receipt.observations)]


def import_receipt(run: Path, receipt_path: Path, out: Path, verify: Callable[[dict], None]) -> dict:
    """Copy `run` to a new `out` with the receipt's evidence appended.

    `verify` is the collector's check that the receipt matches its raw records; it raises ValueError.
    """
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if file_digest(receipt_path) != digest(receipt):
        raise ValueError("receipt bytes do not match their content hash")
    verify(receipt)
    records = evidence_from_receipt(receipt, run)
    existing = {r["evidence_id"] for r in read_rows(run / "evidence.jsonl")}
    if any(r.evidence_id in existing for r in records):
        raise ValueError("receipt is already imported into this run")
    out.mkdir(parents=True, exist_ok=False)
    for name in ("findings.jsonl", "evidence.jsonl", "summary.json"):
        shutil.copyfile(run / name, out / name)
    if (run / "observations").is_dir():
        shutil.copytree(run / "observations", out / "observations")
    (out / "observations").mkdir(exist_ok=True)
    shutil.copyfile(receipt_path, out / "observations" / f"{digest(receipt)}.json")
    with (out / "evidence.jsonl").open("a", encoding="utf-8") as stream:
        stream.write("\n" + "\n".join(r.model_dump_json() for r in records) + "\n")
    from fva.export.worksheet import write
    result = write(out)
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    summary["verdicts"] = result["verdicts"]
    summary.setdefault("runtime_observations", []).append(
        {"collector": records[0].tool_versions["collector"], "receipt_sha256": digest(receipt),
         "records": len(records)})
    write_json(out / "summary.json", summary)
    return {"records": len(records), "receipt_sha256": digest(receipt), "verdicts": result["verdicts"]}
