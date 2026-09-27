"""Import the Juice Shop PoC ledger (Polaris findings pulled via MCP + final dispositions).

Each JSONL row becomes one Finding, one `imported_assessment` EvidenceRecord and one
Verdict. The imported evidence is labelled as such: it records what the PoC concluded,
it is not fresh evidence collected by this tool. Its main use is as the answer key for
the benchmark harness.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fva import reason_codes
from fva.adapters import polaris
from fva.schemas import DeploymentProfile, EvidenceRecord, EvidenceType, Stance, Surface, Verdict, VerdictValue

_NS = uuid.UUID("5b0c3f1e-7a44-4a4e-9f55-9d1f6f6e2a10")

JUICESHOP_PROFILE = DeploymentProfile(
    profile_id="juiceshop-20.2.0-local-npm-start",
    name="Juice Shop 20.2.0, local `npm start`, fresh install",
    source_commit="1618a611b173b4bf114028e6e02549950606e29d",
    language_packs=("node",),
    extra_path_rules=(("data/static/codefixes/*", Surface.fixture),),
    base_url="http://127.0.0.1:3000",
)

_STANCE = {VerdictValue.confirmed: Stance.supports, VerdictValue.not_applicable: Stance.refutes,
           VerdictValue.valid_non_security: Stance.non_security, VerdictValue.needs_review: Stance.neutral}


def _id(kind: str, key: str) -> str:
    return str(uuid.uuid5(_NS, f"{kind}:{key}"))


def load(path: Path, profile: DeploymentProfile = JUICESHOP_PROFILE):
    """Findings come from the Polaris adapter; the PoC's disposition columns become evidence + verdicts."""
    run, findings = polaris.load(path, source_commit=profile.source_commit)
    now = datetime.now(timezone.utc)
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    evidence, verdicts = [], []
    for f, r in zip(findings, rows, strict=True):
        sid = f.source_finding_id
        code = reason_codes.LEGACY_POC_MAP[r["classification"]]
        verdict = reason_codes.verdict_for(code)
        summary = r.get("evidence") or ""
        if r.get("runtime_component_version"):
            summary += f" [scanned {r['component_version']}, installed {r['runtime_component_version']}]"
        if r.get("counterevidence_or_proof_gap"):
            summary += f" Gap: {r['counterevidence_or_proof_gap']}"
        eid = _id("evidence", sid)
        evidence.append(EvidenceRecord(
            evidence_id=eid, finding_ids=(f.finding_id,), evidence_type=EvidenceType.imported_assessment,
            method=r.get("validation_method") or "unknown", stance=_STANCE[verdict],
            summary=summary.strip(), deployment_profile_id=profile.profile_id,
            collected_at=now, tool_versions={"source": "juice-shop PoC ledger"}))
        verdicts.append(Verdict(
            verdict_id=_id("verdict", sid), finding_id=f.finding_id, deployment_profile_id=profile.profile_id,
            verdict=verdict, reason_codes=(code,), confidence=r.get("confidence") or "medium",
            evidence_ids=(eid,), narrative=summary.strip(), decided_at=now,
            decided_by={"method": "import", "source": "poc_ledger",
                        "legacy_classification": r["classification"],
                        "legacy_disposition": r["disposition"],
                        "reason_vocabulary": reason_codes.VOCABULARY_VERSION}))
    return run, findings, evidence, verdicts
