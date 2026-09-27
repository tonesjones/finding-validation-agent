import json
from pathlib import Path

from fva.invariants import check_verdict
from fva.schemas import DeploymentProfile, EvidenceRecord, Finding, Verdict


def test_examples_validate():
    d = json.loads((Path(__file__).parent / "fixtures" / "examples.json").read_text())
    DeploymentProfile.model_validate(d["profile"])
    Finding.model_validate(d["finding"])
    ev = {e["evidence_id"]: EvidenceRecord.model_validate(e) for e in d["evidence"]}
    check_verdict(Verdict.model_validate(d["verdict"]), ev)
