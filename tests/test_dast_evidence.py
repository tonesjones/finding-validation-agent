from datetime import datetime, timezone

import pytest

from fva.correlation.dast_evidence import to_evidence
from fva.invariants import InvariantError, check_verdict
from fva.schemas import FindingLink, LinkKind, RuntimeMode, Stance, Verdict


def _link(conf, kind=LinkKind.sast_dast):
    return FindingLink(link_id=f"l-{conf}", kind=kind, from_finding_id="sast", to_finding_id="dast",
                       confidence=conf, basis=("cwe", "route"), method="m")


def _verdict(value, codes, evidence_ids):
    return Verdict(verdict_id="v", finding_id="sast", deployment_profile_id="p", verdict=value,
                   reason_codes=codes, confidence="high", evidence_ids=evidence_ids, narrative="n",
                   decided_at=datetime.now(timezone.utc), decided_by={"method": "rules"})


def test_high_link_supports_and_confirms():
    ev = to_evidence(_link("high"), profile_id="p")
    assert ev.stance is Stance.supports and ev.finding_ids == ("sast", "dast")
    check_verdict(_verdict("confirmed", ("DAST_OBSERVED",), (ev.evidence_id,)), {ev.evidence_id: ev})


@pytest.mark.parametrize("conf", ["medium", "low"])
def test_weaker_link_is_neutral_and_cannot_confirm(conf):
    ev = to_evidence(_link(conf), profile_id="p")
    assert ev.stance is Stance.neutral
    with pytest.raises(InvariantError):
        check_verdict(_verdict("confirmed", ("DAST_OBSERVED",), (ev.evidence_id,)), {ev.evidence_id: ev})
    check_verdict(_verdict("needs_review", ("INSUFFICIENT_EVIDENCE",), (ev.evidence_id,)), {ev.evidence_id: ev})


def test_mode_none_and_sca_links_produce_nothing():
    assert to_evidence(_link("high"), profile_id="p", mode=RuntimeMode.none) is None
    assert to_evidence(_link("high", LinkKind.sca_sast), profile_id="p") is None


def test_dast_evidence_needs_profile():
    ev = to_evidence(_link("high"), profile_id="p")
    with pytest.raises(ValueError):
        type(ev).model_validate({**ev.model_dump(), "deployment_profile_id": None})
