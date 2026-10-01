import random

import pytest

from fva.correlation.grouping import group
from fva.schemas import Finding, FindingLink, LinkKind, Severity


def _f(fid, kind):
    return Finding(finding_id=fid, run_id="r", source_tool="polaris", source_finding_id=fid, rule_id="x",
                   title="t", severity=Severity.high, finding_type=kind, raw_evidence_ref="raw:sha256:0#/")


def _l(lid, kind, a, b, conf="high"):
    return FindingLink(link_id=lid, kind=kind, from_finding_id=a, to_finding_id=b, confidence=conf,
                       basis=("cwe",), method="m")


F = [_f("dast1", "dast"), _f("sast1", "sast"), _f("sca1", "sca"), _f("lone", "sast")]
L = [_l("l1", LinkKind.sast_dast, "sast1", "dast1"), _l("l2", LinkKind.sca_sast, "sca1", "sast1", "low")]


def test_chain_is_one_issue_with_sast_primary():
    issues = group(F, L)
    big = next(i for i in issues if len(i.finding_ids) == 3)
    assert big.primary_finding_id == "sast1" and big.link_ids == ("l1", "l2")
    assert big.finding_ids == ("dast1", "sast1", "sca1")


def test_unlinked_is_singleton_and_no_loss():
    issues = group(F, L)
    single = next(i for i in issues if i.finding_ids == ("lone",))
    assert single.primary_finding_id == "lone" and single.link_ids == ()
    assert sum(len(i.finding_ids) for i in issues) == len(F)


def test_shuffled_inputs_equal():
    base = group(F, L)
    rng = random.Random(1)
    for _ in range(10):
        f, l = F[:], L[:]
        rng.shuffle(f), rng.shuffle(l)
        assert group(f, l) == base


def test_min_confidence_splits():
    issues = group(F, L, min_confidence="high")
    assert sorted(i.finding_ids for i in issues) == [("dast1", "sast1"), ("lone",), ("sca1",)]


def test_dangling_link_raises():
    with pytest.raises(ValueError):
        group(F, [_l("x", LinkKind.sast_dast, "sast1", "nope")])
