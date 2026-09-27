"""Checks against the real (private, git-ignored) PoC ledger. Skipped when absent."""
import collections
import json
from pathlib import Path

import pytest

from fva.adapters import poc_ledger
from fva.invariants import check_verdict
from fva.schemas import Surface
from fva.surface import classify_finding

ROOT = Path(__file__).resolve().parents[1] / "data" / "poc-report"
LEDGER = ROOT / "final-validation-ledger.jsonl"
SUMMARY = ROOT / "runtime-validation-summary.json"
pytestmark = pytest.mark.skipif(not LEDGER.exists(), reason="private PoC ledger not present")

BUCKET = {"confirmed_current_security": "confirmed", "not_relevant_to_tested_runtime": "not_applicable",
          "valid_nonsecurity_quality": "valid_non_security", "reachable_likely_needs_safe_deeper_test": "needs_review"}
LEGACY_SURFACE = {"challenge_fixture": Surface.fixture}
# Paths where the classifier and the PoC disagree on purpose. Each needs a human decision.
# Dockerfile: PoC counted it as production; generic rules call it infrastructure (not used by `npm start`).
KNOWN_DISAGREEMENTS = {"Dockerfile"}


@pytest.fixture(scope="module")
def loaded():
    return poc_ledger.load(LEDGER)


def test_every_id_preserved(loaded):
    _, fs, _, _ = loaded
    raw = [json.loads(l)["candidate_id"] for l in LEDGER.open(encoding="utf-8") if l.strip()]
    assert [f.source_finding_id for f in fs] == raw
    assert len(set(raw)) == len(raw) == 570


def test_bucket_counts_match_poc_summary(loaded):
    *_, vs = loaded
    want = {BUCKET[k]: n for k, n in json.loads(SUMMARY.read_text())["overallBuckets"].items()}
    assert dict(collections.Counter(v.verdict.value for v in vs)) == want


def test_all_verdicts_pass_invariants(loaded):
    _, _, es, vs = loaded
    idx = {e.evidence_id: e for e in es}
    for v in vs:
        check_verdict(v, idx)


def test_surface_classifier_reproduces_poc_boundary(loaded):
    _, fs, _, _ = loaded
    rows = [json.loads(l) for l in LEDGER.open(encoding="utf-8") if l.strip()]
    mismatches = []
    for f, r in zip(fs, rows):
        want = LEGACY_SURFACE.get(r["surface"]) or Surface(r["surface"])
        got = classify_finding(f, poc_ledger.JUICESHOP_PROFILE)
        if got is not want and r["location"] not in KNOWN_DISAGREEMENTS:
            mismatches.append((r["location"], r["surface"], got.value))
    assert not mismatches, mismatches[:10]
