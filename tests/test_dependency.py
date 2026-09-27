import json
from pathlib import Path

import pytest

from fva.adapters import polaris
from fva.correlation.dependency import reconcile, to_evidence
from fva.langpacks import REGISTRY
from fva.schemas import Stance

FIX = Path(__file__).parent / "fixtures"
INV = REGISTRY["node"].read_inventory(FIX / "package-lock.min.json")


def sca(component, version, tmp_path, ecosystem=None):
    row = {"candidate_id": component, "tool": "SCA", "severity": "high", "issue_type": "t",
           "component": component, "component_version": version}
    p = tmp_path / "f.jsonl"
    p.write_text(json.dumps(row) + "\n")
    return polaris.load(p)[1][0]


def test_inventory_parsing():
    names = {(p.name, p.version, p.dev) for p in INV}
    assert ("jsonwebtoken", "9.0.0", True) in names and ("mocha", "10.0.0", True) in names
    assert not any(p.install_path.endswith("local-link") for p in INV)


@pytest.mark.parametrize("component,version,status,stance", [
    ("Auth0_node-jsonwebtoken", "0.4.0", "scanned_version_present", Stance.neutral),  # alias
    ("multer", "1.4.5-lts.1", "version_drift", Stance.refutes),
    ("expressjsmorgan", "1.10.0", "not_installed", Stance.refutes),  # aliased name absent
    ("SomeVendorName", "1.0", "unresolved_name", Stance.neutral),  # unknown spelling: no claim
])
def test_reconcile(tmp_path, component, version, status, stance):
    r = reconcile(sca(component, version, tmp_path), INV)
    assert r.status == status
    assert to_evidence(r, inventory_ref="lock:x").stance is stance


def test_dev_only_flag(tmp_path):
    r = reconcile(sca("mocha", "10.0.0", tmp_path), INV)
    assert r.dev_only is True and "dev dependency only" in to_evidence(r, inventory_ref="x").summary


ROOT = Path(__file__).resolve().parents[1] / "data"
LOCK = ROOT / "resolved" / "juiceshop-20.2.0-package-lock-resolved-2026-09-27.json"
LEDGER = ROOT / "poc-report" / "final-validation-ledger.jsonl"


@pytest.mark.skipif(not (LOCK.exists() and LEDGER.exists()), reason="private data not present")
def test_reproduces_poc_version_drift():
    inv = REGISTRY["node"].read_inventory(LOCK)
    _, fs = polaris.load(LEDGER)
    rows = [json.loads(l) for l in LEDGER.open(encoding="utf-8") if l.strip()]
    for f, r in zip(fs, rows):
        if f.package:
            drift = reconcile(f, inv).status == "version_drift"
            assert drift == (r["classification"] == "stale_dependency_instance"), f.package
