import argparse

import pytest

import fva.__main__ as cli

PROFILE = "examples/profiles/juiceshop.json"


def args(**kw):
    base = dict(client="codex", model=None, dry_run=False, no_route=False, astra=None)
    return argparse.Namespace(**{**base, **kw})


@pytest.fixture
def made(monkeypatch):
    for v in ("FVA_MODEL_JUNIOR", "FVA_MODEL_SENIOR"):
        monkeypatch.delenv(v, raising=False)
    calls = []
    monkeypatch.setattr(cli, "_client", lambda name, model: calls.append((name, model)) or type("C", (), {"model_id": f"{name}:{model}"})())
    return calls


def test_codex_routes_by_default(made):
    r = cli._router(args())
    assert r.routed and [m for _, m in made] == ["gpt-6-luna", "gpt-6-sol"]


def test_no_route_uses_sol(made):
    r = cli._router(args(no_route=True))
    assert not r.routed and made == [("codex", "gpt-6-sol")]


def test_explicit_model_wins(made):
    cli._router(args(model="gpt-6-luna"))
    assert made == [("codex", "gpt-6-luna")]


def test_other_clients_are_not_routed(made):
    assert not cli._router(args(client="claude-code")).routed and made == [("claude-code", None)]


@pytest.mark.parametrize("kw", [dict(astra=["id"], no_route=True), dict(astra=["id"], model="x"),
                                dict(astra=["id"], client="claude-code")])
def test_astra_needs_routing(made, kw):
    with pytest.raises(SystemExit):
        cli._router(args(**kw))


def test_missing_lockfile_warns(tmp_path, monkeypatch, capsys):
    from fva import pipeline
    seen = {}
    monkeypatch.setattr(pipeline, "run", lambda **kw: seen.update(kw) or {})
    monkeypatch.setattr(pipeline, "load_findings", lambda _: [])
    cli.main(["assess", "--dry-run", "--source", str(tmp_path), "--profile-file", PROFILE,
              "--lockfile", str(tmp_path / "missing.json"),
              "--out", str(tmp_path / "out"), "--workers", "3", "--credential-model", "skip"])
    assert "lockfile not found" in capsys.readouterr().err
    assert seen["lockfile"] is None and seen["workers"] == 3 and seen["credential_model"] == "skip"


def test_default_lockfile_is_none_without_warning(tmp_path, monkeypatch, capsys):
    from fva import pipeline
    monkeypatch.setattr(pipeline, "run", lambda **kw: {})
    monkeypatch.setattr(pipeline, "load_findings", lambda _: [])
    cli.main(["assess", "--dry-run", "--source", str(tmp_path), "--profile-file", PROFILE,
              "--out", str(tmp_path / "out")])
    assert capsys.readouterr().err == ""


def test_juiceshop_example_profile_matches_code_profile():
    from fva.adapters.poc_ledger import JUICESHOP_PROFILE
    assert cli.load_profile(PROFILE) == JUICESHOP_PROFILE


def test_missing_sast_paths_warns_and_existing_paths_do_not(tmp_path, capsys):
    from fva.schemas import Finding, FindingLocation, FindingType, Severity

    def finding(path):
        return Finding(finding_id=path, run_id="run", source_tool="polaris", source_finding_id=path,
                       rule_id="rule", title=path, severity=Severity.low, finding_type=FindingType.sast,
                       location=FindingLocation(path=path), raw_evidence_ref="raw:test")

    (tmp_path / "present.ts").write_text("ok", encoding="utf-8")
    findings = [finding("present.ts"), finding("missing.ts")]
    cli.warn_missing_sast_paths(findings, tmp_path)
    assert "warning: 1 of 2 SAST finding paths not found under" in capsys.readouterr().err
    cli.warn_missing_sast_paths([findings[0]], tmp_path)
    assert capsys.readouterr().err == ""


def test_assess_requires_profile_file():
    with pytest.raises(SystemExit):
        cli.main(["assess", "--source", "."])
