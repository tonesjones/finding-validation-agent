import argparse

import pytest

import fva.__main__ as cli


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
    cli.main(["assess", "--dry-run", "--source", str(tmp_path), "--lockfile", str(tmp_path / "missing.json"),
              "--out", str(tmp_path / "out"), "--workers", "3", "--credential-model", "skip"])
    assert "lockfile not found" in capsys.readouterr().err
    assert seen["lockfile"] is None and seen["workers"] == 3 and seen["credential_model"] == "skip"


def test_delegated_subcommand(tmp_path, capsys):
    from pathlib import Path
    cli.main(["census", str(Path(__file__).parent / "fixtures" / "polaris_mcp_sast.json"), "--out", str(tmp_path)])
    assert (tmp_path / "census.md").exists() and "sast=1" in capsys.readouterr().out
