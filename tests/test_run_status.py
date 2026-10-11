"""A run must never look complete when it is not: summary.json status, exit code and downstream readers."""
import json

import pytest

import fva.__main__ as cli
from fva import pipeline
from fva.export import report, worksheet
from tests.test_pipeline_workers import FakeClient, _run, _setup

PROFILE = "examples/profiles/juiceshop.json"


def test_clean_run_is_complete(tmp_path):
    s, out, _ = _run(tmp_path, "o", FakeClient(), 1)
    assert s["status"] == "complete"
    assert json.loads((out / "summary.json").read_text())["status"] == "complete"


def test_cluster_error_makes_run_partial(tmp_path):
    s, out, _ = _run(tmp_path, "o", FakeClient(fail_on="Sink-3"), 1)
    assert s["status"] == "partial" and s["errors"] == 1
    assert json.loads((out / "summary.json").read_text())["status"] == "partial"


def test_cli_exits_2_on_partial(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(pipeline, "run", lambda **kw: {"status": "partial", "errors": 2})
    monkeypatch.setattr(pipeline, "load_findings", lambda _: [])
    monkeypatch.setattr(cli, "_client", lambda *_: FakeClient())  # CI has no model CLI on PATH
    with pytest.raises(SystemExit) as e:
        cli.main(["assess", "--source", str(tmp_path), "--profile-file", PROFILE, "--out", str(tmp_path / "o")])
    cap = capsys.readouterr()
    assert e.value.code == 2 and "partial ->" in cap.err and "2 cluster errors" in cap.err
    assert "done ->" not in cap.out


def test_cli_prints_done_when_complete(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(pipeline, "run", lambda **kw: {"status": "complete", "errors": 0})
    monkeypatch.setattr(pipeline, "load_findings", lambda _: [])
    monkeypatch.setattr(cli, "_client", lambda *_: FakeClient())  # CI has no model CLI on PATH
    cli.main(["assess", "--source", str(tmp_path), "--profile-file", PROFILE, "--out", str(tmp_path / "o")])
    assert "done ->" in capsys.readouterr().out


def test_stale_summary_removed_at_start_and_only_it(tmp_path):
    src, fj, prof = _setup(tmp_path)
    out = tmp_path / "o"
    out.mkdir()
    (out / "summary.json").write_text(json.dumps({"status": "complete", "stale": True}))
    (out / "keep.txt").write_text("x")
    seen = []

    class Watch(FakeClient):
        def complete(self, *a, **k):
            seen.append((out / "summary.json").exists())  # must already be gone while the run is in progress
            return super().complete(*a, **k)

    pipeline.run(findings_spec=str(fj), source_root=src, profile=prof, client=Watch(), out_dir=out,
                 log=lambda _: None)
    assert seen and not any(seen)
    assert "stale" not in json.loads((out / "summary.json").read_text()) and (out / "keep.txt").exists()


def test_exception_writes_failed_summary_without_message(tmp_path, monkeypatch):
    src, fj, prof = _setup(tmp_path)
    out = tmp_path / "o"

    def explode(*a, **k):
        raise ValueError("secret-token-123")

    monkeypatch.setattr(pipeline, "write_findings_index", explode)
    with pytest.raises(ValueError):
        pipeline.run(findings_spec=str(fj), source_root=src, profile=prof, client=FakeClient(), out_dir=out,
                     log=lambda _: None)
    text = (out / "summary.json").read_text()
    assert json.loads(text) == {"status": "failed", "error": "ValueError"} and "secret" not in text


def test_readers_refuse_failed_run(tmp_path):
    _, out, _ = _run(tmp_path, "o", FakeClient(), 1)
    (out / "summary.json").write_text(json.dumps({"status": "failed", "error": "ValueError"}))
    with pytest.raises(SystemExit, match="failed run"):
        worksheet.load(out)


def test_old_summary_without_status_loads_silently(tmp_path, capsys):
    _, out, _ = _run(tmp_path, "o", FakeClient(), 1)
    s = json.loads((out / "summary.json").read_text())
    del s["status"]
    (out / "summary.json").write_text(json.dumps(s))
    assert worksheet.load(out)[2] == "p"
    assert capsys.readouterr().err == ""


def test_report_on_partial_run_warns(tmp_path, capsys):
    _, out, _ = _run(tmp_path, "o", FakeClient(fail_on="Sink-3"), 1)
    report.write(out)
    assert "partial run" in capsys.readouterr().err
