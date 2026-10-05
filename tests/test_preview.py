import json
import re
from pathlib import Path

from fva import __main__ as cli
from fva.export import preview
from tests.test_worksheet import run  # noqa: F401  (fixture: findings t,l,m,d,q; one issue each)


def _rows(run):
    return {r["source_finding_id"]: r for r in
            (json.loads(x) for x in (run / "preview.jsonl").read_text(encoding="utf-8").splitlines())}


def _set_status(run, statuses):
    p = run / "findings.jsonl"
    rows = [json.loads(x) for x in p.read_text().splitlines()]
    for r in rows:
        r["triage_status"] = statuses.get(r["source_finding_id"])
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n")


def test_review_rows_never_change(run):
    preview.write(run)
    rows = _rows(run)
    for sid in ("POL-m", "POL-q"):  # model-only: routed to review
        r = rows[sid]
        assert r["action"] == "none (open, not auto-verified)"
        assert r["suggested_status"] is None and r["suggested_severity"] is None and "comment" not in r


def test_change_rows_and_missing_status(run):
    preview.write(run)
    rows = _rows(run)
    assert len(rows) == 5 and all(r["current_status"] is None for r in rows.values())
    assert rows["POL-d"]["action"] == "change" and rows["POL-d"]["suggested_status"] == "To be fixed"
    assert rows["POL-t"]["action"] == "change" and rows["POL-t"]["suggested_severity"] == "informational"


def test_already_matching(run):
    _set_status(run, {"POL-d": "To be fixed"})
    preview.write(run)
    rows = _rows(run)
    assert rows["POL-d"]["action"] == "none (already matches)" and "comment" not in rows["POL-d"]
    assert rows["POL-d"]["current_status"] == "To be fixed"
    _set_status(run, {"POL-d": "To be fixed", "POL-l": "Not triaged"})
    preview.write(run)
    assert _rows(run)["POL-l"]["action"] == "change"


def test_comment_has_no_summary_and_all_unapproved(run):
    p = run / "evidence.jsonl"
    lines = [json.loads(x) for x in p.read_text().splitlines()]
    for d in lines:
        d["summary"] = "RAWRECEIPT-SECRET"
        d["detail_ref"] = "receipts/RAWRECEIPT-DETAIL"
    p.write_text("\n".join(json.dumps(d) for d in lines) + "\n")
    preview.write(run)
    rows = _rows(run)
    assert all(r["approved"] is False for r in rows.values())
    c = rows["POL-d"]["comment"]
    assert "e4 (dast_observation/supports/m)" in c and "DAST_OBSERVED" in c and "i-d" in c and "confirmed" in c
    for n in ("preview.jsonl", "preview.md"):
        assert "RAWRECEIPT" not in (run / n).read_text(encoding="utf-8")


def test_markdown_header_and_counts(run):
    preview.write(run)
    md = (run / "preview.md").read_text(encoding="utf-8")
    assert "ASSUMED" in md and "dry run" in md and "nothing was written to Polaris" in md and "approval" in md
    assert "| change |" in md and "| POL-d |" in md and "| POL-m |" not in md


def test_deterministic_bytes_and_lf(run):
    preview.write(run)
    first = [(run / n).read_bytes() for n in ("preview.jsonl", "preview.md")]
    preview.write(run)
    assert first == [(run / n).read_bytes() for n in ("preview.jsonl", "preview.md")]
    assert all(b"\r" not in b for b in first)


def test_no_network_imports():
    src = Path(preview.__file__).read_text(encoding="utf-8")
    for mod in ("fva.polaris_mcp", "urllib", "http", "requests", "socket"):
        assert not re.search(rf"^\s*(import|from)\s+{re.escape(mod)}\b", src, re.M), mod


def test_cli_preview(run, capsys):
    cli.main(["preview", str(run)])
    assert "'rows': 5" in capsys.readouterr().out
