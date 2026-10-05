import base64
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from fva import runtime


MARKER = "FVA_EXECUTION_PROOF_12345"


@pytest.fixture
def prepared(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.txt").write_text("synthetic local execution fixture\n")
    source_hash = runtime.pin(source).content_sha256
    run = tmp_path / "run"
    run.mkdir()
    row = {"finding_id": "f", "source_finding_id": "synthetic-f", "finding_type": "sast",
           "disposition": "assess", "cwe": ["CWE-94"], "severity": "high", "title": "code execution",
           "source_tool": "fixture", "issue_id": "fixture-issue", "primary": True,
           "path": "app.txt", "line": 1, "package": None, "endpoint": None}
    (run / "findings.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
    (run / "evidence.jsonl").write_text("", encoding="utf-8")
    runtime.write_json(run / "summary.json", {"profile": "p", "source_content_sha256": source_hash})
    return source, run


def make_plan(run, origin="http://127.0.0.1:12345"):
    summary = json.loads((run / "summary.json").read_text())
    return runtime.Plan(profile_id="p", source_content_sha256=summary["source_content_sha256"],
                        findings_sha256=runtime.file_digest(run / "findings.jsonl"),
                        allowed_urls=(origin + "/control", origin + "/probe"),
                        pairs=(runtime.ProbePair(finding_id="f", marker=MARKER,
                                                rationale="Synthetic server executes the probe and returns a computed marker.",
                                                probe=runtime.RequestSpec(url=origin + "/probe"),
                                                control=runtime.RequestSpec(url=origin + "/control")),))


def inputs(tmp_path, plan):
    plan_path = tmp_path / "plan.json"
    approval_path = tmp_path / "approval.json"
    runtime.write_json(plan_path, plan.model_dump(mode="json"))
    runtime.write_json(approval_path, {"plan_sha256": runtime.digest(plan.model_dump(mode="json")),
                                      "decision": "approved", "approved_by": "fixture operator",
                                      "method": "interactive-tty",
                                      "acknowledged_plan_prefix": runtime.digest(plan.model_dump(mode="json"))[:12],
                                      "approved_at": "2026-10-03T00:00:00Z"})
    return plan_path, approval_path


@pytest.mark.parametrize("mutation", ["remote", "post", "outside", "marker", "same", "localhost", "0.0.0.0", "10.0.0.1"])
def test_gate_rejects_entire_plan_before_network(prepared, tmp_path, monkeypatch, mutation):
    source, run = prepared
    plan = make_plan(run).model_dump(mode="json")
    if mutation == "remote":
        plan["allowed_urls"][0] = "http://example.com:80/control"
    elif mutation in {"localhost", "0.0.0.0", "10.0.0.1"}:
        plan["allowed_urls"][0] = f"http://{mutation}:12345/control"
    elif mutation == "post":
        plan["pairs"][0]["probe"]["method"] = "POST"
    elif mutation == "outside":
        plan["pairs"][0]["control"]["url"] = "http://127.0.0.1:12345/other"
    elif mutation == "marker":
        url = "http://127.0.0.1:12345/" + MARKER
        plan["allowed_urls"][1] = plan["pairs"][0]["probe"]["url"] = url
    else:
        plan["pairs"][0]["probe"] = plan["pairs"][0]["control"]
    plan = runtime.Plan.model_validate(plan)
    plan_path, approval = inputs(tmp_path, plan)
    monkeypatch.setattr(runtime, "fetch", lambda spec: pytest.fail("gate sent a request"))
    with pytest.raises(ValueError):
        runtime.collect(run, source, plan_path, approval, tmp_path / "collection")
    assert not (tmp_path / "collection").exists()


@pytest.mark.parametrize("mutation", ["pending", "plan", "source", "profile", "findings"])
def test_gate_requires_exact_approval_and_run_binding(prepared, tmp_path, monkeypatch, mutation):
    source, run = prepared
    plan = make_plan(run)
    plan_path, approval = inputs(tmp_path, plan)
    if mutation in {"pending", "plan"}:
        content = json.loads(approval.read_text())
        content["decision" if mutation == "pending" else "plan_sha256"] = mutation
        runtime.write_json(approval, content)
    elif mutation == "source":
        (source / "app.txt").write_text("changed source")
    elif mutation == "profile":
        summary = json.loads((run / "summary.json").read_text())
        summary["profile"] = "other"
        runtime.write_json(run / "summary.json", summary)
    else:
        with (run / "findings.jsonl").open("a") as stream:
            stream.write("\n")
    monkeypatch.setattr(runtime, "fetch", lambda spec: pytest.fail("gate sent a request"))
    with pytest.raises(ValueError):
        runtime.collect(run, source, plan_path, approval, tmp_path / "collection")


def test_approval_template_cannot_approve_or_overwrite(prepared, tmp_path):
    from fva.__main__ import main
    _, run = prepared
    plan_path, _ = inputs(tmp_path, make_plan(run))
    out = tmp_path / "pending.json"
    main(["runtime", "approval-template", str(plan_path), "--out", str(out)])
    receipt = json.loads(out.read_text())
    assert receipt["decision"] == "pending" and receipt["approved_by"] == ""
    with pytest.raises(FileExistsError):
        main(["runtime", "approval-template", str(plan_path), "--out", str(out)])


@pytest.fixture
def server(prepared):
    _, run = prepared
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            source_hash = json.loads((run / "summary.json").read_text())["source_content_sha256"]
            self.send_response(302 if self.path == "/redirect" else 200)
            self.send_header("X-FVA-Source-SHA256", "wrong" if self.path == "/wrong" else source_hash)
            if self.path == "/duplicate-identity":
                self.send_header("X-FVA-Source-SHA256", "wrong")
            if self.path in {"/probe", "/duplicate-identity"}:
                self.send_header("X-Record-Banner", "RecordDesk/1.2.3")
            self.send_header("Location", "/never-follow")
            self.end_headers()
            if self.path == "/slow":
                try:
                    for _ in range(30):
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(0.2)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            elif self.path in {"/probe", "/sca-probe"}:
                # The fixture computes a marker, rather than reflecting a marker from a request.
                self.wfile.write(bytes([ord(c) for c in MARKER]))
            elif self.path == "/huge":
                self.wfile.write(b"x" * (runtime.MAX_BYTES + 1))
            else:
                self.wfile.write(self.path.encode())

        def log_message(self, *args):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_port}", seen
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()


def collect_fixture(prepared, tmp_path, origin):
    source, run = prepared
    plan_path, approval = inputs(tmp_path, make_plan(run, origin))
    out = tmp_path / "collection"
    runtime.collect(run, source, plan_path, approval, out)
    return out


def test_live_collection_import_and_worksheet_confirmation(prepared, tmp_path, server):
    from fva.export import worksheet
    from fva.__main__ import main
    _, run = prepared
    origin, seen = server
    collection = collect_fixture(prepared, tmp_path, origin)
    original = {p.name: p.read_bytes() for p in run.iterdir()}
    out = tmp_path / "imported"
    main(["runtime", "import", str(run), str(collection), "--out", str(out)])
    assert seen == ["/control", "/probe"]
    row = worksheet.build(out)[0]
    assert row["fva_verdict"] == "confirmed" and row["reason_codes"] == "RUNTIME_CONFIRMED"
    assert json.loads((out / "summary.json").read_text())["verdicts"] == {"confirmed": 1}
    assert {p.name: p.read_bytes() for p in run.iterdir()} == original
    records = runtime.read_rows(out / "evidence.jsonl")
    assert records[0]["detail_ref"].split("#")[0] == "raw:sha256:" + runtime.file_digest(out / "runtime-receipt.json")
    with pytest.raises(FileExistsError):
        runtime.import_collection(run, collection, out)


@pytest.mark.parametrize("change", ["receipt", "evidence", "profile", "findings", "missing", "duplicate", "format"])
def test_modified_import_cannot_confirm(prepared, tmp_path, server, change):
    from fva.export import worksheet
    _, run = prepared
    origin, _ = server
    collection = collect_fixture(prepared, tmp_path, origin)
    out = tmp_path / "imported"
    runtime.import_collection(run, collection, out)
    if change == "receipt":
        receipt = json.loads((out / "runtime-receipt.json").read_text())
        receipt["observations"][0]["probe"]["body_b64"] = base64.b64encode(b"changed").decode()
        runtime.write_json(out / "runtime-receipt.json", receipt)
    elif change in {"evidence", "duplicate"}:
        evidence = runtime.read_rows(out / "evidence.jsonl")
        if change == "evidence":
            evidence[0]["method"] = "hand-built"
        else:
            evidence.append(evidence[0])
        (out / "evidence.jsonl").write_text("\n".join(json.dumps(e) for e in evidence))
    elif change == "profile":
        summary = json.loads((out / "summary.json").read_text())
        summary["profile"] = "other"
        runtime.write_json(out / "summary.json", summary)
    elif change == "findings":
        with (out / "findings.jsonl").open("a") as stream:
            stream.write("\n")
    elif change == "format":
        receipt = json.loads((out / "runtime-receipt.json").read_text())
        runtime.write_json(out / "runtime-receipt.json", receipt)
    else:
        (out / "runtime-receipt.json").unlink()
    assert worksheet.build(out)[0]["fva_verdict"] == "needs_review"
    assert "Runtime" in worksheet.write(out)["warning"]


@pytest.mark.parametrize("change", ["identity", "control", "negative", "error", "truncated", "source", "request"])
def test_inconclusive_or_mismatched_receipt_does_not_confirm(prepared, tmp_path, server, change):
    _, run = prepared
    origin, _ = server
    collection = collect_fixture(prepared, tmp_path, origin)
    receipt = json.loads((collection / "receipt.json").read_text())
    observed = receipt["observations"][0]
    if change == "identity":
        observed["probe"]["source_content_sha256"] = "wrong"
    elif change in {"control", "negative"}:
        observed["control" if change == "control" else "probe"]["body_b64"] = base64.b64encode(
            MARKER.encode() if change == "control" else b"absent").decode()
    elif change == "error":
        observed["probe"]["error"] = "transport failure"
    elif change == "truncated":
        observed["probe"]["truncated"] = True
    elif change == "source":
        receipt["source_after"] = "changed"
    else:
        observed["probe"]["url"] = origin + "/outside"
    if change in {"source", "request"}:
        with pytest.raises(ValueError):
            runtime.evidence_from_receipt(receipt, run)
    else:
        records = runtime.evidence_from_receipt(receipt, run)
        assert all(e.stance.value == "neutral" for e in records)


def test_redirect_is_retained_but_never_followed_and_body_is_capped(server):
    origin, seen = server
    response = runtime.fetch(runtime.RequestSpec(url=origin + "/redirect"))
    assert response["status"] == 302 and seen == ["/redirect"]
    response = runtime.fetch(runtime.RequestSpec(url=origin + "/huge"))
    assert response["truncated"] is True
    assert len(base64.b64decode(response["body_b64"])) == runtime.MAX_BYTES


def test_trickle_response_hits_total_io_deadline(server):
    origin, _ = server
    start = time.monotonic()
    response = runtime.fetch(runtime.RequestSpec(url=origin + "/slow"))
    assert response["error"] == "transport failure"
    assert time.monotonic() - start < 5


def test_source_change_during_collection_cannot_import(prepared, tmp_path, monkeypatch):
    source, run = prepared
    plan_path, approval = inputs(tmp_path, make_plan(run))

    def fetch(spec):
        (source / "app.txt").write_text("changed during probes")
        return {"url": spec.url, "method": "GET", "error": "transport failure"}

    monkeypatch.setattr(runtime, "fetch", fetch)
    collection = tmp_path / "collection"
    runtime.collect(run, source, plan_path, approval, collection)
    with pytest.raises(ValueError, match="source changed"):
        runtime.import_collection(run, collection, tmp_path / "imported")


@pytest.mark.parametrize("location", ["path", "query"])
@pytest.mark.parametrize("encoded", [MARKER.lower(), "%2546" + MARKER[1:],
                                    base64.b64encode(MARKER.encode()).decode(),
                                    MARKER.encode().hex(),
                                    base64.b64encode(MARKER.encode().hex().encode()).decode()])
def test_encoded_marker_rejected_before_network(prepared, tmp_path, monkeypatch, location, encoded):
    source, run = prepared
    plan = make_plan(run).model_dump(mode="json")
    url = "http://127.0.0.1:12345/" + (encoded if location == "path" else "probe?x=" + encoded)
    plan["allowed_urls"][1] = plan["pairs"][0]["probe"]["url"] = url
    plan_path, approval = inputs(tmp_path, runtime.Plan.model_validate(plan))
    monkeypatch.setattr(runtime, "fetch", lambda spec: pytest.fail("encoded reflection sent a request"))
    with pytest.raises(ValueError, match="marker"):
        runtime.collect(run, source, plan_path, approval, tmp_path / "collection")


@pytest.mark.parametrize("tty,stdout_tty,ack", [(False, True, "correct"), (True, False, "correct"),
                                                (True, True, "wrong"), (True, True, "correct")])
def test_interactive_approval_requires_tty_and_exact_ack(prepared, tmp_path, monkeypatch,
                                                         tty, stdout_tty, ack):
    from types import SimpleNamespace
    from fva.__main__ import main
    _, run = prepared
    plan = make_plan(run)
    plan_path, _ = inputs(tmp_path, plan)
    out = tmp_path / "interactive.json"
    monkeypatch.setattr(runtime.sys, "stdin", SimpleNamespace(isatty=lambda: tty))
    displayed = []
    class Output:
        def isatty(self):
            return stdout_tty

        def write(self, value):
            displayed.append(value)

        def flush(self):
            pass
    monkeypatch.setattr(runtime.sys, "stdout", Output())
    prefix = runtime.digest(plan.model_dump(mode="json"))[:12]
    answers = iter(["Fixture reviewer", prefix if ack == "correct" else "wrong"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    if not tty or not stdout_tty or ack != "correct":
        with pytest.raises(ValueError):
            main(["runtime", "approve", str(plan_path), "--out", str(out)])
        assert not out.exists()
    else:
        main(["runtime", "approve", str(plan_path), "--out", str(out)])
        receipt = json.loads(out.read_text())
        runtime.validate_approval(plan, receipt)
        shown = "".join(displayed)
        assert all(text in shown for text in (plan.pairs[0].probe.url, plan.pairs[0].control.url,
                                              MARKER, plan.pairs[0].rationale))


@pytest.mark.parametrize("change", ["legacy", "future", "naive", "invalid_name"])
def test_invalid_approval_rejected_before_network(prepared, tmp_path, monkeypatch, change):
    source, run = prepared
    plan_path, approval_path = inputs(tmp_path, make_plan(run))
    approval = json.loads(approval_path.read_text())
    if change == "legacy":
        del approval["method"]
    elif change == "invalid_name":
        approval["approved_by"] = 123
    else:
        approval["approved_at"] = "2099-01-01T00:00:00Z" if change == "future" else "2026-10-03T00:00:00"
    runtime.write_json(approval_path, approval)
    monkeypatch.setattr(runtime, "fetch", lambda spec: pytest.fail("invalid approval sent a request"))
    with pytest.raises(ValueError):
        runtime.collect(run, source, plan_path, approval_path, tmp_path / "collection")


def test_approval_after_collection_cannot_back_import(prepared, tmp_path, server):
    _, run = prepared
    origin, _ = server
    collection = collect_fixture(prepared, tmp_path, origin)
    receipt = json.loads((collection / "receipt.json").read_text())
    receipt["collected_at"] = "2026-10-02T23:59:59Z"
    with pytest.raises(ValueError, match="precede collection"):
        runtime.evidence_from_receipt(receipt, run)


def test_missing_receipt_warning_is_visible_in_summary_and_html(prepared, tmp_path, server):
    from fva.export import worksheet
    _, run = prepared
    origin, _ = server
    collection = collect_fixture(prepared, tmp_path, origin)
    out = tmp_path / "imported"
    runtime.import_collection(run, collection, out)
    (out / "runtime-receipt.json").unlink()
    summary = worksheet.write(out)
    assert "receipt missing" in summary["warning"]
    assert "receipt missing" in (out / "worksheet.html").read_text()
    assert summary["verdicts"] == {"needs_review": 1}


def test_second_import_into_derived_run_is_explicitly_rejected(prepared, tmp_path, server):
    _, run = prepared
    origin, _ = server
    collection = collect_fixture(prepared, tmp_path, origin)
    out = tmp_path / "imported"
    runtime.import_collection(run, collection, out)
    with pytest.raises(ValueError, match="one collection"):
        runtime.import_collection(out, collection, tmp_path / "second")


def oracle_plan(source, run, oracle, origin="http://127.0.0.1:12345"):
    plan = make_plan(run, origin).model_dump(mode="json")
    plan["source_root"] = str(source)
    pair = plan["pairs"][0]
    pair["oracle"] = oracle
    if oracle == "header_disclosure":
        pair.pop("marker")
        pair.update(header_name="X-Record-Banner", expected_value="RecordDesk/1.2.3")
    if oracle == "sca_marker":
        pair["call_site"] = "routes/template.js:2"
        plan["entrypoints"] = ["server.js"]
        plan["allowed_urls"][1] = pair["probe"]["url"] = origin + "/sca-probe"
    return plan


def oracle_finding(source, run, oracle):
    row = runtime.read_rows(run / "findings.jsonl")[0]
    if oracle == "header_disclosure":
        (source / "app.txt").write_text('res.setHeader("X-Record-Banner", "RecordDesk/1.2.3")\n')
        row.update(finding_type="sast", cwe=["CWE-201"], path="app.txt", line=1)
    else:
        (source / "server.js").write_text("const template = require('./routes/template')\napp.get('/sca-probe', template.run)\n")
        routes = source / "routes"
        routes.mkdir()
        (routes / "template.js").write_text("import _ from 'lodash'\n_.template(input)\n")
        row.update(finding_type="sca", cwe=[], path=None, line=None)
        evidence = {"evidence_id": "f:callsite:called", "finding_ids": ["f"],
                    "evidence_type": "static_source", "method": "advisory_call_site:called",
                    "stance": "supports", "summary": "CVE-2021-23337 affects lodash template: template at routes/template.js:2",
                    "deployment_profile_id": "p", "collected_at": "2026-10-03T00:00:00Z"}
        (run / "evidence.jsonl").write_text(json.dumps(evidence) + "\n")
    (run / "findings.jsonl").write_text(json.dumps(row) + "\n")
    summary = json.loads((run / "summary.json").read_text())
    summary["source_content_sha256"] = runtime.pin(source).content_sha256
    runtime.write_json(run / "summary.json", summary)


def test_execution_plan_digest_unchanged(prepared):
    _, run = prepared
    plan = make_plan(run)
    pair = plan.model_dump(mode="json")["pairs"][0]
    assert set(pair) == {"finding_id", "probe", "control", "marker", "rationale"}
    assert set(plan.model_dump(mode="json")) == {"profile_id", "source_content_sha256",
                                                 "findings_sha256", "allowed_urls", "pairs"}
    # findings.jsonl is written in text mode, so its hash depends on the OS line ending; the format check does not.
    stable = plan.model_dump(mode="json") | {"findings_sha256": "0" * 64}
    assert runtime.digest(stable) == "8fc06852f6a8676c20ab48fa95100ebb16088e3f37f1ea76052f5068a6a0c0bb"


@pytest.mark.parametrize("oracle", ["header_disclosure", "sca_marker"])
def test_oracle_collects_support_with_bound_control(prepared, tmp_path, server, oracle):
    source, run = prepared
    oracle_finding(source, run, oracle)
    origin, seen = server
    plan = runtime.Plan.model_validate(oracle_plan(source, run, oracle, origin))
    plan_path, approval = inputs(tmp_path, plan)
    collection = tmp_path / "collection"
    runtime.collect(run, source, plan_path, approval, collection)
    receipt = json.loads((collection / "receipt.json").read_text())
    records = runtime.evidence_from_receipt(receipt, run)
    if oracle == "header_disclosure":
        assert receipt["observations"][0]["probe"]["headers"] == {"x-record-banner": "RecordDesk/1.2.3"}
        assert receipt["observations"][0]["control"]["headers"] == {"x-record-banner": None}
    assert [e.stance.value for e in records] == ["supports", "neutral"]
    assert records[1].tool_versions["control_for"] == records[0].evidence_id
    assert seen == (["/control", "/probe"] if oracle == "header_disclosure" else ["/control", "/sca-probe"])
    out = tmp_path / "imported"
    runtime.import_collection(run, collection, out)
    assert json.loads((out / "summary.json").read_text())["verdicts"] == {"confirmed": 1}


@pytest.mark.parametrize("oracle", ["header_disclosure", "sca_marker"])
@pytest.mark.parametrize("change", ["outside", "post", "unknown"])
def test_new_oracles_reject_unapproved_requests_before_network(prepared, tmp_path, monkeypatch, oracle, change):
    source, run = prepared
    oracle_finding(source, run, oracle)
    plan = oracle_plan(source, run, oracle)
    pair = plan["pairs"][0]
    if change == "outside":
        pair["probe"]["url"] = "http://127.0.0.1:12345/other"
    elif change == "post":
        pair["probe"]["method"] = "POST"
    else:
        pair["oracle"] = "unrecognized"
    plan_path, approval = inputs(tmp_path, runtime.Plan.model_validate(plan))
    monkeypatch.setattr(runtime, "fetch", lambda *args: pytest.fail("gate sent a request"))
    with pytest.raises(ValueError):
        runtime.collect(run, source, plan_path, approval, tmp_path / "collection")


@pytest.mark.parametrize("change", ["missing_record", "wrong_site", "wrong_route"])
def test_sca_requires_called_site_on_probed_route(prepared, tmp_path, monkeypatch, change):
    source, run = prepared
    oracle_finding(source, run, "sca_marker")
    plan = oracle_plan(source, run, "sca_marker")
    if change == "missing_record":
        (run / "evidence.jsonl").write_text("")
    elif change == "wrong_site":
        plan["pairs"][0]["call_site"] = "routes/template.js:3"
    else:
        plan["allowed_urls"][1] = plan["pairs"][0]["probe"]["url"] = "http://127.0.0.1:12345/unrelated"
    plan_path, approval = inputs(tmp_path, runtime.Plan.model_validate(plan))
    monkeypatch.setattr(runtime, "fetch", lambda *args: pytest.fail("gate sent a request"))
    with pytest.raises(ValueError, match="call site|route"):
        runtime.collect(run, source, plan_path, approval, tmp_path / "collection")


@pytest.mark.parametrize("change", ["cwe", "source_value"])
def test_header_requires_disclosure_finding_and_source_literal(prepared, tmp_path, monkeypatch, change):
    source, run = prepared
    oracle_finding(source, run, "header_disclosure")
    if change == "cwe":
        row = runtime.read_rows(run / "findings.jsonl")[0]
        row["cwe"] = ["CWE-94"]
        (run / "findings.jsonl").write_text(json.dumps(row) + "\n")
    plan = oracle_plan(source, run, "header_disclosure")
    if change == "source_value":
        plan["pairs"][0]["expected_value"] = "Other/1.2.3"
    plan_path, approval = inputs(tmp_path, runtime.Plan.model_validate(plan))
    monkeypatch.setattr(runtime, "fetch", lambda *args: pytest.fail("gate sent a request"))
    with pytest.raises(ValueError):
        runtime.collect(run, source, plan_path, approval, tmp_path / "collection")


@pytest.mark.parametrize("oracle", ["header_disclosure", "sca_marker"])
@pytest.mark.parametrize("response", ["control", "probe"])
def test_new_oracles_require_identity_on_both_responses(prepared, tmp_path, server, oracle, response):
    source, run = prepared
    oracle_finding(source, run, oracle)
    origin, _ = server
    plan_path, approval = inputs(tmp_path, runtime.Plan.model_validate(oracle_plan(source, run, oracle, origin)))
    collection = tmp_path / "collection"
    runtime.collect(run, source, plan_path, approval, collection)
    receipt = json.loads((collection / "receipt.json").read_text())
    receipt["observations"][0][response]["source_content_sha256"] = None
    assert all(e.stance.value == "neutral" for e in runtime.evidence_from_receipt(receipt, run))


def test_header_value_must_match_exactly(prepared, tmp_path, server):
    source, run = prepared
    oracle_finding(source, run, "header_disclosure")
    origin, _ = server
    plan_path, approval = inputs(tmp_path, runtime.Plan.model_validate(oracle_plan(source, run, "header_disclosure", origin)))
    collection = tmp_path / "collection"
    runtime.collect(run, source, plan_path, approval, collection)
    receipt = json.loads((collection / "receipt.json").read_text())
    receipt["observations"][0]["probe"]["headers"]["x-record-banner"] = "RecordDesk/1.2.3-extra"
    assert all(e.stance.value == "neutral" for e in runtime.evidence_from_receipt(receipt, run))


def test_header_receipt_rejects_unapproved_headers(prepared, tmp_path, server):
    source, run = prepared
    oracle_finding(source, run, "header_disclosure")
    origin, _ = server
    plan_path, approval = inputs(tmp_path, runtime.Plan.model_validate(oracle_plan(source, run, "header_disclosure", origin)))
    collection = tmp_path / "collection"
    runtime.collect(run, source, plan_path, approval, collection)
    receipt = json.loads((collection / "receipt.json").read_text())
    receipt["observations"][0]["probe"]["headers"]["set-cookie"] = "unapproved"
    with pytest.raises(ValueError, match="unapproved header"):
        runtime.evidence_from_receipt(receipt, run)


def test_duplicate_identity_header_cannot_support(prepared, tmp_path, server):
    source, run = prepared
    oracle_finding(source, run, "header_disclosure")
    origin, _ = server
    plan = oracle_plan(source, run, "header_disclosure", origin)
    plan["allowed_urls"][1] = plan["pairs"][0]["probe"]["url"] = origin + "/duplicate-identity"
    plan_path, approval = inputs(tmp_path, runtime.Plan.model_validate(plan))
    collection = tmp_path / "collection"
    runtime.collect(run, source, plan_path, approval, collection)
    receipt = json.loads((collection / "receipt.json").read_text())
    assert receipt["observations"][0]["probe"]["source_content_sha256"] is None
    assert all(e.stance.value == "neutral" for e in runtime.evidence_from_receipt(receipt, run))


@pytest.mark.parametrize("app,accepted", [
    ("import express from 'express'\nconst app = express()\n", True),
    ("const express = require('express')\nconst app = express()\n", True),
    ("const app = createServer()\n", False),  # no framework import and no literal value
])
def test_framework_default_header_needs_the_framework_import(prepared, app, accepted):
    source, run = prepared
    oracle_finding(source, run, "header_disclosure")
    (source / "app.txt").write_text(app)
    summary = json.loads((run / "summary.json").read_text())
    summary["source_content_sha256"] = runtime.pin(source).content_sha256
    runtime.write_json(run / "summary.json", summary)
    plan = oracle_plan(source, run, "header_disclosure")
    plan["source_content_sha256"] = summary["source_content_sha256"]
    plan["pairs"][0].update(header_name="X-Powered-By", expected_value="Express")
    if accepted:
        runtime.bind_run(runtime.Plan.model_validate(plan), run)
    else:
        with pytest.raises(ValueError, match="absent near the finding line"):
            runtime.bind_run(runtime.Plan.model_validate(plan), run)


def test_imported_receipt_still_verifies_after_the_checkout_changes(prepared, tmp_path, server):
    source, run = prepared
    oracle_finding(source, run, "header_disclosure")
    origin, _ = server
    plan_path, approval = inputs(tmp_path, runtime.Plan.model_validate(oracle_plan(source, run, "header_disclosure", origin)))
    runtime.collect(run, source, plan_path, approval, tmp_path / "collection")
    out = tmp_path / "imported"
    runtime.import_collection(run, tmp_path / "collection", out)
    evidence = [runtime.EvidenceRecord.model_validate_json(line)
                for line in (out / "evidence.jsonl").read_text().splitlines() if line.strip()]
    (source / "app.txt").write_text("edited after import\n")
    trusted, warning = runtime.verify_runtime(out, evidence)
    assert warning is None and len(trusted) == 2
    with pytest.raises(ValueError, match="pinned source root"):  # a fresh import re-checks the source
        runtime.import_collection(run, tmp_path / "collection", tmp_path / "again")
