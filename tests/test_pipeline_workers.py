"""Parallel model calls: run(workers=N) must give the same output as the sequential run, in cluster order."""
import json
import random
import threading
import time

import pytest

from fva import pipeline
from fva.reasoning.model import CodexCliClient
from fva.schemas import DeploymentProfile

N = 6
REPLY = json.dumps({"claims": [{"statement": "user input reaches the sink", "stance": "supports",
                                "citations": [{"path": "routes/login.ts", "line": 1, "quote": "sink(req.body.x)"}]}]})


class FakeClient:
    """Answer does not depend on call order; sleeps a random 0-50 ms; reports a per-thread model like the CLI."""
    model_id = "fake"

    def __init__(self, fail_on: str | None = None):
        self.fail_on, self.threads = fail_on, set()
        self._rng = random.Random(7)
        self._rng_lock = threading.Lock()

    def complete(self, system, user, *, max_tokens=2000):
        with self._rng_lock:
            pause = self._rng.random() * 0.05
        time.sleep(pause)
        self.threads.add(threading.get_ident())
        self.last_reported_model = f"m-{threading.get_ident()}"
        if self.fail_on and f"title: {self.fail_on}\n" in user:
            raise RuntimeError(f"boom on {self.fail_on}")
        return REPLY


def _setup(tmp_path):
    src = tmp_path / "src"
    (src / "routes").mkdir(parents=True, exist_ok=True)
    (src / "server.ts").write_text("import './routes/login'\n")
    (src / "routes/login.ts").write_text("sink(req.body.x)\n" * 20)
    rows = [{"candidate_id": f"F{n}", "tool": "SAST", "severity": "low", "issue_type": f"Sink-{n}", "cwe": "CWE-20",
             "location": "routes/login.ts", "line": n} for n in range(1, N + 1)]
    fj = tmp_path / "f.jsonl"
    fj.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    prof = DeploymentProfile(profile_id="p", name="t", language_packs=("node",), entrypoints=("server.ts",))
    return src, fj, prof


def _run(tmp_path, name, client, workers):
    src, fj, prof = _setup(tmp_path)
    log: list[str] = []
    out = tmp_path / name
    s = pipeline.run(findings_spec=str(fj), source_root=src, profile=prof, client=client, out_dir=out,
                     workers=workers, log=log.append)
    return s, out, log


def _lines(out, name):
    return [json.loads(l) for l in (out / name).read_text().splitlines()]


def _stable_assessments(out):
    rows = _lines(out, "assessments.jsonl")
    for r in rows:
        for a in r.get("attempts", []):
            a.pop("seconds", None)
            a.pop("agent_model", None)  # reported per thread by the fake client
        r.pop("agent_model", None)
    return rows


def _stable_evidence(out):
    rows = []
    for e in _lines(out, "evidence.jsonl"):
        if e["evidence_type"] != "model_assessment":
            continue
        # evidence_id is deterministic; collected_at and tool_versions.agent_model (per thread) are not compared
        rows.append({k: e[k] for k in ("evidence_id", "finding_ids", "stance", "method", "summary")})
    return rows


def test_workers_output_matches_sequential(tmp_path):
    c1, c4 = FakeClient(), FakeClient()
    s1, out1, log1 = _run(tmp_path, "w1", c1, 1)
    s4, out4, log4 = _run(tmp_path, "w4", c4, 4)
    assert s1["clusters"] == s4["clusters"] == N and s1["stance"] == s4["stance"] == {"supports": N}
    assert _stable_assessments(out1) == _stable_assessments(out4)
    assert _stable_evidence(out1) == _stable_evidence(out4) and len(_stable_evidence(out1)) == N
    # the log lines are in cluster order too, with the same text
    assert [l.split("]")[0] for l in log4 if l.startswith("[")] == [f"[{i}/{N}" for i in range(1, N + 1)]
    assert [l for l in log1 if l.startswith("[")] == [l for l in log4 if l.startswith("[")]
    # the pool really did run in other threads
    assert threading.get_ident() not in c4.threads and len(c1.threads) == 1


def test_workers_keep_cluster_order(tmp_path):
    _, out, _ = _run(tmp_path, "w4", FakeClient(), 4)
    a = _lines(out, "assessments.jsonl")
    assert [r["source_finding_ids"] for r in a] == [[f"F{n}"] for n in range(1, N + 1)]


def test_workers_error_is_recorded_in_order_and_run_continues(tmp_path):
    s, out, log = _run(tmp_path, "w4", FakeClient(fail_on="Sink-3"), 4)
    assert s["errors"] == 1 and s["clusters"] == N - 1
    a = _lines(out, "assessments.jsonl")
    assert [r["source_finding_ids"] for r in a] == [[f"F{n}"] for n in range(1, N + 1)]
    assert "error" in a[2] and "boom on Sink-3" in a[2]["error"] and a[2]["tier"] == "fixed"
    assert all("error" not in r and r["stance"] == "supports" for i, r in enumerate(a) if i != 2)
    assert any(l.startswith("[3/6] ERROR") for l in log)
    # the same failure under workers=1 is recorded identically
    _, out1, _ = _run(tmp_path, "w1", FakeClient(fail_on="Sink-3"), 1)
    assert _stable_assessments(out1) == _stable_assessments(out)


def test_cli_client_reported_model_and_tokens_are_per_thread():
    c = CodexCliClient(command="python -c pass")
    assert c.last_reported_model is None and c.last_tokens is None
    seen, barrier = {}, threading.Barrier(2)

    def worker(name, tokens):
        c.last_reported_model, c.last_tokens = f"model-{name}", tokens
        barrier.wait(timeout=5)  # both threads have written before either reads
        seen[name] = (c.last_reported_model, c.last_tokens)

    ts = [threading.Thread(target=worker, args=(n, t)) for n, t in (("a", 1), ("b", 2))]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert seen == {"a": ("model-a", 1), "b": ("model-b", 2)}
    assert c.last_reported_model is None  # the main thread never set it


def test_router_creates_each_tier_client_once(tmp_path):
    from fva.reasoning.routing import Router
    made, gate = [], threading.Barrier(4)

    def make(name):
        made.append(name)
        time.sleep(0.02)
        return FakeClient()

    r = Router({}, make=make)

    def go():
        gate.wait(timeout=5)
        r.client("junior")

    ts = [threading.Thread(target=go) for _ in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(made) == 1
