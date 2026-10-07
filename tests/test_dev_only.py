import json

import pytest

from fva.adapters import polaris
from fva.correlation import dependency, dev_only
from fva.langpacks import REGISTRY
from fva.reasoning.assessor import MODEL_CODES
from fva.schemas import DeploymentProfile, VerdictValue
from fva.verdicts import suggest_verdict


PROFILE = DeploymentProfile(profile_id="p", name="test", language_packs=("node",), entrypoints=("server.js",))


def setup_case(tmp_path, files=None, packages=None, target="pkg"):
    root = tmp_path / "src"
    root.mkdir()
    for rel, text in (files or {}).items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"lockfileVersion": 3, "packages": packages or {
        "": {}, f"node_modules/{target}": {"version": "1.0.0", "dev": True}}}))
    inp = tmp_path / "findings.jsonl"
    inp.write_text(json.dumps({"candidate_id": "S", "tool": "SCA", "severity": "medium", "issue_type": "DoS",
                              "component": target, "component_version": "1.0.0"}) + "\n")
    f = polaris.load(inp)[1][0]
    inv = REGISTRY["node"].read_inventory(lock)
    return root, lock, inv, f, inp


def evidence(case):
    root, lock, inv, f, _ = case
    return dev_only.build_index(root, lock, inv, PROFILE).evidence(dependency.reconcile(f, inv), "p")


def test_unreferenced_and_verdict(tmp_path):
    case = setup_case(tmp_path)
    ev = evidence(case)
    assert ev and ev.method == "dev_only:not_shipped" and ev.deployment_profile_id == "p"
    verdict, codes, confidence, cited = suggest_verdict(
        {"finding_id": case[3].finding_id, "disposition": "dependency:dev_only_not_shipped"}, [ev])
    assert (verdict, codes, confidence) == (VerdictValue.not_applicable, ("DEV_DEPENDENCY_NOT_SHIPPED",), "medium")
    assert cited == [ev]
    assert "DEV_DEPENDENCY_NOT_SHIPPED" not in MODEL_CODES


def test_excluded_files(tmp_path):
    files = {p: "require('pkg')" for p in ("test/a.js", "README.md", "package.json", "package-lock.json",
                                          "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
                                          "node_modules/a/x.js", ".git/x", "openapi.json")}
    assert evidence(setup_case(tmp_path, files))


@pytest.mark.parametrize("path,text", [
    ("server.js", "require('pkg')"), ("a.vue", '<script>import x from "pkg/x"</script>'),
    ("a.scss", '@import "~pkg/x";'), ("vite.config.js", "import x from 'pkg'"),
    ("a.css", "a {background: url(pkg/x)}"), ("Dockerfile", "RUN echo pkg/x"),
    ("a.svelte", "import('pkg')"), ("a.less", '@import "pkg/x"'),
    ("config.json", '{"path":"pkg/x"}'), ("build.sh", "echo `pkg`"),
    ("a.html", '<script src="node_modules/pkg/x"></script>'),
])
def test_counted_references(tmp_path, path, text):
    assert evidence(setup_case(tmp_path, {path: text})) is None


@pytest.mark.parametrize("key", ["dependencies", "optionalDependencies", "peerDependencies"])
def test_transitive_dev_dependency(tmp_path, key):
    packages = {"": {}, "node_modules/tool": {"version": "1", "dev": True, key: {"middle": "1"}},
                "node_modules/middle": {"version": "1", "dev": True, "dependencies": {"pkg": "1"}},
                "node_modules/pkg": {"version": "1.0.0", "dev": True}}
    assert evidence(setup_case(tmp_path, {"vite.config.js": "require('tool')"}, packages)) is None


def test_any_non_dev_instance(tmp_path):
    packages = {"node_modules/pkg": {"version": "1.0.0", "dev": True},
                "node_modules/a/node_modules/pkg": {"version": "2.0.0"}}
    assert evidence(setup_case(tmp_path, packages=packages)) is None


def test_missing_or_invalid_lock(tmp_path):
    root, lock, inv, f, _ = setup_case(tmp_path)
    result = dependency.reconcile(f, inv)
    assert dev_only.build_index(root, None, inv, PROFILE).evidence(result, "p") is None
    for text in ('{}', '{"packages": null}', 'bad json'):
        lock.write_text(text)
        assert dev_only.build_index(root, lock, inv, PROFILE).evidence(result, "p") is None
    lock.unlink()
    assert dev_only.build_index(root, lock, inv, PROFILE).evidence(result, "p") is None


@pytest.mark.parametrize("target,text,closes", [
    ("vuex", "import x from 'vue'", True), ("vue", "import x from 'vuex'", True),
    ("vue", "import x from 'vue-router'", True), ("vue", "import x from 'vue/dist/x'", False),
    ("@scope/name", 'import x from "@scope/name/sub"', False),
    ("@scope/name", 'import x from "@scope/name-extra"', True),
])
def test_name_boundaries(tmp_path, target, text, closes):
    assert bool(evidence(setup_case(tmp_path, {"app.js": text}, target=target))) is closes


def test_read_error_keeps_open(tmp_path, monkeypatch):
    from pathlib import Path
    case = setup_case(tmp_path, {"app.vue": "hello"})
    original = Path.read_bytes

    def read(path):
        if path.name == "app.vue":
            raise PermissionError("denied")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", read)
    assert evidence(case) is None


def test_version_drift_keeps_existing_rule(tmp_path):
    case = setup_case(tmp_path, packages={"node_modules/pkg": {"version": "2", "dev": True}})
    assert evidence(case) is None


def test_pipeline_closure(tmp_path):
    from fva import pipeline
    from fva.export import worksheet
    from fva.reasoning.model import ScriptedClient
    root, lock, _, _, inp = setup_case(tmp_path, {"server.js": "console.log(1)"})
    out = tmp_path / "out"
    summary = pipeline.run(findings_spec=str(inp), source_root=root, profile=PROFILE, lockfile=lock,
                           client=ScriptedClient([]), out_dir=out, log=lambda *_: None)
    assert summary["skipped"] == {"dependency:dev_only_not_shipped": 1}
    assert summary["clusters"] == 0
    row, = worksheet.build(out)
    assert row["fva_verdict"] == "not_applicable"
    assert row["reason_codes"] == "DEV_DEPENDENCY_NOT_SHIPPED"
    assert row["evidence_ids"]


def test_closure_across_installed_versions(tmp_path):
    packages = {"node_modules/tool": {"version": "1", "dev": True},
                "node_modules/a/node_modules/tool": {"version": "2", "dev": True,
                                                     "dependencies": {"pkg": "1"}},
                "node_modules/pkg": {"version": "1.0.0", "dev": True}}
    assert evidence(setup_case(tmp_path, {"build.sh": "tool"}, packages)) is None


def test_scan_once_for_multiple_findings(tmp_path, monkeypatch):
    from fva import pipeline
    from fva.correlation.locate import SourceIndex
    from fva.correlation.reachability import build_graph
    from pathlib import Path
    root, lock, _, f, _ = setup_case(tmp_path, {"app.vue": "hello"})
    reads = []
    original = Path.read_bytes

    def read(path):
        reads.append(path)
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", read)
    graph = build_graph(root, ["app.vue"], PROFILE)
    pipeline.prepare([f, f], root, PROFILE, lock, "sha", SourceIndex(root, ["app.vue"]), graph)
    assert reads.count(root / "app.vue") == 1


@pytest.mark.parametrize("severity", ["high", "critical"])
def test_high_impact_closure_stays_open(tmp_path, severity):
    from fva.triage import route
    case = setup_case(tmp_path)
    ev = evidence(case)
    result = route(case[3].finding_id, severity, VerdictValue.not_applicable,
                   ("DEV_DEPENDENCY_NOT_SHIPPED",), "medium", [ev], profile="p")
    assert result == ("review", ("HIGH_IMPACT_CLOSURE",))


def test_closure_from_referenced_non_dev_package(tmp_path):
    packages = {"node_modules/lib": {"version": "1", "peerDependencies": {"pkg": "1"}},
                "node_modules/pkg": {"version": "1.0.0", "dev": True}}
    assert evidence(setup_case(tmp_path, {"server.js": "require('lib')"}, packages)) is None


def test_large_file_is_scanned(tmp_path):
    assert evidence(setup_case(tmp_path, {"dist/bundle.js": "x" * (3 * 1024 * 1024) + "\nrequire('pkg')"})) is None
