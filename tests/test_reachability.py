import json
from pathlib import Path

import pytest

from fva.adapters import polaris
from fva.correlation.reachability import assess, build_graph, to_evidence
from fva.langpacks import REGISTRY
from fva.schemas import DeploymentProfile, Stance, Surface

NODE = REGISTRY["node"]
P = DeploymentProfile(profile_id="p", name="t", language_packs=("node",), entrypoints=("server.ts",),
                      extra_path_rules=(("data/static/codefixes/*", Surface.fixture),))


def test_import_parsing():
    src = ("import a from 'express'\nimport * as b from \"./lib/b\"\nimport { c } from '@scope/pkg/sub'\n"
           "const d = require('jsonwebtoken')\nexport { e } from './e'\nconst f = await import('./dyn.js')\n"
           "import 'side-effect'\nimport fs from 'node:fs'\n")
    specs = NODE.imports(src)
    assert [s for s, _ in specs] == ["express", "./lib/b", "@scope/pkg/sub", "jsonwebtoken", "./e", "./dyn.js",
                                     "side-effect", "node:fs"]
    assert specs[3][1] == 4
    assert [NODE.package_of(s) for s, _ in specs] == ["express", None, "@scope/pkg", "jsonwebtoken", None, None,
                                                      "side-effect", None]


def test_resolve_local():
    files = {"lib/b.ts", "lib/index.ts", "routes/x.ts", "e/index.js", "dyn.ts"}
    assert NODE.resolve_local("./lib/b", "server.ts", files) == "lib/b.ts"
    assert NODE.resolve_local("../lib", "routes/x.ts", files) == "lib/index.ts"
    assert NODE.resolve_local("./e", "server.ts", files) == "e/index.js"
    assert NODE.resolve_local("./dyn.js", "server.ts", files) == "dyn.ts"


@pytest.fixture
def repo(tmp_path):
    w = lambda p, t: ((tmp_path / p).parent.mkdir(parents=True, exist_ok=True), (tmp_path / p).write_text(t))
    w("server.ts", "import { login } from './routes/login'\n")
    w("routes/login.ts", "import jwt from 'jsonwebtoken'\nexport const login = 1\n")
    w("routes/orphan.ts", "export const x = 1\n")
    w("test/login.test.ts", "import chai from 'chai'\nimport mocha from 'mocha'\n")
    w("data/static/codefixes/fix_1.ts", "import yaml from 'js-yaml'\n")
    return tmp_path


def _f(tmp_path, **row):
    base = {"candidate_id": "x", "severity": "low", "issue_type": "t"}
    p = tmp_path / "f.jsonl"
    p.write_text(json.dumps({**base, **row}) + "\n")
    return polaris.load(p)[1][0]


def _graph(repo):
    files = [p.relative_to(repo).as_posix() for p in repo.rglob("*") if p.is_file() and "f.jsonl" not in p.name]
    return build_graph(repo, files, P)


def test_sast_graph(repo, tmp_path):
    g = _graph(repo)
    r = assess(_f(tmp_path, tool="SAST", location="routes/login.ts", line=1), g, P)
    assert r.status == "in_entrypoint_graph" and r.detail == "server.ts -> routes/login.ts"
    assert assess(_f(tmp_path, tool="SAST", location="routes/orphan.ts", line=1), g, P).status == "not_in_entrypoint_graph"


@pytest.mark.parametrize("component,status,stance", [
    ("Auth0_node-jsonwebtoken", "imported_by_reachable_code", Stance.neutral),  # alias applied
    ("mocha", "imported_only_outside_deployment", Stance.refutes),
    ("js-yaml", "imported_only_outside_deployment", Stance.refutes),  # only in a fixture
    ("lodash", "not_imported_directly", Stance.neutral),
])
def test_sca_import_status(repo, tmp_path, component, status, stance):
    g = _graph(repo)
    r = assess(_f(tmp_path, tool="SCA", component=component, component_version="1"), g, P)
    assert r.status == status
    assert to_evidence(r, source_content_sha256="0" * 64, profile_id="p").stance is stance


def test_static_reachability_never_supports(repo, tmp_path):
    g = _graph(repo)
    r = assess(_f(tmp_path, tool="SAST", location="routes/login.ts", line=1), g, P)
    assert to_evidence(r, source_content_sha256="0" * 64, profile_id="p").stance is not Stance.supports
