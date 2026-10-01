from datetime import datetime, timezone

from fva.correlation.package_link import link, link_all
from fva.correlation.reachability import CodeGraph
from fva.schemas import DeploymentProfile, Finding, FindingLocation, PackageRef, Severity

P = DeploymentProfile(profile_id="p", name="t", language_packs=("node",), entrypoints=("server.ts",))
G = CodeGraph(files={"routes/login.ts", "test/a.test.ts"},
              package_uses={"jsonwebtoken": [("routes/login.ts", 1)], "chai": [("test/a.test.ts", 1)]})


def _f(fid, kind, **kw):
    return Finding(finding_id=fid, run_id="r", source_tool="polaris", source_finding_id=fid, rule_id="x",
                   title="t", severity=Severity.high, finding_type=kind, raw_evidence_ref="raw:sha256:0#/", **kw)


def _sca(pkg, cwe=()):
    return _f(f"sca-{pkg}", "sca", package=PackageRef(name=pkg, version="1"), cwe=cwe)


def _sast(path, line=5, cwe=("CWE-347",)):
    return _f(f"sast-{path}", "sast", location=FindingLocation(path=path, start_line=line), cwe=cwe)


def test_same_file_matching_cwe_is_high():
    l = link(_sca("jsonwebtoken", ("CWE-347",)), _sast("routes/login.ts"), G, P)
    assert l.confidence == "high" and l.basis == ("shipped_import_same_file", "cwe", "sink_after_import")


def test_same_file_without_cwe_is_low():
    assert link(_sca("jsonwebtoken"), _sast("routes/login.ts"), G, P).confidence == "low"


def test_test_only_import_never_links():
    assert link(_sca("chai", ("CWE-347",)), _sast("test/a.test.ts"), G, P) is None


def test_other_file_never_links():
    assert link(_sca("jsonwebtoken", ("CWE-347",)), _sast("routes/other.ts"), G, P) is None


def test_link_all_deterministic():
    a = link_all([_sca("jsonwebtoken", ("CWE-347",)), _sca("chai")], [_sast("routes/login.ts")], G, P)
    assert len(a) == 1 and a == link_all([_sca("chai"), _sca("jsonwebtoken", ("CWE-347",))],
                                         [_sast("routes/login.ts")], G, P)
