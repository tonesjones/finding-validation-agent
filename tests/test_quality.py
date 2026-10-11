from fva import pipeline, triage
from fva.correlation import locate, quality, reachability
from fva.schemas import DeploymentProfile, Finding, FindingLocation, FindingType, Severity
from fva.verdicts import suggest_verdict

PROFILE = DeploymentProfile(profile_id="p", name="test", language_packs=("node",), entrypoints=("server.js",))


def finding(fid, rule_id, path="server.js", kind=FindingType.sast, line=1):
    return Finding(finding_id=fid, run_id="r", source_tool="polaris", source_finding_id=fid, rule_id=rule_id,
                   title="t", severity=Severity.medium, finding_type=kind, cwe=("CWE-398",),
                   location=FindingLocation(path=path, start_line=line), raw_evidence_ref="raw:sha256:" + "0" * 64)


def test_only_listed_sast_checkers_are_quality():
    assert quality.checker(finding("a", "no_effect|typescript")) == "no_effect"
    assert quality.checker(finding("b", "NO_EFFECT")) == "no_effect"
    assert quality.checker(finding("c", "copy_paste_error|typescript")) is None  # same CWE-398, not listed
    assert quality.checker(finding("d", "no_effect", kind=FindingType.dast)) is None


def test_pipeline_closes_quality_checker_as_non_security_without_a_model_call(tmp_path):
    (tmp_path / "server.js").write_text("void run()\nisAdmin == true\n")
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "a.test.js").write_text("x == 2\n")
    index = locate.SourceIndex.build(tmp_path)
    graph = reachability.build_graph(tmp_path, sorted(index.files), PROFILE)
    shipped, in_test, other = (finding("q", "no_effect|typescript"), finding("t", "no_effect", "test/a.test.js"),
                               finding("o", "copy_paste_error|typescript"))
    risky = finding("s", "no_effect|typescript", line=2)  # a no-effect comparison can be a mistyped security check
    batch = pipeline.prepare([shipped, in_test, other, risky], tmp_path, PROFILE, None, "a" * 64, index, graph)
    assert batch.disposition == {"q": "quality:no_effect", "t": "surface:test", "o": "assess", "s": "assess"}
    assert sorted(f.finding_id for fs in batch.clusters.values() for f in fs) == ["o", "s"]
    row = {"finding_id": "q", "disposition": batch.disposition["q"], "deployment_profile_id": "p"}
    verdict, codes, conf, cited = suggest_verdict(row, batch.pre_evidence["q"])
    assert (verdict.value, codes, conf) == ("valid_non_security", ("QUALITY_NOT_SECURITY",), "medium")
    assert triage.route("q", "medium", verdict, codes, conf, cited, profile="p") == ("auto", ())
    assert triage.route("q", "high", verdict, codes, conf, cited, profile="p") == ("review", ("HIGH_IMPACT_CLOSURE",))


def test_discard_idiom():
    f = finding("q", "no_effect")
    for line in ("void run()", "  void p.then(x)", "if (deletedDate) void deleteProduct(id)", "cached ??= load()",
                 "this.x ??= 1"):
        assert quality.discard_idiom(f, [line]), line
    for line in ("isAdmin == true", "user.role === 'admin'", "a + b", "voidCount++", "if (f(a)) void g()", ""):
        assert not quality.discard_idiom(f, [line]), line
    assert not quality.discard_idiom(finding("q", "no_effect", line=5), ["void run()"])
