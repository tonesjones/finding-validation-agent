from fva.correlation.advisory_applicability import applicable
from fva.schemas import DeploymentProfile, Finding, FindingType, PackageRef, Severity


def finding(advisory="CVE-2021-23337", name="lodash", ecosystem="npm"):
    return Finding(finding_id="f", run_id="r", source_tool="polaris", source_finding_id="s",
                   rule_id=advisory, title="t", severity=Severity.high, finding_type=FindingType.sca,
                   package=PackageRef(name=name, version="4.17.20", ecosystem=ecosystem,
                                      advisory_id=advisory), raw_evidence_ref="raw:sha256:" + "0" * 64)


def test_known_advisory_range_is_exact_and_conservative():
    f = finding()
    assert applicable(f, "4.17.20") is True
    assert applicable(f, "4.17.21") is False
    assert applicable(f, "4.18.0") is False
    assert applicable(f, "3.10.1") is True
    array_path = finding("CVE-2026-2950")
    assert applicable(array_path, "4.17.22") is True
    assert applicable(array_path, "4.17.23") is True
    assert applicable(array_path, "4.18.0") is False


def test_unknown_advisory_or_version_format_stays_unknown():
    assert applicable(finding("CVE-9999-1"), "4.17.20") is None
    assert applicable(finding(), "4.17.20-beta") is None
    assert applicable(finding(), "04.17.20") is None
    assert applicable(finding(), "4.17.²") is None
    assert applicable(finding(name="other"), "4.17.20") is None
    assert applicable(finding(ecosystem="pypi"), "4.17.20") is None


def test_pipeline_closes_only_a_supported_out_of_range_installed_version(tmp_path):
    import json
    from fva import pipeline
    from fva.correlation import locate, reachability
    from fva.verdicts import suggest_verdict

    source = tmp_path / "source"
    source.mkdir()
    (source / "server.js").write_text("import lodash from 'lodash'\n")
    lock = tmp_path / "package-lock.json"
    profile = DeploymentProfile(profile_id="p", name="test", language_packs=("node",),
                                entrypoints=("server.js",))

    def prepare(version):
        lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {
            "": {}, "node_modules/lodash": {"version": version}}}))
        finding_row = finding().model_copy(update={"package": PackageRef(
            name="lodash", version=version, ecosystem="npm", advisory_id="CVE-2021-23337")})
        index = locate.SourceIndex.build(source)
        graph = reachability.build_graph(source, sorted(index.files), profile)
        return finding_row, pipeline.prepare([finding_row], source, profile, lock, "a" * 64, index, graph)

    affected, affected_batch = prepare("4.17.20")
    assert affected_batch.disposition[affected.finding_id] == "assess"
    unaffected, unaffected_batch = prepare("4.17.21")
    row = {"finding_id": unaffected.finding_id, "disposition": unaffected_batch.disposition[unaffected.finding_id],
           "deployment_profile_id": profile.profile_id}
    verdict, codes, _, evidence = suggest_verdict(row, unaffected_batch.pre_evidence[unaffected.finding_id])
    assert verdict.value == "not_applicable" and codes == ("ADVISORY_VERSION_MISMATCH",)
    assert any(e.method == "advisory_range:not_affected" and e.stance.value == "refutes" for e in evidence)
