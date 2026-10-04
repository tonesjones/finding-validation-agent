from fva.correlation.advisory_applicability import applicable
from fva.schemas import Finding, FindingType, PackageRef, Severity


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


def test_unknown_advisory_or_version_format_stays_unknown():
    assert applicable(finding("CVE-9999-1"), "4.17.20") is None
    assert applicable(finding(), "4.17.20-beta") is None
    assert applicable(finding(name="other"), "4.17.20") is None
    assert applicable(finding(ecosystem="pypi"), "4.17.20") is None
