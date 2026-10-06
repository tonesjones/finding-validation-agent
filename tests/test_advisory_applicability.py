import pytest

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
    (source / "server.js").write_text("import lodash from 'lodash'\nlodash.template('x')\n")
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


@pytest.mark.parametrize('advisory,below,first,last,above', [
    ('CVE-2020-28500', '3.10.1', '4.0.0', '4.17.20', '4.17.21'),
    ('CVE-2021-23337', None, '0.0.0', '4.17.20', '4.17.21'),
    ('CVE-2025-13465', '3.10.1', '4.0.0', '4.17.22', '4.17.23'),
    ('CVE-2026-2950', None, '0.0.0', '4.17.23', '4.17.24'),
    ('CVE-2026-4800', '3.10.1', '4.0.0', '4.17.23', '4.17.24'),
])
def test_every_advisory_matches_published_boundaries(advisory, below, first, last, above):
    f = finding(advisory)
    if below is not None:
        assert applicable(f, below) is False
    assert applicable(f, first) is True
    assert applicable(f, last) is True
    assert applicable(f, above) is False


@pytest.mark.parametrize('version', ['4.17', '4.17.20.1', '4.17.20+build', '4.17.20-rc.1',
                                    '4.017.20', '4.17.020', '4.17.２０', '9' * 5000 + '.0.0'])
def test_noncanonical_or_overlong_versions_stay_unresolved(version):
    assert applicable(finding(), version) is None

FUNCS = frozenset({"template", "omit", "unset"})


@pytest.mark.parametrize("src,sites", [
    ("import _ from 'lodash'\n_.template(x)\n", [("template", 2)]),
    ("import * as lo from 'lodash'\nlo?.omit(a, b)\n", [("omit", 2)]),
    ("const _ = require('lodash')\nconst t = _.template\n", [("template", 2)]),
    ("import { template as t, map } from 'lodash'\n", [("template", 1)]),
    ("const { unset: u } = require('lodash')\n", [("unset", 1)]),
    ("const t = require('lodash/template')\n", [("template", 1)]),
    ("import omit from 'lodash/fp/omit.js'\n", [("omit", 1)]),
    ("require('lodash').template(x)\n", [("template", 1)]),
    ("import _ from 'lodash'\n_.map(xs, f)\n", []),
])
def test_call_sites_found(src, sites):
    from fva.langpacks import REGISTRY
    assert REGISTRY["node"].call_sites(src, "lodash", FUNCS) == (sites, [])


@pytest.mark.parametrize("src,line", [
    ("import _ from 'lodash'\n_['temp' + 'late'](x)\n", 2),
    ("import _ from 'lodash'\nhelpers(_)\n", 2),
    ("import _ from 'lodash'\n_(xs).omit('a')\n", 2),
    ("import _ from 'lodash'\n_.chain(o).omit('a')\n", 2),
    ("const lib = await import('lodash')\n", 1),
    ("export * from 'lodash'\n", 1),
    ("import 'lodash'\n", 1),
    ("const { ...all } = require('lodash')\n", 1),
    ("const b = require('lodash/_baseUnset')\n", 1),
    ("module.exports = { lo: require('lodash') }\n", 1),
])
def test_unresolvable_uses_are_reported(src, line):
    from fva.langpacks import REGISTRY
    assert line in REGISTRY["node"].call_sites(src, "lodash", FUNCS)[1]


def _scan_status(tmp_path, files, advisory, dependents=()):
    from fva.correlation import advisory_applicability as aa
    for rel, text in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text)
    profile = DeploymentProfile(profile_id="p", name="t", language_packs=("node",), entrypoints=("server.js",))
    scan = aa.scan_calls(tmp_path, sorted(files), profile)
    return aa.call_site_status(finding(advisory), scan, None if dependents is None else list(dependents))


def test_call_site_status(tmp_path):
    called = {"server.js": "import _ from 'lodash'\n_.template(t)\n"}
    assert _scan_status(tmp_path / "a", called, "CVE-2021-23337")[0] == "called"
    assert _scan_status(tmp_path / "a", called, "CVE-2025-13465")[0] == "not_called"
    assert _scan_status(tmp_path / "a", called, "CVE-2025-13465", dependents=None)[0] == "no_lockfile"
    assert _scan_status(tmp_path / "a", called, "CVE-2025-13465", ["node_modules/x"])[0] == "installed_dependents"
    assert _scan_status(tmp_path / "a", called, "CVE-2020-28500")[0] == "internal_callers"
    assert _scan_status(tmp_path / "a", called, "CVE-9999-1") is None
    dynamic = {"server.js": "import _ from 'lodash'\nrun(_)\n"}
    assert _scan_status(tmp_path / "b", dynamic, "CVE-2025-13465")[0] == "unresolved_use"
    test_only = {"server.js": "x()\n", "test/a.spec.js": "import _ from 'lodash'\n_.omit(a)\n"}
    assert _scan_status(tmp_path / "c", test_only, "CVE-2025-13465")[0] == "not_called"
    page = {"server.js": "x()\n", "public/index.html": '<script src="/lodash.min.js"></script>\n'}
    assert _scan_status(tmp_path / "d", page, "CVE-2025-13465")[0] == "unresolved_use"
    global_use = {"server.js": "x()\n", "public/app.js": "_.omit(a, 'b')\n"}
    assert _scan_status(tmp_path / "e", global_use, "CVE-2025-13465")[0] == "called"


def test_pipeline_closes_uncalled_function_at_medium_confidence(tmp_path):
    import json
    from fva import pipeline, triage
    from fva.correlation import locate, reachability
    from fva.verdicts import suggest_verdict

    source = tmp_path / "source"
    source.mkdir()
    (source / "server.js").write_text("import lodash from 'lodash'\nlodash.template('x')\n")
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"lodash": "4.17.20"}}, "node_modules/lodash": {"version": "4.17.20"}}}))
    profile = DeploymentProfile(profile_id="p", name="test", language_packs=("node",), entrypoints=("server.js",))
    index = locate.SourceIndex.build(source)
    graph = reachability.build_graph(source, sorted(index.files), profile)
    omit, tmpl = finding("CVE-2025-13465"), finding().model_copy(update={"finding_id": "g"})
    batch = pipeline.prepare([omit, tmpl], source, profile, lock, "a" * 64, index, graph)
    assert batch.disposition == {"f": "dependency:vulnerable_function_not_called", "g": "assess"}
    row = {"finding_id": "f", "disposition": batch.disposition["f"], "deployment_profile_id": "p"}
    verdict, codes, conf, cited = suggest_verdict(row, batch.pre_evidence["f"])
    assert (verdict.value, codes, conf) == ("not_applicable", ("VULNERABLE_FUNCTION_NOT_CALLED",), "medium")
    assert triage.route("f", "high", verdict, codes, conf, cited, profile="p") == ("review", ("HIGH_IMPACT_CLOSURE",))
    assert triage.route("f", "medium", verdict, codes, conf, cited, profile="p") == ("auto", ())
    called = [e for e in batch.pre_evidence["g"] if e.method == "advisory_call_site:called"]
    assert called and called[0].stance.value == "supports" and "server.js:2" in called[0].summary
    row_g = {"finding_id": "g", "disposition": "assess", "finding_type": "sca", "deployment_profile_id": "p"}
    likely, codes_g, conf_g, _ = suggest_verdict(row_g, batch.pre_evidence["g"])
    assert (likely.value, codes_g, conf_g) == ("likely", ("VULNERABLE_FUNCTION_CALLED",), "medium")


def test_option_calls_resolve_only_plain_literal_options():
    from fva.langpacks.node import NodePack
    text = ("import clean from 'sanitize-html'\n"
            "export const a = (h) => clean(h)\n"
            "clean(h, { allowedTags: [], allowedAttributes: {}, // note, here\n  'transformTags': { a: (t) => t }, })\n"
            "clean(h, opts)\n"
            "clean(h, { ...base })\n"
            "clean.defaults.allowedTags.push('textarea')\n"
            "const raw = require('sanitize-html')('x')\n")
    calls, unresolved = NodePack().option_calls(text, "sanitize-html")
    assert calls == [(2, {}), (3, {"allowedTags": "[]", "allowedAttributes": "{}", "transformTags": "{ a: (t) => t }"})]
    assert unresolved == [5, 6, 7, 8]
    assert NodePack().option_calls("import { defaults } from 'sanitize-html'\n", "sanitize-html") == ([], [1])


@pytest.mark.parametrize("advisory,options,status", [
    ("CVE-2024-21501", "", "precondition_absent"),
    ("CVE-2024-21501", ", { allowedAttributes: {} }", "precondition_absent"),
    ("CVE-2024-21501", ", { allowedAttributes: { '*': ['style'] } }", "precondition_possible"),
    ("CVE-2024-21501", ", { allowedAttributes: false }", "precondition_possible"),
    ("CVE-2021-26539", ", { allowedTags: ['iframe'] }", "precondition_absent"),
    ("CVE-2021-26540", ", { allowedIframeHostnames: [] }", "precondition_possible"),
    ("CVE-2019-25225", ", { transformTags }", "precondition_possible"),
    ("CVE-2026-63670", ", { allowedTags: ['b', 'option'] }", "precondition_absent"),
    ("CVE-2026-63670", ", { allowedTags: ['b', 'textarea'] }", "precondition_possible"),
    ("CVE-2026-63670", ", { allowedTags: tags }", "precondition_possible"),
    ("CVE-2026-63670", ", options", "unresolved_use"),
])
def test_option_preconditions(tmp_path, advisory, options, status):
    from fva.correlation import advisory_applicability as aa
    (tmp_path / "server.js").write_text(f"const clean = require('sanitize-html')\nclean(input{options})\n")
    profile = DeploymentProfile(profile_id="p", name="test", language_packs=("node",), entrypoints=("server.js",))
    scan = aa.scan(tmp_path, ["server.js"], profile, "sanitize-html")
    assert aa.precondition_status(finding(advisory, "sanitize-html"), scan, [])[0] == status
    assert aa.precondition_status(finding(advisory, "sanitize-html"), scan, ["node_modules/x"])[0] in (
        status, "installed_dependents")
    assert aa.precondition_status(finding("CVE-2016-1000237", "sanitize-html"), scan, []) is None


def test_pipeline_closes_absent_option_precondition_at_medium_confidence(tmp_path):
    import json
    from fva import pipeline
    from fva.correlation import locate, reachability
    from fva.verdicts import suggest_verdict

    source = tmp_path / "source"
    source.mkdir()
    (source / "server.js").write_text("import clean from 'sanitize-html'\nclean(input, { allowedTags: [] })\n")
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"sanitize-html": "1.4.2"}}, "node_modules/sanitize-html": {"version": "1.4.2"}}}))
    profile = DeploymentProfile(profile_id="p", name="test", language_packs=("node",), entrypoints=("server.js",))
    index = locate.SourceIndex.build(source)
    graph = reachability.build_graph(source, sorted(index.files), profile)

    def sanitize(fid, advisory):
        return finding(advisory, "sanitize-html").model_copy(update={"finding_id": fid, "package": PackageRef(
            name="sanitize-html", version="1.4.2", ecosystem="npm", advisory_id=advisory)})

    batch = pipeline.prepare([sanitize("a", "CVE-2021-26539"), sanitize("b", "CVE-2026-40186"),
                              sanitize("c", "CVE-2016-1000237")], source, profile, lock, "a" * 64, index, graph)
    assert batch.disposition == {"a": "dependency:advisory_precondition_absent",
                                 "b": "dependency:advisory_version_unaffected", "c": "assess"}
    row = {"finding_id": "a", "disposition": batch.disposition["a"], "deployment_profile_id": "p"}
    verdict, codes, conf, _ = suggest_verdict(row, batch.pre_evidence["a"])
    assert (verdict.value, codes, conf) == ("not_applicable", ("ADVISORY_PRECONDITION_ABSENT",), "medium")


@pytest.mark.parametrize("options,settings,expected", [
    ("", "", "precondition_absent"),
    (", { variable }", "", "precondition_absent"),
    (", { variable: 'data' }", "", "precondition_absent"),
    (", { imports: { helper } }", "", "precondition_possible"),
    (", { imports: undefined }", "", "precondition_possible"),
    (", { imports: {} }", "", "precondition_possible"),
    (", options", "", "unresolved_use"),
    (", getOptions()", "", "unresolved_use"),
    (", { ...base, variable }", "", "unresolved_use"),
    (", { variable }", "_.templateSettings.imports = { helper }", "unresolved_use"),
    (", { variable }", "lodash.templateSettings.imports.x = helper", "unresolved_use"),
    ("", "_.templateSettings = { imports: { helper } }", "unresolved_use"),
    ("", "Object.assign(_.templateSettings.imports, { helper })", "unresolved_use"),
    (", { variable }", "_.templateSettings['imports'].x = helper", "unresolved_use"),
    (", { variable }", "test-only", "precondition_absent"),
])
def test_lodash_imports_precondition_preserves_variable_advisory(tmp_path, options, settings, expected):
    import json
    from fva import pipeline
    from fva.correlation import locate, reachability
    from fva.verdicts import suggest_verdict

    source = tmp_path / "source"
    source.mkdir()
    (source / "server.js").write_text(
        "import lodash from 'lodash'\n"
        f"lodash.template('Hello <%= data.name %>'{options})\n")
    if settings:
        if settings == "test-only":
            (source / "tests").mkdir()
            (source / "tests/settings.js").write_text("_.templateSettings.imports.x = helper\n")
        else:
            # No import or 'lodash' token: global defaults in any shipped file must block closure.
            (source / "settings.js").write_text(settings + "\n")
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"lodash": "4.17.20"}}, "node_modules/lodash": {"version": "4.17.20"}}}))
    profile = DeploymentProfile(profile_id="p", name="test", language_packs=("node",), entrypoints=("server.js",))
    index = locate.SourceIndex.build(source)
    graph = reachability.build_graph(source, sorted(index.files), profile)
    imports = finding("CVE-2026-4800")
    variable = finding().model_copy(update={"finding_id": "g"})
    batch = pipeline.prepare([imports, variable], source, profile, lock, "a" * 64, index, graph)
    evidence = batch.pre_evidence["f"]
    option = next(e for e in evidence if e.method.startswith("advisory_option:"))
    assert option.method == "advisory_option:" + expected
    assert option.tool_versions == {"advisory_option": "imports"}
    assert option.stance.value == ("refutes" if expected == "precondition_absent" else "neutral")
    row = {"finding_id": "f", "disposition": batch.disposition["f"],
           "finding_type": "sca", "deployment_profile_id": "p"}
    verdict, codes, _, _ = suggest_verdict(row, evidence)
    if expected == "precondition_absent":
        assert batch.disposition["f"] == "dependency:advisory_precondition_absent"
        assert (verdict.value, codes) == ("not_applicable", ("ADVISORY_PRECONDITION_ABSENT",))
    else:
        assert batch.disposition["f"] == "assess"
        assert verdict.value in ("likely", "needs_review")
    row_g = {**row, "finding_id": "g", "disposition": batch.disposition["g"]}
    verdict_g, codes_g, _, _ = suggest_verdict(row_g, batch.pre_evidence["g"])
    assert (verdict_g.value, codes_g) == ("likely", ("VULNERABLE_FUNCTION_CALLED",))


@pytest.mark.parametrize("text", [
    "_.template('x', { variable: 'data'",  # unbalanced call
    "_.template(`Hello ${name}`, { variable })",  # opaque template expression
    "const t = _.template; t('x', options)",  # alias cannot be followed
    "import t from 'lodash/template'; t('x', options)",
    "import { template as t } from 'lodash'; t('x', options)",
    "_.template(...args)",
    "_.template('x', { [option]: value })",
])
def test_lodash_unparsed_template_call_fails_closed(tmp_path, text):
    from fva.correlation import advisory_applicability as aa
    (tmp_path / "server.js").write_text(text + "\n")
    profile = DeploymentProfile(profile_id="p", name="test", language_packs=("node",), entrypoints=("server.js",))
    scan = aa.scan(tmp_path, ["server.js"], profile, "lodash")
    evidence, disposition = aa.use_evidence(finding("CVE-2026-4800"), scan, [], "p")
    assert evidence.method == "advisory_option:unresolved_use"
    assert disposition is None


@pytest.mark.parametrize("binding,name", [
    ("", "_"),
    ("", "lodash"),
    ("import * as lo from 'lodash'\n", "lo"),
    ("const lo = require('lodash')\n", "lo"),
])
def test_lodash_template_options_with_globals_and_namespace_aliases(binding, name):
    from fva.langpacks.node import NodePack
    calls, unresolved = NodePack().option_calls(binding + f"{name}.template('x', {{ variable }})\n", "lodash")
    assert calls == [(binding.count("\n") + 1, {"variable": "variable"})]
    assert unresolved == []
