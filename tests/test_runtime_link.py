import pytest

from fva.correlation.runtime_link import build_route_map, link, link_all
from fva.schemas import EndpointRef, Finding, FindingLocation, Severity


def _f(fid, kind, **kw):
    return Finding(finding_id=fid, run_id="r", source_tool="polaris", source_finding_id=fid, rule_id="x",
                   title="t", severity=Severity.high, finding_type=kind, raw_evidence_ref="raw:sha256:0#/", **kw)


SAST = _f("sast", "sast", cwe=("CWE-89",), location=FindingLocation(path="routes/search.ts", start_line=23))
DAST = _f("dast", "dast", cwe=("CWE-89",),
          endpoint=EndpointRef(method="get", path="/rest/products/search", parameter="q", parameter_location="query"))
SOURCE = {"routes/search.ts": ["// line"] * 18 + ["let criteria: any = req.query.q === 'undefined' ? '' : req.query.q"]
          + ["x"] * 4 + ["models.sequelize.query(`SELECT * FROM Products WHERE name LIKE '%${criteria}%'`)"]}


@pytest.fixture
def routes(tmp_path):
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes/search.ts").write_text("export function searchProducts () {}\n")
    (tmp_path / "server.ts").write_text(
        "import * as search from './routes/search'\n"
        "app.get('/rest/products/search', search.searchProducts())\n")
    return build_route_map(tmp_path, ["server.ts", "routes/search.ts"], ("server.ts",))


def test_route_map_from_express(routes):
    assert routes == {("GET", "/rest/products/search"): {"routes/search.ts"}}


def test_juice_shop_search_sqli_links_high(routes):
    l = link(SAST, DAST, routes, SOURCE)
    assert l.confidence == "high" and l.basis == ("cwe", "route", "parameter")
    assert (l.from_finding_id, l.to_finding_id) == ("sast", "dast")


def test_route_without_parameter_is_medium(routes):
    assert link(SAST, DAST, routes, {}).confidence == "medium"


def test_route_name_only_is_low():
    assert link(SAST, DAST, {}, SOURCE).confidence == "low"


def test_cwe_mismatch_never_links(routes):
    xss = _f("dast2", "dast", cwe=("CWE-79",), endpoint=DAST.endpoint)
    assert link(SAST, xss, routes, SOURCE) is None


def test_unrelated_route_never_links(routes):
    other = _f("dast3", "dast", cwe=("CWE-89",), endpoint=EndpointRef(path="/rest/user/login", parameter="email"))
    assert link(SAST, other, routes, SOURCE) is None


def test_endpoint_rejects_host():
    with pytest.raises(ValueError):
        EndpointRef(path="http://juice.internal/rest")


def test_link_all_deterministic(routes):
    assert link_all([SAST], [DAST], routes, SOURCE) == link_all([SAST], [DAST], routes, SOURCE)
