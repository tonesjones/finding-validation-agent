"""End-to-end with fixtures: DAST import -> SAST<->DAST link -> group -> DAST evidence -> confirmed verdict."""
from datetime import datetime, timezone
from pathlib import Path

from fva.adapters import polaris
from fva.correlation.dast_evidence import to_evidence
from fva.correlation.grouping import group
from fva.correlation.runtime_link import build_route_map, link_all
from fva.invariants import check_verdict
from fva.schemas import Finding, FindingLocation, Severity, Verdict

FIX = Path(__file__).parent / "fixtures"


def test_juice_shop_search_sqli_becomes_one_confirmed_issue(tmp_path):
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes/search.ts").write_text("x\n")
    (tmp_path / "server.ts").write_text("import * as search from './routes/search'\n"
                                        "app.get('/rest/products/search', search.searchProducts())\n")
    routes = build_route_map(tmp_path, ["server.ts", "routes/search.ts"], ("server.ts",))
    _, (dast,) = polaris.load_dast(FIX / "polaris_mcp_dast.json")
    sast = Finding(finding_id="sast", run_id="r", source_tool="polaris", source_finding_id="s", rule_id="sqli",
                   cwe=("CWE-89",), title="SQL Injection", severity=Severity.high, finding_type="sast",
                   location=FindingLocation(path="routes/search.ts", start_line=3), raw_evidence_ref="raw:sha256:0#/")
    other = sast.model_copy(update={"finding_id": "other", "location": FindingLocation(path="routes/login.ts")})
    source = {"routes/search.ts": ["const criteria = req.query.q", "", "query(criteria)"]}

    links = link_all([sast, other], [dast], routes, source)
    assert [l.confidence for l in links] == ["high"]
    issues = group([sast, other, dast], links)
    (issue,) = [i for i in issues if len(i.finding_ids) > 1]
    assert issue.primary_finding_id == "sast" and set(issue.finding_ids) == {"sast", dast.finding_id}
    assert sum(len(i.finding_ids) for i in issues) == 3

    ev = to_evidence(links[0], profile_id="p")
    check_verdict(Verdict(verdict_id="v", finding_id="sast", deployment_profile_id="p", verdict="confirmed",
                          reason_codes=("DAST_OBSERVED",), confidence="high", evidence_ids=(ev.evidence_id,),
                          narrative="n", decided_at=datetime.now(timezone.utc), decided_by={"method": "rules"}),
                  {ev.evidence_id: ev})
