import pytest

from fva.adapters.poc_ledger import JUICESHOP_PROFILE as P
from fva.schemas import Surface as S
from fva.surface import classify_path


@pytest.mark.parametrize("path,expected", [
    ("routes/login.ts", S.production_candidate),
    ("test/api/userApiSpec.ts", S.test),
    ("frontend/src/app/app.guard.spec.ts", S.test),
    ("docker-compose.test.yml", S.test),
    ("infrastructure/terraform/main.tf", S.infrastructure),
    ("terraform/main.tf", S.infrastructure),
    ("swagger.yml", S.api_spec),
    ("data/static/codefixes/loginAdminChallenge_1.ts", S.fixture),  # app-specific rule
    ("data/static/users.yml", S.production_candidate),
])
def test_juiceshop_paths(path, expected):
    assert classify_path(path, P) is expected


def test_boundary_evidence():
    from fva.schemas import Finding, FindingLocation, FindingType, Severity, Stance
    from fva.surface import match_rule, to_evidence

    def f(path):
        return Finding(finding_id=f"id-{path}", run_id="r", source_tool="t", source_finding_id=path, rule_id="x",
                       title="t", severity=Severity.low, finding_type=FindingType.sast,
                       location=FindingLocation(path=path, start_line=1), raw_evidence_ref="raw:sha256:" + "0" * 64)

    assert match_rule("routes/login.ts", P) == (S.production_candidate, None)
    surface, pattern = match_rule("data/static/codefixes/x.ts", P)
    assert surface is S.fixture and pattern == "data/static/codefixes/*"
    e = to_evidence(f("data/static/codefixes/x.ts"), P)
    assert e.stance is Stance.refutes and e.detail_ref == pattern and e.deployment_profile_id == P.profile_id
    assert to_evidence(f("routes/login.ts"), P).stance is Stance.neutral
    assert to_evidence(f("routes/login.ts"), P).evidence_id == to_evidence(f("routes/login.ts"), P).evidence_id
