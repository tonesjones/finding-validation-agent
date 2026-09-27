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
