"""Language-independent path conventions (IaC, API specs, docs)."""
from fva.schemas import Surface as S

GENERIC_RULES: tuple[tuple[str, S], ...] = (
    ("**/*.test.yml", S.test),
    ("**/*.test.yaml", S.test),
    ("**/*.tf", S.infrastructure),
    ("**/terraform/*", S.infrastructure),
    ("**/docker-compose*.yml", S.infrastructure),
    ("**/docker-compose*.yaml", S.infrastructure),
    ("**/Dockerfile*", S.infrastructure),
    ("**/k8s/*", S.infrastructure),
    ("**/helm/*", S.infrastructure),
    ("**/.github/workflows/*", S.infrastructure),
    ("**/swagger.yml", S.api_spec),
    ("**/swagger.yaml", S.api_spec),
    ("**/swagger.json", S.api_spec),
    ("**/openapi.*", S.api_spec),
    ("**/*.md", S.documentation),
    ("docs/*", S.documentation),
)
