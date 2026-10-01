# Routing log

`date | task ID | model | result | notes`

2026-10-01 | T1 schema design | opus | pass | EndpointRef, FindingLink, GroupedIssue, RuntimeMode, dast_observation
2026-10-01 | T2 runtime mode gate | haiku | fix | Opus added http(s) scheme check and trimmed docstrings
2026-10-01 | T3 Polaris DAST adapter | sonnet | pass | also scrubs Host header from snippets
2026-10-01 | T4 SAST↔DAST linking | opus | pass |
2026-10-01 | T5 SCA↔SAST linking | opus | pass | file-level import basis, not call-level
2026-10-01 | T6 grouping | sonnet | pass |
2026-10-01 | T7 DAST evidence + invariants | opus | pass | plus end-to-end fixture test
2026-10-01 | T8 docs/status | haiku | pass |
