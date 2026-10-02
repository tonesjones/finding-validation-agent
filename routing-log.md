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

2026-10-02 session (review follow-ups; format: date | task | model | inline/delegated | result | tokens | notes)
2026-10-02 | T0 analysis pkg + dev install | opus | inline | pass | n/a |
2026-10-02 | T1 verdicts.py refactor | opus | inline | pass | n/a | first cut dropped a helper; caught by tests
2026-10-02 | T2 rule closures cite evidence | opus | inline | pass | n/a | unknown surface made neutral, not refutes
2026-10-02 | T3a parallel model calls | sonnet | delegated | pass | 79k total | ordered consumption, thread-local CLI fields, router lock
2026-10-02 | T3b credential skip, lockfile warning, flags | opus | inline | pass | n/a |
2026-10-02 | T3c CI workflow + .gitattributes | haiku | delegated | fix | 40k total | Opus added cache-dependency-path (pip cache needs a dependency file)
2026-10-02 | T4a Polaris MCP inventory | sonnet | delegated | fix | 68k total | Opus added UUID/long-id scrubbing to error strings
2026-10-02 | T4b field census | sonnet | delegated | pass | 66k total | sanitization verified on fixtures
2026-10-02 | T4c correlation value | sonnet | delegated | pass | 89k total | metric arithmetic hand-checked in tests
2026-10-02 | T4d CLI wiring (census, correlation-value) | opus | inline | pass | n/a |
2026-10-02 | T5a README + docs/operations.md | sonnet | delegated | fix | 86k total | Opus fixed flow-diagram alignment
2026-10-02 | T5b CHECKPOINT/CLAUDE/ROADMAP, drop PROJECT_STATUS | opus | inline | pass | n/a |
2026-10-02 | T6 review, commits, push | opus | inline | pass | n/a |
