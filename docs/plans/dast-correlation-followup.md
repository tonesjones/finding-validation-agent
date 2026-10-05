# DAST correlation follow-up

Status: saved-evidence source review complete; the owner approved the exact scope.
Launch stopped at the technical preflight gates below. This document alone is
not a scan authorization receipt.

## Saved evidence

The first FVA scan produced nine substantive observations and two informational
records. A bounded source review retained zero verified SAST-to-DAST identity
links and zero new confirmations. Source context is not finding identity:

| Observation | Source context | Remaining evidence gap |
|---|---|---|
| Server error and stack trace at `/api/` | Angular fallback rejects API paths, then error middleware handles them | No SAST finding shares CWE-755; raw response body unavailable |
| Deprecated headers | Candidate: feature-policy middleware | Exact reported header needs its response artifact |
| Missing content-type protection at `/socket.io/` | Socket.IO attaches separately from Express security middleware | Verify the actual response, not just middleware placement |
| Missing CSP and HSTS | Security middleware and local HTTP deployment | Configuration observations are not SQLi/XSS sink identities |
| Cache control at `/robots.txt` | Robots middleware | No matching SAST CWE-525; actual cache semantics remain unverified |
| Sensitive form over HTTP | SPA uses same-origin login service | Exact observed form unavailable; shared SAST CWEs occur on other surfaces |
| Internal IP disclosure | Application-configuration route serializes configuration | No matching SAST CWE-212; confirm the reported response field |

Saved artifact links point to internal HTTP services. They were not dereferenced.
The documented test-artifact download API supports screenshots only. Do not invent
a public request/response download URL. Raw receipts stay under ignored `data/`.

## Proposed bounded local pass

- Pinned Juice Shop source and existing Docker image; private network, Secure
  Tunnel, and an independent request/payload guard. Only its operator control port
  binds to loopback. No hosted targets or external browser destinations.
- Two modes: unauthenticated and one temporary non-admin authenticated account.
  Account creation is local container setup. One legitimate login POST is allowed
  for session setup; active tests remain GET-only. Login SQLi is excluded.
- Attack only product search (`q`) and the SPA search fragment (`q`). Enable only
  SQLI, XSS.DOM and XSS.REF, using verified profile settings. Read back settings;
  the docs disagree on an inclusion-field name, so do not guess the configuration.
- Per mode: 15 minutes, two concurrent requests, two requests/second, 1,500 total
  requests, 200-character query limit and bounded response size. Reject writes,
  stacked SQL, UNION/exfiltration, file/function execution, delay/resource-exhaustion
  payloads, stored XSS, command execution, SSRF, uploads and checkout operations.
- SQL control/probe: SELECT-only false/true boolean predicates; compare product
  counts. DOM control/probe: plain text versus a harmless window-property marker;
  observe execution, not reflection. Exact values and scope digest are in ignored
  `data/dast-correlation/scope-plan.json`.
- No launch until the exact scope is approved, guard boundaries are tested,
  runtime identity is checked, settings are verified and session proof is present.
  Stop if a boundary cannot be enforced; do not silently broaden scope.

## Measurement

Keep `20261005-fva-dast` immutable. Compare the same static finding IDs and labeled
population; count new DAST observations separately. Report authentication and
coverage, guard rejections, verified links and precision by tier, incorrect
demotions, attributable confirmations/closures, auto share/agreement and fresh
versus cached assessment cost. Zero links means undefined precision.

Use routed Luna/Sol assessment with four workers where assessment is needed. Sol
checks every relationship; model output never confirms. Custom control results
must not be imported through unsupported confirming oracles. Direct DAST-to-SCA
mapping remains outside this pass.

Preparation validation: 658 tests passed, five skipped. No repeat scan or runtime
probe ran during preparation.

## Approved-scope preflight

The owner approved the proposed scope with "ok go for it". The existing profile
API returned manual settings, with active attacks disabled, and no effective
engine/browser settings. The official configuration references disagree on
inclusion and Smart Settings field names; no configuration was guessed or uploaded.

A disposable local HTTP fixture showed that both an approved browser fragment
and an unapproved fragment arrive at the server as `/`. A server-side guard cannot
inspect the DOM search payload. Browser-level destination and payload enforcement
must be verified before the proposed scan can run. The old Docker network also
permits outbound traffic and needs an isolated replacement.

The target remains stopped. No account creation, login, target security probe or
follow-up scan ran. Approval is sufficient; the remaining work is to resolve these
technical gates, build/test the guard and isolated runtime, and verify the session.

## Local browser control runner

`fva/node/browser_boundary.cjs` now provides an optional local Playwright runner.
It adds no required Python or Node dependency. The caller supplies Playwright and
a browser executable, exact approved control/query values and pinned static paths.

Each initial DOM test URL is checked in full, including its fragment, before a
fresh browser context opens. Browser networking is offline and a deny-only proxy
provides fallback protection. Permitted HTTP requests are fulfilled through a
Node broker that accepts only numeric loopback, exact-origin GETs to the selected
routes and values. It applies the approved rate, count, duration and response-size
limits. Redirects and compressed responses are rejected. WebSockets, service
workers, downloads, popup/child-frame navigation and subsequent document requests
are blocked. The broker does not forward authentication headers or cookies yet.

The initial-fragment allowlist is for a trusted control runner. It is not proof
against arbitrary same-document fragment mutation or arbitrary application script
execution. Do not give a scanner or an interactive payload driver access to it.
Network effects remain guarded, but a local execution marker is not imported as
confirmation through an unsupported oracle.

Tests exercise disposable loopback fixtures, never hosted destinations. In a real
browser, the harmless marker executed only for the probe and the control had none;
the unapproved fixture received zero HTTP requests or WebSocket upgrades.
`node tests/browser_boundary.cjs` runs policy/transport checks. Set
`FVA_PLAYWRIGHT_MODULE` and `FVA_BROWSER_EXECUTABLE` to run the real-browser checks
as well; pytest invokes the same checks when Node is available.

This runner is not installed in Polaris's browser. The native browser integration,
effective settings, isolated target and authenticated session remain launch gates.

Implementation validation: 659 tests passed, five skipped, with real-browser
checks enabled. The baseline scanner metrics are unchanged; active/authenticated
DAST value remains unmeasured.
