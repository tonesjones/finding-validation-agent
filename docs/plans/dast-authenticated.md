# Authenticated DAST attempts

## Likely cause: host exclusion matched every target URL

Review on 2026-10-05 found a settings difference that fits zero target requests.
The successful unauthenticated scan set no `excludedHosts`. Both authenticated
attempts set one entry, a negative lookahead meant to exclude every host except
the target. Its `$` anchor follows the optional port, so it fails to match only a
bare origin. Any URL with a path, including the recording's login URL and every
crawled page, matches and is excluded. If the engine matches full URLs, it may
send no requests, which fits zero counter movement and stalled progress. If its
regex engine rejects lookahead, the setting is invalid instead. Neither reading
is proven, but both point to the same entry.

`excludedAttackUrls` uses the same lookahead pattern. The recording also omits
the `setViewport` first step that Chrome Recorder exports emit.

Corrected private settings drop `excludedHosts`, because network placement already
confines the target, and add `setViewport`. They also drop the lookahead attack
exclusion. That widens active checks to `/rest/` routes other than product search.
The owner must approve that scope or name explicit `/rest/` exclusions before any
relaunch. No scan ran during this review.

## Corrected-settings run (2026-10-05)

The owner approved the wider attack scope and one relaunch. Preflight matched the
earlier attempts: non-admin login, basket 401 then 200, identical settings
read-back and tunnel identity. The scan stopped at progress 66 again, but this time
Polaris marked it `Failed` after about 11 minutes. Its error detail said the login
preflight failed because fingerprint generation hit a context deadline. The export
had zero issues, so the zero-issue stop rule applies.

The host exclusion fix moved the failure: the scanner now attempts the login
recording and gives a concrete reason, where before it stalled silently. The open
problem is that the recorded login, or the authenticated-state check after it,
does not finish in time. A next attempt could raise the authenticator's
`timeoutMultiplier` (documented default 1), but only with separate owner approval.

## Owner-authorized direct-network retry

After the first zero-issue stop, the owner explicitly authorized one retry on the
original non-internal Docker network, with the target published only at
`127.0.0.1:3000`. The temporary HTTP guard and internal network were removed from
the scan path. The same SQLI/XSS checker limits, login/logout exclusions,
authentication method and 15-minute timeout were retained.

The WSL loopback HEAD check returned 200. Docker Desktop was the only installed
WSL distribution; it had no curl binary and rejected Docker CLI invocation there.
The WSL check therefore used `wget --spider`, and Linux `curl -I` in the tunnel's
Docker network independently returned 200 for the configured private target.
Port inspection verified loopback-only publication. The restarted app reset the
test account; it was recreated locally, then a fresh Chrome session verified
anonymous basket 401 and non-admin authenticated basket 200. All 357 pinned source
files matched. The fresh recording was uploaded, downloaded and compared exactly;
the previous scan was reconciled as cancelled before one new scan was accepted.

The retry again remained in the native scanning phase until the fifteen-minute
wall-clock limit. Cancellation returned `Cancelled`; the read-only export
succeeded with zero issues. The zero-issue stop rule applies again. No further
scan or assessment ran, and the temporary tunnel and target were stopped.

Exact target interface counters did not change over the 641 seconds between the
first post-launch sample and the final sample. Sampling began after preflight and launch, so it
does not establish a request count for the entire run or prove authentication.
Native authenticated coverage remains unproven. Removing the internal network
did not yield a successful scan; the native execution cause remains unresolved.
Do not attribute the first attempt's result to network isolation without evidence.

Baseline metrics below remain unchanged. Fresh assessment cost for the retry is
$0.00000 because no assessment ran; scan and subscription cost are unmeasured.
Validation again passed: 658 tests, five skipped. This branch still adds no public
runner or production code.

## First attempt

Status: stopped on 2026-10-05. The native scan was cancelled at approximately
15 minutes with zero scanner requests at the target. Its read-only export
succeeded and contained zero issues. The owner's zero-issue stop rule applies:
no further scan, assessment or confirmation work was performed.

## What passed

- The pinned Juice Shop image matched 357 source files, with zero mismatches or
  missing files. No application source was changed.
- Juice Shop ran on an internal Docker network with no default outbound route.
  A temporary HTTP forwarder connected the tunnel to that isolated target.
  Only the operator port was exposed on loopback; no hosted target was probed.
- One local non-admin account was created. A fresh local Chrome session logged
  in successfully. The same basket returned 401 anonymously and 200 with that
  account's session. Credentials and receipts remain under ignored `data/`.
- A Chrome Recording JSON flow was constructed and locally exercised with
  Chrome. It was not exported through the DevTools Recorder UI. Native replay
  compatibility remains unproven because the scanner never reached the target.
- The profile accepted the uploaded settings artifact. Downloading that artifact
  returned identical JSON. The profile also read back active attacks enabled.
  This verifies persistence, not the scanner's effective settings or login.
- Exactly one native scan was accepted. The Linux Secure Tunnel reported that
  its service started successfully. No duplicate scan was launched.

## Scope and result

The owner authorized local account setup and one authenticated follow-up. Active
checks were limited to SQLI, XSS.DOM and XSS.REF; login attacks and logout were
excluded. Neither disputed inclusion field was used. The uploaded timeout was
15 minutes, with two requests per second and two browser workers. The temporary
HTTP guard limited forwarding to approved GET routes and the exact legitimate
login POST, with 1,500 requests, a 200-character search query limit and bounded
responses. One pinned static bundle exceeded 1 MiB and received an exact-size,
SHA-256-checked exception so the SPA could load; probe responses retained 1 MiB.
Boundary checks rejected UNION, delay and write payloads before forwarding.

The local recording restricted browser networking to the local target. The
separate browser runner proposed in PR #40 was not used or integrated. Target
network isolation and native host exclusions replaced that proposed launch gate;
the HTTP guard cannot inspect SPA fragments, and native browser enforcement was
not measured in this attempt.

At the wall-clock limit, Polaris still reported `In Progress` at progress 66.
Cancellation returned `Cancelled`. Guard metadata recorded zero scanner requests,
zero authenticated basket successes and zero scanner payload rejections. The
documented screenshot-artifact listing was empty. The export returned success
with zero issues. These observations do not identify why native scanning did not
reach the target; do not infer a login failure, settings error or tunnel fault.
The tunnel, guard and target were stopped after cancellation; local account data
was preserved. Raw control-plane responses, settings and credentials stay private.

## Value measurement

Keep the first run immutable. Its nine substantive DAST observations and two
informational records yielded zero verified SAST-to-DAST links and zero new
confirmations in the saved-evidence source review. Header/configuration source
context did not establish SQLi/XSS finding identity. Raw response artifacts were
not available through the documented screenshot-only download API; internal
artifact URLs were not dereferenced.

This attempt supplies no new findings or coverage. It therefore cannot measure
authenticated active DAST value or change the baseline:

| Measurement | Retained baseline |
|---|---|
| Scanner rows | 518 SAST + 56 SCA + 11 DAST = 585 |
| Auto share / auto agreement | 83.8% / 99.4% |
| Incorrect demotions, all / auto | 0 / 0 |
| SAST-to-DAST links, high / medium / low | 0 / 0 / 0 |
| Link precision, each tier | Undefined; no links |
| New confirmations / closures from DAST | 0 / 0 |
| Fresh assessment cost, this attempt | $0.00000; no assessment ran |

Historical priced cache cost remains $0.16134 with incomplete coverage. Scan,
subscription and infrastructure costs were not measured. Any later assessment
retains Luna bulk / Sol sensitive and `supports` escalation routing, four workers,
and the rule that model output never confirms.

Next work, if separately authorized after this stop: diagnose native execution
and obtain scanner-origin authenticated coverage before repeating a value
comparison. Do not broaden attacks or relax correlation thresholds to compensate.

Validation: 658 tests passed, five skipped. No production code or public browser
runner was added in this branch.
