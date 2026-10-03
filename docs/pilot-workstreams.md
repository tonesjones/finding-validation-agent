# Pilot workstreams

The user split the pilot on 2026-10-02. This chat owns FVA evaluation. A separate
chat owns connecting Polaris and proving a repeatable scan-and-export workflow.

Current identity: the replacement neutral handoff and clean Git revision are now
available. Source commit is `9ac51601c57e95f37cd5720dad3e6e6ab21ba2a2`; the current
reports are `handoff/public-preflight/preflight.json` and `.md`. The hosted target is
public and requires no X-Desk-Key. Existing discovery remains bound to the previous
source revision and cannot be presented as discovery of the updated app. Fresh
source-only discovery completed for this revision using the user-approved fixed
`gpt-6-sol` model: six cited candidates, zero rejected, still unvalidated. See
CHECKPOINT.md for the audit, frozen 12-case preparation and human review materials.

As of 2026-10-03, SAST and SCA are complete in the dedicated pilot application/project.
The reconciled exports contain one low SAST issue and five SCA issues (two high,
three medium). FVA imported all six and prepared scanner-only cases; rules-only
returned six needs_review suggestions. DAST remains NOT_LAUNCHED because the user
has no entitlement. Its findings and coverage remain unknown.

The separate DAST sample proved endpoint/method importer compatibility and exposed
bugs now repaired. It supplies no evidence for the pilot app. Actual pilot DAST bodies,
links and scanner traffic remain unverified. The latest static import audit is under
the ignored `data/ingestion/` directory; its exact path is in `data/LOCAL-NOTES.md`.

## FVA evaluation stays here

- Preserve the completed source-only discovery and its six unvalidated candidates.
- Use fixed Sol 6 for this pilot; investigate Sol 6.1 access for a separate later run.
- Combine current-revision discovery with the completed static findings, review proposed links,
  freeze case packets and obtain human link approvals and private label receipts.
- Run the smoke and paired rules-only/model-only/hybrid assessment, human-grade the
  shared responses, then score frozen outputs. Gold remains excluded until scoring.
- A static-only comparison can proceed once its private labels are frozen. Adding
  DAST later requires a new preparation and label receipt, leaving the static run intact.

## Polaris workflow moves to the separate chat

1. Verify account access, project permissions, scanner availability and existing
   configuration. Use current official product documentation and observed behavior.
2. With the user, select the simplest supported source submission method for SAST/SCA
   and configure the public hosted DAST target. No hosting credential is required
   by the current handoff; verify actual scanner connectivity before launch.
3. Verify connectivity and source/deployment identity, run the scans, and record test
   IDs, completion/failure status and coverage limitations. Verify DAST requests in
   Worker logs rather than relying only on a successful configuration screen.
4. Retrieve complete raw results and supporting issue-type metadata. Reconcile
   pagination, totals and original finding IDs. Validate actual DAST fields against
   the FVA import contract before claiming compatibility.
5. Save a short reusable runbook and only the scripts/configuration needed to repeat
   the verified process. Record which steps are automated and which require a person.

The separate chat must not change the frozen demo source, inspect the private planting
ledger or receipts, read discovery candidates, or grade FVA results. Only clean source
and the neutral handoff directory recorded in `data/LOCAL-NOTES.md` are available to it.
Any necessary source/runtime change must be raised with the user because it would
require a new identity and could invalidate the completed discovery comparison.

## Return contract

Return an artifact-location summary containing:

- Source commit/content hash and deployed version used for each scan.
- Polaris application/project/branch and scan/test identifiers.
- Separate SAST, SCA and DAST states and coverage limitations. Pending is not zero.
- Complete raw export paths, issue-type metadata, file hashes, pagination/count
  reconciliation and redacted DAST request/response observations where available.
- Actual DAST ingestion check results, with gaps explicitly identified.
- Repeatable runbook/script locations, required inputs and remaining manual steps.

Credentials must remain outside exports supplied to model packets and outside Git.
Do not message this chat automatically; the user can bring the handoff back or
explicitly authorize cross-chat messaging.
