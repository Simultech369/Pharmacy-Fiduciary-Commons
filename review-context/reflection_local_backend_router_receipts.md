# Reflection Round Artifact: `local-backend-router-receipts`

This artifact records what the slice actually proves locally. It must not be
used as a green badge for broader backend routing, persistence, or dashboard
runtime claims unless the listed evidence has been rerun against the current
workspace.

```yaml
slice_id: local-backend-router-receipts
intended_scope: >
  Make the dashboard/demo onboarding path legible through a visual receipt flow,
  while separating synthetic fixture receipts from contract-backed checks and
  local backend routing claims.
staged_files: []
slice_files_promoted_in_head:
  - dashboard/index.html
  - dashboard/web3_integration.js
  - test/DashboardCredibility.test.js
unstaged_conflicts:
  - ONBOARDING.md is modified for the newcomer first-run path.
  - test/ZKNullifierFixtureGate.test.js is modified for the project-scoped ZK fixture gate.
  - Multiple review-context and handoff artifacts are untracked ambient work.
verification_run:
  - command: npx.cmd hardhat test test\DashboardCredibility.test.js
    cwd: C:\Users\Josh\Desktop\PBMRebateTreasuryFinal
    exit_code: 0
    result: 4 passing
  - command: npm.cmd run check:frontend
    cwd: C:\Users\Josh\Desktop\PBMRebateTreasuryFinal
    exit_code: 0
    result: Frontend production build checks passed
failures:
  - No focused dashboard credibility or frontend build failures.
  - Browser console exercise was not completed in this reflection pass; do not count it as evidence.
false_green_risks:
  - Synthetic receipt data can be mistaken for live contract-backed state.
  - A generated visual receipt is not evidence that a live backend route executed locally.
  - A source URL of localhost is not enough to prove loopback execution unless the request is captured.
  - Frontend build success does not prove every click handler is exercised in a browser.
  - Current workspace is dirty; staged-only safety claims are not valid until rerun from a staged-only or clean target set.
  - Human-readable mismatch risk: "local" can imply local_machine even when an environment variable routes to hosted OPENAI_COMPAT_BASE_URL.
  - Human-readable mismatch risk: "staged slice is green" can hide a mixed working tree.
  - Human-readable mismatch risk: "dashboard smoke recovered" can hide broken JS/HTML DOM contracts.
reviewer_findings:
  - dashboard/web3_integration.js uses localhost:3000 for proxy health and registration requests.
  - Dashboard DOM IDs used by the visual receipt functions are present in dashboard/index.html.
  - Dashboard credibility tests lock in the first-run receipt flow and synthetic/prototype labels.
commit_verdict: GREEN_FOR_VISUAL_RECEIPT_UI_AND_STATIC_FRONTEND_CHECKS
promotion_status: PROMOTED_TO_HEAD_AS_UI_SLICE_NOT_AS_LIVE_BACKEND_PROOF
```

---

## Definitions

- **local_backend**: Loopback-only model or proxy execution unless explicitly overridden.
- **router_receipt**: Record of the actual execution attempt and resolved endpoint, not the intended route.
- **persisted**: Append succeeded and lifecycle ownership exists.

---

## Claims Under Reflection

1. **Claim 1**: If backend is local, the resolved endpoint is loopback.
2. **Claim 2**: If a request is ephemeral, no durable files change.
3. **Claim 3**: If a receipt says `local_machine`, the resolved endpoint is local.
4. **Claim 4**: Staged safety checks pass without unstaged files.
5. **Claim 5**: Dashboard DOM IDs required by JavaScript exist in HTML.

---

## Evidence Status

- **Staged-only test**: Not established in the current dirty workspace. Focused
  dashboard credibility tests passed, but staged-only safety needs a clean or
  explicitly staged rerun.
- **Loopback mock provider capture**: Not established by the current tests. Source
  inspection shows `localhost:3000`; a future pass should capture the actual
  request endpoint.
- **Filesystem mutation sentinel**: Not established in the current dirty
  workspace. A future pass should snapshot the target paths before and after the
  ephemeral action.
- **Browser console test**: Not established in this pass. `check:frontend`
  passed, but that is a static production-bundle check rather than browser
  click/console evidence.
