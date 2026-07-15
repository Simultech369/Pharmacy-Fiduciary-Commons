# Phase 0 Closeout Board

This board implements the **Phase-Gated Decision System** to transition from "reviewer relay" to structured, priority-driven milestone tracking.

## Active Objective
**Close Phase 0 Readiness Gaps** (Prevent overclaims, secure contract boundaries, ensure safe local verification, and prepare deployment scaffolding).

## Baseline

- Created after committed baseline `78e2a6b Harden deployment preflight and voucher integrity checks`.
- This board is the control surface for new Phase 0 work once committed.
- Temporary review artifacts and raw prompt files remain outside the board unless explicitly promoted into tracked repo history.

---

## 1. Process & Priority Rules

### Reviewer Cadence
* **Start of Slice**: 1 no-edits reviewer to challenge the plan.
* **Before Commit**: 1 no-edits reviewer to check the diff.
* **After Push**: Optional Grok/Kimi/Zero narrative or disruption pass.
* *Rule*: Avoid passing every finding to every model. Commit/push the current slice or explicitly abandon it before starting a new reviewer pass.

### Priority Rule
Work is prioritized **only** if it:
1. Prevents irreversible deployment harm.
2. Prevents privacy/security overclaim.
3. Protects user funds or governance separation.
4. Closes a Phase 0 launch gate.
5. Adds regression coverage for already-built behavior.
*Everything else is parked/backlogged.*

### Decision Buckets
1. **Fix Now**: High-priority defects/gaps entering implementation immediately.
2. **Test Now**: Critical validation tasks entering implementation immediately.
3. **Document**: Clarifying language, warning additions, or record-keeping updates.
4. **Backlog**: Valid claims or gates parked for future development phases.
5. **Reject**: False positives or out-of-scope claims.

---

## 2. Phase 0 Closeout Board

This table tracks 13 Phase 0 gates mapped from `PRODUCTION_READINESS_CHECKLIST.md`, including the `2A` offline workflow and `3A` patient-fund liquidity sub-gates.

| Gate | Current Evidence | Reviewer Claims | Decision | Next Action | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Front End Build Hygiene** | Dashboard build tasks exist. Production check script (`npm run check:frontend`) is configured. | Kimi Finding 1 misread the root README as legacy procurement boilerplate. Separately, public labels must continue distinguishing synthetic/mock/local checks from production credentials. | **Reject** (Finding 1)<br>**Document** (Labels) | Run `npm run check:frontend` during frontend slices; keep user-facing labels explicit about synthetic/mock/local status. | **Open** |
| **2. Database & Auth Boundaries** | Local-only prototype with synthetic/mock data. No database, hosted auth, or API. | None. | **Backlog** | Conduct trust boundary review when a hosted database or auth provider (e.g. Supabase, Firebase) is proposed. | **Open** |
| **3. Offline Workflow Safety** | [continuity-engine.mjs](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/tools/resilience/continuity-engine.mjs) handles offline vouchers with all-key MAC coverage and shape checks. [ContinuityAndAdversarialTools.test.js](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/test/ContinuityAndAdversarialTools.test.js) covers verification logic and field mutation. | Console output "Verified Status: TRUE" overclaimed local MAC strength (Kimi Finding 3). Grok still flags possible user confusion around offline artifacts. | **Fix Now** (Implemented)<br>**Backlog** (Tabletops) | Keep `LOCAL INTEGRITY ONLY (NOT A ZK PROOF)` wording. Run SMS, paper, proxy, lost-connectivity, and duplicate-receipt tabletop drills before any public non-digital workflow claim. | **Partially Closed** |
| **4. Version Control & Handoff Pins** | Git initialized. Commits tracked. Obsolete references in committed handoffs were updated during the Kimi reconciliation slice. Untracked raw review artifacts remain intentionally outside history. | Handoff pins obsolete HEAD commit reference (Kimi Finding 2). | **Fix Now** (Implemented)<br>**Document** | Before promoting any handoff or review artifact, verify `git rev-parse HEAD`, `git status --short`, and whether the file is historical or current. | **Closed / Monitor** |
| **5. Patient Fund Matching Liquidity** | [PatientFundParticipatoryBudgeting.sol](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/contracts/PatientFundParticipatoryBudgeting.sol) enforces `dryRunFinalize`/`previewFinalize` checks. Tests cover underfunding. | None. | **Document** | Keep `dryRunFinalize` operator runbook steps updated and visible in dashboard/admin docs. | **Closed / Monitor** |
| **6. API Security & Hidden Fields** | No public APIs yet. Public forms are local. [PublicFormThreatModel.test.js](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/test/PublicFormThreatModel.test.js) tests honeypots. | None. | **Backlog** | Add server-side verification and CSRF token mechanisms when backend integration begins. | **Open** |
| **7. Hosting & Deployment Policy** | Fail-before-write policy checks in [deploy-timelock-and-treasury.js](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/scripts/deploy-timelock-and-treasury.js) and [deployment-policy.js](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/scripts/deployment-policy.js). | Deploy script allowed open timelock executor on non-local "demo" env (Kimi Finding 5). Grok notes that alternate deployment paths still require release discipline. | **Fix Now** (Implemented)<br>**Backlog** (Release discipline) | Keep the deploy script as the authoritative path; add release checklist or CI gates before any testnet/mainnet deployment workflow. | **Partially Closed** |
| **8. Rate Limiting & Abuse Controls** | None present yet. | None. | **Backlog** | Implement rate limiting in API middleware when backend is built. | **Open** |
| **9. Caching** | No caching layers or API headers exist yet. | None. | **Backlog** | Set explicit cache-control headers during API design. | **Open** |
| **10. Scaling** | No database or background workers exist. | None. | **Backlog** | Design pagination for event log queries in the dashboard. | **Open** |
| **11. Error Tracking & Observability** | No hosted tracking SDKs (Sentry, etc.) integrated. | None. | **Backlog** | Select privacy-compliant logging/tracking provider once backend is selected. | **Open** |
| **12. ADA / WCAG Accessibility** | [continuity-kit.html](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/tools/offline/continuity-kit.html) has an offline verifier UI. Public dashboard accessibility still needs launch-grade verification. | None. | **Document** | Run automated accessibility checks and manual screen reader verification before launch. | **Open** |
| **13. Contract Security & Pause Gates** | [PBMRebateTreasury.sol](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/contracts/PBMRebateTreasury.sol) contains pause gates. [SCANNER_TRIAGE.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/SCANNER_TRIAGE.md) is populated. | `updateSanction` bypassed guardian pause (Kimi Finding 4). | **Fix Now** / **Test Now** (Implemented)<br>**Backlog** (Scanner refresh) | Added `whenNotPaused` modifier to `updateSanction` and verified passing tests. Rerun Slither/Aderyn/targeted scanner checks before release claims. | **Partially Closed** |

---

## 3. Parking Lot / Backlog Items
* **SMS & Paper Workflows**: Parked until SMS/paper gateway APIs or trusted-proxy schemas are introduced.
* **Hosted Database & RLS**: RLS table policy verification is parked until Supabase/Firebase integration starts.
* **Server-Side API Rate Limiting**: Parked until middleware API endpoints are introduced.
* **Error Redaction Logs**: Log cleaning is parked until an error tracking provider (e.g. Sentry) is integrated.
* **Alternate Deployment Entrypoints**: Parked until a release workflow exists; the tracked deploy script remains the authoritative path.
* **Scanner Refresh**: Parked until the next release/audit-prep slice.
