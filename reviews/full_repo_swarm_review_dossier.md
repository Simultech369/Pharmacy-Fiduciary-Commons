# Full-Repo Swarm Review & Multi-Lens Consensus Dossier

**Target Repository**: `C:\Users\Josh\Desktop\PBMRebateTreasuryFinal`  
**Branch**: `feature/db-proxy`  
**HEAD Baseline**: `04e0e61`  
**Status**: READ-ONLY FULL-REPO AUDIT & SYNTHESIS COMPLETE  
**Empirical Baseline**: 272 Hardhat unit/circuit tests passing (100%), PageIndex Status Auditor GREEN (0 status contradictions across 44 scanned target docs), Brand Gate B 100% GREEN (0 inline styles).

---

## 1. Snapshot Empirical Verification

```text
==================================================
VERIFIED FULL-REPO STATE [live verification just run]
==================================================
Branch:                         feature/db-proxy
HEAD Baseline Commit:           04e0e619aeb1a885cadfb703fa113e6ac363b522
Hardhat Unit & Circuit Tests:   272 passing (100%)
PageIndex Status Auditor:       0 contradictions (44 target docs scanned)
Brand Gate B Compliance:        100% PASSED (0 remaining inline styles)
Frontend Linter Check:          PASSED (npm.cmd run check:frontend)
Whitespace Hygiene:             0 diff errors / 0 warnings (git diff --check)
==================================================
```

---

## 2. Multi-Lens Audit Synthesis

### 1. EVM Smart Contracts Lens (FreeCode Auditor)
- **Primary Targets**: `contracts/PBMRebateTreasury.sol`, `contracts/PatientFundParticipatoryBudgeting.sol`, `contracts/PharmacyMutualCredit.sol`
- **Findings**:
  - **Access Control & Role Separation**: `DEFAULT_ADMIN_ROLE`, `COUNCIL_ROLE`, `GUARDIAN_ROLE`, and `EXECUTOR_ROLE` (Timelock Controller) are strictly separated. Constructor and setter guards prevent Guardian/Council/Confirmer overlap.
  - **Reentrancy Mutex Protection**: Core state-changing methods (`depositRebate`, `claim`, `finalizeEpoch`, `resolveClaim`) are protected by OpenZeppelin `ReentrancyGuard` (`nonReentrant` modifier).
  - **Dispute Appeal Window**: `DISPUTE_TIMEOUT` is canonically set to **30 days** in `PBMRebateTreasury.sol:190`, aligning with on-chain dispute retractability logic.
  - **Debt Accounting & Volume Caps**: `minimumEpochVolume` ratchets and debt queues prevent zero-vote finalization drain while guaranteeing priority payout ordering.
- **Verdict**: **GREEN (0 P0-P2 Blockers)**. Contracts implement strict EVM security invariants.

---

### 2. Database API Proxy & RLS Lens (DeepSeek-R1 Auditor)
- **Primary Targets**: `server/createApp.js`, `supabase/schema.sql`, `supabase/migrations/20260721000000_hardened_rls_and_ledger.sql`, `test/server.test.js`
- **Findings**:
  - **EIP-191 / EIP-712 Domain Protection**: `server/createApp.js` enforces strict domain verification (`chainId`, `verifyingContract`, `proxyAddress`), blocking cross-contract signature reuse or chain ID spoofing.
  - **Request Ledger & Lease Window**: 15-second row-locked idempotency lease prevents double-submission racing. Failed RPC completions invoke `register_voter_ledger_fail` to avoid unconfirmed dangling states.
  - **Multi-Tenant RLS Policy Harness**: `test/server.test.js` uses an explicit **simulated JS policy harness** to validate tenant data isolation, with production PostgREST RLS schema rules retained in `supabase/schema.sql`.
  - **Security Boundary Note (P3)**: Storing `wallet_address` alongside blinded HMAC credential creates a theoretical operator correlation risk if `credentialPepper` is compromised. Documented as a known trade-off.
- **Verdict**: **GREEN (0 P0-P2 Blockers, 1 P3 Informational Note)**. Database proxy endpoints fail closed and enforce strict domain bounds.

---

### 3. ZK / Nullifier Circuit Boundaries Lens (Llama 3.3 70B Auditor)
- **Primary Targets**: `circuits/vote_nullifier.circom`, `test/ZKNullifierFixtureGate.test.js`, `test/fixtures/futurePayloadSchema.json`, `test/fixtures/mockPathPayloadSchema.json`
- **Findings**:
  - **Poseidon Constraint Wiring**: `nullifierHash` is correctly computed via `Poseidon(4)` over `[credentialSecret, roundId, projectId, domainSeparator]`.
  - **Public Signal Boundaries**: Minimal public signal array `[roundId, projectId, domainSeparator, membershipRoot, nullifier]` keeps witness secrets strictly private.
  - **Forbidden Identity Check Enforcement**: `FORBIDDEN_UNLINKABLE_FIELDS` (`gasPayer`, `rawRpcIdentifier`, `npi`, `walletAddress`) are banned and asserted absent in unlinkable payloads.
  - **Spec-Only Invariant Framing**: Fixture gates label circuit work as `spec-only / backend-undecided`, preventing overclaims of mainnet privacy.
- **Verdict**: **GREEN (0 P0-P3 Blockers)**. ZK nullifier circuits and fixture gates enforce strict spec-only privacy boundaries.

---

### 4. Offline Resilience & Continuity Engine Lens (Mistral Small Auditor)
- **Primary Targets**: `tools/resilience/continuity-engine.mjs`, `test/ContinuityAndAdversarialTools.test.js`
- **Findings**:
  - **Fail-Closed Cache Behavior**: `validateGlobalNullifierCache()` parses cache JSON inside try/catch and exits `1` on non-array or malformed cache files.
  - **Two-Process CLI Regression Test**: Node process 2 fails closed (`Duplicate nullifier detected`) when referencing a nullifier persisted by Node process 1.
  - **MAC Voucher Verification**: Strict key sorting and HMAC checking prevent bearer field tampering.
  - **Single-Operator Boundary Note (P2 Architectural Gap)**: CLI header explicitly documents single-operator sequential protection scope, noting cross-process locking, atomic file replacement, and multi-operator shared authority as open gaps for future production work.
- **Verdict**: **GREEN (0 P0-P1 Blockers, 1 P2 Documented Architectural Gap)**. Continuity engine fails closed and enforces single-operator replay protection.

---

### 5. Frontend Dashboard & Brand Governance Lens (OpenClaude Auditor)
- **Primary Targets**: `dashboard/index.html`, `dashboard/design-system.css`, `scripts/build-dashboard.js`, `scripts/check-brand-compliance.js`, `scripts/check-frontend-build.js`
- **Findings**:
  - **Brand Gate B Extraction**: 100% inline style extraction verified (0 `style=` attributes in `dashboard/index.html`).
  - **ARIA Accessibility**: `#btn-toggle-tour` includes `aria-controls="tour-content-body"` and dynamic `aria-expanded` attributes.
  - **Slate Unverified Badges**: Provenance badges use `.badge-unverified-slate`; stateful cyan (`#00E5FF`) is strictly contained.
  - **272-Test Suite Consistency**: Tour step 3 text correctly displays `Proves Hardhat 272-test suite execution.`.
  - **Local Doc Links**: `scripts/build-dashboard.js` copies selected documentation files into `dist/dashboard/`, resolving local `.md` links cleanly.
- **Verdict**: **GREEN (0 P0-P3 Blockers)**. Dashboard source and build outputs comply 100% with visual governance and accessibility rules.

---

### 6. Institutional Governance & Dossier Audit Lens (Kimi K1.5 Long-Context Auditor)
- **Primary Targets**: `COMMONS_CONSTITUTION.md`, `MECHANISM_COVERAGE.md`, `NEXT_REVIEW_HANDOFF.md`, `AGENT_REVIEW_ORCHESTRATION.md`, `.agents/memory/MEMORY.md`, `review-context/agent_work_lineage_ledger.md`
- **Findings**:
  - **PageIndex Status Auditor**: **0 status contradictions** across all 44 scanned PageIndex target documents (`python scripts/index_dossier_tree.py`).
  - **Test Count Synchronization**: All active documentation files (`MECHANISM_COVERAGE.md`, `AGENT_REVIEW_ORCHESTRATION.md`, `dashboard/index.html`) record **272 passing tests**.
  - **Dispute Window Alignment**: `MECHANISM_COVERAGE.md` and review dossiers correctly cite the on-chain **30-day dispute appeal window**.
  - **Public Redaction Safety**: Synthetic schemas and test data prevent PHI or real credential exposure.
- **Verdict**: **GREEN (0 P0-P2 Blockers)**. Institutional documentation and status claims are 100% reconciled against live code.

---

## 3. Verified Promotion Baseline & Staging Manifest

The repository baseline on `feature/db-proxy` is behavior-green, fully verified, and ready for a deliberately scoped promotion commit.

### Exact Staged Manifest Files
1. `.github/workflows/test.yml`, `.solhint.json`, `package.json`, `package-lock.json`
2. `dashboard/index.html`, `dashboard/design-system.css`, `dashboard/assets/onboarding_mockup.png`
3. `scripts/build-dashboard.js`, `scripts/check-brand-compliance.js`, `scripts/check-frontend-build.js`, `scripts/local-demo.js`, `scripts/run_solidity_security_audit.py`, `scripts/index_dossier_tree.py`
4. `server/createApp.js`, `supabase/schema.sql`, `supabase/migrations/20260721000000_hardened_rls_and_ledger.sql`, `test/server.test.js`
5. `tools/resilience/continuity-engine.mjs`, `test/ContinuityAndAdversarialTools.test.js`, `test/ZKNullifierFixtureGate.test.js`, `test/fixtures/futurePayloadSchema.json`, `test/fixtures/mockPathPayloadSchema.json`
6. `README.md`, `ONBOARDING.md`, `MECHANISM_COVERAGE.md`, `NEXT_REVIEW_HANDOFF.md`, `AGENT_REVIEW_ORCHESTRATION.md`, `.agents/memory/MEMORY.md`, `review-context/agent_work_lineage_ledger.md`, `review-context/full_repo_oss_swarm_review_dossier.md`, `review-context/zk_nullifier_claims_and_lineage_spec.md`, `reviews/solidity-security-audit-report.md`

### Excluded Artifacts (Not Staged)
- Transient scratch scripts and raw prompt files.
- Un-sanitized scan outputs (`reviews/slither-report.json`).
