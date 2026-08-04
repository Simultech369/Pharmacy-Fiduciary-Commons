# Single Compact Repository State Ledger

> **Governance Directive**: Created per Codex 5.5 / Senior Reviewer instruction to eliminate state compression debt and prevent models from reviewing divergent historical snapshots.

---

### Core State Matrix

- **Repo**: `C:\Users\Josh\Desktop\PBMRebateTreasuryFinal`
- **Current branch/HEAD**: `feature/db-proxy` @ `04e0e619aeb1a885cadfb703fa113e6ac363b522` (`[dirty working tree]` with 280 passing unit tests)
- **Current intended slice**: Native Harness Engineering, Master Verification Runner, State Ledger Control Surface, and Brand Gate B / Impeccable Visual Polish.
- **Working Tree Notice**: Reviewers must evaluate working-tree and untracked control content alongside committed HEAD.

---

### File Boundaries

#### Files in Primary Implementation Slice
- `contracts/PBMRebateTreasury.sol`
- `contracts/PatientFundParticipatoryBudgeting.sol`
- `contracts/PharmacyMutualCredit.sol`
- `server/createApp.js`
- `tools/resilience/state-machine-verifier.mjs`
- `tools/resilience/continuity-engine.mjs`
- `scripts/check-brand-compliance.js`
- `dashboard/design-system.css`
- `dashboard/index.html`

#### State Ledger & Control Files in Review Scope (Proof Dependencies)
- `SOLVENCY_DEBT_SEMANTICS.md`
- `review-context/SINGLE_REPO_STATE_LEDGER.md`
- `reviews/rotational_swarm_review_dossier.md`
- `scripts/eval_constitutional_rubric.py`
- `scripts/index_dossier_tree.py`
- `scripts/observability_dashboard.py`
- `scripts/run_solidity_security_audit.py`
- `scripts/verify_all.py`

#### Files Explicitly Excluded
- `contracts/drafts/` (`CooperativeParticipatoryBudgeting.sol`, `ReflexiveFiduciaryManifold.sol` - unintegrated draft modules)
- `circuits/vote_nullifier.circom` (spec-only mock ZK path, not production privacy)
- `test/mocks/` (test harness mock helpers)

---

### Claim Status & Verification

#### Claims Currently Believed Fixed `[live verification just run]`
1. **Solvency Packet Compiler**: `scripts/index_dossier_tree.py` includes `contracts/PBMRebateTreasury.sol` and `SOLVENCY_DEBT_SEMANTICS.md`.
2. **Native State Machine Verifier**: `tools/resilience/state-machine-verifier.mjs` provides a standalone fail-closed reference model for debt queues, PB rounds, and offline vouchers; it is not runtime contract enforcement.
3. **Portable Master Verification Runner**: `scripts/verify_all.py` executes 5 fail-closed steps with cross-platform binary resolution (`shutil.which`).
4. **Hardhat Test Suite**: **280 / 280 passing unit tests (100% GREEN)** `[live verification just run]`.
5. **Brand Gate B & Impeccable Visual Compliance**: **100% Passed (0 inline styles, curated motion tokens <= 300ms, curated HSL color tokens)** `[live verification just run]`.
6. **PageIndex Status Auditor**: **0 status contradictions across 15 target documents** `[live verification just run]`.
7. **Swarm Observatory Evidence Gate**: **7 reconciled router metadata receipts, 0 evidence violations, 0.0% violation-derived inconsistency score** `[live verification just run]`.
8. **Slither Artifact Policy**: Explicitly documented `--skip-slither` static artifact parsing behavior in `scripts/run_solidity_security_audit.py`.

#### Claims Still Disputed / Open Non-Claims
1. **ZK Privacy Bounds**: `circuits/vote_nullifier.circom` is spec-only/mock ZK. It does NOT provide production-grade zero-knowledge privacy.
2. **Production Solvency Readiness**: System is a prototype. No live mainnet deployment, real fund custody, or live PHI handling exists.
3. **Draft Contract Decoupling**: `CooperativeParticipatoryBudgeting.sol` and `ReflexiveFiduciaryManifold.sol` remain unintegrated draft modules.

---

### Control & Next Actions

- **Latest controlling reviewer verdict**: **Codex 5.5 State Compression Directive**: Freeze review expansion; maintain single compact state ledger; evaluate live working-tree control content.
- **Next implementation action**: None before promotion review.
- **Next review action**: Read-only Codex 5.5 promotion review against this compact ledger and exact working-tree manifest.
