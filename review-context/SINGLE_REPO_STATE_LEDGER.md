# Single Compact Repository State Ledger

> **Governance Directive**: Created per Codex 5.5 / Senior Reviewer instruction to eliminate state compression debt and prevent models from reviewing divergent historical snapshots.

---

### Core State Matrix

- **Repo**: `C:\Users\Josh\Desktop\PBMRebateTreasuryFinal`
- **Current branch baseline**: `main` (`[dirty working tree]`; local PBM hardening changes plus review sidecars pending granular commit slicing)
- **Current intended slice**: Proof-boundary cleanup, narrow PBM-core commit preparation, and follow-up verification slices.
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
- `docs/design/SOLVENCY_DEBT_SEMANTICS.md`
- `review-context/SINGLE_REPO_STATE_LEDGER.md`
- `reviews/rotational_swarm_review_dossier.md`
- `scripts/eval_constitutional_rubric.py`
- `scripts/index_dossier_tree.py`
- `scripts/observability_dashboard.py`
- `scripts/dossier_rag_retrieval.py`
- `scripts/eval_dossier_rag.py`
- `scripts/run_solidity_security_audit.py`
- `scripts/council_orchestrator.py`
- `scripts/verify_all.py`
- `review-context/AI_SYSTEMS_CONCEPT_COVERAGE.md`

#### Files Explicitly Excluded
- `contracts/CooperativeParticipatoryBudgeting.sol` and `contracts/ReflexiveFiduciaryManifold.sol` (unintegrated draft modules)
- `circuits/vote_nullifier.circom` (spec-only mock ZK path, not production privacy)
- `test/mocks/` (test harness mock helpers)

---

### Claim Status & Verification

#### Claims Currently Believed Fixed `[generated cache]`
1. **Solvency Packet Compiler**: `scripts/index_dossier_tree.py` includes `contracts/PBMRebateTreasury.sol` and `SOLVENCY_DEBT_SEMANTICS.md`.
2. **Native State Machine Verifier**: `tools/resilience/state-machine-verifier.mjs` provides a standalone fail-closed reference model for debt queues, PB rounds, and offline vouchers; it is not runtime contract enforcement.
3. **Portable Master Verification Runner**: `scripts/verify_all.py` executes the unified 9-step master promotion pipeline with cross-platform binary resolution (`shutil.which`).
4. **Hardhat Test Suite**: `scripts/verify_all.py` records that `npx --no-install hardhat test` exited successfully during the latest 9-step master runner. Exact passing-test totals must come from fresh console output or a receipt that records the count.
5. **Brand Gate B & Impeccable Visual Compliance**: **100% Passed (0 inline styles, curated motion tokens <= 300ms, curated HSL color tokens)** `[generated cache]`.
6. **PageIndex Status Auditor**: **0 status contradictions across 13 target documents** `[generated cache]`.
7. **Swarm Observatory Evidence Gate**: **8 reconciled router metadata receipts, 0 evidence violations, 0.0% violation-derived inconsistency score** `[generated cache]`.
8. **Local Dossier Retrieval Eval**: **26 golden domain questions and 8 adversarial negative probes pass with hit rate@5 1.0, MRR 0.8731, NDCG@5 0.9063, and no-hit accuracy 1.0** `[generated cache]`.
9. **Slither Artifact Policy**: Explicitly documented `--skip-slither` static artifact parsing behavior in `scripts/run_solidity_security_audit.py`.
10. **Dual-Chain Council Verifier**: `scripts/council_orchestrator.py` now verifies 11 receipt invariants for an explicitly simulated demo mode. It does not claim live Docker isolation, live model voting, provider ZDR, or live human authorization. Scratch-engine adversarial-gauntlet counts remain external claims unless freshly rerun or receipt-backed.
11. **On-Chain Solvency Check**: `PBMRebateTreasury.sol` implements the atomic `solvencyCheck()` view function returning `(isSolvent, delta, expectedBalance, actualBalance)`.
12. **Permission-Aware Packet Compiler**: `scripts/compile_review_packet.py` deterministically inspects file diffs, classifies sensitivity tiers (`PUBLIC_SAFE`, `INTERNAL`, `ZDR`, `LOCAL_ONLY`), and generates provenance receipts. It is not by itself a runtime permission layer or provider-route attestation.
13. **Solvency Invariant Coverage**: `test/foundry/TreasurySolvencyInvariant.t.sol` and `test/PBMRebateTreasury.fuzz.test.js` target solvency delta conservation, bucket conservation, and escrow sum invariants across randomized multi-epoch lifecycles. Treat Foundry depth/statefulness as proven only after a fresh Forge run or durable Forge receipt.
14. **Zero-Sum Mutual Credit Property Invariance**: `test/PharmacyMutualCredit.test.js` proves zero-sum balance conservation ($\sum b_i = 0$) and strict capacity adherence under 50-step randomized state transitions and boundary limit edge cases.
15. **Zero-Database Resilience & Offline Continuity**: `tools/resilience/zero-database-drill.mjs` and `test/ZeroDatabaseLiveness.test.js` exercise local offline-continuity behavior (client-side HMAC vouchers, Merkle proof reconstruction, and on-chain claim paths). This is local drill evidence, not production disaster-recovery proof.
16. **Agent Claim Lie Detector & Cross-Auditor**: `scripts/verify_agent_claims.py` and `test/AgentClaimVerifier.test.js` parse review dossiers and fail closed against targeted false claims such as fake commit hashes, hallucinated line bounds, ungrounded claims, and test-count inflation patterns.

#### Claims Still Disputed / Open Non-Claims
1. **Semantic ZK Mock**: `circuits/vote_nullifier.circom` is spec-only/mock ZK. It does NOT provide production-grade zero-knowledge privacy.
2. **Production Solvency Readiness**: Local prototype only; no live deployment, no live fund custody, no live fund movement, and no live PHI.
3. **Draft Contract Decoupling**: `contracts/CooperativeParticipatoryBudgeting.sol` and `contracts/ReflexiveFiduciaryManifold.sol` remain unintegrated draft modules.
4. **Lexical Local Retrieval Bounds**: `scripts/dossier_rag_retrieval.py` is lexical local Markdown retrieval with line citations. It is not PDF/page-number RAG, neural embedding search, ColBERT/late-interaction retrieval, web fallback, or production knowledge infrastructure.
5. **Execution Receipt Bounds**: Local execution receipts are non-cryptographic run metadata, not proof of execution or artifact authenticity. Mock and demo receipts must be explicitly labeled by mode and must never be described as live Docker isolation or live human approval.

---

### Control & Next Actions

- **Latest controlling reviewer verdict**: **Codex 5.6Sol Architecture Review**: proof-boundary-first; do not commit the full 29-file bundle as one baseline.
- **Next implementation action**: prepare a narrow PBM-core slice after claim cleanup, keeping review sidecars and generated cache separate unless explicitly approved.
- **Next review action**: staged-manifest review against this compact ledger, exact working-tree manifest, and fresh verification output.
