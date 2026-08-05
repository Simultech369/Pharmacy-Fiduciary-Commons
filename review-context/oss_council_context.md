# OSS Council Review Context — Pharmacy Fiduciary Commons

Status: Active context for multi-agent council review of `.next` roadmap sorting and ordering.

## 1. Repository State & Evidence Lineage
- Local Path: `C:\Users\Josh\Desktop\PBMRebateTreasuryFinal`
- Active Branch: `feature/db-proxy` [live verification just run]
- Baseline HEAD: `04e0e619aeb1a885cadfb703fa113e6ac363b522` [committed HEAD]
- Test Suite Health: 266 passing unit, security, EIP-191/712 server, Circom circuit, and ZK fixture tests [live verification just run]

## 2. Recently Implemented Milestones (Lineage Ledger Entries 013-016)
1. **Gate DB1 Database Proxy & RLS Hardening**:
   - `server/createApp.js`: EIP-191 voter domain verification, EIP-712 relayer typed data checks, 15-second row-locked request ledger idempotency, domain-separated HMAC credential hashing.
   - `test/server.test.js`: 19/19 passing security & RLS isolation tests.
2. **Circom VoteNullifier Circuit**:
   - `circuits/vote_nullifier.circom`: Poseidon Merkle membership constraints, project/round-scoped nullifier derivation.
   - `test/ZKNullifierCircuit.test.js`: 9/9 passing constraint & witness validation tests.
3. **ZK Nullifier Fixture Gate & Leakage Matrix**:
   - `test/ZKNullifierFixtureGate.test.js`: 18/18 passing fixture schema, semantic wallet-linkable vs unlinkable path, metadata leakage budget, and verifier governance tests.
4. **PageIndex Dossier Tree Indexer**:
   - `scripts/index_dossier_tree.py`: 42 documentation files indexed, zero state contradictions across repository.

## 3. Candidate Roadmap Items for `.next`

### Item A: ZK Nullifier Witness Generator & Proof Verification Adapter
- *Objective*: Build client-side witness preparation scripts and stateless verifier adapter interfaces without introducing live third-party RPC dependencies.
- *Primary Files*: `circuits/vote_nullifier.circom`, `test/ZKNullifierFixtureGate.test.js`, `test/ZKNullifierCircuit.test.js`.
- *Invariants*: Preserve public signal ordering; ensure forbidden metadata (timestamps, RPC IPs, raw credentials) remains strictly out of proof payloads.

### Item B: Offline Continuity Double-Spend Guard & Global Nullifier Cache Validator
- *Objective*: Implement dry-run intake validation for offline continuity relay packets to prevent cross-batch replay attacks before batch submission.
- *Primary Files*: `tools/resilience/continuity-engine.mjs`, `test/ContinuityAndAdversarialTools.test.js`, `tools/offline/continuity-kit.html`.
- *Invariants*: Fail closed on MAC mismatch or duplicate nullifiers; omit stable wallet-to-pharmacy mappings.

### Item C: Participatory Budgeting Solvency Safeguards & Match Cap Policy
- *Objective*: Enforce quadratic matching pool caps per project and clarify shortfall-aware round lifecycle notices in UI and contracts.
- *Primary Files*: `contracts/PatientFundParticipatoryBudgeting.sol`, `test/PatientFundParticipatoryBudgeting.test.js`, `SOLVENCY_OWNER_DECISION_WORKSHEET.md`.
- *Invariants*: Never treat observed shortfall reduction as guaranteed liquidity repayment; preserve Ostrom-commons governance bounds.

### Item D: Cybernetic Jazz Diorama Design System Refinement & Accessibility Hardening
- *Objective*: Refine frontend UI styling (obsidian dark, jazz cyan signals, warm amber warnings), eliminate inline style leaks, and verify keyboard/screen-reader accessibility compliance.
- *Primary Files*: `dashboard/design-system.css`, `dashboard/index.html`, `scripts/check-brand-compliance.js`, `scripts/check-frontend-build.js`.
- *Invariants*: Zero generic AI visual slop; 100% brand gate compliance; zero un-styled DOM elements.

## 4. Specific Council Sorting Question
As the Review Council (Grok / Strategist / Skeptic / Advocate):
1. Rank Items A, B, C, D in exact execution order for `.next`.
2. Identify the single biggest security or privacy risk in Item A and Item B.
3. Define the smallest proof-bounded test slice to implement first under `.next`.
