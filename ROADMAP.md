# Implementation Roadmap

This document outlines the four development and deployment phases of the Fiduciary Rebate Commons. The timeline scales with security audits and community readiness.

---

## Phase 0: Prototype Hardening Gate

The project remains in this phase until the public-facing and operational gates are demonstrably satisfied. This phase is intentionally allowed to hold design decisions open while making the unresolved parts explicit.

- **Actions**:
  - Keep the contract test suite green on a supported Node runtime.
  - Resolve production-readiness checklist items for frontend minification, private source maps, secrets, database/RLS, API authorization, rate limiting, caching, scaling, error tracking, and ADA/WCAG accessibility before public launch.
  - Select hosting, database, auth, and form-intake providers only after a documented trust-boundary review. Cloudflare, Supabase, Firebase, Clerk, and any Bolin/IODR-style identity provider remain candidates, not settled architecture.
  - Document any intentionally undecided policy choices in `OPEN_DESIGN_DECISIONS.md` instead of implying they are settled.
  - Keep dashboard data synthetic or contract-backed with visible provenance labels.
  - Treat public forms as hostile intake surfaces: require server-side validation, abuse controls, and privacy review before collecting user, pharmacy, patient, credential, vote, or export data.
  - Keep secrets out of committed files and browser bundles. Server-side `.env` files are local deployment inputs only; production secrets must live in provider secret stores with environment separation.
  - Exercise the offline/non-digital workflow gates in `PRODUCTION_READINESS_CHECKLIST.md` with tabletop scenarios for SMS, paper voucher, trusted-proxy, delayed-sync, duplicate-receipt, forged-receipt, and lost-connectivity cases before claiming non-digital access.
  - Define privacy-safe, fraud-resistant care-continuity metric ingestion before using CRR or similar wellbeing metrics to prioritize funding.
  - Maintain scanner triage artifacts for Slither, Aderyn, and targeted Mythril runs; no unresolved high-confidence scanner finding should be carried forward without a written acceptance rationale.
  - Preserve scanner-promoted roadmap items from `SCANNER_TRIAGE.md`: forced-ETH recovery rehearsals, chain-specific timestamp assumptions, `resolveClaim` readability review, and role-ownership evidence.
  - Keep the read-only `dryRunFinalize` / `previewFinalize` operator path wired into dashboards so expected project shares can be compared with actual token liquidity before finalization.
- **Success Criteria**: Local/testnet claims remain accurate, readiness gaps are visible, and public materials do not imply audit, production, or mainnet readiness.

---

## Phase 1: Security Audit & Testnet Deployment

The primary goal of Phase 1 is code validation and parameter calibration.

- **Actions**:
  - Secure a formal third-party smart contract security audit for the treasury and any adjacent contract intended for deployment.
  - Deploy the contract to Ethereum Sepolia and Arbitrum Sepolia testnets.
  - Calibrate initial parameters: `initialDailyCap`, `RECALL_DELAY`, and `governanceBP`.
  - Build and validate the off-chain Merkle tree generator and proof distribution scripts.
  - Run the dashboard against testnet addresses without presenting test data as production data.
- **Success Criteria**: No unresolved critical or high-severity audit findings; full test suite passes on a supported Node runtime; testnet deployment addresses, chain IDs, and operating parameters are documented.

---

## Phase 2: First Live Epoch (Small Capital Guardrails)

Mainnet deployment begins only after Phase 0 and Phase 1 gates are satisfied. The first live epoch should be treated as a constrained operational trial, not proof of production maturity.

- **Actions**:
  - Deploy the contract to mainnet (e.g. Arbitrum One or Base for low gas costs).
  - Configure a 3/5 Safe for `_council`, a separate root-confirmer Safe or governance address, a separate guardian, and a timelocked executor.
  - Rehearse forced-ETH recovery through the timelocked executor and document the exact `environmentalFund` destination before accepting mainnet funds.
  - Document selected-chain timestamp behavior and operator notice windows for root proposal expiry, recall delay, stale recovery, credential deadlines, voucher expiry, and matching-share reclaim grace periods.
  - Review `PBMRebateTreasury.resolveClaim` for readability before formal audit; keep behavior-preserving refactors gated by the existing accounting invariant and dispute-resolution regression tests.
  - Run the first live epoch using a low daily cap (e.g. $1,000 maximum daily volume) and small deposits.
  - Launch a production-built public dashboard only after frontend hardening, accessibility, rate limiting, cache policy, error tracking, and deployment checks pass.
- **Success Criteria**: Successful claim execution, no locked funds, no misleading production claims, and accurate tracking of contract-backed omissions or explicitly labeled submitted evidence.

---

## Phase 3: First Participatory Budgeting Round

Activate the community allocation layers for matching patient fund reserves.

- **Actions**:
  - Accumulate the Patient Fund from the 10% claim routing fee and unclaimed epoch recalls.
  - Deploy the credential-gated voting portal using the contract's squared vote-count weighting.
  - Evaluate canonical contribution-based QF separately before making any QF claim.
  - Run the first local participatory budgeting round for patient co-pay assistance and independent pharmacy resilience.
  - Audit and distribute matches to community projects based on unique participant support.
- **Success Criteria**: > 70% of Patient Fund resources allocated to preventative care projects with zero Sybil incidents detected.

---

## Phase 4: Adjacent Primitives & Parallel Infrastructure

Scale the system by launching adjacent, decoupled primitives to form a complete parallel health infrastructure.

- **Actions**:
  - Build the **Pharmacy Cooperative Procurement Layer** for shared formulary intelligence.
  - Develop the **Pharmacy Mutual Credit Clearing / Voucher Ledger** to stabilize pharmacy liquidity during reimbursement delays.
  - Establish the **Rebate Transparency Registry** as a public-facing legal dashboard exposing market-wide net pricing discrepancies.
  - Prototype privacy-safe offline receipt reconciliation only after the non-digital workflow tabletop exercises define the required evidence, review, and appeal paths.
- **Success Criteria**: Successful integration of adjacent tools, lower operating costs for participating independent pharmacies, and reduced dependency on corporate PBMs.
