# Implementation Roadmap

This document outlines the four development and deployment phases of the Fiduciary Rebate Commons. The timeline scales with security audits and community readiness.

---

## Phase 1: Security Audit & Testnet Deployment

The primary goal of Phase 1 is code validation and parameter calibration.

- **Actions**:
  - Secure a formal third-party smart contract security audit for `PBMRebateTreasury.sol`.
  - Deploy the contract to Ethereum Sepolia and Arbitrum Sepolia testnets.
  - Calibrate initial parameters: `initialDailyCap`, `RECALL_DELAY`, and `governanceBP`.
  - Build and validate the off-chain Merkle tree generator and proof distribution scripts.
- **Success Criteria**: Zero high-severity vulnerabilities found; 100% test suite pass on testnets.

---

## Phase 2: First Live Epoch (Small Capital Guardrails)

We begin mainnet deployment under strict risk-mitigated caps to observe live interactions.

- **Actions**:
  - Deploy the contract to mainnet (e.g. Arbitrum One or Base for low gas costs).
  - Configure a 3/5 Gnosis Safe for `_council` and a 2-day `TimelockController` for `_executor`.
  - Run the first live epoch using a low daily cap (e.g. $1,000 maximum daily volume) and small deposits.
  - Launch the public dashboard showing active claims and the **Ledger of Omissions** (PBM non-recorded deposits).
- **Success Criteria**: Successful claim execution, zero locked funds, and accurate tracking of omitted deposits.

---

## Phase 3: First Participatory Budgeting & Quadratic Funding Round

Activate the community allocation layers for matching patient fund reserves.

- **Actions**:
  - Accumulate the Patient Fund from the 10% claim routing fee and unclaimed epoch recalls.
  - Deploy the off-chain QF matching portal with verifiable credential/attestation gates.
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
- **Success Criteria**: Successful integration of adjacent tools, lower operating costs for participating independent pharmacies, and reduced dependency on corporate PBMs.
