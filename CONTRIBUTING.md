# Contributing to Pharmacy Fiduciary Commons

Thank you for your interest in reviewing and improving Pharmacy Fiduciary Commons.

> **Important Boundary Notice**
> Pharmacy Fiduciary Commons is a tested prototype seeking external review. It is not audited, not deployed to mainnet, not production-ready, and must not be used with real funds, real PHI, or real pharmacy credential material.

---

## What This Does

* **Verifiable Rebate Accounting**: Tracks quarterly manufacturer rebate deposits, administrative fee deductions, and pharmacy distribution allocations via Merkle tree roots ([`contracts/PBMRebateTreasury.sol`](contracts/PBMRebateTreasury.sol)).
* **Participatory Budgeting**: Demonstrates quadratic matching calculations and solvency debt tracking for patient community grants ([`contracts/PatientFundParticipatoryBudgeting.sol`](contracts/PatientFundParticipatoryBudgeting.sol)).
* **Mutual Credit Clearing**: Models bilateral credit lines with daily volume caps for independent pharmacy networks ([`contracts/PharmacyMutualCredit.sol`](contracts/PharmacyMutualCredit.sol)).
* **Client Witness Isolation**: Hardens prototype witness-input construction against RPC and network side-channel leakage ([`tools/zk/ClientWitnessAdapter.js`](tools/zk/ClientWitnessAdapter.js)) [committed HEAD].
* **Deterministic Verification Ladder**: Provides a 10-step verification command for tests, linters, privacy checks, and claim grounding ([`scripts/verify_all.py`](scripts/verify_all.py)) [committed HEAD].

---

## What This Does Not Claim

* **No Mainnet Deployment**: The current evidence boundary is local test harness execution. Any future testnet deployment must be documented with chain ID, address, and verification receipts.
* **No Real-Funds Custody**: This code has not undergone an independent third-party security audit. Never deposit live assets.
* **No Protected Health Information (PHI)**: Test fixtures and dashboard panels are for synthetic demonstration only and must not contain real patient records, pharmacy credentials, or claims logs.
* **No Production ZK Unlinkability**: The client witness adapter mitigates metadata leakage at the client layer, but wallet linking, gas payer timing, and relayer networks remain known privacy boundaries.
* **No Autonomous External Authority**: Council engine scripts and agent review dossiers are local analytical tools, not autonomous governance entities.

---

## How To Verify Locally

All claims in this repository must be reproducible locally.

### Prerequisites
* Node.js `20.x` or `22.x`
* Python `3.11` or `3.12`
* Git

### Verification Commands
```bash
# 1. Install dependencies
npm install

# 2. Run Hardhat unit & state machine tests (438 tests)
npx hardhat test

# 3. Build & check frontend dashboard governance
npm run build:dashboard
npm run check:frontend

# 4. Check readiness and local privacy leak scanner
npm run check:readiness -- --env local
python scripts/privacy_leak_scanner.py

# 5. Run the master 10-step verification ladder
python scripts/verify_all.py
```
A successful run produces a local generated receipt at `cache/verification_master_receipt.json` with `10/10 PASSED` [generated cache].

---

## How To Review

We organize external collaborator feedback into five dedicated review lanes:

1. **Solidity & Treasury Invariants**: Escrow balance preservation, non-reentrancy, access control role segregation, and cap bounds.
2. **ZK & Privacy Boundary**: Witness sanitization, field element validation, and network metadata isolation [committed HEAD].
3. **Public Documentation & Claim Calibration**: Ensuring every document clearly states prototype boundaries without overclaiming audit status or readiness.
4. **Dashboard Accessibility & UI**: WCAG 2.4.1 keyboard navigation, screen-reader semantics, and Brand Gate B compliance (zero inline styles).
5. **Dependency Migration Review**: Assessment of deferred major version upgrades (OpenZeppelin v5, Hardhat v3) [external reviewer claim].

Please use the issue templates in [`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/) to route your feedback into the appropriate lane.

---

## Review & Pull Request Guidelines

1. **Grounded Evidence**: Every proposed change or finding must cite exact file paths, line bounds, and tests.
2. **Brand Gate B Strictness**: The dashboard HTML and CSS strictly forbid inline `style="..."` attributes. All styles must reside in `design-system.css` or scoped `<style>` blocks.
3. **No Credential Exposure**: Never submit pull requests or issues containing private keys, live API secrets, PHI, or real pharmacy transaction logs.
4. **Clean Verification**: Before requesting review, confirm that `python scripts/verify_all.py` passes 10/10 locally.
