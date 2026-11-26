# Threat Model: Voluntary Deposits & What a Ledger Omission Can and Cannot Prove

**Status:** Prototype Boundary Specification  
**Scope:** `contracts/PBMRebateTreasury.sol`, `dashboard/`, `scripts/export-portability.js`, `docs/ops/OMISSION_LEDGER.md`

---

## 1. Core Premise: Voluntary On-Chain Deposits

`PBMRebateTreasury` is an opt-in ERC-20 custody and Merkle distribution prototype. Calling `depositRebate(uint256 amount, string calldata source)` is **strictly voluntary**:

- Smart contract bytecode cannot compel a Pharmacy Benefit Manager (PBM), health plan sponsor, pass-through administrator, or drug manufacturer to transfer funds on-chain.
- In the off-chain pharmaceutical supply chain, drug manufacturers typically pay post-sale rebates negotiated and administered by PBMs or plan intermediaries ([FTC July 2024 Interim Staff Report on PBMs](https://www.ftc.gov/reports/pharmacy-benefit-managers-powerful-middlemen-inflating-drug-costs-threatening-independent-pharmacies)). On-chain, `depositRebate()` accepts transfers from **any non-sanctioned address**—whether operated by a PBM, a self-insured employer/union plan, a transparent pass-through vendor, or a manufacturer—and records only `msg.sender`, `amount`, `block.timestamp`, and an unauthenticated `source` string.

---

## 2. Proof Matrix: Deposits vs. Absences

| Observation | What It **Can** Prove | What It **Cannot** Prove Alone |
| :--- | :--- | :--- |
| **Recorded `RebateDeposited` event** | Address `msg.sender` transferred `amount` of the configured payout token into `PBMRebateTreasury` at `block.timestamp` with the caller-supplied `source` string. | Legal corporate identity of `msg.sender` (without verified address attestation), whether `amount` equals 100% of rebates owed off-chain, or whether value was retained elsewhere as administrative/formulary fees. |
| **Zero deposits from an address or period ("Ledger Absence")** | Zero payout tokens were deposited into **this specific contract address** on **this chain** from the queried address during the queried block range. | That any organization owed money, withheld rebates, breached a contract, or violated law. An absence is **not** proof of an unpaid obligation without an independent expected-deposit record. |
| **Paired Absence + Independent Expected-Deposit Record ("Actionable Omission")** | A measurable discrepancy exists between an independently documented off-chain expectation (for example, a signed pass-through contract schedule, audited NCPDP/claims reconciliation, or signed rebates-due attestation) and on-chain treasury receipts. | Automatic legal liability. Discrepancies may still reflect off-ledger settlement, timing windows, disputed claims, or confidential contractual carve-outs requiring human/legal review. |

---

## 3. Threat & Evasion Vectors

| Vector | Mechanism | Mitigation / Required Guardrail |
| :--- | :--- | :--- |
| **Unverified `source` Metadata Spoofing** | Any non-sanctioned wallet can deposit `1 wei` with a misleading `source` string (e.g., naming a third-party PBM or manufacturer). | Treat `source` as untrusted caller memo text. Never attribute corporate identity without cryptographic address verification or public registry filings. Note: `1 wei` dust deposits cannot reset the 180-day stale recovery timer (`epochStartTimestamp` is used instead of `lastDepositTimestamp`). |
| **Fee Relabeling & Off-Ledger Routing** | An intermediary may pass zero "rebates" while routing equivalent value through administrative fees, GPO/rebate-aggregator fees, data fees, or off-chain bank wires. | Classify under the neutral reconciliation taxonomy in [OMISSION_LEDGER.md](../ops/OMISSION_LEDGER.md); require contract definitions and off-chain audit schedules before asserting a pass-through gap. |
| **Defamation / Misattribution on Public UIs** | Naming real companies next to synthetic or unverified omission figures creates legal and credibility risk. | Public demo surfaces (`dashboard/`) render only provenance-labeled synthetic entities (`data-provenance="synthetic-fixture"`) and enforce safe-harbor disclaimers (`test/DashboardCredibility.test.js`). |
| **Payout Token Accounting Drift** | Rebasing, fee-on-transfer, or upgradeable blacklist tokens could break `solvencyCheck()` conservation between internal buckets and `IERC20.balanceOf(address(this))`. | Deployments must use a standard non-rebasing, non-fee-on-transfer ERC-20 token (verified in `test/PBMRebateTreasury.security.test.js`). |
| **Claimant Profiling & Retaliation** | Public `msg.sender` addresses, claim amounts, gas funding, and RPC metadata can correlate participating independent pharmacies and trigger network retaliation or audit targeting. | Documented as an active launch blocker in [RETALIATION_AND_PRIVACY_THREAT_MODEL.md](RETALIATION_AND_PRIVACY_THREAT_MODEL.md) and [IDENTITY_NULLIFIER_DESIGN.md](IDENTITY_NULLIFIER_DESIGN.md). Current mock ZK paths do **not** provide production unlinkability. |
