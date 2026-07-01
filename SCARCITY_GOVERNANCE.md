# Scarcity Governance (Proposed)

This document records the current gap between transparent treasury routing and actual scarcity allocation. It is a proposed governance design surface, not an implemented contract mechanism.

> [!IMPORTANT]
> **NOT IMPLEMENTED**: The current contracts do not decide who receives scarce medicine, scarce credit, or scarce patient-fund support when needs exceed available resources. Under today's prototype, allocation decisions remain council- and process-dependent.

---

## 1. Why This Exists

The Commons can make rebate flows visible and route funds, but crisis conditions may involve shortages that accounting cannot solve:

* patient-fund liquidity is insufficient;
* local pharmacies lack inventory;
* distributor allocations are capped;
* PBMs or payers delist participating pharmacies;
* internet, wallet, or chain access fails;
* credential issuers revoke or delay participant standing.

In those cases, security must mean more than "the treasury cannot be stolen." It must include continuity, dignity, privacy, and legitimate triage.

---

## 2. Current Boundary

Current implementation supports:

* patient-fund inflows through claims, recalls, and sweeps;
* participatory budgeting rounds for projects;
* mutual-credit capacity and voucher accounting;
* dispute flags, evidence hashes, and council/root-confirmer remediation paths.

These are partial supports, not scarcity governance. For example, the `exclusionRemediationReserve` can fund approved root-exclusion remediation without draining ordinary distribution liquidity, `PatientFundParticipatoryBudgeting` can distribute a pre-funded matching pool, and `PharmacyMutualCredit` can reserve credit capacity for vouchers. None of these mechanisms decides which patient receives scarce medicine, verifies physical inventory, creates a partial-payment queue, or replaces a ratified triage process.

Current implementation does **not** support:

* automatic scarcity triage;
* patient-level medicine prioritization;
* inventory-aware allocation;
* non-council emergency allocation authority;
* offline claim clearing;
* enforceable community-jury override.
* partial matching payouts or debt queueing for underfunded patient-fund rounds;
* bad-debt writeoffs, insolvency handling, or cooperative liquidation in the mutual-credit ledger.

---

## 3. Proposed Triage Principles

Any future scarcity process should be evaluated against these principles:

1. **Continuity first**: prioritize avoiding abrupt interruption of chronic or life-sustaining medications.
2. **Dignity by design**: do not require public disclosure of diagnosis, poverty, immigration status, disability, or stigmatized medication need.
3. **Local knowledge with review**: local pharmacies and patient advocates can surface urgent needs, but must be reviewable for favoritism or coercion.
4. **No silent exclusion**: denied or delayed support should produce a reason code and appeal path.
5. **Anti-capture**: no single council, issuer, PBM-facing institution, or pharmacy network should control all scarcity decisions.

---

## 4. Required Before Public Use

Before claiming scarcity governance, the project needs:

* ratified eligibility and appeal rules;
* privacy-preserving need signals;
* de-identified continuity metrics;
* inventory or availability attestations with uncertainty metadata;
* emergency issuer and credential-revocation appeal procedures;
* offline receipt reconciliation;
* tests or tabletop exercises covering shortage, issuer capture, PBM retaliation, internet outage, and patient-fund depletion.

---

## 5. Mutual-Credit Default And Bad Debt

`PharmacyMutualCredit` records zero-sum balances and reserved voucher capacity. It does not create collateral, inventory, insurance, or a bankruptcy process.

Before mutual credit is used as crisis infrastructure, the Commons must define:

* maximum credit-limit policy and review cadence;
* who can approve large credit-limit increases;
* what happens when a pharmacy cannot settle its negative balance;
* whether positive credit holders bear loss, receive patient-fund support, or enter a cooperative liquidation process;
* how voucher recipients are warned that credit balances are not the same as guaranteed medicine or stablecoin redemption;
* how bad-debt decisions are appealed and reported without exposing patient data.

Until those rules exist, mutual credit should be described as a settlement and liquidity-support ledger, not as a guarantee of medicine supply or full redemption.
