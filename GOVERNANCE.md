# Pharmacy Fiduciary Commons: Governance Framework

This document defines the rules, roles, and accountability mechanisms governing the Pharmacy Fiduciary Commons. The system is designed under Ostrom-commons principles to manage shared resources without extractive capture.

---

## 1. Mission

The mission of the Pharmacy Fiduciary Commons is to establish a transparent, on-chain rebate pass-through infrastructure that redirects captured pharmaceutical surplus directly back to independent local pharmacies and the patients they serve. This is preventative health infrastructure designed to keep critical health access floors viable, prevent pharmacy deserts, and eliminate opaque middleman extraction.

---

## 2. Eligible Beneficiaries

1. **Independent Pharmacies**: Privately owned, community-focused pharmacies that dispense prescriptions on thin margins and lack the legal leverage of large corporate chains.
2. **Patients**: Individuals residing in designated healthcare-desert regions or facing precarity in accessing medically necessary prescription drugs.

---

## 3. Council Duties

The Council is a 3/5 multisig address (e.g., Gnosis Safe) representing the trust root of the treasury. The Council is explicitly restricted to:
* **Epoch Management**: Starting and finalizing epochs (`finalizeEpoch`).
* **Root Management**: The council proposes Merkle roots for epoch allocations using `proposeRoot`. A separately configured root-confirmer Safe or governance address must approve the proposal using `confirmRoot`.
* **Recall Operations**: Returning unclaimed epoch funds to the Patient Fund after the 30-day recall delay.
* **Sanction Administration**: Placing or lifting sanctions on claimant addresses with reason codes.
* **Dispute Resolution**: Reviewing and resolving flagged claims (`resolveClaim`). Exclusion payouts require prior approval from the separately governed root confirmer and remain subject to treasury caps.
* **Emergency Action**: Unpausing the system (only the Guardian can pause, only the Council can unpause).

---

## 4. Council Selection, Removal & Patient Voice

* **Annual Nominations**: Signers are elected from community health organizers, independent pharmacy cooperative representatives, and patient advocacy groups. Nominations are held annually.
* **Patient Voice & Nominations**: Any verified participant pharmacy or patient advocate group can nominate a candidate.
* **Removal Petition Threshold**: If a Council member is suspected of negligence, conflict of interest, or capture, a public petition signed by **at least 10% of active participant pharmacies and patients** (based on unique claimant addresses over the last 4 epochs) forces an on-chain signer replacement vote.
* **Signer Rotation**: Council membership uses `DEFAULT_ADMIN_ROLE`. Root-confirmer rotation is executed through the timelock, and the contract rejects any address that would simultaneously hold council and root-confirmation authority.

---

## 5. Conflict of Interest (COI) Policy

* No Council member may hold a financial interest, executive role, or consulting agreement with any Pharmacy Benefit Manager (PBM) or major commercial pharmacy chain.
* Any transaction or Merkle root proposal allocating funds to a pharmacy affiliated with a Council member must be declared, and that member must recuse themselves from root generation and voting.

---

## 6. How Evidence is Reviewed

* **Root Generation**: Off-chain Merkle tree generators use validated dispensing reports (NCPDP standards) to calculate allocations.
* **Exclusion Auditing**: When an exclusion dispute is flagged (`flagExclusion`), the pharmacy must submit verifiable dispensing data to the Council audit board. The Council checks this evidence against the epoch's deposited rebate files, the root confirmer independently approves any proposed payout, and the Council then executes or dismisses the resolution. Approved payouts draw only from the explicitly funded exclusion-remediation reserve, never from root escrow or future distribution liquidity.
* **Audit Transparency**: All audited dispensing data summaries and matching rebate deposits are published under structural transparency guidelines on the public dashboard.

---

## 7. Membership & Participation

* **Who counts as a Member**: Any independent pharmacy or patient advocate holding an eligible, active, unexpired, non-revoked credential bound to the registering wallet. The current registry and issuer pin are prototype trust roots, not a production identity authority.
* **Pharmacy Participation**: Pharmacies verify credentials, query the ledger of omissions, claim epoch rebates, and flag disputes.
* **Patient Participation**: Patients participate in allocating Patient Fund resources via local Participatory Budgeting rounds.

---

## 8. Sanctions, Appeals Timeline & Evidence Window

* **Sanctions**: Applied only for verified double-claiming, fake dispensing records, or Sybil behavior. All sanctions are reason-coded and logged publicly on-chain via the `SanctionUpdated` event.
* **Appeals Timeline**:
  - Any sanctioned pharmacy may register an appeal directly on-chain using the `appealSanction(string reason)` function.
  - The Council has a **strict 14-day window** from the `SanctionAppealed` block timestamp to review the submitted evidence.
  - The Council must issue a public summary of findings and either sustain or lift the sanction (`updateSanction(account, false, "Appeal approved")`) before the 14 days expire.
* **Public Evidence Window**: The appeal case, relevant dispensing records, and the Council's final justification summary must be published to the public dashboard within 7 days of resolution, keeping all enforcement actions fully legible and contestable.

---

## 9. Nested Enterprises (Dizzy as Judgment Layer)

Following Ostrom's Principle of Nested Enterprises, the Pharmacy Fiduciary Commons is a bounded treasury layer, but it does not attempt to solve all cognitive or ideological disputes within its own smart contract code.
- **Arbitration Layer**: *Dizzy the Polymath* functions as the off-chain judgment and arbitration layer.
- **Escalation Path**: If a dispute between the Council and a participant pharmacy remains unresolved after the 14-day window, or if a conflict of interest claim is made against the Council, the parties may escalate the case to the Dizzy agent framework.
- **Judgment Outputs**: Dizzy evaluates the claim against the `LEGAL-GUARDRAILS` and the `MECHANISM_SIEVE` to output a structured recommendation. The Council is expected to align on-chain votes with Dizzy's findings to preserve institutional legitimacy.
