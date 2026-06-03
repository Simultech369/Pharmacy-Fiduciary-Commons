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
* **Root Management**: Proposing and confirming Merkle roots for epoch allocations (`proposeRoot`, `confirmRoot`) based on verified off-chain dispensing records.
* **Recall Operations**: Returning unclaimed epoch funds to the Patient Fund after the 30-day recall delay.
* **Sanction Administration**: Placing or lifting sanctions on claimant addresses with reason codes.
* **Dispute Resolution**: Reviewing and resolving flagged claims (`resolveClaim`).
* **Emergency Action**: Unpausing the system (only the Guardian can pause, only the Council can unpause).

---

## 4. Council Selection and Removal

* **Selection**: Signers are elected from community health organizers, independent pharmacy cooperative representatives, and public health advocates.
* **Removal**: A signer may be removed or replaced via a 3/5 vote of the remaining Council members, or by an automatic trigger if a conflict of interest is breached.
* **DEFAULT_ADMIN_ROLE**: Enforced on-chain to allow signer rotation as keys expire or rotate.

---

## 5. Conflict of Interest (COI) Policy

* No Council member may hold a financial interest, executive role, or consulting agreement with any Pharmacy Benefit Manager (PBM) or major commercial pharmacy chain.
* Any transaction or Merkle root proposal allocating funds to a pharmacy affiliated with a Council member must be declared, and that member must recuse themselves from root generation and voting.

---

## 6. How Evidence is Reviewed

* **Root Generation**: Off-chain Merkle tree generators use validated dispensing reports (NCPDP standards) to calculate allocations.
* **Exclusion Auditing**: When an exclusion dispute is flagged (`flagExclusion`), the pharmacy must submit verifiable dispensing data to the Council audit board. The Council checks this evidence against the epoch's deposited rebate files.
* **Audit Transparency**: All audited dispensing data summaries and matching rebate deposits are published under structural transparency guidelines on the public dashboard.

---

## 7. Membership & Participation

* **Who counts as a Member**: Any verified independent pharmacy with active dispensing credentials on the registry, and patients participating in local health access programs.
* **Pharmacy Participation**: Pharmacies verify credentials, query the ledger of omissions, claim epoch rebates, and flag disputes.
* **Patient Participation**: Patients participate in allocating Patient Fund resources via local Participatory Budgeting rounds.

---

## 8. Sanctions & Appeals

* **Sanctions**: Applied only for verified double-claiming, fake dispensing records, or Sybil behavior. All sanctions are reason-coded and logged publicly on-chain via the `SanctionUpdated` event.
* **Appeals**: Any sanctioned pharmacy may register an appeal directly on-chain using the `appealSanction(string reason)` function. This emits a `SanctionAppealed` event, forcing the Council to review the sanction within 14 days and publish an audit report.
