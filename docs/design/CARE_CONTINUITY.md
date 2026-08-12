# Care Continuity & Human Capabilities Framework

This document outlines the conceptual and operational framework for ensuring that the **Pharmacy Fiduciary Commons** serves actual care continuity, rather than mistaking auditable token routing for human well-being.

> [!NOTE]
> **GOVERNANCE POSTURE**: This framework guides the long-term design of adjacent primitives and community patient fund policies. It establishes that *auditable value flow is not the same as reliable care*, and that *the system may be secure while participants are unsafe*.

---

## 1. The Core Principle: Care Continuity

The Fiduciary Commons exists to keep critical access floors viable for patients and local pharmacies. If capitalism fails to meet basic needs, the system must degrade gracefully to secure human capability. We define getting needs met through three dimensions:

1. **Physical Availability**: Having the medication physically present in the geography when it is clinically required.
2. **Economic Viability**: Restructuring margins so that neither the patient nor the pharmacy is forced to absorb losses from PBM extraction.
3. **Operational Liveness**: Ensuring access does not depend on a single centralized key, stable internet connection, or functioning institutional network.

---

## 2. Continuity Risk Taxonomy

Value routing (Merkle claims, participatory budgeting) is necessary but insufficient. To map real-world barriers to care, the Commons categorizes four core continuity risks:

| Risk Class | Description | Operational Impact | Commons Counter-Pressure |
| :--- | :--- | :--- | :--- |
| **Supply Stockouts** | Manufacturer shortages, distributor caps, or distribution network delays. | Patients face sudden therapy gaps regardless of wallet funds. | **Cooperative Formulary Coordination**: Off-chain inventory or formulary sharing can use [PharmacyMutualCredit](contracts/PharmacyMutualCredit.sol) only as a financial settlement layer; the contract does not track drug inventory, SKU availability, or formulary status. |
| **Payer Formulary Shifts** | PBMs suddenly reclassifying drugs or altering co-pay tiers. | Direct increase in financial barriers to medication adherence. | **Omission Ledger Tracking**: Classifying formulary shifts as PBM omissions under [OMISSION_LEDGER.md](OMISSION_LEDGER.md). |
| **Network Exclusions** | PBMs auditing, penalizing, or delisting independent pharmacies. | Patients lose local providers; pharmacy solvency degrades. | **Retaliation Tiers**: Shielded operational paths and cooperative defense reserves (see [RETALIATION_AND_PRIVACY_THREAT_MODEL.md](RETALIATION_AND_PRIVACY_THREAT_MODEL.md)). |
| **Infrastructure Degradation** | Internet outages, blockchain network congestion, stablecoin failures, or licensing registry lockouts. | Electronic claims and on-chain voting fail. | **Minimal Offline Mode**: Offline paper vouchers and SMS-fallback verification mechanisms. |

---

## 3. Human Capabilities Metrics

To keep feedback loops connected to operational reality, the project defines the following human-centered metrics. These contrast with financial indicators like Total Value Locked (TVL) or contract volume:

### 3.1 Continuous Refill Ratio (CRR)
* **Definition**: The percentage of patients on chronic therapies within the commons who maintain their refills within a `<= 3`-day variance from clinical schedule.
* **Target**: `> 95%`.
* **Operational Trigger**: If the CRR drops below $90\%$ in a specific district, the Council should prioritize local pharmacy credit limit expansions (`updateCreditLimit`) and local patient fund projects. This is a policy trigger, not an automated contract control.

### 3.2 Emergency Fill Access (EFA)
* **Definition**: The availability of local mutual-credit capacity and emergency vouchers to cover immediate medication fills under sudden network outages or reimbursement delays.
* **Target**: Every registered pharmacy should hold at least 30 days of average credit capacity. This is a policy target, not an implemented admission rule.
* **Current Mechanism**: Supported by peer credit limit allocations in [PharmacyMutualCredit.sol](contracts/PharmacyMutualCredit.sol), but the 30-day capacity target is not contract-enforced.

### 3.3 Non-Digital Workflow Adoption (NDWA)
* **Definition**: The volume of claims, vouchers, or disputes processed via SMS, physical paper, or trusted cooperative proxies, relative to direct web-connected wallet interactions.
* **Target**: Support at least `20%` of transactions offline to prevent digital exclusion.
* **Current Status**: Partially implemented. The repository contains draft offline voucher generation (`continuity-engine.mjs`) and deterministic offline-receipt reconciliation (`reconcile-vouchers.mjs`) tools (local integrity evidence only). SMS integration and live, production-grade on-chain reconciliation workflows remain unimplemented.

### 3.4 Medication Choice Autonomy (MCA)
* **Definition**: Measures the degree of patient and pharmacist agency to substitute alternative generics or adapt care pathways when faced with payer formulary shifts or distributor stockouts, preventing hyper-optimization of financial margins at the cost of patient choice.
* **Target**: `> 90%` of exclusions resolved with patient-approved alternative substitutions.
* **Current Status**: Policy guideline for cooperative formulary coordination.

---

## 4. Operationalizing Capabilities: Community Juries

When algorithmic or contract evidence conflicts with human survival needs, the commons rejects automated finality.
* **The Rule of Override**: If a patient or pharmacy is excluded from a claim because of a technical error (e.g. Merkle proof mismatch or credential registry omission), they should be able to submit a dispute flag accompanied by participant testimony (as defined in [EVIDENCE_METADATA.md](EVIDENCE_METADATA.md)).
* **Community Evidence Juries**: For contested exclusions, a future community jury process could advise the Council and root confirmer on whether strict protocol enforcement would cause clinical harm. Any remediation payout still requires the implemented `exclusionRemediationReserve` funding, root-confirmer approval, and council resolution path in [PBMRebateTreasury.sol](contracts/PBMRebateTreasury.sol).
* **Governance Boundary**: Community juries are strictly advisory until a ratified process and contract-recognized authority exist. Today, the Council and root confirmer remain the final on-chain actors for remediation payouts and dispute resolution.

For scarce-fund and scarce-medicine triage boundaries, see [SCARCITY_GOVERNANCE.md](SCARCITY_GOVERNANCE.md).
