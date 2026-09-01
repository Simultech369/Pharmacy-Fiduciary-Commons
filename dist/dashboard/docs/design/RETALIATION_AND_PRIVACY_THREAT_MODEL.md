# Retaliation & Privacy Threat Model

This document outlines the threat landscape, attack vectors, and mitigations concerning corporate retaliation, participant profiling, and patient privacy within the **Pharmacy Fiduciary Commons**.

> [!IMPORTANT]
> **THREAT ENVIRONMENT**: Independent pharmacies and vulnerable patients operate in highly adversarial environments. Pharmacy Benefit Managers (PBMs) and payer networks maintain extensive surveillance and auditing capabilities. The central maxim of this model is: **The system may be secure while participants are unsafe.**

---

## 1. Threat Actors & Motivations

| Adversarial surveillance actor | Motivations | Typical leverage |
| :--- | :--- | :--- |
| Payer / PBM | Prevent pass-through, terminate networks, use audits as sanctions | Claims data, network contracts, audit rights, legal pressure |
| Data broker | Profile diagnoses, extract precarity, correlate identities | Public ledgers, address clustering, pharmacy and location data |

### 1.1 Pharmacy Benefit Managers (PBMs) & Insurance Carriers
* **Motivation**: Protect profit margins, suppress rebate transparency, and deter participation in cooperative commons.
* **Capabilities**: Direct access to dispensing databases (NCPDP registries), network participation agreements (ability to delist pharmacies), and legal departments capable of filing defamation or trade-secret lawsuits.
* **Vector**: Monitoring public blockchain transaction volumes, tracking wallet addresses back to physical pharmacy locations, and matching Merkle claims to private NCPDP records.

### 1.2 Opaque Data Aggregators & Brokers
* **Motivation**: Aggregate, correlate, and monetize patient health and financial precarity profiles.
* **Capabilities**: Large-scale scraping of public ledgers, machine-learning-based address clustering, and correlation of public keys with real-world identities.
* **Vector**: Linking participatory budgeting votes cast by specific credential hashes across rounds to infer diagnostic categories or geographic locations.

---

## 2. Threat Scenarios & Attack Vectors

### 2.1 Public Key Correlation & Network Delisting
* **Attack**: A pharmacy claims its rebate allocation via `claim` on [PBMRebateTreasury.sol](contracts/PBMRebateTreasury.sol). A PBM crawler matches the on-chain transfer amount and timestamp to its internal dispensing records, identifying the pharmacy's public wallet address.
* **Consequence**: The PBM subjects the pharmacy to aggressive post-payment audits, reduces its MAC (Maximum Allowable Cost) rates, or terminates its network agreement, forcing bankruptcy.
* **Mitigation**:
  1. **Immediate**: Strict separation of operational wallets from claim-submission keys.
  2. **Planned roadmap**: Migrate to the ZK-based epoch-scoped nullifiers described in [IDENTITY_NULLIFIER_DESIGN.md](IDENTITY_NULLIFIER_DESIGN.md) to decouple claim eligibility from public key identity.

### 2.2 Patient Dignity & Precarity Profiling
* **Attack**: A patient advocate votes on a local community health project (e.g. co-pay assistance for a stigmatized medication) using `castVote` in [PatientFundParticipatoryBudgeting.sol](contracts/PatientFundParticipatoryBudgeting.sol).
* **Consequence**: The patient's voting history is tied to a stable credential hash across multiple rounds. A corporate payer correlates this hash with a location and medication category, using the proxy data to increase premiums or exclude the patient from coverage.
* **Mitigation**:
  1. **Policy**: Apply the **Patient Dignity Protocol**: no patient-facing interface may capture or publish diagnostic codes, poverty levels, or stigmatized drug categories.
  2. **Technical roadmap**: Implement round-scoped voting nullifiers to support vote privacy across rounds.

### 2.3 Evidence Leakage & PHI Exposure
* **Attack**: To appeal a sanction or flag a dispute, a pharmacy or patient uploads raw dispensing records containing HIPAA-protected Protected Health Information (PHI) to a public IPFS gateway, placing the hash in the `evidenceHash` parameter.
* **Consequence**: Permanent, public exposure of patient names, prescribers, and medical histories on an immutable ledger.
* **Mitigation**:
  1. **Schema guidance**: [EVIDENCE_METADATA.md](EVIDENCE_METADATA.md) requires de-identifying all uploaded preimages (e.g. using `NCPDP_SANS_PHI_EXPORT`).
  2. **Access controls**: Preimages must be encrypted using keys bound to the `availability` policy (e.g. `COUNCIL_CONFIDENTIAL` or `AUDITOR_VISIBLE`).

---

## 3. Participant Safety Tiers

To protect participants at varying levels of risk, the Commons defines three operational tiers. Only the public-address and stable-credential surfaces exist in the current prototype; shielded operation remains proposed roadmap work.

| Tier | Current status | Visibility | Intended For | Protection Level |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1: Shielded** | **Proposed / roadmap only** | Off-chain, zero-knowledge proofs only. | Vulnerable pharmacies in highly consolidated markets; individual patients. | **Maximum**: Claims and votes would be submitted via ZK nullifiers, preventing public key or transaction-volume correlation. Not available in the current contracts. |
| **Tier 2: Pseudonymous** | **Current prototype surface** | Public wallet address, stable credential hash. | Standard independent pharmacies under normal operating conditions. | **Moderate**: Transactions are public, but real-world identity is shielded off-chain by trusted credential issuers. |
| **Tier 3: Public** | **Current prototype surface when intentionally disclosed** | Fully verified public address. | Large cooperatives, cooperative aggregators, and public policy stewards. | **None**: Addresses are explicitly linked to real-world entities to build public fiduciary comparison benchmarks. |

---

## 4. The Patient Dignity Protocol

The Fiduciary Commons commits to a strict rule governing patient interactions:

> **No patient-facing process or dashboard, whether on-chain or off-chain, shall require the disclosure of a patient's diagnosis, poverty level, immigration status, disability, or stigmatized medication need.**

1. **Synthetic Proofs**: Patient eligibility for co-pay assistance should use zero-knowledge assertions of income or coverage without disclosing actual financial records.
2. **Cooperative Proxies**: Patient fund payouts should route through cooperative pharmacy proxies where possible rather than requiring individual patient wallet creation, keeping patient identity off-chain.
