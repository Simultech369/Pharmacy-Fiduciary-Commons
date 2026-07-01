# Draft Constitution v0.1 (Non-Ratified)

**Pharmacy Fiduciary Commons**  
*Status: Draft Proposal. This document has not been participant-ratified and does not possess binding legal or political authority over the commons.*

This draft proposes a potential interpretive framework. Until ratified, it does not override contracts, governance documents, or existing procedures. For the planned path toward formal validation, see [RATIFICATION_PROCEDURE.md](RATIFICATION_PROCEDURE.md).

---

## 1. Standpoint & Purpose

The Pharmacy Fiduciary Commons is a federated fiduciary commons: collectively governed infrastructure that socializes captured pharmaceutical surplus, resists concentrated authority, aspires to permit local autonomy and meaningful exit, and uses permissionless experimentation without allowing wealth, technical expertise, or institutional status to become permanent political power. For a comparison of this model to transparent Web2 enterprise PBM platforms, see [WEB2_TRANSPARENT_PBM_COMPARISON.md](WEB2_TRANSPARENT_PBM_COMPARISON.md).

---

## 2. Constitutional Principles

Each principle is categorized by its enforcement nature: **Protocol-Enforced** (hardcoded in smart contract bytecode), **Procedural** (defined by administrative workflow or docs), or **Aspirational / Interpretive** (unrealized target design or guiding posture).

### 2.1 No Permanent Sovereign
* **Definition**: No single role, council, confirmer, relayer, AI, or developer holds absolute, unappealable authority. All administrative powers must be bounded, separation of duties must be enforced, and roles must be replaceable.
* **Status**: **Partially protocol-enforced; otherwise proposed/procedural**. 
  * The `COUNCIL_ROLE` can propose roots but cannot confirm them.
  * The `ROOT_CONFIRMER_ROLE` must confirm proposals.
  * The `GUARDIAN_ROLE` can pause but cannot unpause or transfer funds.
  * Timelock and role isolation exist, but council elections and removal petitions are only documented, not enforced in contract code.

### 2.2 Subsidiarity
* **Definition**: Decisions belong at the smallest competent level (the pharmacy, the local cooperative federation, the patient community) rather than being centralized at the global contract layer.
* **Status**: **Aspirational**. The current implementation manages most policies at the global contract level, lacking local federation autonomy in code.

### 2.3 Socialized Surplus, Not Socialized Loss
* **Definition**: Captured value (rebates) belongs to the communities and independent pharmacies. Under no circumstances may the risks of novel mechanisms or experimental features be shifted downward to harm patients or pharmacies.
* **Status**: **Partially protocol-enforced; broader risk allocation aspirational**. 
  * Smart contract reserve partitioning is protocol-enforced (escrow, governance, and remediation are separated).
  * The broader promise that experimental losses can never harm participants is not contract-enforced.

### 2.4 Forkability and Portability
* **Definition**: Participants must be able to export their transactional history, Merkle proofs, and claims to form another federation without losing ledger legibility.
* **Status**: **Tool-supported prototype / proposed right**. 
  * Export scripts are off-chain prototype tooling. They do not guarantee credential portability, automatic federation formation, or continued claim recognition on other networks.

### 2.5 Pluralism without Fragmentation
* **Definition**: Local groups may adopt different policies and local contribution rules while sharing common verification and interoperability protocols.
* **Status**: **Procedural / Aspirational**. Requires modular contracts to enforce distinct local rules.

### 2.6 Anti-Plutocracy
* **Definition**: Tokens, deposits, or raw capital must never purchase political authority or skew governance decisions.
* **Status**: **Partially protocol-enforced**.
  * Participatory budgeting uses credential-gated approval voting with squared project-weight matching for registered voters. This is non-token-weighted, but amplifies majorities and is not intrinsically anti-plutocratic.

### 2.7 Contestable Identity
* **Definition**: Credentials establish limited capabilities, not a totalizing institutional identity. Any sanction, revocation, or exclusion must be reason-coded, visible, and appealable.
* **Status**: **Partial protocol support plus unimplemented procedure**.
  * Sanction updates emit reason codes and appeal submissions require a non-zero evidence hash, but credential revocation has no general appeal mechanism, and the 14-day council response window is documented rather than contract-enforced.
  * To protect pharmacy and patient participants from PBM network retaliation and diagnostic profiling, the project defines security through participant safety tiers and the Patient Dignity Protocol, detailed in **[RETALIATION_AND_PRIVACY_THREAT_MODEL.md](RETALIATION_AND_PRIVACY_THREAT_MODEL.md)**.

### 2.8 Legible Power
* **Definition**: Every privileged action must expose who acted, under what authority, and using what evidence.
* **Status**: **Partially protocol-enforced**.
  * Dispute flags, dispute resolutions, and sanction appeals bind non-zero evidence hashes on-chain. Other admin events still show actions more often than full underlying evidence or rationale.

### 2.9 Bounded Experimentation
* **Definition**: Novel financial or coordination mechanisms must begin with strict volume caps, sandboxes, reversibility, and explicit risk-bearing parameters.
* **Status**: **Partially protocol-enforced**.
  * Treasury volume caps exist, but universal sandboxes, reversibility, and explicit risk-bearing rules do not.

### 2.10 The Protocol is Not the Community
* **Definition**: The blockchain provides commitment and evidence. It does not replace or exhaust social knowledge, lived experience, or legitimate political judgment.
* **Status**: **Aspirational / interpretive**.
  * Blockchain commits to allocations but does not govern the human relations surrounding pharmacy operations. The limits of technical value flows vs. actual care continuity, including stockout management and proposed community-jury escalation pathways, are defined in **[CARE_CONTINUITY.md](CARE_CONTINUITY.md)**.

---

## 3. Epistemic Claim-Authority Framework

To prevent the production of "truth" from becoming an opaque administrative monopoly, the commons distinguishes and maps the following forms of knowledge:

1. **observed contract state**: Chain-derived events and current state, interpreted under finality, deployment, and provenance assumptions.
2. **administrative assertion**: Off-chain declarations submitted by managers (e.g., proposed Merkle roots, registry databases).
3. **participant testimony**: Direct reports from actors (e.g., exclusion disputes, sanction appeal statements).
4. **empirical measurement**: Method-bound observations or records from the physical and institutional world, carrying provenance, uncertainty, and collection limitations.
5. **derived calculation**: Math performed on raw data (e.g., cooperative savings spreads, matching ratios).
6. **model inference**: Predictions or recommendations from off-chain agents (e.g., Dizzy's advisory findings).
7. **normative decision**: Political choices made by governance (e.g., project approvals, sanction updates).
8. **contested claim**: Unsettled assertions under dispute (e.g., active exclusion disputes).
9. **unknown or unavailable evidence**: Data that is missing or proprietary (e.g., confidential PBM manufacturer rebate files).

Each claim processed or presented by the commons should carry provenance, confidence metadata where applicable, contestation status, and explicit authority limits. For the schema and rules governing these commitments, see [EVIDENCE_METADATA.md](EVIDENCE_METADATA.md).

---

## 4. Participant Rights

| Right | Description | Status |
| :--- | :--- | :--- |
| **Right to Exit (Portability)** | Export epoch claims, receipts, and proofs. | **Tool-supported prototype** (via offline JSON export scripts). |
| **Right to Voice (Voting)** | Credential-gated approval voting on local patient fund projects. | **Partially protocol-enforced** (for eligible registered voters). |
| **Right to Appeal** | Challenge sanctions, exclusions, or coordinate changes. | **Partially protocol-supported** (submission is contract-supported; response procedure is not enforced). |
| **Right to Audit** | Verify contract state, matching ratios, and omission gaps. | **Tool-supported prototype / inspectable** (via public events and verifier CLI tools). |
| **Cross-Chain Exit Migration** | Automatically move balances and assets to another network. | **Absent**. Requires separate governance, deployment, credential-recognition, and asset-migration mechanisms; portability exports alone cannot move assets. |

---

## 5. Candidate Amendment Models (For Participant Review)

Amendments to this draft constitution or the core governance parameters of the contracts are **proposed candidate workflows** and could undergo community review:

* **High-Friction Timelock**: Any change to roles, caps, or matching bases could be scheduled through the `TimelockController` with a minimum delay, allowing participants time to inspect and coordinate exit.
* **Multi-Role Consent**: A candidate model proposes requiring separate proposals by the `COUNCIL_ROLE` and execution approval by another role (or subsequent community voting weights) for specific governance changes. The root confirmer does not currently approve every timelocked governance change.

---

## 6. Draft Constitutional Alignment Matrix

| Constitutional Clause | Codebase/Spec Element | Status | Gaps / Next Steps |
| :--- | :--- | :--- | :--- |
| **No Permanent Sovereign** | `contracts/OZTimelockControllerImport.sol` | Partial protocol-enforced | Timelock and role isolation alone do not ensure replaceability of all authorities; council elections and removal petitions are unimplemented. |
| **Subsidiarity** | `contracts/PharmacyMutualCredit.sol` | Aspirational | Most decisions are at the global contract level; local federated autonomy is absent in code. Scarce-resource triage remains proposed in [SCARCITY_GOVERNANCE.md](SCARCITY_GOVERNANCE.md). |
| **Socialized Surplus** | `contracts/PBMRebateTreasury.sol` | Partially protocol-enforced | Bucket separation is enforced; broader risk-allocation models remain aspirational. |
| **Stale Recovery Liveness** | `contracts/PBMRebateTreasury.sol#L1104` | Mitigated tested design risk | Stale recovery is gated by `epochStartTimestamp`, so dust deposits no longer extend the 180-day recovery delay; current-root and unexpired pending-root guards remain. |
| **Forkability & Portability** | `scripts/export-portability.js` | Tool-supported prototype | Portability depends on off-chain tools; does not guarantee automatic federation or claim recognition. |
| **Anti-Plutocracy** | `contracts/PatientFundParticipatoryBudgeting.sol` | Partially protocol-enforced | Uses credential-gated approval voting with squared project-weight matching, which amplifies majorities but rejects token weight. |
| **Contestable Identity** | `contracts/PBMRebateTreasury.sol#L1220` | Partial protocol support + unimplemented procedure | Sanction appeals require evidence hashes, but revocation lacks appeal; the 14-day council response window is only documented, not contract-enforced. Privacy-preserving credentials use the [IDENTITY_NULLIFIER_DESIGN.md](IDENTITY_NULLIFIER_DESIGN.md) direction. Retaliation mitigations are detailed in [RETALIATION_AND_PRIVACY_THREAT_MODEL.md](RETALIATION_AND_PRIVACY_THREAT_MODEL.md). |
| **Legible Power** | Event emission logs | Partially protocol-enforced | Dispute and appeal events bind evidence hashes, but many admin events still do not include complete rationale records. |
| **Bounded Experimentation**| `contracts/PBMRebateTreasury.sol#L1141` | Partially protocol-enforced | Treasury caps exist; universal sandboxes, reversibility, and explicit risk-bearing rules do not. |
| **Protocol is Not Community**| `WELLBEING_METRICS.md` | Aspirational / Docs-only | Wellbeing auditing is absent in code (CLI tool not implemented). Care continuity boundaries and proposed escalation frameworks are defined in [CARE_CONTINUITY.md](CARE_CONTINUITY.md). |
