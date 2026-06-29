# Comparison: Web2 Transparent PBM SaaS vs. Pharmacy Fiduciary Commons

This document provides a comparative analysis between transparent Web2 pharmacy benefit managers (PBMs)—using **Judi Health** (formerly Capital Rx) as a primary benchmark—and the **Pharmacy Fiduciary Commons**.

---

## 1. Market Validation

The growth and rebranding of Judi Health validates a major market demand: employers, plan sponsors, and independent pharmacies are actively seeking an alternative to the opaque, extractiveness of legacy PBMs. By pegging reimbursement to the National Average Drug Acquisition Cost (NADAC) and charging flat administrative fees, Web2 platforms demonstrate that transparency is a viable commercial model.

However, the Pharmacy Fiduciary Commons is not designed to compete as "another PBM SaaS." Its goals, trust assumptions, and ownership structures differ fundamentally.

---

## 2. Core Architectural Comparison

### Trust Architecture: Vendor Governance vs. Bounded Trust Roots
* **Web2 SaaS (Judi Health)** operates under **vendor governance**. Clients must trust the corporate entity, its proprietary database systems, and its SOC 2 audits. Although contractually transparent, the data is stored in centralized cloud mainframes controlled by the company.
* **Pharmacy Fiduciary Commons** is designed to be **publicly verifiable with bounded trust roots**. It uses multi-signature contracts (`PBMRebateTreasury`) to escrow and distribute funds based on cryptographic Merkle roots. Rather than trusting a single corporate middleman, participants verify allocations off-chain and execute claims directly via the blockchain.

### Rebate Visibility: Contractual Auditing vs. The Ledger of Omissions
* **Web2 SaaS** relies on post-hoc contractual audits to verify that rebates are passed through.
* **Pharmacy Fiduciary Commons** uses the **Ledger of Omissions**. Because the contract records every deposit on-chain, non-participation is immediately legible. While the system cannot *force* PBMs to deposit rebates, their failure to do so is recorded as a permanent, public, and mathematically measurable silence.

### Surplus Economics: Corporate Retained vs. Socialized Commons
* **Web2 SaaS** structures administrative fees to generate corporate profit for investors and venture capital backers.
* **Pharmacy Fiduciary Commons** programs a socialized surplus directly into the claim pipeline. **10% of every gross claim** is automatically routed to a community-governed Patient Fund. Unclaimed epoch funds, sweeps, and dispute liquidations also flow back to this pool to support community health projects.

### Forkability & Portability: Vendor Lock-in vs. Exit Package
* **Web2 SaaS** platforms create high switching costs and vendor lock-in through proprietary APIs and closed data formats.
* **Pharmacy Fiduciary Commons** ensures exit legitimacy. If participants disagree with the Council, they can package their portability export data (generated via `scripts/export-portability.js`), the current open-source code commit, and the credential policy, to launch an independent fork.

---

## 3. Scope and Limitations (Honest Baseline)

To maintain integrity, we distinguish what the Commons currently implements versus what is aspirational:
* **Publicly Verifiable, Not Trustless**: The Commons is not fully "trustless." It relies on bounded trust roots. The Council must propose roots, and a separate Root Confirmer must verify them. If both roles collude, they can submit incorrect roots (mitigated by role separation and dispute windows, but still a trust assumption).
* **Information Asymmetry**: Legibility of PBM omissions relies on pharmacies and auditors having external access to dispensing records. The contract itself does not automatically discover missing deposits without this input.
* **Privacy Tradeoffs**: In its current state, the Commons uses public wallet addresses for claiming and voting. Fully preserving claimant privacy requires migrating to the proposed scoped-nullifier architecture (see `IDENTITY_NULLIFIER_DESIGN.md`) to prevent corporate profiling.

---

## 4. Disruption And Evasion Matrix

The Commons should sharpen the mechanisms that an incumbent can imitate only by giving up discretionary opacity. A normal dashboard can copy transparency language; it is harder to copy participant-controlled evidence, portable exit, and constrained governance.

| Incumbent pattern | Likely evasion path | Commons counter-pressure | Current status |
|-------------------|---------------------|--------------------------|----------------|
| Rebate pass-through is promised by contract language | Reclassify value as admin fees, network terms, formulary services, or post-period adjustments | Require deposit/reconciliation evidence and publish omission entries with neutral provenance | Docs-only plus on-chain deposits |
| Claims and exclusions are resolved inside proprietary workflows | Delay, bundle, or settle disputes without participant-verifiable records | Bind flags, approvals, and resolutions to evidence hashes and public accounting buckets | Partially contract-supported |
| Transparency portals show selected metrics | Make dashboards impressive while leaving raw proofs, root inputs, and omission logic inaccessible | Keep exportable roots, proofs, events, and verification scripts as the source of authority | Script-supported, needs chain reconciliation |
| Member voice is advisory | Route hard decisions through vendor-controlled policy boards | Ratify constituency thresholds, appeals, and fork/exit rights before claiming democratic control | Proposed/docs-only |
| Privacy is handled by vendor confidentiality | Centralize identifiers and create profiling leverage | Move toward scoped nullifiers and reduce stable cross-round credential handles | Proposed/docs-only |

Strategic implication: the strongest wedge is not "cheaper PBM software." It is a verifiable fiduciary pattern where omissions, exceptions, and governance choices become inspectable artifacts. That is the part to sharpen as a weapon.
