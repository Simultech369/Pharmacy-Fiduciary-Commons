# Wellbeing Dashboard & Transparency Interface

This document specifies the required views, data queries, and reporting elements for the Fiduciary Rebate Commons public dashboard. Transparency is the core product — this interface makes omissions, flows, and ecological outcomes instantly visible to the community.

---

## 1. Interface Views & Architecture

The front-end client queries the smart contract events, the Omission Ledger, and the Patient Fund participatory system to present four core views.

### 1.1 The Ledger of Omissions View
- **Purpose**: Expose PBM non-participation and missing deposits.
- **Key Elements**:
  - **PBM Dropdown**: Select the target PBM or insurer.
  - **Quarterly Status Grid**: A visual grid (updated each epoch) showing columns for quarters (e.g. Q1 2026, Q2 2026) and rows for expected vs. recorded deposit receipts.
  - **"Not Recorded" Indicators**: Quarters with zero logged deposits are highlighted in red and explicitly labeled as: `[Not recorded in this treasury]`.
  - **Estimated Gaps Calculator**: Evaluates average historical volume against actual deposits to calculate the estimated dollar gap in passed-through rebates.

### 1.2 Claims & Disbursements View
- **Purpose**: Document successful rebate routing to local pharmacies.
- **Key Elements**:
  - **Epoch Summary**: Displays total volume, active pharmacy count, and current `epochEscrow` balance for the active epoch.
  - **Pharmacy Claim Log**: Table of claim events showing timestamp, pharmacy address, gross amount, and status (Claimed, Flagged, Disputed).
  - **Dispute Flag Indicators**: Highlighted entries for active `flagExclusion` disputes, showing dispute status and Council review timer countdown (14-day limit).

### 1.3 Patient Fund matching & Flow View
- **Purpose**: Monitor the accumulation and participatory allocation of the Patient Fund.
- **Key Elements**:
  - **Inflow Rate Tracker**: Live calculation of 10% gross claim pass-throughs routed directly to the `patientFund`.
  - **PB/QF Projects Board**: List of submitted community health projects, current small-dollar votes, and quadratic matching allocations.
  - **Idle Surplus Alert**: Countdown timer for unallocated funds approaching the 90-day anti-hoarding limit, displaying when they will automatically roll over to the next PB/QF round.

### 1.4 Ecological Impact Receipts
- **Purpose**: Audit the verifiable material waste and logistics efficiency of projects.
- **Key Elements**:
  - **Waste Diversion Log**: Total weight of unused medications safely recycled or disposed of, backed by certified disposal manifests.
  - **Logistics Carbon Counter**: Calculated carbon offset from pharmacy energy microgrids and route-optimization deliveries.
  - **Project Receipts**: Clickable files detailing energy audits and equipment specifications for funded projects.

---

## 2. Technical Implementation Specifications

- **Hosting**: Distributed via IPFS / decentralized storage to prevent domain censorship.
- **Data Source**: Custom Subgraph indexing `PBMRebateTreasury` events:
  - `RebateDeposited`
  - `RootConfirmed`
  - `Claimed`
  - `ClaimFlagged`
  - `SanctionUpdated`
  - `SanctionAppealed`
- **Zero-Knowledge Proofs**: Future support for zk-proof claims history to protect patient privacy while proving cumulative assistance volume.
