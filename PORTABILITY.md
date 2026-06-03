# Exit and Data Portability Standards

Following the core Wellbeing Commons principles, the Pharmacy Fiduciary Commons guarantees that every participant can exit the system and export their full history. To prevent lock-in or platform dependency, all protocol data is portable, structured, and legally open.

---

## 1. Exportable Datasets

Participants (pharmacies, patients, and advocates) can trigger exports of their data directly from the public dashboard or via direct contract queries.

### 1.1 For Independent Pharmacies
- **Claims History**: Complete log of all submitted claims across epochs, exported in open formats (CSV/JSON), including:
  - Epoch number
  - Gross rebate amount claimed
  - 10% Patient Fund contribution amount
  - On-chain transaction hashes
- **Verifiable Merkle Proofs**: The exact Merkle proofs, leaf hashes, and tree parameters used to validate claims. This allows pharmacies to prove their historical dispensing volumes and allocations to third-party auditors independently.
- **Dispute and Flag Records**: Detailed logs of any flagged exclusion disputes, appeal submissions, and Council justification resolutions.

### 1.2 For Patient Fund Participants
- **Matching Contributions Log**: Portable records of all small-dollar votes cast, proposal support histories, and verified patient attestations.
- **Hardship Grant Receipts**: Anonymized but cryptographically verifiable receipts of copay assistance, emergency fills, or logistics support received.
- **Governance History**: Voting and proposal records submitted during the participatory budgeting rounds.

### 1.3 For Auditors and Public Registries
- **Ledger of Omissions Dumps**: Complete dataset of recorded vs. unrecorded PBM deposits across all quarters, formatted for integration into legal or research databases.
- **Treasury Ledger**: Raw, transaction-level history of all treasury deposits, fee splits, and recall operations.

---

## 2. Technical Formats & Interoperability

- **Open Formats**: All exports use standard `.csv`, `.json`, or `.xml` schemas. No proprietary software or platform account is required to read or parse the data.
- **Cryptographic Signatures**: Exports include the corresponding on-chain signatures from the Council and claimant addresses to prove data authenticity outside of this platform's interface.
- **Zero Lock-In**: Participant credentials are built on open verifiable credential standards (e.g. W3C VC / DID), allowing pharmacists to transfer their verified identities and reputation records to other cooperatives, purchasing networks, or audit systems.
