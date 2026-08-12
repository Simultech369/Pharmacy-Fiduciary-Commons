# Scoped Identity and Nullifier Design Note

This document outlines the proposed architecture for privacy-preserving identity management within the **Pharmacy Fiduciary Commons**.

> [!IMPORTANT]
> **DESIGN DIRECTION**: This is a proposed design roadmap. The current testnet deployment uses stable credential hashes for voter registration and Merkle claims. The ZK-proofs and nullifiers described below represent future upgrades to protect claimant privacy from corporate retaliation.

---

## 1. The Risk of Stable Credential Hashes

In the current prototype, credential verification uses stable cryptographic signatures and public wallet addresses. In a production environment, this introduces significant risks:
* **Payer Profiling**: PBMs and large insurance carriers can monitor the public blockchain, link claim volumes to specific pharmacy addresses, and retaliate by terminating their networks or reducing reimbursement rates.
* **Corrupted Anonymity**: If a pharmacy's public key is linked to its real-world identity once, their entire claim history, dispute filings, and voting records become retroactively visible.

To resolve this, the project rejects using a single stable identifier for all purposes. Instead, we advocate a **hybrid scoped-nullifier** approach.

---

## 2. The Core Principle: Separation of Identity Concerns

We do not ask a single identifier to handle uniqueness, accountability, continuity, privacy, revocation, and migration simultaneously. Instead, we decouple these roles:

```
                  ┌───────────────────────┐
                  │ Real-World License    │
                  │ (NCPDP / NPI Registry)│
                  └───────────┬───────────┘
                              │
               [Issuer / Auditor Custody Only]
                              │
            ┌─────────────────┴─────────────────┐
            ▼                                   ▼
 ┌────────────────────┐               ┌────────────────────┐
 │  Voting Nullifier  │               │   Claim Nullifier  │
 │  (Round-Scoped)    │               │   (Epoch-Scoped)   │
 └────────────────────┘               └────────────────────┘
   * Double-voting                      * Blocks double-claiming
     prevention                           without linking wallet
   * Refreshed each                     * Re-randomized each
     budgeting round                      distribution epoch
```

---

## 3. Scoped-Nullifier Architecture

### 1. Voting: Round-Scoped Nullifiers
To participate in participatory budgeting, a voter proves membership in the electorate using a Zero-Knowledge Proof (ZKP) of their credential.
* A **Round-Scoped Nullifier** ($\eta_{round}$) is derived from the credential secret and the specific round ID:
  $$\eta_{round} = \text{Hash}(\text{Credential Secret}, \text{Round ID})$$
* This prevents double-voting within the round but makes it mathematically impossible to link votes cast by the same pharmacy across different rounds.

### 2. Claims/Disputes: Epoch-Scoped Nullifiers
For claiming rebates or flagging disputes:
* An **Epoch-Scoped Nullifier** is generated for the distribution epoch:
  $$\eta_{epoch} = \text{Hash}(\text{Credential Secret}, \text{Epoch ID})$$
* A pharmacy can prove they are eligible for an allocation and submit a dispute without revealing their public wallet address or linking their claim to their voting record.

### 3. Deployment-Scoped Identity
* The mapping of real-world credentials to cryptographic secrets is maintained offline under strict custody of trusted issuers or independent auditors. Public blockchain events contain only the nullifiers and ZK proofs.

---

## 4. Continuity, Revocation, and Migration

* **Migration & Exit**: When migrating to a new deployment or forking the protocol, participants can generate a ZK proof of continuity. This proves they were a valid participant in the old system without disclosing their nullifier history.
* **Revocation**: Instead of publishing a public blacklist of stable identity hashes, credential revocation uses cryptographic accumulators (e.g., Merkle trees or cryptographic accumulators). Voters prove non-membership in the revoked accumulator in zero-knowledge.


---

## 5. Critical Profiling and Correlation Risk Warning

> [!CAUTION]
> **PROFILING VECTOR**: The current prototype’s use of stable on-chain credential hashes constitutes the highest long-term threat to participant safety.

By observing repeated transactions containing the same stable hash across multiple epochs, an adversary (such as a predatory PBM, insurer, or national pharmacy chain) can correlate claims, votes, and disputes. This allows them to build a detailed operational profile of individual independent pharmacies, completely undermining on-chain anonymity and enabling targeted retaliation.

Consequently, **the scoped-nullifier architecture proposed in this document is a mandatory production launch gate, not a post-launch upgrade.** The prototype must never be deployed on public networks with stable identity hashes.

---

## 6. Implemented Design Fixture and Test Gate

A static ZK/nullifier design fixture and test gate has been implemented to make pre-circuit privacy boundaries executable before real proof work begins. These assertions are evaluated in `test/ZKNullifierFixtureGate.test.js` using the fixtures located under `test/fixtures/`.

### Verified Properties
1. **Payload Boundaries**: Any payload declaring the `unlinkable` target must not contain wallet address, stable credential hash, NPI, NCPDP, secrets, witnesses, or co-expose voter identity.
2. **Domain Separation**: Verification that distinct, unique nullifiers are generated for `round_voting`, `epoch_claim`, `dispute`, `portability_export`, `migration`, and `emergency_burn_revocation` to prevent cross-workflow correlation.
3. **Governance States**: Rules enforcing governance metadata (activation windows, quorum thresholds, and upgrade redirection pointers) for active and deprecated verifiers.
4. **Metadata Leakage Budget**: Checking that exact timestamps, gas source wallet addresses, raw RPC credentials, and support ticket identifiers are banned from privacy-claimed payloads.

### Remaining Open Design Decisions
The following areas are intentionally undecided and must be finalized before circuit implementation:
- **Participant Identity Unit**: Selecting the exact entity to bind eligibility to (NPI/NCPDP, wallet, credential, physical location, legal entity, etc.).
- **Secret Custody/Recovery Model**: Selecting safe mechanisms for backup, rotation, recovery, and device loss without introducing backdoors.
- **Verifier/Root Governance**: Specifying multi-signature thresholds, pause governance, and revocation freshness verification.
- **Hosted Provider and Metadata Limits**: Ensuring hosted database logs (Supabase, Firebase, Clerk) and relayer metadata do not compromise the on-chain ZK shield.
