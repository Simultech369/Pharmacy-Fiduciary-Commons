# Evidence Metadata Schema

This document defines the schema for committing dispute and audit evidence to the **Pharmacy Fiduciary Commons**.

In the `PBMRebateTreasury` contract, actions such as flagging a claim (`flagClaim`), resolving a dispute (`resolveClaim`), or appealing a sanction (`appealSanction`) require a `bytes32 evidenceHash` parameter. This schema provides the structure for the off-chain preimages corresponding to those on-chain hashes.

> [!IMPORTANT]
> **SCHEMA/POLICY ONLY**: The smart contracts only store the cryptographic hash of the evidence. The metadata and preimage reside off-chain according to the availability rules defined below.

---

## 1. Core Semantics: The Four Pillars of Evidence

To prevent confusion between cryptographic commitments and actual truth, the Commons defines a strict semantic hierarchy:

1. **Evidence Commitment**: The `bytes32 evidenceHash` is recorded on-chain, proving that a specific evidence document existed at a certain timestamp. It does *not* prove that the content is true or currently readable.
2. **Evidence Availability**: The preimage of the hash is made available to authorized parties (defined by the `availability` enum below) so that it can be inspected.
3. **Evidence Interpretation**: An auditor, council member, or participant reviews the decrypted evidence preimage and evaluates its validity.
4. **Governance Decision**: The Council or authorized role takes action based on their interpretation (e.g., executing `resolveClaim` to approve or dismiss).

---

## 2. Metadata Schema Fields

Every evidence package must publish a JSON metadata descriptor matching the fields below before the corresponding hash is committed to the blockchain:

```json
{
  "evidenceHash": "0x...",               // bytes32 SHA-256 / Keccak-256 hash of the evidence preimage
  "evidenceType": "DISPENSING_RECORD",    // Enum value (see below)
  "claimType": "NORMAL_DISPUTE",         // e.g., NORMAL_DISPUTE, EXCLUSION_DISPUTE, SANCTION_APPEAL
  "custodian": "0x...",                  // Wallet address or entity holding the preimage
  "availability": "PARTICIPANT_VISIBLE", // Enum value (see below)
  "privacyClass": "GDPR_COMPLIANT_PHI",   // Classification of contained data (e.g., PHI, PII, Public)
  "createdAt": 1782240000,               // Unix timestamp of metadata generation
  "validFrom": 1782240000,               // Start date of evidence scope
  "validTo": 1782326400,                 // End date of evidence scope
  "redactionPolicy": "NCPDP_DEIDENTIFIED",// Description of data scrubbing/redaction applied
  "challengeWindow": 1209600,            // Seconds during which this evidence can be disputed (e.g., 14 days)
  "sourceMethod": "NCPDP_SANS_PHI_EXPORT",// System/method of origin
  "confidence": "HIGH",                  // Subjective or automated confidence score (LOW, MEDIUM, HIGH)
  "uncertainty": "Contains estimated DIR fee offsets", // Text describing known limitations
  "relatedEpoch": 3,                     // Associated epoch number
  "relatedRound": 0,                     // Associated voting round (if applicable)
  "relatedAction": "CLAIM_FLAG",         // Action triggered on-chain
  "preimageAccessProcedure": "Decryption request routed to council-confirmer KMS" // Steps to request access
}
```

---

## 3. Metadata Enums

### Availability Enum
Determines who has the right/ability to request and decrypt the preimage:
* `PUBLIC`: Fully readable by anyone (e.g., community governance minutes).
* `PARTICIPANT_VISIBLE`: Visible to any registered pharmacy or council member (de-identified data).
* `AUDITOR_VISIBLE`: Accessible only to independent, contractually bound security/financial auditors.
* `COUNCIL_CONFIDENTIAL`: Visible to the 3/5 Council Safe only (sensitive operational details).
* `SEALED_PENDING_APPEAL`: Held by an escrow key, only to be decrypted if a dispute escalates to arbitration.
* `UNAVAILABLE`: Preimage has been deleted due to retention policy or privacy compliance (e.g., GDPR right to be forgotten).

### Evidence Type Enum
Defines the technical format and source of the evidence:
* `DISPENSING_RECORD`: De-identified pharmacy dispensing records matching NCPDP standards.
* `REBATE_FILE`: PBM manufacturer rebate allocation statements.
* `CLAIM_PROOF`: Cryptographic proof proving allocation or eligibility.
* `OMISSION_ASSERTION`: Audited reports alleging a PBM failed to deposit funds.
* `SANCTION_RATIONALE`: Official explanation and documentation for sanctioning an address.
* `APPEAL_STATEMENT`: Written defense and counter-evidence submitted by a sanctioned address.
* `CREDENTIAL_ATTESTATION`: Signed identity or license certification from a trusted issuer.
* `MODEL_OUTPUT`: Algorithmic calculations (e.g., synthetic baseline estimates).
* `GOVERNANCE_MINUTES`: Signed transcripts of council meetings and voter rounds.
