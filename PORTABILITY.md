# PORTABILITY.md
Data portability specifications and export schemas for the Pharmacy Fiduciary Commons.

---

## 1. Overview
To prevent lock-in and ensure participant exit rights as defined in [CONSTITUTION.md](file:///C:/Users/Josh/.gemini/antigravity/scratch/Dizzy-the-Polymath/CONSTITUTION.md), any pharmacy, patient, or advocate participating in the commons must be able to export their full ledger records in a structured, machine-readable format.

The primary export format is JSON. Every export must carry cryptographic proof of provenance, linking it back to the on-chain smart contract state.

---

## 2. Machine-Readable Export Schema (JSON)

An export payload contains four top-level arrays: `claims`, `merkle_proofs`, `votes`, and `receipts`.

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "PharmacyCommonsExportPayload",
  "type": "object",
  "properties": {
    "exporter": {
      "type": "string",
      "description": "Ethereum address of the participant requesting the export"
    },
    "exported_at": {
      "type": "string",
      "format": "date-time"
    },
    "claims": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "claimId": { "type": "string" },
          "patientId": { "type": "string" },
          "pharmacyAddress": { "type": "string" },
          "ndc": { "type": "string" },
          "quantity": { "type": "integer" },
          "claimedAt": { "type": "string", "format": "date-time" },
          "status": { "type": "string", "enum": ["submitted", "flagged", "resolved"] },
          "transactionHash": { "type": "string" }
        },
        "required": ["claimId", "patientId", "pharmacyAddress", "ndc", "quantity", "claimedAt", "status"]
      }
    },
    "merkle_proofs": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "claimRoot": { "type": "string" },
          "proof": {
            "type": "array",
            "items": { "type": "string" }
          },
          "leafIndex": { "type": "integer" },
          "blockNumber": { "type": "integer" }
        },
        "required": ["claimRoot", "proof", "leafIndex", "blockNumber"]
      }
    },
    "votes": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "voter": { "type": "string" },
          "project": { "type": "string" },
          "weight": { "type": "string" },
          "signature": { "type": "string" },
          "epoch": { "type": "integer" }
        },
        "required": ["voter", "project", "weight", "signature", "epoch"]
      }
    },
    "receipts": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "receiptId": { "type": "string" },
          "hash": { "type": "string" },
          "signature": { "type": "string" },
          "details": { "type": "object" }
        },
        "required": ["receiptId", "hash", "signature"]
      }
    }
  },
  "required": ["exporter", "exported_at", "claims", "merkle_proofs", "votes", "receipts"]
}
```
