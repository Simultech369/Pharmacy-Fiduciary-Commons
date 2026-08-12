# Phase 4 Design Specification: Durable Offline Voucher Settlement Saga Queue

> **Status**: DESIGN DRAFT / PROOF-BOUNDED SPECIFICATION
> **Target Subsystem**: `server/createApp.js` & `contracts/PharmacyMutualCredit.sol`
> **Evidence Lineage**: `[dirty working tree]`

---

## 1. Executive Summary & Problem Statement

When independent community pharmacies issue offline mutual credit vouchers (`PharmacyMutualCredit.sol`), they submit asynchronous reconciliation batches to the Database API Proxy server. Under transient network outages, database write locks, or Supabase connection timeouts, naive HTTP intake endpoints either fail immediately or risk double-settling vouchers upon client retries.

Phase 4 establishes an **in-memory and durable Saga Queue with Dead-Letter Queue (DLQ)** mechanisms to **target idempotent, exactly-once-style settlement semantics**, automatic exponential retries, and clean fail-closed isolation.

---

## 2. Architecture & State Machine

```mermaid
flowchart TD
    A["Voucher Intake Request (POST /api/vouchers/reconcile)"] --> B{"Crypto & Schema Validation"}
    B -- Invalid Signature / Schema --> C["400/401 Reject -> DLQ (Unrecoverable)"]
    B -- Valid --> D{"Derive Saga Key sha256(voucherId + pharmacy + amount + nonce)"}
    D --> E{"Check Nonce Ledger & Saga State"}
    E -- State: completed --> F["200 Cached Result (Replay Invariant)"]
    E -- State: pending / retrying --> G["429 Lease Lock Active"]
    E -- New Entry --> H["Enqueue Saga Task (State: pending)"]
    H --> I{"Attempt On-Chain / Database Commit"}
    I -- Success --> J["State: completed & Return 200"]
    I -- Transient Failure (Lock/Timeout) --> K{"Retry Count < 3?"}
    K -- Yes --> L["Schedule Exponential Backoff Retry (State: retrying)"]
    L --> I
    K -- No (Max Retries Reached) --> M["State: dead_letter & Notify Operator Alert"]
```

---

## 3. Formal Invariants

| Invariant ID | Name | Constraint & Proof Boundary |
| :--- | :--- | :--- |
| **INV-SAGA-1** | **Strict Idempotency** | The saga key `sha256(voucherId + pharmacyAddress + amount + clientNonce)` must be unique. Duplicate submissions return the previous execution result. |
| **INV-SAGA-2** | **Double-Settlement Shield** | Before executing on-chain claim or database insert, the worker MUST assert `voucher_status != 'settled'` and `consumed_nonces` does not contain the saga key. |
| **INV-SAGA-3** | **Bounded Retries** | Transient errors (e.g. 503/504 database connection timeouts) permit at most **3 automatic retries** with exponential backoff (1s, 2s, 4s). |
| **INV-SAGA-4** | **Unrecoverable Dead-Letter Isolation** | Payloads failing cryptographic verification, domain signatures, or exceeding 3 retries transition directly to `dead_letter` state and never regress to `pending`. |
| **INV-SAGA-5** | **Zero Identity Leakage** | All error responses emitted by the saga queue return generic error codes (`500 Database transaction failed` / `400 Invalid signature`) without exposing database hostnames, stack traces, or raw patient credentials. |

---

## 4. Proposed Database / Ledger Schema (Supabase RLS Enforced)

```sql
CREATE TABLE IF NOT EXISTS voucher_settlement_saga (
  saga_key TEXT PRIMARY KEY,
  voucher_id TEXT NOT NULL,
  pharmacy_address TEXT NOT NULL,
  amount_cents BIGINT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'retrying', 'completed', 'dead_letter')),
  retry_count INT NOT NULL DEFAULT 0,
  last_error TEXT,
  payload_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Row-Level Security (RLS) Policy
ALTER TABLE voucher_settlement_saga ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Pharmacies can read own saga entries"
  ON voucher_settlement_saga FOR SELECT
  USING (auth.jwt() ->> 'wallet_address' = pharmacy_address OR auth.role() = 'service_role');
```

---

## 5. Verification & Test Plan

1. **Unit Tests (`test/VoucherSagaQueue.test.js`)**:
   - `it("settles valid voucher batch idempotently on first attempt")`
   - `it("prevents double-settlement on duplicate voucher submission")`
   - `it("retries transient DB write lock failures up to 3 times before DLQ transition")`
   - `it("routes unrecoverable signature failures directly to dead_letter state")`
2. **Hardhat & Dossier Verification**:
   - Run `npx hardhat test test/VoucherSagaQueue.test.js`
   - Run `python scripts/index_dossier_tree.py`
