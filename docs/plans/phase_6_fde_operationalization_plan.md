# Phase 6 Local Prototype: FDE-Grade Operationalization & Voucher Saga Profiling

> **Status**: LOCAL PROTOTYPE / PROOF-BOUNDED IMPLEMENTATION
> **Target Subsystem**: `server/createApp.js`, `test/Phase6Operationalization.test.js`, and `scripts/context_hygiene_audit.py`
> **Evidence Lineage**: `[dirty working tree]`

---

## 1. Executive Summary & Problem Statement

With Phase 4 (`POST /api/vouchers/reconcile`) live in code (`commit f9aa727`), the Database API Proxy requires enterprise FDE-grade operationalization to trace saga execution lifecycles, monitor DLQ thresholds, publish route-level rate-limit contracts, and surface sanitized RCA diagnostics without leaking raw secrets or patient identities.

Phase 6 implements **Saga Observability Telemetry**, **DLQ Alerting Counters**, and **Sanitized RCA Profiling** inside the `GET /api/health/observability` envelope.

This slice does **not** claim production telemetry, live Supabase metric reads, Prometheus/OpenTelemetry export, or a production RCA platform. The current proof surface is a local/prototype in-memory saga snapshot when the proxy is constructed with a test saga ledger. When no saga snapshot source is present, the endpoint reports `not_live_instrumented` instead of fake zero counts.

---

## 2. Telemetry Architecture & Envelope Expansion

The `GET /api/health/observability` endpoint expands to report local saga telemetry metrics when an in-memory saga snapshot is available:

```json
{
  "status": "healthy",
  "live_contract_reads": false,
  "debt_queue_status": "not_live_instrumented",
  "saga_queue_telemetry": {
    "saga_queue_status": "instrumented_in_memory",
    "metric_source": "prototype_memory_snapshot",
    "pending_count": 0,
    "retrying_count": 0,
    "dead_letter_count": 0,
    "completed_count": 1,
    "active_leases_count": 0,
    "alert_status": "healthy"
  },
  "rate_limit_contracts": {
    "voter_registration_max": 100,
    "relay_intake_max": 100,
    "voucher_reconciliation_max": 50,
    "window_ms": 900000
  },
  "sanitized_rca": {
    "trace_scope": "aggregate_counts_only",
    "raw_trace_logging": false,
    "redacted_fields": ["authorization", "cookie", "signature", "credentialPepper", "pharmacyAddress", "voucherId", "amount"]
  }
}
```

---

## 3. Formal Invariants for Phase 6

| Invariant ID | Name | Constraint & Proof Boundary |
| :--- | :--- | :--- |
| **INV-OP-1** | **Sanitized Saga Metrics** | Saga telemetry reported by `GET /api/health/observability` includes queue depths (`pending`, `retrying`, `dead_letter`, `completed`) without exposing specific voucher IDs, pharmacy addresses, or financial totals. |
| **INV-OP-2** | **Rate Limit Visibility** | Rate limiting contracts and sliding-window configuration parameters are published in the telemetry body and contract headers for client SLA monitoring. |
| **INV-OP-3** | **DLQ Threshold Alerting** | When `dead_letter_count > 0`, the proxy sets `saga_queue_telemetry.alert_status: "DLQ_ATTENTION_REQUIRED"` while retaining generic 500/400 HTTP error responses to clients. |
| **INV-OP-4** | **Zero Identity Redaction** | The prototype RCA envelope advertises aggregate-only diagnostics and redacted fields; no authorization headers, JWT tokens, EIP-191 signatures, voucher IDs, pharmacy addresses, or salted HMAC keys are emitted in the response body. |

---

## 4. Verification & Test Plan

1. **Unit Tests (`test/Phase6Operationalization.test.js`)**:
   - `it("returns saga queue telemetry counters in GET /api/health/observability")`
   - `it("redacts pharmacy identities, voucher IDs, and financial amounts from observability response")`
   - `it("reports not_live_instrumented instead of fake zeros when no saga snapshot source exists")`
2. **Master Suite Verification**:
   - Run `npx hardhat test`
   - Run `python scripts/context_hygiene_audit.py --pretty`
   - Run `python scripts/index_dossier_tree.py`
