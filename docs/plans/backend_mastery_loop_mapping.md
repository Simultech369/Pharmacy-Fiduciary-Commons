# Backend Mastery Loop Mapping

> **Status**: PLANNING MAP / PROOF-BOUNDED ROADMAP
> **Source**: Operator-provided six-stage backend mastery reference images.
> **Evidence Lineage**: `[dirty working tree]`

This map translates the six-stage backend learning framework into the Pharmacy Fiduciary Commons repository without importing generic scale theater. Each stage is treated as a concrete trust surface: what the repo already proves, what is only specified, and what should be built next.

---

## 1. Stage Mapping

| Stage | Framework Focus | PBM Repo Translation | Current Evidence | Remaining Gap |
| :--- | :--- | :--- | :--- | :--- |
| **Stage 1: Foundations** | HTTP request lifecycle, clients/servers, DNS/TCP/TLS, verbs/status codes, REST, data formats | Database proxy request lifecycle, CORS/rate limits, JSON validation, EIP-191/EIP-712 request authorization | `server/createApp.js`, `test/server.test.js`, `docs/design/database_proxy_request_lifecycle.md` | Deployment-level DNS/TLS path is documented conceptually, not live-hosted or monitored. |
| **Stage 2: Data Layer** | Relational schema, SQL, normalization, indexes, transactions, ORM/raw SQL tradeoffs | Supabase/Postgres ledger design, RLS tenant boundaries, idempotency lease RPCs, saga queue SQL plan | `test/server.test.js`, `docs/plans/durable_voucher_saga_queue_plan.md` | Real migrations, indexes, transaction isolation tests, and production query plans remain future work. |
| **Stage 3: Core Skills** | Authentication, authorization, validation, error handling, layered middleware, background jobs, caching, realtime | Domain-separated signatures, actor authorization matrix, sanitized fail-closed responses, bounded payload handling | `test/server.test.js`, `test/DisasterRecoveryOutage.test.js`, `docs/design/database_proxy_request_lifecycle.md` | Background job queue and realtime notification surfaces are not implemented yet. |
| **Stage 4: Scale & Reliability** | Stateless scaling, load balancing, database scaling, message brokers, rate limiting, observability, resilience patterns | Scoped observability envelope, request throttling, outage tests, event-driven voucher saga design | `GET /api/health/observability`, `test/DisasterRecoveryOutage.test.js`, `docs/plans/durable_voucher_saga_queue_plan.md` | Prometheus/OpenTelemetry export, multi-instance lock tests, and real broker-backed queues remain open. |
| **Stage 5: Distributed-Systems Mindset** | CAP tradeoffs, sagas, concurrency/locking, backend security, profiling, multi-tenancy | Solvency invariants, zero-toll dispute retraction, multi-instance saga lock design, RLS isolation rules, scanner triage | `contracts/PBMRebateTreasury.sol`, `test/PBMRebateTreasury.dispute-timeout.test.js`, `docs/ops/SCANNER_TRIAGE.md` | Phase 4 must prove the saga concurrency shield in executable tests before claiming runtime protection. |
| **Stage 6: Ship, Design & Learn** | CI/CD, system design walkthroughs, postmortems, rollback, incident learning | Master verification receipts, rehearsal gate, known failure memory, release checklist, incident runbooks | `scripts/verify_all.py`, `scripts/rehearse_proposal.py`, `docs/ops/KNOWN_FAILURE_POSTMORTEMS.md`, `docs/ops/OPERATIONAL_RUNBOOK.md` | Rehearsal receipts must remain advisory only; CI enforcement and release automation require explicit operator gates. |

---

## 2. Working Plan Alignment

The framework now maps to the repo in this execution order:

1. **Keep Stage 6 honest first**: harden rehearsal receipts so automation recommends and the operator approves.
2. **Build Stage 2 + Stage 5 together**: implement the durable voucher saga queue with transaction, idempotency, RLS, and concurrency tests.
3. **Expand Stage 4 after proofs exist**: add metrics export, queue depth, DLQ counts, retry counts, and multi-instance lease observability.
4. **Backfill Stage 1 deployment proof later**: document real DNS/TLS/API gateway behavior only when a live deployment path exists.

---

## 3. Proof Boundary Rules

- Do not claim production reliability from local Hardhat or mocked Supabase tests.
- Do not claim live solvency metrics until contract readers are wired and tested.
- Do not claim exactly-once settlement; use "idempotent target" or "exactly-once-style semantics" until the full saga path is implemented and stress-tested.
- Do not treat model review output as authority. Model/harness reviews provide candidate disagreement and evidence prompts; deterministic tests and operator approval control execution.

---

## 4. Next Useful Test Slices

| Priority | Slice | Why It Matters |
| :--- | :--- | :--- |
| **P1** | Rehearsal receipt unit tests | Locks the authority boundary before any autonomous-looking loop gets more capable. |
| **P2** | Voucher saga duplicate submission test | Proves retries and repeated client submissions cannot double-settle the same voucher key. |
| **P3** | Multi-instance lease contention test | Targets the highest-value unproven distributed-systems race. |
| **P4** | RLS tenant isolation test for saga rows | Ensures pharmacy-level data boundaries survive queue implementation. |
| **P5** | Observability queue metrics test | Makes reliability visible without inventing fake live financial readings. |
