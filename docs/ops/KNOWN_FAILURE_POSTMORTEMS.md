# Known Failure Postmortem Library & Rehearsal Memory Base

> **Status**: OPERATIONAL POSTMORTEM LIBRARY
> **Purpose**: Serves as the historical memory base for `scripts/rehearse_proposal.py` and pre-commit rehearsal gates.
> **Evidence Lineage**: `[dirty working tree]`

---

## Postmortem Index

### `MEM-001`: Fake Solvency Telemetry Overclaim
- **Date**: 2026-08-11
- **Subsystem**: `server/createApp.js` (`GET /api/health/observability`)
- **Root Cause**: The proxy initial implementation returned hardcoded fake `"0"` / `"zero_debt"` solvency values, overclaiming live RPC telemetry before on-chain readers were connected.
- **Remediation & Guardrail**: Reconciled to a scoped observability envelope (`live_contract_reads: false`, `debt_queue_status: "not_live_instrumented"`, `null` financial values). Rehearsal Gate flags any proposal attempting to hardcode fake live telemetry.

---

### `MEM-002`: Overclaimed Proof Boundary & ZK Unlinkability
- **Date**: 2026-08-11
- **Subsystem**: ZK Nullifier Verifier Spec & Governance Docs
- **Root Cause**: Documentation phrased draft circuits as providing "production unlinkability" and "guaranteed exactly-once settlement," violating the Weakest Valid Claim Rule.
- **Remediation & Guardrail**: Phrasing calibrated to "target idempotent, exactly-once-style settlement semantics" and `proof_scope: "local_schema_gate"`.

---

### `MEM-003`: Disaster Recovery Test Payload Parameter Mismatch
- **Date**: 2026-08-12
- **Subsystem**: `test/DisasterRecoveryOutage.test.js` & `server/createApp.js`
- **Root Cause**: Initial DR outage test payloads placed relayer signature parameters inside a nested `relayerAuth` object instead of top-level request body fields (`issuerSignature`, `relayerNonce`, `relayerDeadline`), causing pre-db signature validation to fail with `400` instead of reaching the 500 DB outage handler.
- **Remediation & Guardrail**: Helper updated to format exact top-level fields. Test suite asserts both pre-db `401` signature rejection and post-db `500` outage fail-closed behavior.

---

### `MEM-004`: External Provider Guardrail Privacy Block
- **Date**: 2026-08-11
- **Subsystem**: Multi-Agent Review Swarm & OpenRouter Integration
- **Root Cause**: Pre-commit hook attempted to send raw uncommitted git diffs to OpenRouter external API, violating privacy policy.
- **Remediation & Guardrail**: External cloud model reviews restricted to `PUBLIC_COMMITTED` packets or explicitly approved public baselines. For local/dirty diffs, local Ollama models or deterministic schema rules lead.

---

### `MEM-005`: Raw Model Ledger Staging & Residue Leak Risk
- **Date**: 2026-08-11
- **Subsystem**: `reviews/model_attempt_ledger.jsonl`
- **Root Cause**: `git add -A` staged raw model attempt logs containing provider user IDs and raw API error strings.
- **Remediation & Guardrail**: Added `reviews/model_attempt_ledger.jsonl` and `reviews/model_attempts/` to `.gitignore`. Unstaged raw ledger files before commit.

---

### `MEM-006`: Stale Branch Header Mismatch in Dossier Tree
- **Date**: 2026-08-12
- **Subsystem**: `review-context/SINGLE_REPO_STATE_LEDGER.md` & `review-context/AI_SYSTEMS_CONCEPT_COVERAGE.md`
- **Root Cause**: Review context headers claimed branch baseline `feature/db-proxy` after `main` was fast-forwarded.
- **Remediation & Guardrail**: `python scripts/index_dossier_tree.py` continuously audits document status claims against Git HEAD, reporting 0 contradictory claims before promotion.
