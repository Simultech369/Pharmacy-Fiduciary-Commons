# Candidate Agent Spec Rules — LEARNINGS_QUEUE.md

> **Purpose**: When an agent receives a correction or identifies a recurring pitfall, it adds a candidate rule here. Rules remain in candidate status until promoted to [.agents/AGENTS.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/.agents/AGENTS.md) by the human owner.

---

## Candidate Rules Pending Promotion

| Candidate ID | Date Logged | Origin / Context | Proposed Rule | Target Spec | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `LRN-001` | 2026-07-27 | Agent Operating Layer Setup | Always attach data freshness lineage tags (`[committed HEAD]`, `[generated cache]`, etc.) to status claims. | [.agents/AGENTS.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/.agents/AGENTS.md) | `ADOPTED_V0_1` |
| `LRN-002` | 2026-07-27 | Review Orchestration | Record dissenting agent opinions in multi-agent review dossiers instead of forcing artificial consensus. | [.agents/AGENTS.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/.agents/AGENTS.md) | `ADOPTED_V0_1` |
| `LRN-003` | 2026-08-14 | Codex Review Correction | Do not attribute legacy test counts to master verification steps when not stored in receipt JSON. Report receipt pass status and tag Phase 6 test count (323/323) explicitly. | [.agents/AGENTS.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/.agents/AGENTS.md) | `PENDING_REVIEW` |
| `LRN-004` | 2026-08-14 | Codex Review Correction | Label callable endpoints as transport_usable_pending_json_quality when json_valid or quality_valid are false to prevent overclaiming model review usability. | [.agents/AGENTS.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/.agents/AGENTS.md) | `PENDING_REVIEW` |
| `LRN-005` | 2026-08-15 | Codex Review Correction | Explicitly distinguish between test generation commit (0c686be) and receipt-recording commit (517b94d) when stating verification lineage. | [.agents/AGENTS.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/.agents/AGENTS.md) | `PENDING_REVIEW` |
| `LRN-006` | 2026-08-15 | Codex Review Correction | Reference unintegrated draft contracts directly at contracts/*.sol; avoid phantom directory references (e.g. contracts/drafts/). | [.agents/AGENTS.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/.agents/AGENTS.md) | `PENDING_REVIEW` |
| `LRN-007` | 2026-08-21 | Codex Review Correction | Assert underlying boolean qualification gates (`gate1`, `gate2`, `gate3`) in verifier checks rather than relying solely on high-level status string (`REVIEW_USABLE_FRESH`). | [.agents/AGENTS.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/.agents/AGENTS.md) | `PENDING_REVIEW` |
| `LRN-008` | 2026-08-22 | Zero-Database Hardening | Ensure offline continuity models enforce sequential nonces, HMAC signatures, and double-hashed Merkle proof validation with fail-closed outage simulators. | [.agents/AGENTS.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/.agents/AGENTS.md) | `PENDING_REVIEW` |
| `LRN-009` | 2026-08-22 | Agent Claim Cross-Audit | Cross-check markdown review citations against real file line counts and commit histories to prevent ungrounded or hallucinated line numbers in model dossiers. | [.agents/AGENTS.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/.agents/AGENTS.md) | `PENDING_REVIEW` |
| `LRN-010` | 2026-08-26 | Equilibrium & Fast Repair | Resolve micro-defects iteratively before cognitive or architectural overwhelm builds up; fail closed and quarantine poison payloads early (DLQ) when remediation is unreachable. | [.agents/AGENTS.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/.agents/AGENTS.md) | `PENDING_REVIEW` |
| `LRN-011` | 2026-08-26 | Heterogeneous Synergy | Bridge diverse model families and peer CLI runtimes (Codex, OpenClaude, Free-Code, Local OSS) via cryptographic A2A envelopes to prevent single-family echo chambers. | [.agents/AGENTS.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/.agents/AGENTS.md) | `PENDING_REVIEW` |
| `LRN-012` | 2026-09-05 | Codex Review Correction | Scope verifyReceipt claims to canonical payload SHA-256 digest equality; do not claim signature authenticity, issuer trust, or full envelope provenance. | [.agents/AGENTS.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/.agents/AGENTS.md) | `PENDING_REVIEW` |
| `LRN-013` | 2026-09-05 | Codex Review Correction | Label Council Subcommittee Rotation explicitly as deterministic local/simulated receipt verification with model-seat labels; do not claim live independent OSS model evaluation without live inference telemetry. | [.agents/AGENTS.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/.agents/AGENTS.md) | `PENDING_REVIEW` |


---

## Promotion Workflow

1. Agent logs observation in `LEARNINGS_QUEUE.md` under `PENDING_REVIEW`.
2. Human owner reviews candidate rule during routine session sync.
3. Upon approval, rule is promoted to `.agents/AGENTS.md` and status updated to `PROMOTED`.
