# Candidate Agent Spec Rules — LEARNINGS_QUEUE.md

> **Purpose**: When an agent receives a correction or identifies a recurring pitfall, it adds a candidate rule here. Rules remain in candidate status until promoted to [.agents/AGENTS.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/.agents/AGENTS.md) by the human owner.

---

## Candidate Rules Pending Promotion

| Candidate ID | Date Logged | Origin / Context | Proposed Rule | Target Spec | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `LRN-001` | 2026-07-27 | Agent Operating Layer Setup | Always attach data freshness lineage tags (`[committed HEAD]`, `[generated cache]`, etc.) to status claims. | [.agents/AGENTS.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/.agents/AGENTS.md) | `ADOPTED_V0_1` |
| `LRN-002` | 2026-07-27 | Review Orchestration | Record dissenting agent opinions in multi-agent review dossiers instead of forcing artificial consensus. | [.agents/AGENTS.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/.agents/AGENTS.md) | `ADOPTED_V0_1` |

---

## Promotion Workflow

1. Agent logs observation in `LEARNINGS_QUEUE.md` under `PENDING_REVIEW`.
2. Human owner reviews candidate rule during routine session sync.
3. Upon approval, rule is promoted to `.agents/AGENTS.md` and status updated to `PROMOTED`.
