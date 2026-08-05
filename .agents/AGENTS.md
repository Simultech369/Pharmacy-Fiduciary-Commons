# Agent Operating Layer — AGENTS.md

> **Hierarchy Notice**: This document governs AI agent operational behavior, tool usage, and handoff protocols for the `Pharmacy-Fiduciary-Commons` repository. It is explicitly **subordinate** to [COMMONS_CONSTITUTION.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/COMMONS_CONSTITUTION.md) (project domain governance) and [AGENT_REVIEW_ORCHESTRATION.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/AGENT_REVIEW_ORCHESTRATION.md) (multi-agent review protocols).

---

## 1. Core Principles & Operational Mandate

1. **Fiduciary Domain Primacy**: The primary mission of all agents is preserving the integrity of the PBM Rebate Treasury, Solvency Proofs, and Patient Fund protection. Tooling and agent workflows serve the domain, not vice-versa.
2. **Pre-Tool Brevity**: State at most **one sentence** of context before executing tool calls. Gather data first; hypothesize second.
3. **No Meta Summaries**: Do not redundantly restate simple file edits or tool output when the diff or result is self-evident. *Crucial Exception*: This rule does **not** suppress mandatory verification summaries, multi-agent handoff briefs, or final status reports.
4. **Correction-as-Spec**: When an agent receives a corrective instruction or catches a recurring failure, log the candidate rule in [.agents/memory/LEARNINGS_QUEUE.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/.agents/memory/LEARNINGS_QUEUE.md) for human owner review rather than relying on session memory.

---

## 2. Autonomy Matrix (Mapped by Reversibility)

Agent authority is strictly scoped by action reversibility and task authorization:

| Level | Scope | Allowed Actions | Requirement |
| :--- | :--- | :--- | :--- |
| **L1 (Autonomous)** | Read-Only & Inspection | File viewing, ripgrep search, running index/test scripts (`python scripts/index_dossier_tree.py`, `npx hardhat test`). | None. Execute immediately. |
| **L2 (Authorized Proof-Bounded)** | File Modifications | Edits to code, tests, documentation, or ZK circuit files **only when implementation is authorized by user/task intent**. | **Task Authorization + Proof Required**: Edits require explicit task authorization. Post-edit execution of validation script/test is required before declaring task complete. Proof capability alone does not grant edit authority. |
| **L3 (Explicit Permission Gate)** | Irreversible & External | Git commit/push, contract deployment, governance modification ([COMMONS_CONSTITUTION.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/COMMONS_CONSTITUTION.md)), secret handling. | **STOP**: Wait for explicit user/owner confirmation. |

---

## 3. Data Freshness & Lineage Protocol

To eliminate stale or hallucinated status claims across agent handoffs, every status declaration or handoff summary MUST tag its evidence source using one of the following canonical labels:

* `[committed HEAD]` — Claim backed by git HEAD commit state.
* `[dirty working tree]` — Claim backed by current uncommitted local edits.
* `[generated cache]` — Claim derived from `cache/dossier_tree_index.json` or other generated artifacts.
* `[external reviewer claim]` — Claim sourced from an external agent review dossier (e.g., Kimi, Grok, Codex).
* `[live verification just run]` — Claim verified synchronously via command execution during the current session.

---

## 4. Multi-Agent Interoperability

When generating handoffs or reviews for secondary models (Codex, Kimi, Grok, Zero-ZK):
1. **Include Data Freshness Tag**: Always specify lineage label.
2. **Triplicate Handoff Schema**: Pass (1) *Verified Findings*, (2) *Unresolved Risks*, and (3) *Exact Scope of Next Agent's Job*.
3. **Record Dissent**: On high-stakes reviews (Solvency semantics, ZK privacy claims, DB/RLS security), record any dissenting agent findings explicitly instead of forcing artificial consensus.
