# Phase 5: Context Hygiene and Instruction Pruning Plan

> **Status**: DESIGN SPECIFICATION / PHASE 5 PLAN
> **Domain**: Repository scaffolding, context hygiene, and deterministic enforcement
> **Origin**: Codex and Antigravity synthesis of operator-provided prompt hygiene material and the single-agent control plane pattern
> **Evidence Lineage**: `[dirty working tree]`

---

## 1. Executive Summary and Core Principle

> "The main standing prompt should not hold all knowledge. It should point at it."

To prevent instruction bloat, context degradation, and attention decay, Phase 5 separates always-loaded instructions from searchable project memory and moves enforceable rules into deterministic code gates.

```mermaid
graph TD
    subgraph Standing Brief (Always Loaded Under 200 Lines)
        SB[.agents/AGENTS.md: Live Truth, Autonomy Matrix, Fiduciary Primacy]
    end

    subgraph Knowledge Graph and Searchable Memory (Loaded On Demand)
        KG[review-context/repo_knowledge_graph.json]
        PM[docs/ops/KNOWN_FAILURE_POSTMORTEMS.md]
        DS[docs/design and docs/plans]
    end

    subgraph Deterministic Proof Gates (Run Explicitly or in CI)
        DG1[npx hardhat test: Contract and Server Security]
        DG2[python scripts/index_dossier_tree.py: PageIndex Audit]
        DG3[python scripts/rehearse_proposal.py: Rehearsal Risk Evaluator]
        DG4[python scripts/context_hygiene_audit.py: Context Hygiene Audit]
        DG5[python scripts/eval_dossier_rag.py: Retrieval Eval]
    end

    SB -->|Points to| KG
    KG -->|Traverse Edges| PM & DS
    DG1 & DG2 & DG3 & DG4 & DG5 -->|Upstream Enforcement| SB
```

---

## 2. Context Classification and Architecture Separation

| Layer Category | Target Files and Surfaces | Role and Enforcement Rule |
| :--- | :--- | :--- |
| **`standing_brief`** | [`.agents/AGENTS.md`](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/.agents/AGENTS.md) (under 200 lines) | Live truth rules, Autonomy Matrix (L1/L2/L3), Pre-Tool Brevity, and Fiduciary Primacy. Always loaded; stays under the local line budget. |
| **`memory_reference`** | `.agents/memory/`, `docs/ops/KNOWN_FAILURE_POSTMORTEMS.md`, `review-context/repo_knowledge_graph.json`, `docs/design/`, `docs/plans/` | Detailed postmortems, historical model dissent, concept coverage, and design rationale. Loaded on demand via graph traversal or targeted search. |
| **`workflow_skill`** | `scripts/rehearse_proposal.py`, `scripts/index_dossier_tree.py` | Repeatable procedures for rehearsal risk scoring, PageIndex indexing, and external handoff brief generation. |
| **`deterministic_gate`** | `scripts/context_hygiene_audit.py`, `scripts/eval_dossier_rag.py`, `test/server.test.js`, `test/DisasterRecoveryOutage.test.js`, `test/VoucherSagaQueue.test.js`, `test/rehearse_proposal.test.js`, `test/context_hygiene_audit.test.js`, `test/system_prompt_governance.test.js`, `test/repo_knowledge_graph.test.js`, `test/fde_enterprise_mapping.test.js`, `test/observability_dashboard.test.js`, `test/advanced_rag_mapping.test.js` | Automated tests and schema auditors that enforce rules deterministically via code rather than LLM memory. |
| **`stale_or_duplicate`** | Any standing instruction, handoff, or model plan duplicating a rule already enforced by tests/scripts | Candidate for pruning, relocation, or conversion into a deterministic check. |

---

## 3. Phase 5 Implementation Milestones

1. **Milestone 5.1 - Standing Brief Audit**: Verify [`.agents/AGENTS.md`](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/.agents/AGENTS.md) remains under the local 200-line budget and contains the mandatory Truth and Fiduciary rules.
2. **Milestone 5.2 - Knowledge Graph Indexing**: Ensure `review-context/repo_knowledge_graph.json` maps node relationships to target proof files and contains no dangling edges.
3. **Milestone 5.3 - Deterministic Gate Shift**: Offload rule enforcement from prompt instructions to Python/Node scripts (`rehearse_proposal.py`, `index_dossier_tree.py`, `context_hygiene_audit.py`, `eval_dossier_rag.py`).
4. **Milestone 5.4 - Advisory Receipt Enforcement**: Enforce `dizzy.rehearsal_receipt.v1` schema compliance across review loops (`authority_mode: "automation-recommends-user-approves"`, `execution_claimed: false`).

---

## 4. Local Audit Command

Run the context hygiene gate before promoting new agent scaffolding:

```powershell
python scripts/context_hygiene_audit.py --pretty
```

This command classifies context surfaces into `standing_brief`, `memory_reference`, `workflow_skill`, and `deterministic_gate`, verifies the standing brief line budget, checks knowledge graph edge integrity, and rejects brittle prompt-hygiene overclaims.
