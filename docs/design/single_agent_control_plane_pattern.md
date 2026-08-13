# Single-Agent Control Plane Pattern & Elimination of Context-Handoff Decay

> **Status**: ARCHITECTURAL PATTERN SPECIFICATION
> **Domain Alignment**: `Pharmacy-Fiduciary-Commons` Governance, Proxy, and Solvency Observability
> **Evidence Lineage**: `[dirty working tree]`

---

## 1. Executive Summary & Core Mandate

To eliminate context-handoff decay, token blowout, and disconnected action synthesis in complex analytical and governance systems, this repository adopts the **Single-Agent Control Plane Pattern** as a review-loop and automation design rule. It is enforced only where backed by local tests, scripts, and explicit operator approval gates.

```mermaid
graph TD
    subgraph Upstream Deterministic Layer
        A[Statistical / Hardhat Signal Engine] -->|Deterministic Signals| B[Structured Signal Queue]
    end

    subgraph Centralized Control Plane
        B -->|Verified Signal Breach| C[Centralized Reasoning Engine]
        D[Fiduciary Knowledge Graph Control Plane] <-->|Bounded Edge Traversal| C
        C <-->|Fact Retrieval Only| E[Dynamic Sub-Agents / Tools]
    end

    subgraph Output & Execution Boundary
        C -->|Advisory Recommendation| F[Human Owner Approval Gate]
        F -->|Authorized Execution| G[Settlement / Git Commit / Smart Contract]
```

---

## 2. The Three Architectural Pillars

### Pillar 1: The Deterministic Signal Queue (Decouple Statistical Signals)
- **Rule**: Language models are **never** invoked to scan raw data tables or perform initial statistical signal detection.
- **Implementation**: Pure code pipelines (`scripts/index_dossier_tree.py`, Hardhat test runners, and future Python/SQL statistical jobs) calculate test failures, PageIndex claim contradictions, or other deterministic signal breaches.
- **Queue Event**: verified breaches are formatted as structured JSON signals placed on the execution queue before the reasoning engine is awakened.

### Pillar 2: Centralized Reasoning Ownership with Read-Only Sub-Agents
- **Rule**: Distributed judgment across sequentially chained LLMs is strictly forbidden. A single main agent maintains end-to-end diagnostic context.
- **Sub-Agent Authority Boundary**: Sub-agents (e.g., `research`, `self`) are strictly restricted to isolated data fetching and fact extraction. Sub-agents **never** exercise diagnostic judgment or generate independent action plans.
- **Context Density**: All hypothesis formulation, evidence weighting, and synthesis remain inside a single unified context window to prevent downstream disconnects.

### Pillar 3: Knowledge Graph Control Plane (Bounded Traversal)
- **Rule**: Agents navigate domain hypotheses through an explicit Knowledge Graph (`review-context/repo_knowledge_graph.json`, `cache/dossier_tree_index.json`, `review-context/SINGLE_REPO_STATE_LEDGER.md`, `review-context/AI_SYSTEMS_CONCEPT_COVERAGE.md`), not unconstrained raw database queries.
- **Graph Structure**:
  $$\text{Domain Entities (Payer, Treasury, Solvency Proof, Nullifier, Patient Fund)} \xrightarrow{\text{Validated Edges}} \text{Proof Invariants (INV-SAGA-1..7, Zero-Toll Retraction)}$$
- **Bounded Traversal**: Review-loop queries should be proposed along active edges connecting to the target signal node. Current enforcement is proof-bounded to local docs and tests; production query enforcement remains future work.

---

## 3. Failure Mode Anti-Patterns & Direct Remediation

| Legacy Multi-Agent Anti-Pattern | Root Failure Cause | Single-Agent Control Plane Fix |
| :--- | :--- | :--- |
| **Context Handoff Decay** | Passing summaries between chained LLMs strips critical statistical weights and domain context. | Collapse distributed reasoning into a single main agent session holding end-to-end context. |
| **Disconnected Synthesis Actions** | Downstream action nodes lose upstream root cause nuance (e.g. confusing payer tier demotion with sales rep coverage). | Centralized agent retains the complete causal chain from signal detection down to action proposal. |
| **LLM Statistical Hallucination** | Asking LLMs to scan raw datasets for outliers leads to false positives and massive token burn. | Decouple signal detection into upstream deterministic scripts (Python/SQL window functions). |
| **Unbounded Query Exploration** | Agent writes arbitrary SQL/RPC queries, blowing past 50+ turns without arriving at root cause. | Constrain search paths strictly to Knowledge Graph edges with maximum depth and significance thresholds. |
| **Autopilot Overreach** | Autonomous agent directly mutates production state or pushes unreviewed code. | Receipts explicitly enforce `authority_mode: "automation-recommends-user-approves"` and `execution_claimed: false`. |

---

## 4. Implementation Roadmap for PBM Rebate Treasury

1. **Decouple Signal Layer**: Maintain deterministic test runners (`npx hardhat test`), indexers (`python scripts/index_dossier_tree.py`), and rehearsal risk evaluators (`python scripts/rehearse_proposal.py`) as upstream signal generators.
2. **Knowledge Graph Traversal**: Map all voucher saga states (`INV-SAGA-1` to `7`), solvency queues, and RLS tenancy rules into the PageIndex graph control plane.
3. **Receipt Authority Enforcement**: Assert `dizzy.rehearsal_receipt.v1` schema compliance across all automated review loops.
