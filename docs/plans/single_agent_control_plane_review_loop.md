# Single-Agent Control Plane & Multi-Agent Sensor Loop Specification

> **Status**: DESIGN SPECIFICATION / REHEARSAL CONTROL-PLANE MAP
> **Domain**: `Pharmacy-Fiduciary-Commons` Multi-Model Review Loop & Governance
> **Evidence Lineage**: `[dirty working tree]`

---

## 1. Core Paradigm: Swarm as Sensors, Agent as Control Plane

To prevent context degradation, token blowout, and hallucinated action plans across model boundaries, this repository adopts Codex's refined control-plane architecture:

$$\text{Upstream Deterministic Signals} \longrightarrow \text{Parallel OSS Model Sensors} \longrightarrow \text{Single Reasoning Control Plane} \longrightarrow \text{Human Approval Gate}$$

```mermaid
graph TD
    subgraph Deterministic Upstream Signal Queue
        S1[Hardhat Test Suite]
        S2[PageIndex Dossier Auditor]
        S3[Rehearsal Risk Evaluator]
    end

    subgraph Parallel OSS Model Sensors (Evidence Only)
        M1[Gemma / DeepSeek-R1: Race Sensor]
        M2[Qwen-Coder / Kimi: Contradiction Sensor]
        M3[Nemotron / Grok: Spec Boundary Sensor]
    end

    subgraph Single Coherent Control Plane
        KG[review-context/repo_knowledge_graph.json]
        CE[Consolidated Reasoning Control Plane]
        KG <-->|Bounded Traversal| CE
    end

    S1 & S2 & S3 -->|Breach Signal| CE
    CE -->|Narrow Prompt: Find Contradictions| M1 & M2 & M3
    M1 & M2 & M3 -->|Raw Evidence Packets Only| CE
    CE -->|Advisory Recommendation + Receipt| AG[Human Operator Approval Gate]
    AG -->|Authorized Action| EX[Git Commit / Proxy Write / Contract Execution]
```

---

## 2. Reframed Role Matrix

| Component | Architecture Role | Authority & Boundary |
| :--- | :--- | :--- |
| **Deterministic Engine** (`npx hardhat test`, `index_dossier_tree.py`, `rehearse_proposal.py`) | **Upstream Deterministic Authority** | Computes signal breaches, mathematical invariants, schema rules, and PageIndex contradictions before model invocation. |
| **OSS Model Swarm** (Gemma, Qwen, DeepSeek-R1, Kimi, Nemotron) | **Parallel Disagreement & Evidence Sensors** | Bound to narrow tasks ("Find contradictions in this doc", "List 2 plausible races in this diff"). **Never** decides implementation. |
| **Centralized Reasoning Engine** (Codex / Antigravity / Operator Session) | **Single Coherent Control Plane** | Holds unified context, traverses repo Knowledge Graph edges, weights evidence, and synthesizes action recommendations. |
| **Human Operator** | **Level 3 Approval Gate** | Reviews advisory receipts (`dizzy.rehearsal_receipt.v1`) and authorizes irreversible actions (commit, push, deployment). |

---

## 3. The 7-Step Bounded Investigation Loop

1. **Signal Intake**: Upstream deterministic tools detect a breach (e.g. test failure, PageIndex contradiction, or Rehearsal memory risk).
2. **Neighborhood Discovery**: The main agent queries `review-context/repo_knowledge_graph.json` to extract connected domain nodes and proof invariants.
3. **Candidate Hypothesis Generation**: Edges connected to the signal node form the explicit set of testable candidate hypotheses.
4. **Deterministic Verification**: Code, test, or schema checks run to confirm or reject hypotheses.
5. **Parallel Model Disagreement Pass**: OSS model sensors perform narrow, evidence-cited passes to detect hidden edge cases or spec contradictions.
6. **Unified Synthesis & Receipt Generation**: Main agent evaluates model findings against graph edges and generates a `dizzy.rehearsal_receipt.v1` advisory receipt (`execution_claimed: false`).
7. **Human Approval & Execution Gate**: Human operator inspects the receipt and authorizes execution.
