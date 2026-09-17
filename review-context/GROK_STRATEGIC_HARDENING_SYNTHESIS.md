# Grok Strategic Hardening Synthesis & Roadmap Alignment

Generated: 2026-09-17
Target: Codex / Astra Strategic Review
Status: advisory claim packet, not a source-of-truth
Lineage: [external reviewer claim]

---

## 1. Executive Summary

This document synthesizes strategic hardening feedback from Grok regarding the AI engineering, verification, and governance architecture for the `Pharmacy-Fiduciary-Commons` and `CouncilEngine`. It formalizes:
1. **High-ROI Areas to Double Down On** (Evals, local open-weight inference, context engineering, fiduciary vertical focus, hard-tech crypto/Z3 proofs, lightweight cost gates, and cryptographic human authorization).
2. **Peaked / Anti-Pattern Items Explicitly Avoided** (Autonomous agent swarms, MCP bloat, "just add RAG", computer-use agents, un-sandboxed shell loops, and enterprise serving overhead).

---

## 2. Strategic Dispositions: Still-Hyped vs. Peaked Items

### 2.1 Still-Hyped Items (Double-Down Core)

| # | Hyped Item | Disposition & Application to this Project | Repo Implementation Surface |
| :--- | :--- | :--- | :--- |
| 1 | **Local Inference** | [external reviewer claim] **Core Pillar**: Only private, low-concurrency local inference matters (Ollama / llama.cpp). High-throughput serving stacks (vLLM, GPU clusters) are ignored. | `tools/council/model_gateway.py` (`LOCAL_ONLY_VERIFIED`) |
| 2 | **Open-Weight Models** | **Positive**: Prefer local open-weight models (Qwen 2.5 Coder, Mistral, GLM) so sensitive review packets never leave the machine. | `tools/council/qualification_matrix.py` |
| 3 | **Browser Use** | **Avoid**: Headless/computer-use agents expand attack surface and conflict with strict sandboxing and human-gating rules. | Rejected by architectural charter |
| 4 | **Hard-Tech Foundations** | [external reviewer claim] **Core Strength**: Solidity contracts, formal SMT/Z3 math bounds, double-hashed Merkle trees, and cryptographic HMAC human-gating differentiate this project from prompt toys. | `contracts/`, `tools/council/pbm_rebate_formal_invariants.py` |
| 5 | **Context Engineering** | **Active**: Packet sensitivity gating (`PUBLIC_SAFE`, `INTERNAL_NO_TRAIN_OK`), token budgets, and dynamic context assembly. | `scripts/compile_review_packet.py`, `external_a2a_adapter.py` |
| 6 | **Evals & Test Gates** | [external reviewer claim] **Highest ROI**: Golden datasets, trajectory grading, deterministic primary gates (`verify_all.py`), promptfoo-style qualification, and inter-agent injection fuzzing. | `scripts/verify_all.py`, `test/AgentClaimVerifier.test.js` |
| 7 | **Expiring Memory** | **Conceptual Fit**: Lineage ledgers and review-contexts follow clear retention/eviction rules. Full persistent long-term agent memory is avoided. | `review-context/agent_work_lineage_ledger.md` |
| 8 | **Vertical Workflow Focus** | **Foundational**: Independent pharmacy rebate transparency + patient fund participatory budgeting is the primary vertical. Tooling serves the domain. | `COMMONS_CONSTITUTION.md` (Domain Primacy) |
| 9 | **Customer-Shaped Proofs** | **Relevant in Spirit**: Design dashboard proof boundaries and receipts so real community pharmacies and ERISA plan sponsors can verify them. | `dashboard/`, `cache/verification_master_receipt.json` |
| 10 | **Lightweight Cost Routing** | **Narrow Yes**: Simple ordered fallbacks + per-query spend kill-switches ($0.50) + token budgets. Skip multi-tenant cost gateways. | `tools/council/windows_spend_ledger.py` |
| 11 | **Human Gating** | **Non-Negotiable**: Cryptographic sealing of `ApplyAuthorizationReceipt` with SSH/HMAC. Full autonomy is rejected. | `tools/council/human_approval.py` |
| 12 | **Open Evals / Benchmarks** | **Cautious**: Internal golden sets and CI regression are essential. Public leaderboards are premature; the public product is the verifiable ledger. | `cache/lineage_eval_benchmark.jsonl` |

---

### 2.2 Peaked Items (Explicitly Rejected / Avoided)

* **Company Brains / General AI Assistants**: Rejected. We build narrowly scoped, verifiable auditor seats.
* **Autonomous Agent Frameworks (LangChain / CrewAI)**: Rejected. LLM outputs remain strictly advisory; state transitions require deterministic verification and human signatures.
* **Infinite Multi-Agent Crews & MCP-Maxing**: Rejected. Replaced by a minimal 3-family jury (Qwen, GLM, Mistral) and zero-dependency local tools.
* **"Just Add RAG"**: Rejected. Full vector DB / embedding stacks are avoided in favor of deterministic, line-cited lexical retrieval (`dossier_rag_retrieval.py`).
* **Computer-Use Agents**: Rejected due to catastrophic attack surface expansion on production host systems.

---

## 3. Practical Directives for Antigravity & Council Loops

1. [external reviewer claim] **Specs-as-Evals (Pillar 1)**: Acceptance criteria and invariant bounds must precede implementation.
2. **Support-Mined Evals (Pillar 4)**: Every real review failure or model hallucination (e.g., the Codex false positives on `_startRound`) is converted into a regression test case in `system_prompt_governance.test.js` and `LEARNINGS_QUEUE.md`.
3. **Dream-RSI Pattern (Offline Replay)**: Replay candidate prompt adjustments and routing policies against historical review dossiers rather than burning live model API quota.
4. **Vitalik Privacy Orchestrator**: The local model/harness inspects, sanitizes, and strips PHI/PII locally, dispatching only redacted mathematical and architectural proofs to external frontier reviewers.
