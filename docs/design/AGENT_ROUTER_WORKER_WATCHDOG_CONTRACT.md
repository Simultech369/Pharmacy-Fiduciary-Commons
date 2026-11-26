# Agent Control Plane Boundary: Router vs. Worker vs. Watchdog

**Status:** Cross-Repository Operating Rule (Prototype / Offline-Rehearsal Posture)  
**Applies To:** `Dizzy-the-Polymath` (Router), `CouncilEngine` / `tools/council` (Verifier Workers), `PBMRebateTreasuryBackend` (API/Saga Worker), and `Pharmacy-Fiduciary-Commons` (Contracts & Verifier Scripts)

> [!IMPORTANT]
> **No Live Execution Authority**: None of the repositories in this ecosystem is an autonomous production execution layer. All agent components operate in **draft, verification, and rehearsal** posture only and must never silently sign transactions, move real funds, or mutate production governance state.

---

## 1. Strict Role Separation

| Component | Repository / Surface | Permitted Responsibilities | Hard Prohibitions |
| :--- | :--- | :--- | :--- |
| **Router (Single Human Voice)** | `Dizzy-the-Polymath` (`agent_server.mjs`, `lib/dispatch.mjs`) | Sole component allowed to talk to humans on Telegram, GitHub, chat, or the operator inbox. Presents concise approvals, questions, and anomaly alerts; holds human-in-the-loop pause/edit/resume gates; routes follow-up events for an active claim, dispute, or export to the assigned worker. | **Must not** run long blocking tool jobs on the main loop, expose raw tool traces as the primary user UI, or move funds. |
| **Workers (Narrow Specialists)** | `CouncilEngine` (`tools/council`), `scripts/verify-export.js`, `PBMRebateTreasuryBackend` | Execute scoped, deterministic or bounded-model tasks (SMT/Z3 arithmetic invariants, Merkle/export checks, AST/Slither audits, PII-masked model reviews, voucher-saga state transitions) and return schema-validated, support-classed receipts **upward to the Router**. | **Must NEVER message users directly** on Telegram, GitHub, email, or chat, post as separate bots, load unrelated browser/messaging toolbags, or claim production authority. |
| **Watchdog (Progress & Drift Guard)** | `Dizzy` (`runaway_execution_watchdog`) & `CouncilEngine` (`authority_conflict_detector.py`, `gate0_policy_preflight.py`) | Evaluates deterministic progress every `N` steps, enforces token/spend/step ceilings, detects goal drift or repeated failure loops, halts stalled workers, and emits structured alerts **upward to the Router**. | **Must NEVER message humans directly** ("for speed" or otherwise) and must never execute on-chain actions autonomously. |

---

## 2. Human Inbox & Support Classes

1. **Conversation / Inbox First**: Humans interact with a single Router inbox showing pending approvals, clarifying questions, and high-signal alerts. Raw tool logs, AST diffs, and solver traces remain inspectable in secondary audit/replay views—not dumped into user chat channels.
2. **Mandatory Support Classes**: Every substantive answer or recommendation surfaced by the Router must carry an explicit support label—`model-only`, `cited` (chunk-hash verified), `formally checked` (local Z3/Hardhat/Foundry receipt), or `human approved`—and **abstain** when required evidence is missing.
3. **Deterministic Filters First**: Event listeners (CI failures, formal-check failures, export mismatches, contract pause/dispute events) pass through deterministic scripts and schema guards before invoking any language model.
4. **Sanitized Inter-Agent Envelopes**: Messages crossing between Router and Workers are schema-validated, trust-zone tagged, stripped of prompt-injection markers, and scrubbed of sensitive identifiers via edge privacy masking (`tools/council/privacy_orchestrator.py`).
