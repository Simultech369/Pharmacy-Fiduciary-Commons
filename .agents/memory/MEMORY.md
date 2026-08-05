# Agent Memory & Index — MEMORY.md

> **Notice**: This file serves as the canonical index over repository governance, multi-agent review dossiers, and domain specifications. All indexed source files remain in their primary locations.
> **PageIndex Target Scope**: The PageIndex Dossier Tree Indexer (`scripts/index_dossier_tree.py`) currently audits **13 target documents**. This count represents the explicit *PageIndex target set* configured in the auditor script, not every markdown file across the repository.

---

## 1. Contract & Operating Layer

| Source File | Role | Last Sync | Freshness Label | Proof Command | Stale-Risk Note |
| :--- | :--- | :--- | :--- | :--- | :--- |
| [COMMONS_CONSTITUTION.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/COMMONS_CONSTITUTION.md) | Domain Governance Primacy | 2026-07-27 | `[committed HEAD]` | `python scripts/index_dossier_tree.py` | Low risk; foundational project governance. |
| [.agents/AGENTS.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/.agents/AGENTS.md) | Agent Operating Layer (v0.1) | 2026-07-27 | `[dirty working tree]` | `python scripts/index_dossier_tree.py` | Ratified (`DEC-002`); applies strictly to Agent Operating Layer v0.1. |
| [GOVERNANCE.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/GOVERNANCE.md) | Protocol Voting Mechanics | 2026-07-25 | `[committed HEAD]` | `python scripts/index_dossier_tree.py` | Stable governance reference. |

---

## 2. Verifiers & Quality Assurance

| Source File | Role | Last Sync | Freshness Label | Proof Command | Stale-Risk Note |
| :--- | :--- | :--- | :--- | :--- | :--- |
| [AGENT_REVIEW_ORCHESTRATION.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/AGENT_REVIEW_ORCHESTRATION.md) | Multi-Agent Review Protocol | 2026-07-26 | `[dirty working tree]` | `python scripts/index_dossier_tree.py` | High importance; defines cross-model review loops. Modified in local tree. |
| [scripts/index_dossier_tree.py](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/scripts/index_dossier_tree.py) | Status & Contradiction Indexer | 2026-07-27 | `[dirty working tree]` | `python scripts/index_dossier_tree.py` | Executable script; updates `cache/dossier_tree_index.json`. Untracked in working tree. |
| [grok-review-prompt.txt](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/grok-review-prompt.txt) | Grok External Reviewer Prompt | 2026-07-25 | `[dirty working tree]` | N/A | External prompt template; untracked in working tree. |
| [kimi-long-context-review-prompt.txt](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/kimi-long-context-review-prompt.txt) | Kimi Reviewer Prompt Spec | 2026-07-25 | `[dirty working tree]` | N/A | External prompt template; untracked in working tree. |

---

## 3. Multi-Agent Graph & Handoff Bundles

| Source File | Role | Last Sync | Freshness Label | Proof Command | Stale-Risk Note |
| :--- | :--- | :--- | :--- | :--- | :--- |
| [NEXT_REVIEW_HANDOFF.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/NEXT_REVIEW_HANDOFF.md) | Active Multi-Agent Review Packet | 2026-07-26 | `[dirty working tree]` | `python scripts/index_dossier_tree.py` | Moderate risk; modified in local working tree. |
| [ANTIGRAVITY_HANDOFF_BUNDLE_MANIFEST.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/ANTIGRAVITY_HANDOFF_BUNDLE_MANIFEST.md) | Handoff Bundle Topology | 2026-07-26 | `[dirty working tree]` | `python scripts/index_dossier_tree.py` | Untracked in working tree; maps active review bundles across secondary models. |
| [CODEX_KIMI_RECONCILIATION_HANDOFF.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/CODEX_KIMI_RECONCILIATION_HANDOFF.md) | Model Reconciliation Packet | 2026-07-26 | `[dirty working tree]` | `python scripts/index_dossier_tree.py` | Untracked in working tree; tracks resolution between Codex & Kimi findings. |

---

## 4. Operational & Memory Queues

| Source File | Role | Last Sync | Freshness Label | Proof Command | Stale-Risk Note |
| :--- | :--- | :--- | :--- | :--- | :--- |
| [.agents/memory/WAITING_ON_ME.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/.agents/memory/WAITING_ON_ME.md) | Human Owner Decision Queue | 2026-07-27 | `[dirty working tree]` | Manual owner review | High visibility; untracked working file tracking pending decisions (`DEC-001`, `DEC-002`). |
| [.agents/memory/LEARNINGS_QUEUE.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/.agents/memory/LEARNINGS_QUEUE.md) | Candidate Agent Spec Rules | 2026-07-27 | `[dirty working tree]` | Manual owner review | Low risk; untracked working file holding candidate rules prior to promotion. |
| [review-context/agent_work_lineage_ledger.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/review-context/agent_work_lineage_ledger.md) | Verified Work Lineage Ledger | 2026-07-26 | `[dirty working tree]` | `python scripts/index_dossier_tree.py` | Modified in working tree; authoritative ground truth ledger (Entry 001–016). |

---

## 5. Fiduciary & ZK Specifications

| Source File | Role | Last Sync | Freshness Label | Proof Command | Stale-Risk Note |
| :--- | :--- | :--- | :--- | :--- | :--- |
| [SOLVENCY_DEBT_SEMANTICS.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/SOLVENCY_DEBT_SEMANTICS.md) | Debt Definitions & Solvency Specs | 2026-07-26 | `[dirty working tree]` | `python scripts/index_dossier_tree.py` | Untracked in working tree; defines solvency math & debt logic. |
| [ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md) | Nullifier Migration Spec | 2026-07-26 | `[committed HEAD]` | `python scripts/index_dossier_tree.py` | High importance; defines patient privacy rules. |
| [PRODUCTION_READINESS_CHECKLIST.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/PRODUCTION_READINESS_CHECKLIST.md) | Release Readiness Gates | 2026-07-26 | `[dirty working tree]` | `python scripts/index_dossier_tree.py` | Master checklist for deployment verification. |

---

## 6. Loop Taxonomy Mapping (Conceptual Buckets)

> **Notice**: Maps the loop-engineering conceptual taxonomy onto existing repository surfaces without creating redundant physical directories.

| Category | Current Repo Surface | Status | Notes |
| :--- | :--- | :--- | :--- |
| **Contract** | [.agents/AGENTS.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/.agents/AGENTS.md) / [AGENT_REVIEW_ORCHESTRATION.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/AGENT_REVIEW_ORCHESTRATION.md) | `Active` | Agent operational rules and review protocols. |
| **Verifiers** | PageIndex Auditor / `git diff --check` / Hardhat tests | `Active` | Proof and verification surface. |
| **Memory** | [.agents/memory/*](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/.agents/memory/MEMORY.md) | `Active` | Index, decision queues (`WAITING_ON_ME.md`), and learnings (`LEARNINGS_QUEUE.md`). |
| **Ops** | [review-context/agent_work_lineage_ledger.md](file:///c:/Users/Josh/Desktop/PBMRebateTreasuryFinal/review-context/agent_work_lineage_ledger.md) / Handoff Manifests | `Active` | Lineage ledger, handoff packets, and PageIndex cache. |
| **Isolation** | Disposable worktrees / no live secrets / no unauthorized deploys | `Active` | Operational safety boundaries. |
| **Triggers** | Manual kickoff | `Active` | On-demand agent session triggering. |
| **Hooks** | None | `Shelved` | Revisit after current slice is committed. |
| **Daily Loops** | None | `Shelved` | Not needed for current domain slice. |
| **Skills** | None | `Shelved` | Add only after repeated workflows stabilize. |
