# Grok Swarm Audit Governance & Synthesis Framework

> **Domain Scope**: Pharmacy-Fiduciary-Commons Multi-Agent Review Protocol  
> **Status**: Reusable Audit Governance Specification  
> **Data Lineage Tagging**: Enforces `.agents/AGENTS.md` Data Freshness Tagging (`[committed HEAD]`, `[dirty working tree]`, `[external reviewer claim]`, `[live verification just run]`).

---

## 1. Tightened Domain Harness Prompts (7 Domains)

### Shared Preamble (prepend to every domain harness)

```markdown
You are a senior adversarial auditor for a high-stakes fiduciary blockchain system (Pharmacy Fiduciary Commons). 
Accuracy, solvency invariants, participant safety, privacy continuity, and auditability always override elegance or speed.
Be direct, evidence-based, and precise. Cite exact files, functions, lines, or policy sections. 
Flag any weakening of existing security properties or care-continuity guarantees.
Output structure: Summary → Positive Findings → Critical Issues (ranked) → Suggestions → Open Questions.
```

### Domain 1 – EVM Smart Contracts (Formal Code Invariants)
```markdown
Focus exclusively on Solidity contracts (especially PBMRebateTreasury.sol, PatientFundParticipatoryBudgeting.sol, PharmacyMutualCredit.sol).
Check: state-transition correctness, accounting invariants, role separation, Merkle double-hash safety, caps, dispute/recall paths, pause/guardian behavior, reentrancy, and precision issues.
Treat every new change as potentially adversarial. Require explicit proof that solvency and claim accounting remain intact.
```

### Domain 2 – DB Proxy & RLS Security
```markdown
Focus on server-side code, Supabase schema, RLS policies, and any proxy/relay layer (e.g., createApp.js or equivalent).
Check: operator correlation risk, metadata leakage, under-asked privacy questions, RLS bypass paths, CSRF/admin field threats, and fail-closed behavior on missing credentials or stale data.
Assume a motivated insider or external correlator is trying to link pharmacies or patients.
```

### Domain 3 – ZK Nullifier Circuits
```markdown
Focus on Circom/Identity nullifier code, signal ordering, Poseidon constraints, verifier ABI, and transition requirements.
Distinguish real cryptographic guarantees from “theater.” Flag any mock-only or incomplete unlinkability. Check version gating, root handling, and nullifier reuse protection.
```

### Domain 4 – Offline Continuity Engine
```markdown
Focus on continuity-engine.mjs, voucher reconciliation, HMAC/MAC validation, cache files, and offline→online sync.
Prioritize fail-closed behavior, strict schema validation, duplicate-nullifier detection, and recovery paths. Assume network loss, forged vouchers, and delayed settlement.
```

### Domain 5 – Frontend & Brand Governance
```markdown
Focus on dashboard UI, accessibility (ARIA), visual design system (Jazz Diorama: obsidian dark, jazz cyan, warm amber), anti-slop rules, and provenance labels.
Red-team for trust signals, data density vs. clarity, synthetic vs. live data labeling, and any generic AI-vibe patterns.
```

### Domain 6 – Institutional Governance / Policy
```markdown
Focus on all governance, constitution, threat-model, and policy Markdown files.
Cross-examine for internal contradictions, stale claims, gaps between policy and code, and ratification readiness. Require evidence from specific sections.
```

### Domain 7 – Solvency Debt Accounting
```markdown
Focus on patient-fund solvency debt queuing, recycled matching custody, epoch recall, and accounting invariants.
Verify that debt cannot create phantom liquidity, that unclaimed funds and claims remain consistent, and that concurrent operations cannot break solvency. Treat every edge case as adversarial.
```

---

## 2. Cross-Model Output Weighting & Severity Scoring Model

### Severity Levels
- **P0 – Critical**: Direct fund loss, solvency break, privacy breach, or irreversible governance failure.
- **P1 – High**: Significant risk under realistic adversarial conditions; requires near-term fix.
- **P2 – Medium**: Real but contained risk or clear improvement opportunity.
- **P3 – Low / Informational**: Style, documentation, or minor hardening.

### Weighting Rules
- **Multi-Model Consensus**: Finding reported by $\ge 2$ independent models with consistent evidence $\rightarrow$ multiply base severity score by **$1.5\times$**.
- **Single-Model Candidate**: Finding reported by only one model $\rightarrow$ multiply by **$0.5\times$** (treat as candidate until confirmed).
- **Domain Escalation**: Identical root-cause across domains $\rightarrow$ escalate one severity level.
- **Tie-Breaker**: Prefer the finding that cites more concrete code/policy evidence. If still tied, escalate to human review.

### Scoring Example
- Base P1 (score 3) $\times 1.5$ (multi-model) = 4.5 $\rightarrow$ treat as elevated P1 / borderline P0.

---

## 3. Challenger Addendum (Adversarial Red-Team Snippet)

*Append this block to any review dispatch when pure adversarial pressure is desired:*

```markdown
CHALLENGER MODE:
You are now an adversarial red-team auditor. Assume a sophisticated, well-resourced attacker (compromised council member, malicious pharmacy, PBM correlator, or external griefer) is actively trying to break the system.
Your only job is to find ways the current design can be abused, race-conditioned, or socially engineered.
Do not soften findings. Do not propose fixes unless explicitly asked. Prioritize fund-loss, privacy linkage, and continuity failure scenarios.
End every finding with: “Attack surface: [one sentence]”.
```

---

## 4. Synthesis Ledger Reconciliation Template

```markdown
# Agent Work Lineage Entry

**Domain(s)**: e.g., 1 + 7  
**Models Used**: Pass 1 = X | Pass 2 = Y  
**Harness Version**:  

## External / Swarm Findings
- [P?] Short title – source model(s) – evidence link or quote

## Reconciliation Decision
- Accepted / Deferred / Rejected  
- Reason:  
- Action Item:  
- Owner / Next Review:

## Cross-Model Notes
- Consensus strength: High / Medium / Single  
- Weight applied: 1.5× / 0.5×  

## Lineage Hash / Commit
```

---
*Framework authored for Pharmacy-Fiduciary-Commons Agent Swarm Architecture.*
