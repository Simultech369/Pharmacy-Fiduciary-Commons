# Handoff to Codex

**Date:** 2026-08-28
**HEAD Commit:** `8d65694`
**Status:** PBM Fraud Formal Invariants slice completed. Working tree is clean and synced to `origin/main`.

## 1. Verified Findings
- **Data Freshness Tag:** `[committed HEAD]`
- **State:** The master script `verify_all.py` was executed on the working tree right before commit. It passed all 9 stages, covering 428 Hardhat tests and 310 Python tests. All formal invariants (MME limits, refill-too-soon bounds, HHI constraints, and Benford's Law scoping) have been validated and merged.
- **Git State:** `test/PBMFraudFormalInvariants.test.js`, `tools/council/pbm_fraud_formal_invariants.py`, and `tools/council/test_pbm_fraud_formal_invariants.py` have been successfully committed and pushed to `origin/main`.

## 2. Unresolved Risks
- **Solidity CEI Refactoring / Semantic Debates:** The Slither warnings for `depositRebate()` remain present as we explicitly delay refactoring the CEI structure (it intentionally defers state to hide unconfirmed accounting from malicious reentrant token hooks).

## 3. Exact Scope of Next Agent's Job

The next agent should execute the following prompt to polish the UI and Public Documentation for external collaborators:

***

Before editing:
- Verify current git branch, HEAD, and dirty-tree state.
- Preserve unrelated changes.
- Treat external projects as inspiration only. Do not copy code, text, class names, assets, or layout wholesale.

### Aesthetic Directive: `impeccable` + `taste-skill`

We want a highly professional, developer-first, institutional interface.

Use structural inspiration from:
- `https://github.com/pbakaus/impeccable`

Apply the design semantics of:
- `Leonxlnx/taste-skill`
- Specifically the `minimalist-skill` variant: editorial product UI, Notion/Linear vibes, restrained palette, crisp structure.

If using base `taste-skill` dials:
- `MOTION_INTENSITY`: very low
- `VISUAL_DENSITY`: high
- `DESIGN_VARIANCE`: low to moderate
- Tone: institutional, calm, proof-oriented, developer-first

Avoid heavy consumer SaaS styling, oversized marketing hero sections, glow/orb effects, cartoon visuals, and floaty animation.

### UI Targets

- `dashboard/index.html`
- `dashboard/design-system.css`
- `dashboard/web3_integration.js`

### Public Docs Targets

- `README.md`
- `ONBOARDING.md`
- `COMMONS_CONSTITUTION.md`
- `SECURITY.md`

### Public Readiness Goals

The first screen and top-level docs should quickly answer:

- What this project is
- What can be verified today
- What is not production-ready
- What is mock/local/testnet only
- How to run the verifier
- How contributors should safely participate
- Which claims require higher security or Solidity review

Maintain the Weakest Valid Claim rule throughout. Do not upgrade local mocks, signed envelopes, dashboards, or receipts into stronger claims than the evidence supports.

After editing:
- Run the relevant frontend/doc checks.
- Run syntax checks for edited JavaScript.
- Do not run a full verification stamp unless explicitly requested.
- Provide a concise summary of changed surfaces and remaining public-readiness risks.
