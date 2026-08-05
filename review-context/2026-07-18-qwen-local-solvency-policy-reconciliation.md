# Qwen Local Solvency Policy Reconciliation

Status: local-only reviewer signal. Do not treat as owner policy acceptance or implementation approval.

Base checkpoint: `266016c83d544f86dbb67a49240356852e0498b4`

Model route: local Ollama `qwen2.5-coder:7b`

Disclosure class: private/local. No external provider disclosure.

Prompt packet: a distilled summary of `SOLVENCY_DEBT_SEMANTICS.md`, `CODEX_SOLVENCY_PLANNING_ADDENDUM.md`, and the Antigravity start gate. The model did not receive the full repo and did not inspect live code.

## Reviewer Signal

Qwen agreed with the broad planning shape:

- lifecycle liveness and payment liveness must remain separate;
- `totalDebt` should be treated as cached shortfall, not a creditor ledger;
- `roundDeficit` should not be treated as attributable round debt;
- claimant priority, council refund priority, reclaim timing, and naming semantics need explicit decisions;
- Antigravity should not implement while owner decisions are still TBD.

Qwen's generic next steps were legal/stakeholder review, historical data, community input, legal counsel, and documentation.

## Codex Reconciliation

Useful:

- Reinforces that the docs are pointing at the right unresolved decisions.
- Reinforces that implementation should wait for explicit policy acceptance.

Limitations:

- The output was generic and did not cite contract lines or repo files.
- It classified claimant priority and council refund subordination as `SAFE_TO_PLAN`; that is only acceptable if read as "safe to discuss." It is not safe to implement without owner/governance permission.
- It introduced legal-contract language without evidence from the repository. Treat that as a reminder to check governance commitments, not as a factual claim.

Corrected classification:

| Issue | Qwen classification | Codex reconciliation |
|---|---|---|
| Claimant priority under insolvency | `SAFE_TO_PLAN` | `NEEDS_PERMISSION` before code or UI semantics encode it. |
| Council refund subordination | `SAFE_TO_PLAN` | `NEEDS_PERMISSION` before contract behavior changes. |
| Reclaim grace-period policy | `NEEDS_VERIFICATION` | `NEEDS_PERMISSION` plus tests once policy is chosen. |
| Debt/shortfall terminology | `SAFE_TO_PLAN` | `SAFE_TO_PLAN` for docs; `NEEDS_PERMISSION` for ABI/storage/event renames. |

## Handoff Impact

No new blocker was found beyond the existing owner-decision gate. This review does not change the recommended Antigravity start condition:

> Stop if `SOLVENCY_DEBT_SEMANTICS.md` is missing or owner decisions are still TBD.

Next useful local reviewer, if needed: a DeepSeek invariant-focused pass on one narrow question at a time, especially council refund priority, reclaim tolling, or `DebtSettled` semantics.
