# Solvency Owner Decision Worksheet

Status: draft worksheet. Owner working selections captured for SD-01 through SD-06 as deferrals. This captures authority, uncertainty, and deferral. It is not implementation authorization.

Base checkpoint: `266016c83d544f86dbb67a49240356852e0498b4` (`Queue patient fund solvency debt`)

Default when uncertain: `DEFER / DO NOT IMPLEMENT YET`.

Use this file to avoid turning Codex, Codex 5.6, open-source reviewers, existing tests, or current checkpoint behavior into governance authority.

## How To Answer

For each question, choose one:

- `ACCEPT`: select a specific option, with decision-maker, date, and scope.
- `DEFER / DO NOT IMPLEMENT YET`: no current authority or confidence to choose.
- `DISCLOSE CURRENT PROTOTYPE LIMITATION ONLY`: keep current behavior for now, but document it as non-final and do not extend it.

An answer like "not sure", "above my paygrade", or "leave it for governance" maps to `DEFER / DO NOT IMPLEMENT YET`.

## Decision Records

| ID | Question | Current Characterized Behavior | Suggested Interim Status | Accepted Selection | Decision-Maker | Date | Scope / Notes |
|---|---|---|---|---|---|---|---|
| SD-01 | Claimant priority under scarce liquidity | Full-only claims; first successful payable transaction wins available liquidity. | `DEFER / DO NOT IMPLEMENT YET` | `DEFER / DO NOT IMPLEMENT YET` | Owner | 2026-07-20 | Antigravity's recommended implementation/disclosure moves are not accepted yet. Do not implement queues, partial claims, or pro-rata distribution. |
| SD-02 | Council refund priority | Available-balance refunds can send liquidity to council while project claims remain outstanding. | `DEFER / DO NOT IMPLEMENT YET` | `DEFER / DO NOT IMPLEMENT YET` | Owner | 2026-07-20 | Antigravity's recommended implementation/disclosure moves are not accepted yet. Do not add or rely on refund-priority behavior. |
| SD-03 | Unpaid council refund treatment | Unpaid portion may disappear as an obligation rather than become a payable. | `DEFER / DO NOT IMPLEMENT YET` | `DEFER / DO NOT IMPLEMENT YET` | Owner | 2026-07-20 | Antigravity's recommended implementation/disclosure moves are not accepted yet. Unpaid refunds remain untracked. |
| SD-04 | Reclaim timing during insolvency | Fixed reclaim clock can continue while a share is not payable. | `DEFER / DO NOT IMPLEMENT YET` | `DEFER / DO NOT IMPLEMENT YET` | Owner | 2026-07-20 | Antigravity's recommended implementation/disclosure moves are not accepted yet. Do not add tolling or minimum funded window logic. |
| SD-05 | New rounds while underbacked | Lifecycle can continue while shortfall exists. | `DEFER / DO NOT IMPLEMENT YET`; disclose current prototype limitation only | `DEFER / DO NOT IMPLEMENT YET` | Owner | 2026-07-20 | Antigravity's recommended implementation/disclosure moves are not accepted yet. Do not add, remove, recommend, or rely on start-round permissions or restrictions. |
| SD-06 | Debt/shortfall terminology | `totalDebt` and events are cached observed shortfall deltas, not a causal ledger. | `DEFER / DO NOT IMPLEMENT YET` for ABI changes | `DEFER / DO NOT IMPLEMENT YET` | Owner | 2026-07-20 | Antigravity's recommended implementation/disclosure moves are not accepted yet. Do not perform any terminology renaming or documentation disclosure changes. |
| SD-07 | `DebtSettled` meaning | Cached shortfall decrease, regardless of cause. | `DISCLOSE CURRENT PROTOTYPE LIMITATION ONLY` |  |  |  | Do not describe as repayment/funding without path-specific proof. |
| SD-08 | `previewFinalize()` semantics | `isSufficient == false` can coexist with successful finalization. | `DISCLOSE CURRENT PROTOTYPE LIMITATION ONLY` |  |  |  | Dashboard/docs must not treat false as finalization revert. |
| SD-09 | Top-up and refresh operations | Direct transfer changes live balance; refresh syncs cached shortfall. | `DEFER / DO NOT IMPLEMENT YET` for operational automation |  |  |  | Only local mock-token tests after explicit validation approval. |

## Questions Worth Asking Later

These are not blocking questions for Codex right now. They become useful only when someone with authority is ready to choose policy.

1. Who should be protected first when funds are short: earlier winners, all winners pro-rata, fastest claimants, or another class?
2. Should council ever receive refunds while a project share cannot be paid?
3. If the contract was insolvent for the whole claim period, should a project still lose its claim after 90 days?
4. Should the public interface use "debt" language, "shortfall" language, or both with explicit definitions?
5. Should new rounds continue indefinitely while shortfall exists, or should there be a warning, ceiling, or governance pause?

## Current Non-Decision

No further solvency implementation is authorized from this worksheet. The current planning posture is:

- preserve the committed lifecycle-liveness checkpoint as characterization evidence;
- do not encode payment priority;
- do not encode refund priority;
- do not encode reclaim tolling;
- do not automate recovery;
- do not implement dashboard warnings or new disclosure commitments for SD-01 through SD-06;
- do not publish private review context;
- wait for explicit owner/governance and implementation authorization before Antigravity codes.
