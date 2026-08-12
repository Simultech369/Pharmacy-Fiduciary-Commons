# Public Progress Note Draft

Status: draft public-safe copy. Do not publish until the owner approves the exact text and destination.

Base public checkpoint: `266016c83d544f86dbb67a49240356852e0498b4` (`Queue patient fund solvency debt`)

## Short Version

```text
We pushed a patient-fund solvency checkpoint.

It restores lifecycle liveness: in this prototype checkpoint, underbacking is tracked instead of being treated as a universal start/finalize freeze.

It does not restore payment liveness. Claims still depend on real token liquidity, and the next work is to record policy decisions around claim priority, council refunds, reclaim timing, and shortfall terminology before more implementation.
```

## Slightly Fuller Version

```text
We pushed a patient-fund solvency checkpoint for the PBM rebate treasury prototype.

The checkpoint changes round lifecycle behavior: underbacking is recorded and surfaced rather than treated as a universal hard block on round lifecycle calls. That helps the governance process keep moving and makes the underbacked state visible instead of freezing the round.

It does not guarantee claim payment. Project claims still depend on real token liquidity, and the current debt/shortfall labels are prototype accounting labels for observed shortfall changes, not a creditor ledger or repayment proof.

Before the next implementation slice, we are leaving several policy choices explicit and deferred: claimant priority under scarce liquidity, council refund priority, reclaim timing during insolvency, and the long-term debt/shortfall terminology.

The current work is a decision-gated handoff for future implementation intake, not a production release.
```

## Do Not Say Publicly Yet

- "Payment liveness is restored."
- "Claimants are made whole."
- "`DebtSettled` means repayment."
- "Debt is fully solved."
- "Governance approved the policy."
- "Antigravity is authorized to implement."
- "Codex implemented the next slice."
- "Public wallet/mainnet ready."
- "Audited."
- "Production privacy."

## Redaction Checklist

Before publishing, verify the final text excludes:

- local absolute paths;
- dirty working-tree file lists;
- reviewer/model/provider names or routing details;
- raw model outputs;
- private strategy notes;
- participant, wallet, pharmacy, credential, endpoint, or credential-provider details;
- claims about deployment, live funds, production readiness, or audit status.

## Allowed Public Claims

Public-safe claims may describe:

- the exact committed checkpoint;
- lifecycle liveness versus payment liveness;
- unresolved policy questions;
- the existence of a decision-gated handoff process;
- the fact that this remains a prototype.
