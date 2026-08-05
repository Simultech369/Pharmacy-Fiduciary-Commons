# Antigravity Solvency Implementation Packet

Status: draft packet template. Current authorization: no contract, test, dashboard, automation, or deployment implementation authorized.

Current package entry point: `ANTIGRAVITY_HANDOFF_BUNDLE_MANIFEST.md`

Repository: `<LOCAL_REPO_ROOT>`

Base checkpoint: `266016c83d544f86dbb67a49240356852e0498b4` (`Queue patient fund solvency debt`)

## Start Gate

Before any implementation, report:

```powershell
git rev-parse HEAD
git branch --show-current
git status --short
```

Stop unless `HEAD` exactly matches the approved implementation base.

Do not clean, reset, stash, delete, rename, move, absorb, or stage unrelated dirty files. Missing resources are stop conditions; do not substitute closest matches.

## Required Authority Before Editing

Antigravity must have both:

1. accepted policy decisions in `SOLVENCY_OWNER_DECISION_WORKSHEET.md` or `SOLVENCY_DEBT_SEMANTICS.md`;
2. separate implementation authorization naming the allowed slice and files.

If either is absent, stop without editing.

Current status: absent. Therefore stop before implementation.

For any future solvency implementation slice, also consult `PBM_EVM_HACK_LESSONS.md` and mark each hack-derived check as required, deferred, or not applicable. That file is a security-review checklist, not implementation authority.

## Current Decision State

| Area | Current Status | Implementation Permission |
|---|---|---|
| Claimant priority | `DEFER / DO NOT IMPLEMENT YET` | none |
| Council refund priority | `DEFER / DO NOT IMPLEMENT YET` | none |
| Unpaid council refund treatment | `DEFER / DO NOT IMPLEMENT YET` | none |
| Reclaim timing during insolvency | `DEFER / DO NOT IMPLEMENT YET` | none |
| New rounds while underbacked | `DEFER / DO NOT IMPLEMENT YET`; characterize only if docs scope is approved | no new start-round, priority, reclaim, or debt/shortfall logic |
| Debt/shortfall ABI naming | `DEFER / DO NOT IMPLEMENT YET` | none |
| `DebtSettled` wording | disclose as cached shortfall decrease only | docs/dashboard copy only if scoped |
| `previewFinalize()` semantics | disclose non-reverting semantics only | docs/dashboard copy only if scoped |
| Top-up/recovery automation | `DEFER / DO NOT IMPLEMENT YET` | none |

Acceptance criterion for any docs/dashboard/public copy: do not describe `DebtSettled` as repayment, funding, restoration, or being made whole unless the specific execution path proves token receipt or actual obligation payment.

## Candidate Slices After Authorization

These are not currently approved. They are listed only so future authorization can name one narrow slice.

1. Documentation correction slice:
   - possible files: selected stale docs and dashboard copy only;
   - purpose: remove hard-revert language and clarify lifecycle liveness versus payment liveness;
   - no contract behavior changes.
2. Preview semantics slice:
   - possible files: contract/tests/docs selected by authorization;
   - purpose: clarify or adjust `previewFinalize()` outputs after policy choice;
   - no claimant-priority changes unless separately authorized.
3. Event terminology slice:
   - possible files: contract/tests/docs selected by authorization;
   - purpose: rename or document debt/shortfall terms;
   - requires ABI/integration compatibility review.
4. Priority policy slice:
   - possible files: contract/tests/docs selected by authorization;
   - purpose: implement selected claimant and/or council priority;
   - requires explicit owner/governance policy.
5. Reclaim timing slice:
   - possible files: contract/tests/docs selected by authorization;
   - purpose: implement selected tolling or minimum-funded-window rule;
   - requires explicit owner/governance policy.

## Validation Boundary

Use only isolated local mock-token tests after explicit validation approval. Do not use live funds, production credentials, RPC configuration, privileged endpoints, role transfers, deployments, or irreversible approvals.

Before any command that may write, classify:

- exact command;
- expected mutable paths;
- disposable root, if any;
- cleanup target;
- files written, deleted, and remaining.

## Do Not Touch

- Unrelated modified/untracked dashboard, guardrail, review, schema, `PharmacyMutualCredit`, and Antigravity/Kimi artifacts.
- Production deployments, multisigs, credentials, RPC config, databases, live funds, or role transfers.
- Broad treasury/accounting refactors.
- ZK/privacy implementation.
- Automated funding bots or privileged recovery automation.
- Cleanup, reset, branch substitution, closest-match resource selection, or environment repair.

## Safe Current Handoff Summary

The pushed checkpoint restored governance lifecycle liveness while leaving payment liveness dependent on actual token liquidity. The next implementation must not encode claimant priority, council refund priority, reclaim timing, or debt/shortfall terminology until those choices are explicitly authorized.
