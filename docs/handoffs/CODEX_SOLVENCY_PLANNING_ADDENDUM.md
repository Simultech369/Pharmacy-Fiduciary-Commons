# Codex Solvency Planning Addendum

Status: parallel planning note for Antigravity. This file is meant to accompany, not replace, Antigravity's existing handoff documents.

Base public checkpoint: `266016c83d544f86dbb67a49240356852e0498b4` (`Queue patient fund solvency debt`)

Current Antigravity entry point: `ANTIGRAVITY_HANDOFF_BUNDLE_MANIFEST.md`

Primary linked decision artifact: `SOLVENCY_DEBT_SEMANTICS.md`

Authority and safety ledger: `SOLVENCY_REVIEW_AUTHORITY_AND_SAFETY.md`

Owner decision worksheet: `SOLVENCY_OWNER_DECISION_WORKSHEET.md`

Antigravity packet template: `ANTIGRAVITY_SOLVENCY_IMPLEMENTATION_PACKET.md`

External hack-pattern checklist: `PBM_EVM_HACK_LESSONS.md`

Human-facing language/design note: `PBM_HUMAN_LANGUAGE_AND_DESIGN_NOTES.md`

Bounded work loop note: `PBM_BOUNDED_WORK_LOOP_NOTES.md`

Public-safe draft: `PUBLIC_PROGRESS_NOTE_DRAFT.md`

## Why This Exists

Independent planning reviews identified unresolved policy gates; reviewer artifacts remain local and non-authoritative.

The main conclusion: the checkpoint is useful public progress, but the next implementation step should not proceed until policy semantics are explicit. The current contract improves lifecycle liveness, but it does not decide payment priority or create a full debt ledger.

## Role Boundary

- Codex: brainstormer, reviewer, plan editor, and handoff maintainer.
- Codex 5.6: read-only second-opinion reviewer and critique pass.
- Antigravity: candidate implementer only after explicit owner/governance policy acceptance and separate file-scoped implementation authorization.
- Project owner/governance: final authority for claimant priority, council refund priority, reclaim timing, and terminology. When that authority is unavailable or uncertain, the safe planning state is `DEFER / DO NOT IMPLEMENT YET`.

Do not treat model agreement as policy acceptance.

## Planning Summary For Antigravity

The current checkpoint should be described as:

> Governance lifecycle liveness is restored; claimant payment liveness remains dependent on real liquidity.

Avoid describing `totalDebt` as a full debt ledger. It is currently a cached shortfall snapshot. Avoid describing `roundDeficit` as attributable round debt. It records observed increases in global shortfall during round-associated calls.

## Recommended Next Artifact

Before code edits, get owner acceptance on `SOLVENCY_DEBT_SEMANTICS.md` or `SOLVENCY_OWNER_DECISION_WORKSHEET.md`. If an answer is above the current reviewer's authority, mark it `DEFER / DO NOT IMPLEMENT YET` rather than choosing a default.

The minimum useful acceptance decision is:

1. claimant priority during insolvency;
2. council refund priority while project shares are underbacked;
3. reclaim grace-period behavior while shares are not payable;
4. whether storage/events keep debt wording or move toward shortfall wording.

## Local Review Notes

These are advisory reviewer signals only. They do not replace owner decisions or Antigravity implementation judgment.

Independent planning reviews identified unresolved policy gates and wording risks. Reviewer artifacts remain local, non-authoritative claim sources. Do not publish reviewer/provider details or treat reviewer agreement as implementation approval.

## Suggested Antigravity Start Gate

```text
Before any implementation:
1. Report `git rev-parse HEAD`, `git branch --show-current`, and `git status --short`.
2. Stop unless HEAD exactly matches the approved implementation base.
3. Preserve every modified and untracked path; do not clean, reset, absorb, rename, or stage backlog.
4. Confirm that each required policy decision contains an explicit accepted selection, decision-maker, date, and scope. `TBD`, blank, draft recommendation, model agreement, existing code, and existing tests are not acceptance.
5. Confirm separate implementation authorization naming the allowed slice and files.
6. Check `SOLVENCY_REVIEW_AUTHORITY_AND_SAFETY.md` for reviewer-claim disposition and command side-effect classification.
7. If either acceptance or implementation authorization is missing, stop without editing.
```

## Must Fix Before More Solvency Implementation

- Decide claimant priority under insolvency, or keep it deferred.
- Decide whether council refunds are subordinated while project shares are underbacked, or keep it deferred.
- Decide whether insolvency tolls or extends the 90-day reclaim period, or keep it deferred.
- Specify authoritative meanings for `totalDebt`, `roundDeficit`, `DebtQueued`, and `DebtSettled`, or keep ABI/storage/event changes deferred.
- Specify whether obligation cancellation can ever be called settlement, or prohibit repayment/funding language by default.
- Correct preview/dashboard semantics only after explicit docs/dashboard scope is authorized.

## Should Document Before More Solvency Implementation

- Lifecycle liveness is not payment liveness.
- Current full-only claim behavior can create first-successful-transaction competition.
- New rounds may or may not continue while shortfall exists; decide explicitly.
- Local/mock top-up and refresh test sequence:
  1. verify exact token and contract;
  2. query `currentSolvencyShortfall()`;
  3. transfer tokens using an approved local/test flow;
  4. verify ERC-20 balance;
  5. call `refreshSolvencyDebt()`;
  6. verify live shortfall and cached value.
- `refreshSolvencyDebt()` is permissionless but unavailable while paused.

## Explicitly Do Not Touch Yet

- Unrelated modified/untracked dashboard, guardrail, review, schema, `PharmacyMutualCredit`, and Antigravity/Kimi artifacts.
- Production deployments, multisigs, credentials, RPC config, databases, live funds, or role transfers.
- Broad treasury/accounting refactors.
- ZK/privacy implementation.
- Automated funding bots or privileged recovery automation.
- Cleanup, reset, branch substitution, closest-match resource selection, or environment repair.
- Comparison-project internals, prompt-pack systems, memory architecture, provider-routing systems, or broad file-role refactors.

## Implementation Slices After Decisions

Only after decisions are accepted, the likely narrow slices are:

1. Documentation reconciliation: update stale solvency language in selected docs and dashboard copy.
2. Contract semantics: rename or document shortfall/debt events and storage, depending on ABI tolerance.
3. Priority enforcement: add tests and logic for council refund priority and claimant priority.
4. Grace-period handling: add tests and logic for tolling or minimum funded claim windows, if accepted.
5. Preview API correction: align preview outputs with non-reverting finalization semantics.

Each slice should be independently tested and committed, without absorbing unrelated dirty files.

Current authorization: no implementation slice is approved. The Antigravity packet template records the stop condition and candidate slices for later selection.
