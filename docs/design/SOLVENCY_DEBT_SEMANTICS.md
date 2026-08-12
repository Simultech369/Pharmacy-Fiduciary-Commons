# Solvency Debt Semantics

Status: Draft decision artifact for review. Do not treat this file as accepted implementation policy until the project owner explicitly accepts the decisions below.

Base public checkpoint: `266016c83d544f86dbb67a49240356852e0498b4` (`Queue patient fund solvency debt`)

Purpose: define what the patient-fund solvency checkpoint means before further implementation, dashboard work, or automated recovery logic builds on it.

## Authority Rules

No-default rule: every draft recommendation and existing checkpoint behavior remains non-authoritative while its decision field is `TBD`. Existing code, existing tests, model agreement, or a local reviewer note must not be interpreted as ratification of that behavior.

No-causal-ledger rule: `totalDebt`, `roundDeficit`, `DebtQueued`, and `DebtSettled` describe observed shortfall snapshots or deltas only. They do not identify a creditor, debtor, funding source, loss source, repayment, or attributable round liability.

Cancellation rule: reducing or removing an accounting obligation without transferring value to its creditor is obligation cancellation, not repayment. A generic shortfall-reduction event must not imply otherwise.

Implementation-authority rule: owner acceptance of policy semantics does not itself authorize contract, test, dashboard, or documentation edits. Antigravity needs a separate implementation authorization naming the allowed slice and files.

No-authority default: if the owner/governance answer is unavailable, uncertain, or above the current reviewer's authority, mark the decision `DEFER / DO NOT IMPLEMENT YET`. Do not convert uncertainty into a prototype default.

## Scope

The current contract checkpoint restores governance lifecycle liveness in characterized paths: underbacking is tracked instead of being treated as a universal start/finalize freeze. It does not create payment liveness: project claims still require actual token liquidity.

This document intentionally separates:

- accounting obligations recorded by the contract;
- physical token balance held by the contract;
- cached shortfall observation;
- claimant payment priority;
- council refund priority;
- reclaim timing while insolvent.

## Current Terms

Current implementation names:

- `currentSolvencyShortfall()`: live view of `max(requiredSolvencyBalance() - token.balanceOf(address(this)), 0)`.
- `totalDebt`: cached shortfall from the most recent synchronization, not a full debt ledger.
- `roundDeficit[roundId]`: cumulative increases in the global shortfall first observed during calls attributed to that round, not that round's outstanding payable debt.
- `DebtQueued`: observed increase in cached shortfall.
- `DebtSettled`: observed decrease in cached shortfall, regardless of cause.

Open naming issue: if the project wants strict creditor-ledger semantics, these names should be revised or supplemented before more code depends on them. Safer names may be `totalObservedShortfall`, `roundObservedShortfallIncrease`, `ShortfallObserved`, and `ShortfallReduced`.

## Decision Table

| Action | Accounting obligations | Physical balance | Shortfall effect | Allowed while underbacked? | Priority/event meaning |
|---|---:|---:|---:|---|---|
| Direct loss/rebase/burn | Unchanged | Decreases | Increases | N/A | Detection only; no actor attribution unless proved elsewhere. |
| Direct top-up | Unchanged | Increases | Decreases | Yes | Funding only after exact token/contract verification and receive confirmation. |
| `refreshSolvencyDebt()` | Unchanged | Unchanged | Updates cached value only | Yes when unpaused | Snapshot sync; not causal attribution. |
| Start round with fresh funds | Adds active pool obligation and fresh deposit | Increases by exact fresh receipt | Normally unchanged except prior shortfall sync | Decision needed | Must disclose if prior debt exists. |
| Start round with recycled funds | Moves recycled accounting into active pool | Unchanged | Normally unchanged | Decision needed | Does not create physical liquidity. |
| Finalize with votes | Active pool becomes project shares/dust/refund | Refund may reduce balance | Normally unchanged if obligations preserved | Yes, per checkpoint | Must define refund priority before more implementation. |
| Zero-vote finalize | Active pool becomes recycled amount and possible council refund | Refund may reduce balance | May decrease if obligation is cancelled | Yes, per checkpoint | Must define unpaid refund semantics. |
| Claim share | Unclaimed share decreases | Same amount leaves | Normally unchanged | Decision needed | Currently full-only and first-successful-transaction. |
| Reclaim share | Unclaimed share becomes recycled matching pool | Unchanged | Normally unchanged | Decision needed | Must decide whether insolvency tolls grace period. |
| Liability cancellation | Obligation decreases | Unchanged | Decreases | Decision needed | Should not be called settlement unless policy accepts cancellation as settlement. |

## Decisions To Lock Before Further Implementation

Each decision record must include an explicit selected option, decision-maker, date, and scope. Blank fields, `TBD`, draft recommendations, model agreement, existing code, and existing tests are not acceptance.

Interim planning stance: all decisions below are deferred unless explicitly accepted later. `DEFER / DO NOT IMPLEMENT YET` is the safe state; it means no new contract, dashboard, automation, or public-claim behavior should encode that policy.

### 1. Claimant Priority During Insolvency

Options:

- First-successful-transaction: current practical behavior. Simple, but creates claim races and can favor smaller/later claims.
- Oldest-round priority: protects earlier finalized commitments. Requires queueing or claim ordering logic.
- Pro-rata liquidity distribution: reduces race dynamics. Requires partial claims and more accounting.

Draft recommendation: do not silently accept first-successful-transaction as policy. If retained, document it as an explicit prototype limitation.

Decision: TBD.

Interim status: DEFER / DO NOT IMPLEMENT YET.

Question for owner/governance: should scarce liquidity be paid first-successful-transaction, oldest-round first, pro-rata, or some other explicitly governed method?

### 2. Council Refund Priority During Insolvency

Options:

- Council refunds may execute before prior project shares are fully backed.
- Council refunds are subordinated whenever any project share is underbacked.
- Council refunds are converted into explicit payable/refundable accounting and paid only after priority rules are met.

Draft recommendation: subordinate council refunds while project shares are underbacked. The patient-fund contract should not let scarce liquidity leave to council while prior project recipients cannot claim.

Decision: TBD.

Interim status: DEFER / DO NOT IMPLEMENT YET.

Question for owner/governance: should council refunds be allowed, subordinated, or recorded as payable/refundable obligations while project shares are underbacked?

### 3. Reclaim Grace Period While Insolvent

Options:

- Fixed 90-day period from finalization, even if the share was never payable.
- Toll the reclaim clock while the contract is underbacked.
- Require a minimum funded claim window before reclaim.

Draft recommendation: require a minimum funded claim window or toll the reclaim clock while the relevant share cannot be paid.

Decision: TBD.

Interim status: DEFER / DO NOT IMPLEMENT YET.

Question for owner/governance: should the 90-day reclaim window run during insolvency, pause during insolvency, or restart/extend after a funded claim window exists?

### 4. Event And Storage Semantics

Options:

- Keep current names and document them as cached shortfall observations.
- Rename to shortfall terminology before integrations depend on the ABI.
- Add separate ledger events for actual funding settlement and obligation cancellation.

Draft recommendation: use shortfall terminology in docs now. Before new integrations, decide whether ABI names stay for compatibility or get renamed while the prototype is still flexible.

Decision: TBD.

Interim status: DEFER / DO NOT IMPLEMENT YET for ABI/storage/event changes. Docs and dashboard copy may use shortfall wording only if separately authorized.

Question for owner/governance: should the prototype keep debt terminology for ABI continuity, rename toward shortfall terminology before integrations depend on it, or add separate events for funding and cancellation?

## Preview And Dashboard Semantics

`previewFinalize()` and dashboard language must not treat `isSufficient == false` as meaning finalization will revert. For characterized non-reverting paths, it means finalization can record or expose underbacking; it is not a universal non-revert promise.

`isSufficient` means the current balance fully covers prior unclaimed shares plus the active pool before finalization. It is not a can-finalize flag.

`totalRequiredAfterFinalize` should not be treated as equivalent to the `isSufficient` denominator unless the implementation explicitly defines it that way. If recycled zero-vote funds, dust, or unpaid refunds remain accounting obligations, documentation and dashboard copy must name whether they are included.

`DebtSettled` means only that the cached observed shortfall decreased. Do not label it funded, repaid, restored, or creditor-settled without path-specific evidence of token receipt or obligation payment.

Acceptance criterion for any docs, dashboard, handoff, or public copy: do not use "settled", "repaid", "funded", "restored", or "made whole" for shortfall reduction unless the specific execution path proves token receipt or actual obligation payment.

Required distinction:

- lifecycle can continue;
- claim payment depends on actual liquidity;
- `currentSolvencyShortfall()` is the live truth;
- `totalDebt` is a cached snapshot;
- direct token transfer changes balance without emitting a contract funding event;
- `refreshSolvencyDebt()` reconciles cached debt/shortfall events.

## Documentation Surfaces To Reconcile

Known stale or potentially contradictory surfaces:

- `SCARCITY_GOVERNANCE.md` still describes a hard finalization revert and manual-only liveness recovery.
- `SCANNER_TRIAGE.md` still says finalization enforces solvency before council refunds.
- `GOVERNANCE.md` still references an automated refund guard as a future constraint.
- `PATIENT_FUND_POLICY.md` describes current refund and insolvency behavior but needs to align with the accepted priority policy.
- Dashboard finalization copy must distinguish insufficient liquidity from finalization failure.

Do not mass-edit these files until the decisions above are accepted.

## Non-Destructive Workflow Guardrails

- Do not clean, reset, or absorb unrelated dirty files to prepare this work.
- Missing named resources are a stop condition, not permission to operate on nearby resources.
- Do not substitute closest matches for VMs, branches, files, env vars, credentials, deployments, or databases.
- Do not override global `$HOME`, PATH, credentials, RPC endpoints, shell profiles, or provider configuration to make commands pass.
- Do not validate recovery with real funds, production credentials, irreversible approvals, live privileged endpoints, or latent destructive setup.
- Classifiers, reviewers, and guardrails should fail closed and explain uncertainty.

## Acceptance Checklist

Before Antigravity implements the next solvency step:

- [ ] Claimant priority decision accepted.
- [ ] Council refund priority decision accepted.
- [ ] Reclaim grace-period insolvency decision accepted.
- [ ] Event/storage naming or documentation decision accepted.
- [ ] Preview/dashboard semantics accepted.
- [ ] Stale docs to update are explicitly selected.
- [ ] Tests remain isolated to local mock tokens and do not require live credentials, live funds, or production endpoints.
