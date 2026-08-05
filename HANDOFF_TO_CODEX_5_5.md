# Handoff to Codex 5.5: Strategy & Multi-Agent Planning

Status: active planning handoff, updated after checkpoint `266016c83d544f86dbb67a49240356852e0498b4`.

Repository: `<LOCAL_REPO_ROOT>`

## Role Boundary

- Codex 5.5: brainstormer, reviewer, and plan editor.
- Codex 5.6: read-only second-opinion reviewer and critique pass.
- Antigravity: candidate implementer only after explicit owner/governance policy acceptance and separate file-scoped implementation authorization.
- Project owner/governance: final authority for solvency policy choices.

Do not treat model agreement, existing tests, current checkpoint behavior, or a draft markdown recommendation as accepted policy.

## Current Solvency Planning Gate

The checkpoint permits patient-fund round start and finalization while underbacked. This restores governance lifecycle liveness only. It does not ensure payment liveness and does not create a creditor-level debt ledger.

Existing contract behavior and regression tests are characterization evidence, not accepted governance policy. They currently exhibit:

- full-only claims with first-successful-transaction payment competition;
- available-balance council refunds without reserving prior project shares;
- fixed 90-day reclaim timing even if a share was never payable;
- continued lifecycle operations while a shortfall exists.

None of those behaviors may be treated as the owner's chosen policy merely because the checkpoint implements or tests them.

## Stop Before Implementation

Stop until owner/governance records explicit decisions for:

1. claimant priority under scarce liquidity;
2. council refund priority and unpaid-refund treatment;
3. reclaim timing while shares are not payable;
4. new-round behavior while prior obligations are underbacked;
5. exact meanings of `totalDebt`, `roundDeficit`, `DebtQueued`, and `DebtSettled`;
6. exact meanings of `previewFinalize().totalRequiredAfterFinalize` and `previewFinalize().isSufficient`.

Policy acceptance does not itself authorize implementation. Antigravity must receive separate explicit authorization for the selected implementation slice and allowed files.

If owner/governance authority is unavailable, mark the relevant question `DEFER / DO NOT IMPLEMENT YET`. Do not convert uncertainty into a prototype default.

## Non-Destructive Guardrails

- Do not edit, stage, commit, push, branch, clean, reset, delete, rename, or move files unless that action is explicitly authorized.
- Do not access private `file:///` handoffs, run external reviewers, invoke guardrail/provider scripts, or write planning artifacts unless separately authorized.
- Do not repair missing branches, VMs, environment variables, credentials, deployment names, RPC endpoints, or provider configuration.
- Do not substitute closest matches for named resources.
- Treat dirty files as user/Antigravity backlog unless explicitly scoped.
- Use only isolated local mock-token tests after approval; no live funds, credentials, deployments, privileged endpoints, or irreversible approvals.

## Current Planning Artifacts

- `ANTIGRAVITY_HANDOFF_BUNDLE_MANIFEST.md`: current front-door package for Antigravity's solvency handoff.
- `SOLVENCY_DEBT_SEMANTICS.md`: canonical draft decision table.
- `SOLVENCY_OWNER_DECISION_WORKSHEET.md`: deferred/accepted decision capture worksheet.
- `SOLVENCY_REVIEW_AUTHORITY_AND_SAFETY.md`: reviewer authority, claim ledger, artifact roles, and validation side-effect matrix.
- `ANTIGRAVITY_SOLVENCY_IMPLEMENTATION_PACKET.md`: packet template that currently records no implementation authorization.
- `PBM_EVM_HACK_LESSONS.md`: external hack-pattern translation for future security review checklists.
- `PBM_HUMAN_LANGUAGE_AND_DESIGN_NOTES.md`: optional guidance for public-safe copy, handoff voice, and dashboard language.
- `PBM_BOUNDED_WORK_LOOP_NOTES.md`: optional bounded-loop framing for handoff prep, reviewer cycles, and public drafts.
- `PUBLIC_PROGRESS_NOTE_DRAFT.md`: draft public-safe progress copy, not approved for publication.
- `CODEX_SOLVENCY_PLANNING_ADDENDUM.md`: Antigravity-facing planning addendum.
- `AGENT_REVIEW_ORCHESTRATION.md`: bounded reviewer prompt and model-review protocol.
- `review-context/2026-07-18-qwen-local-solvency-policy-reconciliation.md`: local Qwen summary-based advisory pass.
- `review-context/2026-07-18-deepseek-local-debtsettled-reconciliation.md`: local DeepSeek summary-based advisory pass.
- `review-context/2026-07-18-codex56-terra-solvency-handoff-reconciliation.md`: Codex 5.6 Terra read-only handoff review reconciliation.
- `review-context/2026-07-18-codex56-luna-dizzy-crossover-reconciliation.md`: Codex 5.6 Luna read-only crossover review reconciliation.

## Product Strategy Lane

The GPO proxy pivot, PBM retaliation mitigation, and Web3 onboarding strategy remain separate planning lanes. Do not mix those changes into the solvency policy implementation slice unless the owner explicitly combines the scopes.
