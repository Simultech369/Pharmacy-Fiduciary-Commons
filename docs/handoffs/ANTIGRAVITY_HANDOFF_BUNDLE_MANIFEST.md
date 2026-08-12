# Antigravity Handoff Bundle Manifest

Status: current front-door handoff for the patient-fund solvency lane.

Prepared: 2026-07-19.

Repository: `<LOCAL_REPO_ROOT>`

Current base checkpoint: `266016c83d544f86dbb67a49240356852e0498b4` (`Queue patient fund solvency debt`)

## Start Here

This manifest packages the Codex planning work accumulated while Antigravity was unavailable. It is meant to reduce ambiguity, not expand scope.

Current instruction to Antigravity:

> Stop before implementation unless owner/governance has recorded explicit policy decisions and a separate file-scoped implementation authorization exists.

Current authorization: no contract, test, dashboard, automation, deployment, top-up, cleanup, commit, or push action is authorized by this bundle.

## Snapshot Gate

Before relying on this handoff, run:

```powershell
git rev-parse HEAD
git branch --show-current
git status --short
```

Expected:

- branch: `main`
- HEAD: `266016c83d544f86dbb67a49240356852e0498b4`
- working tree: intentionally dirty with local planning artifacts and unrelated Antigravity backlog

If branch or HEAD differs, report `SNAPSHOT_MISMATCH` and stop unless the owner explicitly asks for drift reconciliation.

Do not clean, reset, stash, delete, rename, move, absorb, stage, commit, push, or substitute closest-match files to make the snapshot fit.

## Known Dirty Backlog To Preserve

Tracked modified files currently include unrelated backlog:

- `ANTIGRAVITY_CURRENT_HANDOFF.md`
- `README.md`
- `contracts/PharmacyMutualCredit.sol`
- `dashboard/index.html`
- `dashboard/web3_integration.js`
- `supabase/schema.sql`
- `test/PharmacyMutualCredit.test.js`
- `tools/offline/continuity-kit.html`

Untracked local planning/review artifacts currently include:

- `AGENT_REVIEW_ORCHESTRATION.md`
- `ANTIGRAVITY_KIMI_REVIEW_HANDOFF.md`
- `ANTIGRAVITY_HANDOFF_BUNDLE_MANIFEST.md`
- `ANTIGRAVITY_SOLVENCY_IMPLEMENTATION_PACKET.md`
- `CODEX_KIMI_RECONCILIATION_HANDOFF.md`
- `CODEX_SOLVENCY_PLANNING_ADDENDUM.md`
- `HANDOFF_TO_CODEX_5_5.md`
- `PBM_BOUNDED_WORK_LOOP_NOTES.md`
- `PBM_EVM_HACK_LESSONS.md`
- `PBM_HUMAN_LANGUAGE_AND_DESIGN_NOTES.md`
- `PUBLIC_PROGRESS_NOTE_DRAFT.md`
- `SOLVENCY_DEBT_SEMANTICS.md`
- `SOLVENCY_OWNER_DECISION_WORKSHEET.md`
- `SOLVENCY_REVIEW_AUTHORITY_AND_SAFETY.md`
- `dashboard/design-system.css`
- `grok-review-prompt.txt`
- `kimi-long-context-review-prompt.txt`
- `review-context/`
- `reviews/`
- `scripts/openrouter_review.py`
- `scripts/pre_commit_audit.py`
- `zero-zk-review-prompt.txt`

Treat these as backlog or planning evidence. Do not absorb them into an implementation slice unless the owner explicitly scopes them.

## Bundle Order

Read in this order:

1. `ANTIGRAVITY_HANDOFF_BUNDLE_MANIFEST.md`
   - Current entry point and package map.
2. `ANTIGRAVITY_SOLVENCY_IMPLEMENTATION_PACKET.md`
   - The operative stop gate. It currently authorizes no implementation.
3. `SOLVENCY_OWNER_DECISION_WORKSHEET.md`
   - Decision worksheet. Blank fields and uncertainty mean `DEFER / DO NOT IMPLEMENT YET`.
4. `SOLVENCY_DEBT_SEMANTICS.md`
   - Draft semantics table and policy questions for solvency behavior.
5. `SOLVENCY_REVIEW_AUTHORITY_AND_SAFETY.md`
   - Authority order, artifact roles, claim ledger, side-effect matrix, and public-building boundary.
6. `CODEX_SOLVENCY_PLANNING_ADDENDUM.md`
   - Narrative summary for Antigravity.
7. `HANDOFF_TO_CODEX_5_5.md`
   - Codex reviewer/planner role boundary.
8. Optional advisory notes:
   - `PBM_EVM_HACK_LESSONS.md`
   - `PBM_HUMAN_LANGUAGE_AND_DESIGN_NOTES.md`
   - `PBM_BOUNDED_WORK_LOOP_NOTES.md`
9. Local review protocol and evidence, not public by default:
   - `AGENT_REVIEW_ORCHESTRATION.md`
   - `review-context/*.md`
10. Public-safe draft, not approved for publication:
   - `PUBLIC_PROGRESS_NOTE_DRAFT.md`

## Packet Anchor Table

Hash method: SHA-256 of current UTF-8 file content. For this manifest only, the anchor hash excludes the generated table block between `PACKET_ANCHOR_TABLE_BEGIN` and `PACKET_ANCHOR_TABLE_END`, so the table can carry a stable self-anchor.

<!-- PACKET_ANCHOR_TABLE_BEGIN -->
| File | Packet Class | Role | SHA-256 |
|---|---|---|---|
| `ANTIGRAVITY_HANDOFF_BUNDLE_MANIFEST.md` | local-planning | Front-door manifest and snapshot gate | `445aa2a3f3dd21213c8bc15270125577664cb46714db2d58e4d74c9312fa7250` |
| `ANTIGRAVITY_SOLVENCY_IMPLEMENTATION_PACKET.md` | local-planning | Stop-gated implementation packet template | `a199b7fff06d4521cbadc1f738805368571f30e98bcb3ff512424c317572de5d` |
| `SOLVENCY_OWNER_DECISION_WORKSHEET.md` | local-planning | Owner/governance decision worksheet | `cb9b5599662b65758eacf594c71e137d27cf0bb366baa4080f86e21da72eccc2` |
| `SOLVENCY_DEBT_SEMANTICS.md` | local-planning | Draft solvency semantics and policy table | `69e37ec0d30d56072a3d8a9a1a173e132343cea9f915d67983aa478eef9a7e80` |
| `SOLVENCY_REVIEW_AUTHORITY_AND_SAFETY.md` | local-planning | Authority ledger, claim ledger, and side-effect matrix | `6e4b2eb9dd7ce410c651d54293dcf2462244bccf3a72a5f644421e1c275cf5bc` |
| `PUBLIC_PROGRESS_NOTE_DRAFT.md` | public-draft | Public-safe draft, not publication approved | `ab608b88ee92eed4306ae4341905b66cb456c483438d25bde9db484fe8ab149d` |
| `CODEX_SOLVENCY_PLANNING_ADDENDUM.md` | local-planning | Narrative planning addendum | `595729dc15ce9830b790567061803e8bb5d05bd4143c1ab5781929561ec992f7` |
| `HANDOFF_TO_CODEX_5_5.md` | local-planning | Codex reviewer/planner role boundary | `385966ab1ad8e28e62146cbdff3b2c991197dfce584d7c1c45226228e418d739` |
| `AGENT_REVIEW_ORCHESTRATION.md` | local-planning | Review-packet and model-cycle protocol | `d33722c1d84dbbde00cfbb70cd12a575bf5c74a9837fba739db576661af0453a` |
| `PBM_EVM_HACK_LESSONS.md` | advisory | Security checklist for future authorized slices | `d88d2dafb78dd918c7db735ba25edf8c2678a37fa9c31c0dfa3e1583e5f4be45` |
| `PBM_HUMAN_LANGUAGE_AND_DESIGN_NOTES.md` | advisory | Copy/design guidance, not a style gate | `09c430be8d4adb95e08fd93775be2a37118f5d12c63305aaa392e506b6e97526` |
| `PBM_BOUNDED_WORK_LOOP_NOTES.md` | advisory | Bounded-loop workflow notes, not automation authority | `5c266120d39606ceffac720d47cca347e89d81383944ce322ae4423307a2182f` |
<!-- PACKET_ANCHOR_TABLE_END -->

## Historical Or Local-Only Inputs

These files can contain useful context but are not the current solvency entry point:

- `ANTIGRAVITY_CURRENT_HANDOFF.md`: historical ZK/resilience handoff anchored to an older checkpoint; do not use as the current solvency snapshot gate.
- `ANTIGRAVITY_KIMI_REVIEW_HANDOFF.md`: older Kimi review workflow; local-only unless specifically redacted and approved.
- `CODEX_KIMI_RECONCILIATION_HANDOFF.md`: local reconciliation context, not publication or implementation authority.
- raw model outputs, provider notes, prompt files, and `review-context/`: claim sources only.

## Current Solvency Decision State

Still deferred:

- claimant priority under scarce liquidity;
- council refund priority;
- unpaid council refund treatment;
- reclaim timing during insolvency;
- debt/shortfall ABI and event terminology;
- top-up and refresh automation.

Disclosure-only current prototype limits:

- lifecycle can continue while shortfall exists;
- payment depends on actual token liquidity;
- `DebtSettled` means cached observed shortfall decreased, not repayment;
- `previewFinalize().isSufficient == false` is not a finalization-revert flag.

No existing test, current code behavior, reviewer agreement, or draft recommendation ratifies a policy choice.

## Safe Next Antigravity Action

The first safe Antigravity action is read-only:

1. Verify the snapshot gate.
2. Read this manifest and `ANTIGRAVITY_SOLVENCY_IMPLEMENTATION_PACKET.md`.
3. Confirm whether accepted policy decisions and separate implementation authorization exist.
4. If either is missing, stop and report the missing decision or authorization.

If policy and implementation authorization later exist, Antigravity should be prepared to implement only the named slice and files.

## Explicit Do Not Do

- Do not implement claimant queues, pro-rata claims, partial claims, council-refund subordination, reclaim tolling, debt ceilings, event renames, or automation without explicit authorization.
- Do not run tests/builds/scripts unless the command and side effects are approved.
- Do not touch live funds, RPCs, credentials, multisigs, deployments, databases, roles, approvals, or production endpoints.
- Do not repair missing branches, VMs, environment variables, provider routes, or closest-match resources.
- Do not publish local paths, dirty file lists, reviewer/provider metadata, raw model outputs, private strategy notes, or comparison-project internals.
- Do not turn public progress wording into policy acceptance.

## Handoff Prep Receipt

Loop: Antigravity handoff prep

Scope: PBM solvency planning docs only

Check: no local-path leak in shareable surfaces, no owner-policy overclaim, no implementation authorization implied, no unrelated backlog absorbed

Result: handoff package is ready for read-only Antigravity intake; implementation remains blocked pending policy decisions and authorization.

Final-review disposition: local Mistral/Gemma/Qwen produced docs-only wording refinements; approved Hy3 produced duplicate boundary signal plus a launch-card wording option; Cohere North Mini Code returned provider failure and no claims were promoted.

Next: prepare owner/governance decisions or keep all unresolved items as `DEFER / DO NOT IMPLEMENT YET`.
