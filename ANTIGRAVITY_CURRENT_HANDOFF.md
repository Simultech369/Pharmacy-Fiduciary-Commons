# Antigravity Current Handoff

Prepared for Antigravity against live checkout `f1a8f00275b4d3fff1ee993091e02c692faa29cc` on branch `main`.

## 1. Current Repo State

- Repo: `C:\Users\Josh\Desktop\PBMRebateTreasuryFinal`
- Branch: `main`
- Current HEAD: `f1a8f00275b4d3fff1ee993091e02c692faa29cc`
- Recent relevant ancestor: `a8754e1c32e0fe2b19bbf9d8bb91b0aa3d36d9c9`, which implemented the first mock ZK/nullifier voter-registration milestone.
- The older `ANTIGRAVITY_ZK_HANDOFF.md` is useful design context, but its snapshot gate is stale. It was anchored to `a8754e1c32e0fe2b19bbf9d8bb91b0aa3d36d9c9`, not the current checkout.

Current dirty working tree expected for this handoff after Kimi/Hunyuan reconciliation and GPT-5.6 follow-up:

- Modified tracked files:
  - `ANTIGRAVITY_CURRENT_HANDOFF.md`
  - `ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md`
  - `contracts/PBMRebateTreasury.sol`
  - `scripts/deploy-timelock-and-treasury.js`
  - `test/ContinuityAndAdversarialTools.test.js`
  - `test/DeploymentGovernance.test.js`
  - `test/PBMRebateTreasury.security.test.js`
  - `tools/offline/continuity-kit.html`
  - `tools/resilience/continuity-engine.mjs`
- Untracked files:
  - `ANTIGRAVITY_KIMI_REVIEW_HANDOFF.md`
  - `CODEX_KIMI_RECONCILIATION_HANDOFF.md`
  - `grok-review-prompt.txt`
  - `kimi-long-context-review-prompt.txt`
  - `review-context/`
  - `scripts/deployment-policy.js`
  - `zero-zk-review-prompt.txt`

Focused verification after GPT-5.6 follow-up:

```powershell
npx.cmd hardhat test test\DeploymentGovernance.test.js test\ContinuityAndAdversarialTools.test.js test\PBMRebateTreasury.security.test.js
```

Result: 57 passing tests.

Full suite verification after GPT-5.6 follow-up:

```powershell
npm.cmd test
```

Result: 220 passing tests.

## 2. Why This Handoff Exists

The previous handoff lane focused on the ZK/nullifier mock milestone. The repo has now moved one layer outward into resilience and draft governance scaffolding:

- README language now distinguishes legacy stable-hash linkage risk, semantic mock ZK registration, and production ZK design status.
- `CooperativeParticipatoryBudgeting` now requires enough bootstrap participants to avoid a peer-attestation deadlock.
- `CooperativeParticipatoryBudgeting` now rejects zero-address peer attestations.
- `ReflexiveFiduciaryManifold` now restricts PID mutation to the deployer/controller, handles a zero matching target, and preserves derivative precision before applying `Kd`.
- `continuity-engine.mjs` now fails closed without a local MAC secret, refuses bad voucher MACs, omits voter addresses from offline voucher and relay artifacts, rejects duplicate relay nullifiers, and packages relay output as review material rather than on-chain proof material.
- `adversarial-guard.mjs` now labels tempest fuzzing as simulated local payload classification, not proof of live target defense, and flags synthetic seed-phrase leakage.
- New tests cover those boundaries.

The next Antigravity task should be no-edits review of this post-reconciliation patch. The task is to review whether these changes honestly preserve the ZK/privacy trust boundary, keep draft governance modules from looking production-ready, and avoid smuggling offline continuity artifacts into live settlement authority.

## 3. Primary Review Direction

Primary review direction: no-edits reconciliation of the current resilience/governance draft layer after the mock ZK milestone.

Antigravity should treat the current changes as a claim set until verified against the live repo. The main question is whether the new language, tools, and tests tighten boundaries or accidentally create new overclaims:

- Offline vouchers are degraded-mode recovery material, not on-chain proof material.
- Relay batches are review/intake packets, not production submissions.
- Tempest fuzz output is simulated local classification, not evidence a target blocked an attack.
- Draft governance/manifold contracts are review sketches, not integrated treasury/PB/mutual-credit runtime mechanisms.
- Mock ZK/nullifier registration remains semantic only and does not provide production unlinkability.

## 4. Important Live-Repo Facts To Preserve

- Legacy registration still exposes stable credential hashes and public wallet addresses.
- The mock ZK/nullifier registration slice in `PatientFundParticipatoryBudgeting` remains semantic only.
- Production privacy is still blocked by `msg.sender`, public voting events, gas source, timing, RPC metadata, and support/helpdesk leakage.
- Historical public events cannot be made private retroactively.
- Offline continuity tools must not contain private keys, raw credentials, PHI, witness secrets, or stable wallet-to-pharmacy mappings.
- Paper/offline voucher preimages are sensitive recovery material and must not be exported as mock ZK proofs.
- Local MAC verification is an operator-local integrity check, not protocol authorization.
- Current draft governance modules must not be represented as production mechanisms.
- Core treasury accounting, patient-fund routing, Merkle claims, dispute accounting, mutual-credit balances, voucher accounting, and existing role separation should not be weakened.
- No upgradeable-contract pattern is assumed or recommended.

## 5. Files To Review

Current changed files:

- `MIESSLER_INTEGRATION_TRIAGE.md`
- `PRIVACY_CONTINUITY_INTERVENTION_HANDOFF.md`
- `README.md`
- `REVIEW_ITERATION_PROCESS.md`
- `contracts/CooperativeParticipatoryBudgeting.sol`
- `contracts/ReflexiveFiduciaryManifold.sol`
- `tools/resilience/continuity-engine.mjs`
- `tools/security/adversarial-guard.mjs`
- `test/ContinuityAndAdversarialTools.test.js`
- `test/DraftGovernanceModules.test.js`

Roadmap and boundary context:

- `ANTIGRAVITY_ZK_HANDOFF.md`
- `ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md`
- `PRIVACY_CONTINUITY_INTERVENTION_HANDOFF.md`
- `REVIEW_ITERATION_PROCESS.md`
- `MIESSLER_INTEGRATION_TRIAGE.md`
- `MECHANISM_COVERAGE.md`
- `IDENTITY_NULLIFIER_DESIGN.md`
- `OPEN_DESIGN_DECISIONS.md`
- `ROADMAP.md`
- `PRODUCTION_READINESS_CHECKLIST.md`
- `CARE_CONTINUITY.md`
- `OPERATIONAL_RUNBOOK.md`
- `RETALIATION_AND_PRIVACY_THREAT_MODEL.md`
- `EVIDENCE_METADATA.md`

Baseline runtime files:

- `contracts/PatientFundParticipatoryBudgeting.sol`
- `contracts/PBMRebateTreasury.sol`
- `contracts/PharmacyMutualCredit.sol`
- `test/PatientFundParticipatoryBudgeting.test.js`
- `test/PharmacyMutualCredit.test.js`
- `scripts/register-voter-relayer.mjs`
- `scripts/export-portability.js`
- `scripts/verify-export.js`
- `tools/credentials/credential-policy.mjs`

## 6. Do Not Do Yet

- Do not write Circom circuits.
- Do not import snarkjs or verifier contracts.
- Do not add upgradeable contracts.
- Do not change core treasury accounting, patient-fund routing, Merkle claims, dispute accounting, mutual-credit balances, voucher accounting, or existing role separation.
- Do not claim production privacy.
- Do not use real participant, patient, pharmacy, credential, witness, helpdesk, or PHI data.
- Do not implement live proxy relay, live burn registry, live canary response, live paper-voucher redemption, or live retaliation-mode clearing.
- Do not treat generated offline vouchers, local MACs, or relay batches as settlement authority.
- Do not treat the draft governance/manifold contracts as integrated production runtime.

## 7. Exact Next Review Prompt For Antigravity

```text
Review the current local repo as lead planner and no-edits reviewer. Do not modify files, commit, push, open issues, create PRs, or run further implementation.

Snapshot:
- Repo: C:\Users\Josh\Desktop\PBMRebateTreasuryFinal
- Branch: main
- Expected HEAD: f1a8f00275b4d3fff1ee993091e02c692faa29cc
- Expected modified tracked files:
  - ANTIGRAVITY_CURRENT_HANDOFF.md
  - ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md
  - contracts/PBMRebateTreasury.sol
  - scripts/deploy-timelock-and-treasury.js
  - test/ContinuityAndAdversarialTools.test.js
  - test/DeploymentGovernance.test.js
  - test/PBMRebateTreasury.security.test.js
  - tools/offline/continuity-kit.html
  - tools/resilience/continuity-engine.mjs
- Expected untracked files:
  - ANTIGRAVITY_KIMI_REVIEW_HANDOFF.md
  - CODEX_KIMI_RECONCILIATION_HANDOFF.md
  - grok-review-prompt.txt
  - kimi-long-context-review-prompt.txt
  - review-context/
  - scripts/deployment-policy.js
  - zero-zk-review-prompt.txt

First verify branch, HEAD, and git status. If the snapshot differs, report SNAPSHOT_MISMATCH and stop unless the only differences are explicitly listed above.

Primary mission:
Review the current Kimi/Hunyuan reconciliation plus GPT-5.6 follow-up. Verify whether the deployment preflight now rejects open timelock executors before any non-local deployment transaction, whether continuity voucher MACs cover bearer artifact fields without implying ZK proof, whether `updateSanction` is pause-gated with regression coverage, and whether handoff/ZK docs avoid stale or production-privacy overclaims.

Key changed files:
- ANTIGRAVITY_CURRENT_HANDOFF.md
- ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md
- contracts/PBMRebateTreasury.sol
- scripts/deploy-timelock-and-treasury.js
- scripts/deployment-policy.js
- tools/offline/continuity-kit.html
- tools/resilience/continuity-engine.mjs
- test/ContinuityAndAdversarialTools.test.js
- test/DeploymentGovernance.test.js
- test/PBMRebateTreasury.security.test.js

Roadmap/boundary files:
- ANTIGRAVITY_ZK_HANDOFF.md
- ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md
- PRIVACY_CONTINUITY_INTERVENTION_HANDOFF.md
- REVIEW_ITERATION_PROCESS.md
- MIESSLER_INTEGRATION_TRIAGE.md
- MECHANISM_COVERAGE.md
- IDENTITY_NULLIFIER_DESIGN.md
- OPEN_DESIGN_DECISIONS.md
- ROADMAP.md
- PRODUCTION_READINESS_CHECKLIST.md
- CARE_CONTINUITY.md
- OPERATIONAL_RUNBOOK.md
- RETALIATION_AND_PRIVACY_THREAT_MODEL.md
- EVIDENCE_METADATA.md

Baseline files to verify against:
- contracts/PatientFundParticipatoryBudgeting.sol
- contracts/PBMRebateTreasury.sol
- contracts/PharmacyMutualCredit.sol
- test/PatientFundParticipatoryBudgeting.test.js
- test/PharmacyMutualCredit.test.js
- scripts/register-voter-relayer.mjs
- scripts/export-portability.js
- scripts/verify-export.js
- tools/credentials/credential-policy.mjs

Known verification already run before this prompt:
- npm.cmd test -- --grep "Continuity and adversarial draft tools|Draft governance modules"
- Result before review reconciliation: 6 passing tests
- Result after review reconciliation: 11 passing tests
- npm.cmd test
- Result after review reconciliation: 193 passing tests

Before findings:
List exactly 5 remaining under-asked questions that could derail this resilience/governance layer or corrupt the ZK/nullifier roadmap. For each, include why it matters, who is harmed if ignored, which repo evidence can answer it, and whether it is blocker, roadmap, or product/philosophical.

Then return exactly 8 findings:
1-2: concrete mismatch, stale claim, or overclaim in README or handoff/roadmap docs.
3-4: trust-boundary or data-leakage risk in continuity-engine or adversarial-guard.
5-6: missing tests, invariants, or integration boundaries for CooperativeParticipatoryBudgeting or ReflexiveFiduciaryManifold.
7: participant-safety risk involving payer retaliation, no stable wallet, helpdesk leakage, issuer/auditor compromise, or power loss.
8: recommended next correction or implementation slice, scoped to 1-2 weeks, with exact files likely to change.

For each finding include:
- file/line;
- verified defect vs design risk;
- repo evidence;
- smallest next verification step.

Keep each finding under 140 words. Prioritize exact line references. Do not recommend upgradeable contracts or changes to core accounting/role separation unless explicitly classifying them as rejected/non-goals.
```

## 8. Expected Output From Antigravity

Antigravity should return:

- whether this current handoff is accurate enough to proceed;
- whether any docs still must be corrected before implementation continues;
- whether the current dirty changes should be kept, patched, split, or reverted before commit;
- whether the accepted findings from the prior Antigravity pass were adequately corrected;
- whether the new tests cover the highest-risk claims or miss important boundaries;
- whether the continuity tooling creates any accidental custody, proof, privacy, or settlement-authority confusion;
- whether the draft governance modules need stronger test-only/non-production fencing;
- exact files/tests likely involved in the next code step.

## 9. Recommended Decision After Review

If Antigravity confirms the current direction:

1. Patch any language that still overclaims privacy, live target defense, settlement authority, or production readiness.
2. Add any small missing tests Antigravity identifies around voucher shape, local secret handling, controller access, bootstrap threshold, and zero/edge values.
3. Run the focused tests again.
4. Run `npm.cmd test` before committing.
5. Commit the current resilience/governance reconciliation separately from future ZK circuit or live relay work.

If Antigravity finds a boundary violation:

1. Patch or revert the violating behavior first.
2. Keep the issue scoped to the changed files above unless the finding proves a broader baseline bug.
3. Do not expand into real ZK, live proxy relay, or production governance integration without a new snapshot gate.
