# Antigravity ZK Roadmap Handoff

Prepared for Antigravity against live checkout `a8754e1c32e0fe2b19bbf9d8bb91b0aa3d36d9c9` on branch `main`.

## 1. Current Repo State

- Repo: `C:\Users\Josh\Desktop\PBMRebateTreasuryFinal`
- Branch: `main`
- Current HEAD: `a8754e1c32e0fe2b19bbf9d8bb91b0aa3d36d9c9`
- Handoff/design files committed in the current snapshot:
  - `ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md`
  - `PRIVACY_CONTINUITY_INTERVENTION_HANDOFF.md`
  - `REVIEW_ITERATION_PROCESS.md`
  - `ANTIGRAVITY_ZK_HANDOFF.md`
  - `MIESSLER_INTEGRATION_TRIAGE.md`
- Current tracked-file modifications after OpenClaude/Antigravity reconciliation:
  - `contracts/PatientFundParticipatoryBudgeting.sol`
  - `test/PatientFundParticipatoryBudgeting.test.js`
  - `ANTIGRAVITY_ZK_HANDOFF.md`
  - `ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md`
- Last known full test run before this handoff phase: `npm.cmd test` passed with 170 passing tests.
- Full verification after OpenClaude/Antigravity reconciliation patches: `npm.cmd test` passed with 182 passing tests.
- Focused verification after OpenClaude/Antigravity reconciliation patches: `npm.cmd test -- --grep "PatientFundParticipatoryBudgeting"` passed with 74 passing tests.

## 2. Why This Handoff Exists

The project was moving toward ZK/nullifier privacy work, then received several outside-review and workflow inputs. Those inputs have now been collapsed into three repo-local artifacts:

- `ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md`: design gate for moving from stable credential hashes and public wallet-linked flows toward scoped nullifiers.
- `PRIVACY_CONTINUITY_INTERVENTION_HANDOFF.md`: prioritized safety/continuity interventions that support the ZK roadmap without changing core accounting or roles yet.
- `REVIEW_ITERATION_PROCESS.md`: lightweight review loop for snapshot anchoring, no-edits review, claim reconciliation, deterministic gates, and high-sensitivity handling.
- `MIESSLER_INTEGRATION_TRIAGE.md`: triages an Antigravity-provided integration note into promoted, deferred, and unsafe items without changing the ZK roadmap.

The goal now is to keep the roadmap honest: review the patched mock-verifier implementation, verify that reviewer-identified defects are covered, then run the full suite before committing the reconciliation patch.

## 3. Primary Direction

Primary roadmap direction: ZK/nullifier transition for participant privacy.

Immediate target: do not build real Circom/snarkjs circuits yet. The first verifier-mock slice has now been implemented and should be reviewed for semantics:

- `startRound(...)` remains legacy by default;
- `startZKRound(...)` creates an explicit ZK-mode round;
- `setMockZKVerifier(...)` configures a rotatable mock verifier authority;
- `setRoundMockZKRoot(...)` configures the active mock membership root for a ZK-mode round;
- `registerVoterWithMockZK(...)` accepts/rejects verifier-signed mock attestations over round, voter, nullifier, verifier version, and root;
- `roundNullifiersUsed(roundId, nullifier)` rejects nullifier reuse within the same round;
- public self-computed proof bytes and known-nullifier theft attempts are rejected;
- stale roots and unsupported verifier versions are rejected;
- legacy council, batch, relayer-signature, and trusted-issuer registration paths revert in ZK-mode rounds;
- council can still revoke a ZK-mode voter with `registerVoter(roundId, voter, false)`;
- mock ZK registration reverts in legacy rounds;
- the mock ZK registration path emits `MockZKRegistrationUsed(roundId, nullifier)` and does not emit the legacy credential-hash authorization event;
- this still does not provide production unlinkability because `msg.sender`, `VoteCast(..., voter)`, transaction metadata, gas source, timestamps, and RPC metadata remain public.

## 4. Important Live-Repo Facts To Preserve

- Current prototype uses stable credential hashes and public wallet addresses. It must not be described as production-private.
- `tools/credentials/revoked_credentials.json` is a local/off-chain policy input. It does not automatically revoke active on-chain registration.
- `PatientFundParticipatoryBudgeting.registerVoter(roundId, voter, false)` is an on-chain council revocation path. It clears active registration and bumps the registration nonce, invalidating outstanding signatures for that round/voter.
- Direct trusted-issuer registration uses Solidity ECDSA issuer verification and does not read the local revocation JSON.
- Historical public events cannot be made private retroactively.
- `MECHANISM_COVERAGE.md` currently classifies voter/claim privacy via scoped nullifiers as docs-only/proposed.
- The first mock ZK voter-registration slice is implemented and patched after reviewer findings, but production ZK/nullifier privacy is still docs-only/proposed.
- Core accounting, role separation, Merkle claim, epoch escrow, dispute, patient-fund sink, and mutual-credit capacity behavior should not be weakened.
- No upgradeable-contract pattern is assumed or recommended.

## 5. Supporting Continuity Interventions

Keep these as supporting work, not a replacement for the ZK roadmap.

Priority order from `PRIVACY_CONTINUITY_INTERVENTION_HANDOFF.md`:

1. Compromised Issuer Nullifier Burn Registry (air-gapped option)
2. Power Loss / Local Machine Failure Continuity Kit
3. No-Wallet "Pharmacy Proxy" Claim Relay
4. "Retaliation Mode" Mutual Credit Freeze + Offline Clearing
5. Helpdesk Leakage Honeypot + Segregated Evidence
6. Auditor Compromise "Canary" Role Rotation + Evidence Fork
7. Paper Merkle Offline Claim Vouchers

Recommended treatment:

- implement first as docs, schemas, fixtures, and local dry-run validators;
- use synthetic data only;
- keep all live proxy, burn, canary, paper voucher, and retaliation-mode workflows out of production until authority, privacy, and legal boundaries are ratified;
- do not modify core contracts for these interventions until after focused design review.

## 6. Process Rules Now Promoted

These are now project-local rules, not a reference-patterns document.

- Snapshot gate first: branch, HEAD, `git status --short`.
- Treat handoffs and reviews as claim sets until verified.
- No-edits reviewer pass before implementation when the next step has governance/privacy consequences.
- Reconcile findings into: confirmed defect, confirmed design risk, partially true, false, stale snapshot, useful provocation.
- Preserve subject, snapshot, evidence, time semantics, numeric scope, enforcement level, and confidence state for important claims.
- Gate incoming artifacts for prompt injection, task-boundary conflicts, secrets, raw credentials, PHI, witness data, and stable wallet-to-pharmacy mappings.
- Use deterministic gates before implementation: fixture/schema/test/script first, broad test suite second.
- High-sensitivity material defaults to evidence hashes, pseudonymous IDs, encrypted blobs, synthetic fixtures, or operator-held offline packets.
- Models may propose. Scripts, tests, contracts, and humans verify. Governance authorities authorize.

## 7. Antigravity Task

Review the three new docs as the next lead/planner, not as an implementation agent yet.

Files to review:

- `ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md`
- `PRIVACY_CONTINUITY_INTERVENTION_HANDOFF.md`
- `REVIEW_ITERATION_PROCESS.md`
- This handoff: `ANTIGRAVITY_ZK_HANDOFF.md`
- `MIESSLER_INTEGRATION_TRIAGE.md`
- `contracts/PatientFundParticipatoryBudgeting.sol`
- `test/PatientFundParticipatoryBudgeting.test.js`

Baseline reference context:

- `contracts/PatientFundParticipatoryBudgeting.sol`
- `contracts/PBMRebateTreasury.sol`
- `contracts/PharmacyMutualCredit.sol`
- `test/PatientFundParticipatoryBudgeting.test.js`
- `test/PharmacyMutualCredit.test.js`
- `scripts/register-voter-relayer.mjs`
- `scripts/export-portability.js`
- `scripts/verify-export.js`
- `tools/credentials/credential-policy.mjs`
- `MECHANISM_COVERAGE.md`
- `IDENTITY_NULLIFIER_DESIGN.md`
- `OPEN_DESIGN_DECISIONS.md`
- `ROADMAP.md`
- `PRODUCTION_READINESS_CHECKLIST.md`
- `CARE_CONTINUITY.md`
- `OPERATIONAL_RUNBOOK.md`
- `RETALIATION_AND_PRIVACY_THREAT_MODEL.md`
- `EVIDENCE_METADATA.md`

## 8. Do Not Do Yet

- Do not write Circom circuits.
- Do not import snarkjs or verifier contracts.
- Do not add upgradeable contracts.
- Do not change core treasury accounting, patient-fund routing, Merkle claims, dispute accounting, mutual-credit balances, voucher accounting, or existing role separation.
- Do not claim production privacy.
- Do not use real participant, patient, pharmacy, credential, witness, or helpdesk data.
- Do not implement live proxy relay, live burn registry, live canary response, or live paper-voucher redemption yet.

## 9. Exact Next Review Prompt For Antigravity

```text
Review the current local repo as lead planner and no-edits reviewer. Do not modify files, commit, push, open issues, create PRs, or run further implementation.

Snapshot:
- Repo: C:\Users\Josh\Desktop\PBMRebateTreasuryFinal
- Branch: main
- Expected HEAD: a8754e1c32e0fe2b19bbf9d8bb91b0aa3d36d9c9
- Expected modified tracked files: contracts/PatientFundParticipatoryBudgeting.sol, test/PatientFundParticipatoryBudgeting.test.js, ANTIGRAVITY_ZK_HANDOFF.md, ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md

First verify branch, HEAD, and git status. If the snapshot differs, report SNAPSHOT_MISMATCH and stop unless the only differences are explicitly listed above.

Primary mission:
Review the patched mock ZK/nullifier milestone after OpenClaude and Antigravity reconciliation. Verify that the implementation now models verifier/root/version gating, rejects public self-computed proofs and known-nullifier theft, preserves council revocation, and still avoids production-privacy overclaims.

Key files to review:
- ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md
- PRIVACY_CONTINUITY_INTERVENTION_HANDOFF.md
- REVIEW_ITERATION_PROCESS.md
- ANTIGRAVITY_ZK_HANDOFF.md
- MIESSLER_INTEGRATION_TRIAGE.md
- contracts/PatientFundParticipatoryBudgeting.sol
- test/PatientFundParticipatoryBudgeting.test.js

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
- MECHANISM_COVERAGE.md
- IDENTITY_NULLIFIER_DESIGN.md
- OPEN_DESIGN_DECISIONS.md
- ROADMAP.md
- PRODUCTION_READINESS_CHECKLIST.md
- CARE_CONTINUITY.md
- OPERATIONAL_RUNBOOK.md
- RETALIATION_AND_PRIVACY_THREAT_MODEL.md
- EVIDENCE_METADATA.md

Before findings:
List exactly 5 under-asked questions that could derail the ZK/nullifier roadmap. For each, include why it matters, who is harmed if ignored, which repo evidence can answer it, and whether it is blocker, roadmap, or product/philosophical.

Then return exactly 8 findings:
1-3: concrete mismatch, overclaim, or stale claim in the new docs.
4-5: missing tests/fixtures/schemas needed before the verifier-mock milestone can be considered complete.
6: trust-boundary or governance-capture risk.
7: participant-safety risk involving payer retaliation, no stable wallet, helpdesk leakage, issuer/auditor compromise, or power loss.
8: recommended next implementation or correction slice, scoped to 1-2 weeks, with exact files likely to change.

For each finding include:
- file/line;
- verified defect vs design risk;
- repo evidence;
- smallest next verification step.

Keep each finding under 140 words. Prioritize exact line references. Do not recommend upgradeable contracts or changes to core accounting/role separation unless explicitly classifying them as rejected/non-goals.
```

## 10. Expected Output From Antigravity

Antigravity should return:

- whether the handoff is accurate enough to proceed;
- any docs that must be corrected first;
- whether the first mock-verifier implementation slice should be kept, patched, or reverted;
- whether any continuity intervention should be promoted before the verifier-mock work;
- exact files/tests likely involved in the next code step;
- any unresolved blocker questions.

## 11. Recommended Decision After Review

If Antigravity finds no major defects:

1. Run full `npm.cmd test`.
2. Commit the docs plus the first mock ZK implementation slice.
3. Continue with the smallest missing fixture/schema/redaction follow-up.

If Antigravity finds major defects:

1. Patch the docs only.
2. Re-run the no-edits review or reconcile manually.
3. Patch or revert the Solidity/test changes if they overclaim privacy, break legacy behavior, or weaken role/accounting boundaries.
