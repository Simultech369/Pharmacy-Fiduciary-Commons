# [SUPERSEDED] Next Review Handoff

> [!WARNING]
> **SUPERSEDED / HISTORICAL DOCUMENT**
> This handoff document corresponds to a historical state (HEAD `ba57949` with 193 tests). It has been superseded by the 2026-07-15 review findings and subsequent implementation of the pre-deployment policy checks, bearer voucher integrity updates, and regression test suite.

Prepared from `C:\Users\Josh\Desktop\PBMRebateTreasuryFinal` after the pushed reconciliation commit:

- Branch: `main`
- Reconciliation baseline: `ba57949 Reconcile resilience governance review findings`
- Handoff status: this file was created after `ba57949` and later committed as a planning handoff
- Last full verification before the handoff review: `npm.cmd test` passed with 193 passing tests
- Snapshot rule: the active HEAD for future review should contain this file and descend from `ba57949`

## 1. North Star

Build a Pharmacy Fiduciary Commons:

- transparent rebate custody;
- root-backed pharmacy claim routing;
- patient-fund allocation;
- participant portability and contestable evidence;
- eventually adjacent independent-pharmacy mutual-aid infrastructure.

The project is explicitly still a prototype. It is not audited, not mainnet deployed, not safe for real funds, not safe for real PHI, and not ready for public participant intake.

The right framing is not "trustless." The current framing is: publicly verifiable mechanisms with bounded trust roots, explicit role separation, auditable evidence, and honest disclosure of what is contract-enforced versus script-supported, dashboard-supported, docs-only, or not implemented.

## 2. Current Published State

The implementation checkpoint under review is `ba57949`. This handoff was created and committed after that checkpoint to preserve next-milestone planning.

What was closed in that commit:

- Antigravity-reviewed resilience/governance review findings were reconciled.
- `CooperativeParticipatoryBudgeting.sol` and `ReflexiveFiduciaryManifold.sol` remain decoupled draft modules.
- `CooperativeParticipatoryBudgeting.sol` now avoids bootstrap attestation deadlock and rejects zero-address peer attestations.
- `ReflexiveFiduciaryManifold.sol` now restricts PID mutation to the deployer/controller, handles zero matching targets, and preserves fractional derivative precision before applying `Kd`.
- `continuity-engine.mjs` now fails closed without `LOCAL_MAC_SECRET`, omits voter addresses from offline voucher and relay artifacts, rejects bad voucher MACs, rejects duplicate relay nullifiers, and labels relay output as not ready for on-chain submission.
- `adversarial-guard.mjs` now labels tempest fuzzing as simulation-only and adds synthetic API-key / seed-phrase leakage detection.
- `README.md` now distinguishes legacy stable-hash linkage risk, semantic mock ZK registration, and production ZK design status.
- Older snapshot-bound handoff docs were marked as historical/contextual instead of silently retargeted to the current commit.

What is not closed:

- The resilience/governance mechanisms are not production infrastructure.
- Offline vouchers are not settlement authority.
- Local MACs are not protocol authorization.
- The mock ZK/nullifier path is not production privacy.
- The draft governance/manifold contracts are not integrated into the treasury, patient-fund, or mutual-credit runtime.
- No live proxy relay, live burn registry, live paper-voucher redemption, live canary response, live retaliation freeze, or live ZK verifier integration exists.

## 3. Canonical Phase Roadmap

The canonical roadmap remains the phase map in `ROADMAP.md`.

### Phase 0: Prototype Hardening Gate

Current phase.

Goals:

- keep tests green;
- keep claims honest;
- preserve scanner triage;
- resolve public-readiness gaps;
- make unresolved policy choices visible in `OPEN_DESIGN_DECISIONS.md`;
- avoid public, mainnet, audit, privacy, autonomy, or "production-ready" overclaims.

Important gates before launch:

- public forms and intake safety;
- auth and database boundaries;
- secrets handling;
- rate limits and abuse controls;
- accessibility audit;
- provider trust boundaries;
- offline/non-digital workflow safety;
- privacy-safe metrics;
- scanner refresh and audit prep.

### Phase 1: Security Audit And Testnet Deployment

Goal: code validation and parameter calibration.

Planned work:

- formal third-party audit;
- Sepolia / Arbitrum Sepolia deployment;
- calibrate `initialDailyCap`, `RECALL_DELAY`, and `governanceBP`;
- validate Merkle and proof tooling;
- run dashboard against testnet addresses;
- avoid any implication of production status.

### Phase 2: First Live Epoch With Small Capital Guardrails

Only after Phase 0 and Phase 1 gates pass.

Planned work:

- deploy to a low-gas mainnet such as Arbitrum One or Base;
- configure separate Safe/timelock/guardian/root-confirmer roles;
- rehearse forced-ETH recovery;
- document chain timing assumptions;
- run a constrained first epoch, around a $1,000 maximum daily volume;
- treat the epoch as an operational trial, not proof of maturity.

### Phase 3: First Participatory Budgeting Round

Goal: use patient-fund resources from claim routing and recalls for local participatory allocation.

Current behavior:

- credential-gated voting;
- squared vote-count weighting;
- council/project boundaries;
- semantic mock ZK registration path for testing only.

Deferred:

- canonical QF claims;
- production ZK privacy;
- fully decentralized project eligibility;
- public voter identity unlinkability.

Target use:

- co-pay assistance;
- independent pharmacy resilience;
- patient-fund allocation experiments with honest privacy limits.

### Phase 4: Adjacent Parallel Infrastructure

Goal: broader independent-pharmacy resilience stack.

Candidate infrastructure:

- cooperative procurement;
- mutual-credit / voucher clearing;
- rebate transparency registry;
- offline receipt reconciliation;
- proxy/fallback workflows;
- privacy-safe operational evidence;
- local federation governance experiments.

Current rule: keep adjacent primitives decoupled until reviewed, tested, and explicitly integrated.

## 4. Operational Roadmap Inside Phase 0

The highest-leverage next lane is the ZK/nullifier design gate.

This does not mean writing circuits next. The next step is decision closure and test/fixture design before Circom, snarkjs, Solidity verifier integration, or dashboard ZK UX.

### Lane A: ZK / Nullifier Design Closure

Source: `ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md`.

Decisions required before circuits:

- issuer trust and proof model;
- non-revocation model;
- wallet/address privacy strategy;
- legacy migration boundary;
- verifier and circuit governance;
- proving key and witness handling;
- care-continuity fallback when privacy fails.

Current implemented status:

- first mock slice exists in `PatientFundParticipatoryBudgeting.sol`;
- explicit ZK-mode rounds exist;
- mock verifier/root/version gating exists;
- per-round nullifier reuse protection exists;
- legacy and ZK rounds are separated;
- council revocation in ZK mode is covered;
- tests preserve the fact that wallet/vote linkability remains public.

Core truth:

The mock ZK path is a semantic interface rehearsal only. It does not provide production unlinkability because `msg.sender`, `VoteCast(..., voter)`, transaction gas source, timestamps, and RPC metadata remain public.

Smallest next useful work:

1. Run a no-edits review focused only on the design decisions in `ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md`.
2. Convert accepted decisions into fixture schemas and tests.
3. Define public payload shapes that remove raw credentials, witness material, stable hashes, and voter/nullifier co-exposure where privacy is claimed.
4. Define verifier governance and emergency deprecation rules.
5. Only then consider real circuit work.

### Lane B: Continuity / Retaliation Safety

Source: `PRIVACY_CONTINUITY_INTERVENTION_HANDOFF.md`.

Priority order:

1. Compromised issuer/nullifier burn registry.
2. Power loss / local machine failure continuity kit.
3. No-wallet pharmacy proxy claim relay.
4. Retaliation-mode mutual-credit freeze and offline clearing.
5. Helpdesk leakage honeypot and segregated evidence.
6. Auditor compromise canary role rotation and evidence fork.
7. Paper Merkle offline claim vouchers.

Current posture:

- planning/review slice is closed;
- local synthetic tooling exists for voucher and adversarial-guard boundaries;
- live mechanisms remain future work;
- no offline artifact should be treated as settlement authority;
- no real participant data should be used.

Allowed next work:

- docs;
- schemas;
- synthetic fixtures;
- dry-run validators;
- local static verifier prototypes;
- tests proving redaction and fail-closed behavior.

Not allowed yet:

- live proxy claims;
- custodial wallet workflows;
- live burn enforcement;
- real participant vouchers;
- PHI or real credential material;
- alternate settlement authority.

### Lane C: Production Readiness And Public Intake

Source: `PRODUCTION_READINESS_CHECKLIST.md`.

Current blockers include:

- frontend build hygiene;
- database and auth selection;
- offline/non-digital workflow safety;
- version-control/code-review discipline;
- API design;
- hosting and deployment plan;
- rate limiting;
- caching;
- scaling;
- observability;
- accessibility;
- scanner refresh and public deployment audit prep.

Important note:

Patient fund matching liquidity has operational enforcement implemented, but most public-app infrastructure remains not present or needs design.

### Lane D: Open Policy And Governance Decisions

Source: `OPEN_DESIGN_DECISIONS.md`.

Open areas:

- dismissed disputes and claim-right restoration;
- credential privacy identifier;
- participatory project eligibility;
- stale pool recovery liveness;
- exclusion cap ratchets;
- hosted provider, auth, and form-intake boundaries.

Reviewer should separate:

- contract behavior;
- policy choice;
- docs-only aspiration;
- operational procedure;
- future governance ratification.

## 5. Suggested Next Review Mission

Use a no-edits review first. Do not implement during the first pass.

Primary mission:

Review the pushed `ba57949` checkpoint and orient the next implementation milestone. The reviewer should determine whether the next feature slice should be:

- ZK/nullifier decision closure;
- continuity-kit static prototype;
- proxy-intake schema/validator;
- production-readiness hardening;
- governance/open-decision cleanup;
- or a smaller documentation/test alignment patch before any feature work.

The reviewer should not propose broad architecture until it classifies the exact current implementation state.

## 6. External Antigravity Roadmap Handoff To Reconcile

An external Antigravity handoff exists at:

`C:\Users\Josh\.gemini\antigravity\brain\6b49332e-6b28-4d76-a1f5-1dd0c4cd02b7\roadmap_handoff.md`

Treat it as a proposal set, not as approved roadmap authority. It identifies four critical design areas:

1. ZK participant unit and secrets custody.
2. Dizzy advisory arbitration layer.
3. Hosted provider, auth, and database boundaries.
4. Non-digital workflow and offline care continuity.

### Useful Signal From That Handoff

- It correctly asks what the participant unit is: wallet, credential, NPI/NCPDP location, legal entity, pharmacy operator, or something else.
- It correctly separates local witness/secret generation from relayer-visible proof/nullifier payloads.
- It correctly keeps Dizzy/advisory automation outside direct custody or settlement authority.
- It correctly forces hosted-provider, auth, database, and row-level access choices into the roadmap instead of leaving them implicit.
- It correctly treats offline continuity as a first-class safety lane rather than a dashboard convenience.

### Claims That Need Review Before Adoption

- Binding eligibility to NPI/NCPDP may reduce Sybil risk, but it can also create a stable pharmacy identity handle. This must be reconciled with retaliation risk and public linkability.
- Browser `localStorage` is not automatically acceptable secret custody, even when encrypted with a passphrase. The next review should compare browser, CLI, hardware wallet, passkey, encrypted file, and recovery-packet approaches.
- A "Dizzy public key" or signed advisory report must not become governance authority. It should remain advisory unless a ratified evidence-packet workflow defines its trust boundary.
- Any encrypted dispensing-record workflow risks PHI leakage. Use synthetic packets first, and avoid real dispensing records unless legal/privacy review exists.
- Supabase, Clerk, Cloudflare Workers, or Vercel are plausible options, not selected architecture. Provider choice needs a threat model, RLS/security-rule tests, secret classification, export/deletion story, and retaliation-resistance review.
- Shared-local-secret voucher MACs create operator-custody and multi-node rotation problems. The next review should evaluate per-voucher keys, signer quorums, public-key signatures, threshold custody, or non-shared local validation.
- Offline vouchers containing Merkle proof paths, gross amounts, or pharmacy-adjacent identifiers need privacy classification before any real use.

### How To Use It In The Next Review

The reviewer should compare this external handoff against:

- `ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md`
- `PRIVACY_CONTINUITY_INTERVENTION_HANDOFF.md`
- `OPEN_DESIGN_DECISIONS.md`
- `PRODUCTION_READINESS_CHECKLIST.md`
- `MECHANISM_COVERAGE.md`
- `RETALIATION_AND_PRIVACY_THREAT_MODEL.md`

Expected output for this external handoff:

- classify each proposal as adopt now, adapt into tests/fixtures, docs-only, defer, or reject;
- identify what repo evidence supports or contradicts it;
- name the harmed stakeholder if the proposal is wrong;
- recommend the smallest safe next slice.

## 7. Snapshot Gate For Next Reviewer

Before reviewing:

```powershell
git status -sb
git rev-parse HEAD
npm.cmd test
```

Expected baseline for the next reviewer:

- branch: `main`;
- active HEAD contains this committed `NEXT_REVIEW_HANDOFF.md` file and descends from `ba57949`;
- local branch synced with `origin/main`;
- `npm.cmd test`: 193 passing tests.

If `NEXT_REVIEW_HANDOFF.md` is untracked, the handoff commit has not been applied or pushed in that checkout. Reconcile before accepting snapshot-specific findings.

If any other files are dirty, report `SNAPSHOT_MISMATCH` and reconcile before accepting findings.

## 8. Key Files For Next Review

Roadmap and status:

- `README.md`
- `ROADMAP.md`
- `MECHANISM_COVERAGE.md`
- `PRODUCTION_READINESS_CHECKLIST.md`
- `OPEN_DESIGN_DECISIONS.md`

ZK and privacy:

- `ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md`
- `IDENTITY_NULLIFIER_DESIGN.md`
- `RETALIATION_AND_PRIVACY_THREAT_MODEL.md`
- `contracts/PatientFundParticipatoryBudgeting.sol`
- `test/PatientFundParticipatoryBudgeting.test.js`

Continuity and resilience:

- `PRIVACY_CONTINUITY_INTERVENTION_HANDOFF.md`
- `CARE_CONTINUITY.md`
- `OPERATIONAL_RUNBOOK.md`
- `tools/resilience/continuity-engine.mjs`
- `tools/security/adversarial-guard.mjs`
- `test/ContinuityAndAdversarialTools.test.js`

Draft adjacent governance modules:

- `contracts/CooperativeParticipatoryBudgeting.sol`
- `contracts/ReflexiveFiduciaryManifold.sol`
- `test/DraftGovernanceModules.test.js`

Review process:

- `REVIEW_ITERATION_PROCESS.md`
- `ANTIGRAVITY_CURRENT_HANDOFF.md`
- `ANTIGRAVITY_ZK_HANDOFF.md`
- `MIESSLER_INTEGRATION_TRIAGE.md`

Core runtime baseline:

- `contracts/PBMRebateTreasury.sol`
- `contracts/PharmacyMutualCredit.sol`
- `scripts/export-portability.js`
- `scripts/verify-export.js`
- `tools/credentials/credential-policy.mjs`

External proposal to reconcile:

- `C:\Users\Josh\.gemini\antigravity\brain\6b49332e-6b28-4d76-a1f5-1dd0c4cd02b7\roadmap_handoff.md`

## 9. Do Not Do In The Next Review

- Do not write Circom circuits.
- Do not import snarkjs.
- Do not add a Solidity verifier contract.
- Do not add upgradeable contracts.
- Do not change core treasury accounting.
- Do not change patient-fund routing.
- Do not change Merkle claim accounting.
- Do not change dispute accounting.
- Do not change mutual-credit balances or voucher accounting.
- Do not claim production privacy.
- Do not use real participant, patient, pharmacy, credential, witness, helpdesk, or PHI data.
- Do not implement live proxy relay, live burn registry, live canary response, live retaliation clearing, or live paper-voucher redemption.
- Do not treat generated offline vouchers, local MACs, or relay batches as settlement authority.
- Do not integrate draft governance/manifold modules into production runtime without a new design gate.

## 10. Exact Copy-Paste Prompt For The Next Review

```text
Review the current local repo as a no-edits lead planner. Do not modify files, commit, push, open issues, create PRs, or run implementation.

Snapshot:
- Repo: C:\Users\Josh\Desktop\PBMRebateTreasuryFinal
- Branch: main
- Expected baseline commit in history: ba57949 Reconcile resilience governance review findings
- Expected current HEAD: a later handoff/planning commit that contains NEXT_REVIEW_HANDOFF.md and descends from ba57949
- Expected status: clean and synced with origin/main.
- Expected full-suite result from prior pass: npm.cmd test passed with 193 passing tests.

First verify:
- git status -sb
- git rev-parse HEAD
- git log --oneline -5

If the snapshot differs, report SNAPSHOT_MISMATCH and stop.

Primary mission:
Orient the next feature milestone from the current Phase 0 prototype state. Compare the canonical roadmap in ROADMAP.md with the operational Phase 0 lanes in ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md, PRIVACY_CONTINUITY_INTERVENTION_HANDOFF.md, PRODUCTION_READINESS_CHECKLIST.md, MECHANISM_COVERAGE.md, and OPEN_DESIGN_DECISIONS.md.

Also reconcile the external Antigravity roadmap handoff at:
C:\Users\Josh\.gemini\antigravity\brain\6b49332e-6b28-4d76-a1f5-1dd0c4cd02b7\roadmap_handoff.md

Treat that external file as a proposal set, not as approved roadmap authority. Pay special attention to NPI/NCPDP participant identity, localStorage/CLI secret custody, Dizzy advisory authority, Supabase/Clerk/provider choice, row-level security, offline vouchers, and shared-local-secret MAC handling.

Return:
1. A one-paragraph verdict on whether the current handoff commit and underlying ba57949 baseline are stable enough for next planning.
2. Exactly 10 under-asked questions that could derail the ZK/nullifier, continuity, production-readiness, or governance roadmap. For each: why it matters, who is harmed if ignored, repo evidence to inspect, and whether it is blocker, roadmap, or philosophical/product-direction.
3. Exactly 8 findings, prioritized by risk:
   - 1-2: privacy/nullifier design blockers before real circuits;
   - 3-4: continuity/retaliation safety risks before live offline/proxy workflows;
   - 5: production-readiness blocker before public users;
   - 6: governance legitimacy or role-capture risk;
   - 7: mismatch between roadmap/docs and implemented behavior;
   - 8: recommended next implementation slice, scoped to 1-2 weeks, with exact files likely to change.
4. A ranked recommendation among these next slices:
   - ZK/nullifier design fixture and test gate;
   - static continuity-kit prototype;
   - proxy-intake schema and dry-run validator;
   - production-readiness hardening;
   - governance/open-decision cleanup.

Rules:
- Treat handoffs and prior reviews as claim sets until verified against live code.
- Keep each finding under 140 words.
- Use exact file/line references.
- Do not recommend production privacy claims.
- Do not recommend live proxy, live vouchers, live burn registry, real participant data, or production ZK integration yet.
- Do not recommend changes to core accounting or role separation unless you classify them as rejected/non-goals or prove a live defect.
```

## 11. Likely Next Implementation Slices After Review

These are candidates, not approvals.

### Slice 1: ZK/Nullifier Decision Fixture Gate

Purpose:

Turn design decisions into tests and fixtures before real circuits.

Likely files:

- `ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md`
- `IDENTITY_NULLIFIER_DESIGN.md`
- `OPEN_DESIGN_DECISIONS.md`
- `contracts/PatientFundParticipatoryBudgeting.sol`
- `test/PatientFundParticipatoryBudgeting.test.js`
- possibly a new fixture under `test/fixtures/` or `tools/zk/`

Acceptance:

- explicit nullifier domains;
- participant-unit decision captured as a testable assumption;
- secret-custody threat model captured without committing to browser `localStorage` prematurely;
- verifier governance expectations;
- non-revocation model documented;
- test fixtures distinguish wallet-linkable mock paths from future unlinkable paths;
- no production privacy claim.

### Slice 2: Static Continuity Kit Prototype

Purpose:

A disk-openable verifier for synthetic emergency packets and sample Merkle proof material.

Likely files:

- `PRIVACY_CONTINUITY_INTERVENTION_HANDOFF.md`
- `CARE_CONTINUITY.md`
- `OPERATIONAL_RUNBOOK.md`
- `scripts/verify-export.js`
- `tools/offline/continuity-kit.html`
- new tests for synthetic proof verification and redaction.

Acceptance:

- runs without Node, RPC, or internet;
- uses synthetic data only;
- labels offline proof validity separately from live chain provenance;
- contains no private keys, PHI, raw credentials, witness material, or stable wallet-to-pharmacy mappings.
- avoids treating shared-local-secret MACs as durable multi-operator authorization.

### Slice 3: Proxy Intake Schema And Dry-Run Validator

Purpose:

Define proxy-relay input shape without granting live authority.

Likely files:

- `RETALIATION_AND_PRIVACY_THREAT_MODEL.md`
- `OPERATIONAL_RUNBOOK.md`
- `PRIVACY_CONTINUITY_INTERVENTION_HANDOFF.md`
- new schema under `tools/resilience/` or `schemas/`
- new test file or additions to `test/ContinuityAndAdversarialTools.test.js`

Acceptance:

- synthetic input only;
- no live transaction submission;
- no custodial wallet assumption;
- no voter/nullifier co-exposure where privacy is claimed;
- clear receipt, rate-limit, appeal, and authority fields.
- no Dizzy/advisory recommendation can execute without human/governance approval.

### Slice 4: Production-Readiness Hardening

Purpose:

Reduce launch blockers without moving to launch.

Likely files:

- `PRODUCTION_READINESS_CHECKLIST.md`
- dashboard build files if present;
- `scripts/check-readiness.js`
- scanner triage docs;
- accessibility/readiness tests.

Acceptance:

- readiness checklist gets more machine-checkable;
- no public-user claim;
- no PHI/user-data storage;
- no hosted auth/database choice without threat model.
- provider candidates such as Supabase, Clerk, Cloudflare, or Vercel remain proposals until tested against privacy and exit requirements.

### Slice 5: Governance/Open-Decision Cleanup

Purpose:

Make policy choices impossible to confuse with implemented behavior.

Likely files:

- `OPEN_DESIGN_DECISIONS.md`
- `MECHANISM_COVERAGE.md`
- `README.md`
- `REVIEW_ITERATION_PROCESS.md`

Acceptance:

- each major claim has enforcement level;
- stale snapshot prompts are not reusable without refresh;
- governance-capture risks are explicit;
- docs do not imply autonomy where council/timelock/Safe trust still exists.

## 12. Review Quality Bar

A useful next review should:

- identify missing decisions, not just code bugs;
- name who is harmed by each gap;
- separate blocker, roadmap, and philosophical/product-direction questions;
- preserve exact snapshot discipline;
- treat privacy and care continuity as security, not as documentation polish;
- recommend one small next slice, not a new architecture.

A bad next review would:

- recommend Circom before design decisions are settled;
- treat the mock verifier as privacy;
- treat local continuity artifacts as authority;
- ignore provider/auth/public-intake gates;
- propose integrating draft governance modules into production runtime;
- blur docs-only proposals with contract-enforced behavior.

## 13. Summary For The Next Agent

You are standing at a clean, pushed Phase 0 checkpoint.

The broad roadmap is stable:

1. harden prototype;
2. audit and testnet;
3. small-cap first live epoch;
4. participatory budgeting;
5. adjacent commons infrastructure.

The immediate planning question is narrower:

Which Phase 0 lane should become the next 1-2 week implementation slice?

Default recommendation before review:

Start with ZK/nullifier design closure as fixtures/tests/docs, not real circuits. Keep continuity/retaliation tooling synthetic and local. Keep production-readiness gates parallel and visible. Do not move live funds, real data, or public participants into scope.

---

## 14. Completed Antigravity Review Findings and Verdict

Date: 2026-07-12
Reviewed implementation checkpoint: ba57949

### Verdict
Commit `ba57949` is a highly stable and verified implementation checkpoint. All 193 Hardhat test suite tests executed and passed successfully before the planning handoff was committed. The checkpoint successfully reconciles prior feedback regarding cooperative budgeting deadlocks, reflexive manifold decimals, local MAC fail-closed checks, and synthetic leakage scanning. This handoff records the next planning layer on top of that reproducible baseline.

### 10 Under-Asked Questions

1. **How does binding eligibility to NPI/NCPDP identifiers prevent long-term participant profiling?**
   * *Why it matters*: Shifting Sybil protection to NPI/NCPDP numbers exposes a permanent identity handle. Even with ZK proofs, the mapping between real physical locations and voting/claim patterns can be reconstructed by observing public block times and volumes.
   * *Who is harmed*: Independent pharmacies, who risk retaliatory delisting by payer networks/PBMs.
   * *Repo evidence*: [RETALIATION_AND_PRIVACY_THREAT_MODEL.md:L17-L20](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/RETALIATION_AND_PRIVACY_THREAT_MODEL.md#L17-L20) and [ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md:L30](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md#L30).
   * *Classification/Reconciliation*: Blocker. **Adapt into tests/fixtures**: We must test if location identities are correlation vectors.
2. **Does encrypting ZK secrets in browser `localStorage` open security backdoors via recovery mechanics?**
   * *Why it matters*: Users lose browser storage frequently. Introducing an backup recovery mechanism re-exposes central identity authorities (issuers or council), undermining ZK unlinkability.
   * *Who is harmed*: Pharmacy owners who get locked out of funds or whose identity is deanonymized via recovery.
   * *Repo evidence*: [ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md:L32](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md#L32) and [roadmap_handoff.md:L11-L14](file:///C:/Users/Josh/.gemini/antigravity/brain/6b49332e-6b28-4d76-a1f5-1dd0c4cd02b7/roadmap_handoff.md#L11-L14).
   * *Classification/Reconciliation*: Roadmap. **Defer**: Evaluate air-gapped backups and passkey alternatives over browser storage.
3. **What prevents the Council from rubber-stamping Dizzy's automated advisory decisions?**
   * *Why it matters*: High dispute volume leads to operational fatigue, causing humans to auto-approve Dizzy AI recommendations, turning Dizzy into a de facto execution authority.
   * *Who is harmed*: Claimants whose legitimate disputes are auto-rejected by incorrect algorithm logs.
   * *Repo evidence*: [roadmap_handoff.md:L35-L46](file:///C:/Users/Josh/.gemini/antigravity/brain/6b49332e-6b28-4d76-a1f5-1dd0c4cd02b7/roadmap_handoff.md#L35-L46) and [MECHANISM_COVERAGE.md:L46](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/MECHANISM_COVERAGE.md#L46).
   * *Classification/Reconciliation*: Philosophical/product-direction. **Docs-only**: Keep Dizzy strictly out of the contract state or consensus logic.
4. **Does sharing a local MAC secret for offline vouchers create a single point of compromise?**
   * *Why it matters*: If a shared key validates paper vouchers, a single operator key compromise allows forged voucher generation for the entire federation.
   * *Who is harmed*: The mutual credit pool, which faces drain and insolvency.
   * *Repo evidence*: [continuity-engine.mjs:L37-L48](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/tools/resilience/continuity-engine.mjs#L37-L48) and [PRIVACY_CONTINUITY_INTERVENTION_HANDOFF.md:L315-L316](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/PRIVACY_CONTINUITY_INTERVENTION_HANDOFF.md#L315-L316).
   * *Classification/Reconciliation*: Blocker. **Reject**: Avoid shared symmetric keys; use public-key/signatures or threshold cryptography.
5. **Do offline vouchers containing Merkle proof paths or gross amounts leak patient or pharmacy metadata?**
   * *Why it matters*: If voucher payloads leak structured Merkle branches or exact values, PBM networks can cross-reference physical logs with public data to deanonymize pharmacies.
   * *Who is harmed*: Patients seeking care during internet outages; pharmacies facing profiling.
   * *Repo evidence*: [roadmap_handoff.md:L69-L74](file:///C:/Users/Josh/.gemini/antigravity/brain/6b49332e-6b28-4d76-a1f5-1dd0c4cd02b7/roadmap_handoff.md#L69-L74) and [PRIVACY_CONTINUITY_INTERVENTION_HANDOFF.md:L448-L460](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/PRIVACY_CONTINUITY_INTERVENTION_HANDOFF.md#L448-L460).
   * *Classification/Reconciliation*: Roadmap. **Adapt into tests/fixtures**: Enforce metadata minimization rules on printed codes.
6. **How do offline proxy relays prevent double-spending without live chain state sync?**
   * *Why it matters*: In disconnected environments, multiple relay nodes can accept the same offline voucher or receipt, leading to double-redemption once sync is restored.
   * *Who is harmed*: The treasury matching pool or credit clearing system.
   * *Repo evidence*: [PRIVACY_CONTINUITY_INTERVENTION_HANDOFF.md:L264-L270](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/PRIVACY_CONTINUITY_INTERVENTION_HANDOFF.md#L264-L270) and [continuity-engine.mjs:L171-L212](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/tools/resilience/continuity-engine.mjs#L171-L212).
   * *Classification/Reconciliation*: Blocker. **Adapt into tests/fixtures**: Validate batch intake for duplicate nullifiers before submission.
7. **How will the system prevent accidental leakage of EIP-712 JSON or credential data into helpdesk tickets?**
   * *Why it matters*: Normal users troubleshooting registration errors will upload screenshots or logs containing raw signatures, credentials, or PHI.
   * *Who is harmed*: Patients and pharmacies whose identity is correlated via support databases.
   * *Repo evidence*: [adversarial-guard.mjs:L37-L44](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/tools/security/adversarial-guard.mjs#L37-L44) and [PRIVACY_CONTINUITY_INTERVENTION_HANDOFF.md:L306-L320](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/PRIVACY_CONTINUITY_INTERVENTION_HANDOFF.md#L306-L320).
   * *Classification/Reconciliation*: Roadmap. **Adopt now**: Implement forbidden-string sanitization scanner filters immediately.
8. **Do SaaS providers like Supabase and Clerk create data concentration points prone to correlation?**
   * *Why it matters*: Storing RLS metadata, webhooks, or database logs on third-party cloud systems creates a central honeypot. Insurers or PBMs can profile users through server IP tracking or subpoena.
   * *Who is harmed*: The entire participant network's pseudonymity target.
   * *Repo evidence*: [OPEN_DESIGN_DECISIONS.md:L47-L53](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/OPEN_DESIGN_DECISIONS.md#L47-L53) and [roadmap_handoff.md:L49-L63](file:///C:/Users/Josh/.gemini/antigravity/brain/6b49332e-6b28-4d76-a1f5-1dd0c4cd02b7/roadmap_handoff.md#L49-L63).
   * *Classification/Reconciliation*: Philosophical/product-direction. **Docs-only**: Assess hosting alternatives and RLS constraints through threat modeling.
9. **What prevents the Council from capturing voter registration by rotating mock ZK verifiers or roots?**
   * *Why it matters*: The contract allows the Council to update the verifier and root at any time, letting them invalidate valid voter lists or register arbitrary addresses under mock ZK.
   * *Who is harmed*: The community constituency whose budgeting votes are captured or diluted.
   * *Repo evidence*: [PatientFundParticipatoryBudgeting.sol:L274-L286](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/contracts/PatientFundParticipatoryBudgeting.sol#L274-L286).
   * *Classification/Reconciliation*: Blocker. **Docs-only**: Governance must place these parameter updates under timelocked multisig or voter consensus.
10. **How can the protocol claim to be "ZK mode" when the voter wallet addresses and vote mappings are recorded publicly on-chain?**
    * *Why it matters*: In [PatientFundParticipatoryBudgeting.sol](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/contracts/PatientFundParticipatoryBudgeting.sol), `registeredVoters` and `hasVoted` mappings track public address state. If users think "ZK mode" makes them anonymous, they will be deanonymized instantly on-chain.
    * *Who is harmed*: Participating pharmacies who assume ZK mode protects their identity.
    * *Repo evidence*: [PatientFundParticipatoryBudgeting.sol:L86-L90](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/contracts/PatientFundParticipatoryBudgeting.sol#L86-L90) and [PatientFundParticipatoryBudgeting.sol:L432-L433](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/contracts/PatientFundParticipatoryBudgeting.sol#L432-L433).
    * *Classification/Reconciliation*: Blocker. **Adapt into tests/fixtures**: We must ensure tests explicitly flag that mock ZK rounds do not provide production unlinkability.

### Exactly 8 Findings

#### Finding 1: On-Chain Voter/Vote Mapping Exposure in Mock ZK Mode
The contract [PatientFundParticipatoryBudgeting.sol#L87-L90](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/contracts/PatientFundParticipatoryBudgeting.sol#L87-L90) records registrations and votes using the voter's public wallet address in mappings `registeredVoters` and `hasVoted`. In [PatientFundParticipatoryBudgeting.sol#L433](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/contracts/PatientFundParticipatoryBudgeting.sol#L433), registering with a nullifier still maps to `msg.sender`. This public wallet linkability means that any participant claiming privacy is immediately exposed on-chain. Before writing real circuits, we must define the exact public events and payload structures that remove stable wallet identities and prevent transaction metadata correlation from leaking pharmacy identity.

#### Finding 2: Correlation Risks of NPI/NCPDP Participant Eligibility binding
The external proposal in [roadmap_handoff.md#L10](file:///C:/Users/Josh/.gemini/antigravity/brain/6b49332e-6b28-4d76-a1f5-1dd0c4cd02b7/roadmap_handoff.md#L10) suggests tying voter registration to physical pharmacy identifiers (NPI or NCPDP numbers) to prevent Sybil attacks. Tying proofs to active healthcare registers creates a stable handle that data brokers or PBMs can correlate. They can match the unique signature metadata, registration dates, or transaction volume patterns to deanonymize pharmacies. We must resolve this blocker by adapting the proposal: credential issuers must sign blind assertions, and we must test correlation vectors in [PatientFundParticipatoryBudgeting.test.js](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/test/PatientFundParticipatoryBudgeting.test.js) before implementing circuits.

#### Finding 3: Symmetrical Shared-Key Vulnerability in Offline Vouchers
The offline voucher system in [continuity-engine.mjs#L54-L60](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/tools/resilience/continuity-engine.mjs#L54-L60) verifies QR code authenticity using a Message Authentication Code (`mac`) derived from a symmetric key `LOCAL_MAC_SECRET`. The LOCAL_MAC_SECRET issue is a design blocker only if offline vouchers are promoted to multi-operator or live authority; the current tool remains a local synthetic prototype. If the secret leaks, an attacker can forge vouchers across the entire network, compromising the mutual credit federation. We reject this proposal. Any future offline voucher system must use public-key cryptography or threshold signers to avoid shared secrets.

#### Finding 4: Lack of Double-Spend Prevention in Offline Proxy Relays
The proxy packaging logic in [continuity-engine.mjs:L197-L203](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/tools/resilience/continuity-engine.mjs:L197-L203) prevents duplicate nullifiers only within a single batch folder. Since live settlement authority does not exist yet, this double-spend risk is more precisely a cross-batch replay, relay DoS, or delayed-care risk, not direct capital loss. However, without live contract state synchronization, compiling duplicate offline claims will cause the batch to revert on-chain. We must establish dry-run validation schemas that check a global nullifier cache before proxy relays are allowed.

#### Finding 5: Production-Readiness Database and Auth Blocker
The checklist in [PRODUCTION_READINESS_CHECKLIST.md#L29-L39](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/PRODUCTION_READINESS_CHECKLIST.md#L29-L39) details missing database integrations, Row-Level Security (RLS) rules, and authentication flows. Choosing third-party SaaS providers like Supabase or Clerk introduces correlation and central compromise risks. We must not implement hosted auth or database modules until a complete threat model is documented. We must require that publishable client-side keys are strictly separated from service-role keys in serverless config, backed by automated RLS validation tests.

#### Finding 6: Unlocked Council Authority over Verifier Rotation
In [PatientFundParticipatoryBudgeting.sol#L274-L286](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/contracts/PatientFundParticipatoryBudgeting.sol#L274-L286), the Council role has immediate authority to rotate `mockZKVerifier` and change the round's mock membership roots. If compromised, the Council can invalidate existing voter lists or inject fraudulent voters. This role concentration breaks the Ostrom-commons model. To protect the legitimacy of participatory rounds, verifier and root rotations must be restricted using a timelock or subject to voter approval/appeals.

#### Finding 7: Protocol Mismatch between Advisory Claims and Script Realities
The governance documentation describes Dizzy as an arbitration/judgment layer, but the codebase contains no automated execution enforcement. The tools in [adversarial-guard.mjs#L98](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/tools/security/adversarial-guard.mjs#L98) explicitly label automated checks as simulation-only. This mismatch risks misleading participants into believing automated safety guards exist. We must update the documentation in [MECHANISM_COVERAGE.md#L46](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/MECHANISM_COVERAGE.md#L46) to classify Dizzy as purely advisory, preventing automated oracle output from executing on-chain transactions without Council verification.

#### Finding 8: Recommended Next Milestone Implementation Slice
The recommended 1-2 week next step is the **ZK/nullifier design fixture and test gate**. This slice will formalize accepted design decisions as executable test cases and static schema fixtures, establishing a security baseline before real circuits are written. The files that will change are:
- [ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md) (to record design closures);
- [IDENTITY_NULLIFIER_DESIGN.md](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/IDENTITY_NULLIFIER_DESIGN.md) (to map ZK payload schemas);
- [test/PatientFundParticipatoryBudgeting.test.js](file:///C:/Users/Josh/Desktop/PBMRebateTreasuryFinal/test/PatientFundParticipatoryBudgeting.test.js) (to verify nullifier domain separation and assert that stable wallet identities are not leaked in ZK mode).

### Ranked Recommendation of Next Slices

1. **ZK/nullifier design fixture and test gate** (Highest Priority)
   * *Rationale*: Addressing the profiling and correlation risks of stable credential hashes is the highest priority. Circuits cannot be safely designed until the participant unit, anonymity set size, and on-chain unlinkability mappings are defined as testable assertions.
2. **Proxy-intake schema and dry-run validator**
   * *Rationale*: This is necessary to test if voter/nullifier co-exposure can be prevented at the intake boundary, validating the client-to-relayer data shape without granting live transaction authority on-chain.
3. **Static continuity-kit prototype**
   * *Rationale*: Establishes the operational failsafe (disk-openable HTML verifier) for degraded environments using synthetic Merkle proofs, separating local logic validation from live RPC dependencies.
4. **Governance/open-decision cleanup**
   * *Rationale*: Important for aligning the documentation and codebase, ensuring the advisory status of Dizzy and other proposed models is clear and unambiguous.
5. **Production-readiness hardening**
   * *Rationale*: Although vital, implementing database schemas, auth, and build tooling should run in parallel only after the security and privacy threat models are closed.
