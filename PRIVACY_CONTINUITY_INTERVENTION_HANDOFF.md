# Privacy Continuity Intervention Handoff

Prepared against live checkout `52e6a0d8a543293fda81d9709afaa264dbc2bce7` on `main`.

The incoming handoff note named `ca88314072ce414392ced7b1c9494ffcf79f90e4`, which is present locally but one commit behind the live checkout. This document uses the live checkout because it includes the Patient Fund solvency fix and PB Sink Model tests.

## Operating Posture

These interventions are fiduciary-first continuity measures. They should not weaken the existing core accounting, escrow, Merkle claim, dispute, role-separation, or patient-fund sink behavior. No upgradeable-contract pattern is assumed or recommended.

Use `REVIEW_ITERATION_PROCESS.md` for the next review and implementation loop. Each intervention below should move through snapshot gate, no-edits review, live-repo reconciliation, deterministic fixture/test gate, and only then implementation.

Priority order:

1. Compromised Issuer Nullifier Burn Registry (air-gapped option)
2. Power Loss / Local Machine Failure Continuity Kit
3. No-Wallet "Pharmacy Proxy" Claim Relay
4. "Retaliation Mode" Mutual Credit Freeze + Offline Clearing
5. Helpdesk Leakage Honeypot + Segregated Evidence
6. Auditor Compromise "Canary" Role Rotation + Evidence Fork
7. Paper Merkle Offline Claim Vouchers as a companion redundancy layer

## 1. Compromised Issuer Nullifier Burn Registry

### Refined Description And Exact Scope

Create a local-first emergency registry for revoked or burned credential/nullifier material. In the current prototype this begins as signed JSON bundles and Merkle roots, not as on-chain ZK enforcement. It prepares for the future ZK/nullifier registry by defining bundle shape, signer quorum, offline import, and evidence-hash linkage.

Scope includes:

- issuer key compromise response;
- burn-on-suspicion bundles keyed to evidence hashes;
- offline bundle verification;
- optional Merkle root publication in docs or future governance packets;
- compatibility with future non-revocation proofs.

Scope excludes:

- changing current credential verification semantics in Solidity;
- replacing `trustedCredentialIssuers`;
- adding a real accumulator or circuit before ZK design decisions are settled.

### Implementation Approach

- Docs: add an issuer-burn procedure to `OPERATIONAL_RUNBOOK.md`.
- Tooling: add a small helper later, for example `tools/credentials/burn-registry.mjs`, to verify signed burn bundles and derive a Merkle root.
- Operations: publish weekly signed burn bundles alongside portability artifacts.
- Evidence: require each burn entry to reference an `EVIDENCE_METADATA.md` descriptor hash.
- ZK prep: reserve fields for future nullifier domain, round/epoch scope, and proof root.

### Smallest Viable Experiment

In 1-2 weeks:

- create a sample `tools/credentials/burn_registry.sample.json`;
- write a local verifier that checks bundle shape, signer addresses, evidence hashes, and Merkle root determinism;
- add tests for malformed entries, duplicate burns, stale bundles, and wrong signer quorum;
- document an air-gapped import flow.

### Integration Points

- `tools/credentials/credential-policy.mjs` currently reads `revokedCredentialIds`; the burn registry should remain adjacent until policy is ratified.
- `EVIDENCE_METADATA.md` already defines off-chain evidence hash semantics.
- `ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md` names non-revocation as a blocker before circuits.
- `MECHANISM_COVERAGE.md` should keep this as script-enforced or docs-only until a contract or circuit enforces it.

### Success Metrics And Red-Team Vectors

Success:

- a verifier can reject stale, malformed, unsigned, or conflicting burn bundles offline;
- operators can explain which issuer key or credential scope is burned and why;
- no raw credential, PHI, or stable secret is needed to verify the bundle.

Red-team:

- compromised issuer publishes a false burn;
- council censors a valid burn;
- stale bundle is replayed after a newer clean bundle;
- burn evidence preimage leaks protected data;
- payer correlates burn timing with pharmacy identity.

### Downsides And Mitigations

- Downside: false burns can disenfranchise pharmacies.
  Mitigation: require multi-signer quorum, challenge window, and evidence hash before treating a burn as final.
- Downside: burn metadata can itself become a retaliation signal.
  Mitigation: aggregate by scope and publish delay windows where safety permits.
- Downside: local JSON becomes another trust root.
  Mitigation: document it as a pre-ZK emergency artifact, not a final revocation primitive.

### Feasibility

Implement now as docs plus local tooling. Defer contract/circuit enforcement until the nullifier membership and non-revocation design is settled.

## 2. Power Loss / Local Machine Failure Continuity Kit

### Refined Description And Exact Scope

Create an air-gapped continuity kit for verifying basic participant state, Merkle proof material, signed bundles, and emergency procedures without Node.js, internet, or a live RPC connection.

Scope includes:

- single-file HTML verifier prototype;
- embedded sample data and expected outputs;
- printable operator checklist;
- paper template for evidence hashes, Merkle roots, emergency contacts, and recovery steps;
- explicit limits on what offline mode can and cannot prove.

Scope excludes:

- replacing chain provenance verification;
- using offline outputs as final authority for live claims;
- storing real secrets or PHI in the kit.

### Implementation Approach

- Docs: expand `CARE_CONTINUITY.md` and `OPERATIONAL_RUNBOOK.md` with a power-loss drill.
- Tooling: create a future `tools/offline/continuity-kit.html` that runs in a browser from disk.
- Tests: add fixture-based tests for the JSON data that the HTML verifier consumes.
- Operations: require a quarterly drill where an operator resumes from committed repo state and printed artifacts only.

### Smallest Viable Experiment

In 1-2 weeks:

- build a static HTML proof checker that verifies a sample Merkle proof and a signed emergency bundle from hardcoded sample data;
- add a printable `docs` section or template with QR-friendly fields;
- document exact failure boundaries: "offline mode verifies structure and Merkle math only."

### Integration Points

- `scripts/verify-export.js` already supports offline structure and Merkle math checks.
- `PORTABILITY.md` already distinguishes offline verification from RPC provenance.
- `CARE_CONTINUITY.md` already names infrastructure degradation and minimal offline mode.
- `OPERATIONAL_RUNBOOK.md` already covers emergency pause, verifier rotation, and PB Sink depletion response.

### Success Metrics And Red-Team Vectors

Success:

- a user can open the HTML file from disk and verify sample proof material with no server;
- a reviewer can distinguish offline proof validity from live chain provenance;
- no Node.js dependency is required for the demonstration.

Red-team:

- stale HTML kit accepts revoked proof material;
- QR code encodes PHI or stable identifiers;
- operator confuses sample data with real records;
- malicious support actor asks users to upload the kit output.

### Downsides And Mitigations

- Downside: static kits can become stale.
  Mitigation: include version, build timestamp, expected root list, and expiration.
- Downside: offline verification can be mistaken for final settlement authority.
  Mitigation: make "structure and math only" a visible invariant.
- Downside: printable artifacts can leak identities.
  Mitigation: default to pseudonymous IDs and evidence hashes, not pharmacy names.

### Feasibility

Implement now as docs and a static prototype using existing export verifier semantics. Real production use waits for provider/security review and privacy-safe operational procedures.

## 3. No-Wallet "Pharmacy Proxy" Claim Relay

### Refined Description And Exact Scope

Define a proxy relay path for pharmacies that cannot safely maintain or publicly use a stable wallet. The proxy accepts authenticated paper, SMS, email, or offline evidence hashes, then submits on-chain actions through governed relayer infrastructure.

Scope includes:

- no-wallet participant intake;
- proxy-submitted claims or dispute actions;
- rate limits and delay windows;
- audit logging through evidence hashes;
- future ZK/nullifier compatibility.

Scope excludes:

- custodial wallets without governance approval;
- changing current Merkle leaf accounting;
- bypassing claim proof, dispute evidence, or cap controls.

### Implementation Approach

- Docs: define proxy relay as an operational mode in `OPERATIONAL_RUNBOOK.md`.
- Tooling: reuse relayer concepts from `scripts/register-voter-relayer.mjs`, but do not reuse credential hashes as production identifiers.
- Contracts: avoid core contract changes initially. Use existing role-controlled or participant-authenticated paths only where current semantics allow.
- Governance: require a delay window, appeal path, and signed evidence packet before proxy submission.

### Smallest Viable Experiment

In 1-2 weeks:

- create a sample proxy intake JSON schema with pseudonymous participant ID, evidence hash, requested action, expiry, and operator signature;
- build a dry-run validator that rejects missing evidence hashes, expired requests, duplicate request IDs, and raw PHI fields;
- run it against synthetic sample requests only.

### Integration Points

- `PBMRebateTreasury.sol` already uses Merkle claims, dispute evidence hashes, epoch caps, and patient fund routing.
- `EVIDENCE_METADATA.md` already defines preimage custody and availability classes.
- `scripts/export-portability.js` and `scripts/verify-export.js` can provide participant-held receipts and proof material.
- Future ZK work should determine whether the proxy sees identity, proof witness material, or only a blinded/nullified request.

### Success Metrics And Red-Team Vectors

Success:

- proxy requests can be audited without exposing raw patient or pharmacy data;
- duplicate and stale requests fail locally before any on-chain action;
- participant can later export a receipt proving what the proxy did.

Red-team:

- proxy submits an unauthorized claim;
- payer correlates proxy batch timing to a pharmacy;
- support staff collects raw credentials or PHI;
- participant disputes a proxy action after submission;
- proxy becomes a single censorship point.

### Downsides And Mitigations

- Downside: proxy relay can become custodial or paternalistic.
  Mitigation: require participant-held receipts, dispute windows, and explicit authority scope.
- Downside: proxy metadata can deanonymize users.
  Mitigation: batch requests, delay publication where safe, and separate support identity from on-chain identifiers.
- Downside: legal/healthcare obligations may attach to proxy operators.
  Mitigation: require policy review before real participant use.

### Feasibility

Implement now as docs, schemas, dry-run validators, and synthetic tests. Defer live proxy submission until ZK identity, operational privacy, and legal authority are defined.

## 4. "Retaliation Mode" Mutual Credit Freeze + Offline Clearing

### Refined Description And Exact Scope

Define an emergency operating mode for suspected payer retaliation, network exclusion, or infrastructure degradation. Retaliation Mode freezes new credit expansion and new voucher issuance while preserving a controlled path for clearing already committed offline obligations.

Scope includes:

- governance trigger criteria;
- freeze policy for new mutual credit and vouchers;
- offline batch redemption queue;
- exit criteria and dispute window;
- public warnings that this is not a physical medicine guarantee.

Scope excludes:

- changing core balances, reserved voucher accounting, or role separation now;
- automated triage allocation;
- changing `PharmacyMutualCredit.sol` without a specific tested design.

### Implementation Approach

- Docs: add a runbook procedure and mechanism coverage row.
- Operations: use existing `pause()` only for severe cases, while defining a softer docs-only Retaliation Mode for operator behavior.
- Tooling: add a future dry-run queue validator for offline voucher redemption batches.
- Contracts: no immediate contract changes. A later version could add explicit mode flags only after tests prove they do not break existing capacity accounting.

### Smallest Viable Experiment

In 1-2 weeks:

- define a synthetic offline clearing batch format;
- write a local validator that checks voucher IDs, recipient pseudonyms, amount totals, operator signatures, and duplicate entries;
- document when global pause is appropriate versus when the docs-only freeze procedure is enough.

### Integration Points

- `PharmacyMutualCredit.sol` already enforces participant registration, credit limits, voucher capacity reservation, redemption, expiry cleanup, and guardian pause/council unpause.
- `OPERATIONAL_RUNBOOK.md` already states that no default adjudication, bad-debt socialization, write-offs, or emergency credit freezes are implemented.
- `CARE_CONTINUITY.md` already defines Emergency Fill Access and non-digital workflow adoption as policy targets.

### Success Metrics And Red-Team Vectors

Success:

- operators can freeze new off-chain issuance without implying contract state changed;
- already committed vouchers have a clear reconciliation path;
- expired voucher cleanup remains distinct from debt forgiveness.

Red-team:

- malicious operator uses Retaliation Mode to censor a pharmacy;
- stale offline batch double-redeems a voucher;
- freeze traps pharmacies that need emergency fills;
- payer triggers false retaliation panic to disrupt clearing.

### Downsides And Mitigations

- Downside: a freeze can harm participants who need liquidity.
  Mitigation: define exceptions for pre-committed emergency fills and publish exit criteria.
- Downside: docs-only mode can be mistaken for contract-enforced state.
  Mitigation: label it as operational until code exists.
- Downside: offline clearing can hide bad debt.
  Mitigation: require batch publication, dispute window, and reconciliation receipts.

### Feasibility

Implement now as runbook and synthetic validator. Defer contract-level Retaliation Mode until after a focused mutual-credit design review.

## 5. Helpdesk Leakage Honeypot + Segregated Evidence

### Refined Description And Exact Scope

Design support flows so the helpdesk never receives raw credentials, private keys, witness material, PHI, or stable identity handles. Add a honeypot-style test that detects when support prompts or UI copy accidentally ask users for sensitive material.

Scope includes:

- pseudonymous ticket IDs;
- encrypted evidence blobs;
- access logs;
- forbidden-field scanning;
- sample leakage tests;
- support-script language.

Scope excludes:

- selecting a production support vendor;
- storing real participant records;
- implementing backend RLS before provider choice.

### Implementation Approach

- Docs: add a support intake policy to `OPERATIONAL_RUNBOOK.md` or `PRODUCTION_READINESS_CHECKLIST.md`.
- Tooling: create a future scanner that rejects support examples containing private keys, seed phrases, raw credentials, witness JSON, PHI, or stable wallet-to-pharmacy mappings.
- Evidence: route sensitive preimages through `EVIDENCE_METADATA.md` availability classes instead of helpdesk text.
- UI: design minimal panel copy that says what not to paste without making the interface feel punitive or surveillant.

### Smallest Viable Experiment

In 1-2 weeks:

- add a sample support intake fixture with allowed and forbidden fields;
- write a scanner test that fails on forbidden strings and raw auth blobs;
- add a support response template that asks for evidence hashes and export receipt IDs, not secrets.

### Integration Points

- `PRODUCTION_READINESS_CHECKLIST.md` already blocks public launch on logs, secrets, credential data, and protected records.
- `EVIDENCE_METADATA.md` already defines availability and privacy classes.
- `scripts/export-portability.js` already sanitizes warning messages.
- `ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md` already names dashboard/CLI/support redaction as a pre-circuit decision.

### Success Metrics And Red-Team Vectors

Success:

- support fixtures fail tests when they include raw keys, credentials, witness data, or PHI;
- users can receive help by sharing pseudonymous IDs and evidence hashes only;
- support logs can be audited without revealing participant identity.

Red-team:

- fake support agent asks for authorization JSON;
- screenshot includes wallet address and credential hash;
- encrypted blob access logs identify a pharmacy;
- support ticket correlation reveals retaliation-risk timing.

### Downsides And Mitigations

- Downside: support becomes harder for less technical participants.
  Mitigation: provide a paper/offline path and plain-language templates.
- Downside: honeypot scanner can miss contextual leaks.
  Mitigation: combine pattern scanning with manual review and minimal data collection.
- Downside: encrypted evidence can become unavailable.
  Mitigation: define custodian rotation and sealed appeal procedure.

### Feasibility

Implement now as checklist, fixtures, and static scanner tests. Defer hosted helpdesk integrations until provider trust boundaries and access controls are chosen.

## 6. Auditor Compromise "Canary" Role Rotation + Evidence Fork

### Refined Description And Exact Scope

Define a canary process for auditor or issuer compromise. A quorum of independent auditors publishes weekly signed status hashes. Missing or conflicting canaries trigger role rotation review, evidence-fork procedures, and temporary distrust of new issuer/auditor attestations.

Scope includes:

- signed weekly "alive" hashes;
- quorum and disagreement rules;
- evidence fork for disputed issuer actions;
- role rotation rehearsal;
- public status language.

Scope excludes:

- new on-chain auditor roles today;
- weakening current council/root-confirmer separation;
- automatic sanctions based only on canary failure.

### Implementation Approach

- Docs: add canary rotation procedure to `OPERATIONAL_RUNBOOK.md`.
- Evidence: use `EVIDENCE_METADATA.md` descriptors for disputed canary packets.
- Governance: rehearse `setTrustedCredentialIssuer`, `setRelayerVerifier`, and root-confirmer rotation in testnet operations.
- Tooling: future local script verifies signed canary bundle quorum and detects signer drift.

### Smallest Viable Experiment

In 1-2 weeks:

- create a signed canary bundle sample with three synthetic auditors;
- add a local verifier that accepts quorum, rejects stale bundles, and reports missing signers;
- document a manual evidence-fork flow for disputed issuer burns or credential revocations.

### Integration Points

- `PatientFundParticipatoryBudgeting.sol` has `setTrustedCredentialIssuer` and `setRelayerVerifier`.
- `PBMRebateTreasury.sol` already separates council, guardian, executor, and root confirmer authorities.
- `OPERATIONAL_RUNBOOK.md` already covers relayer verifier key rotation and emergency pause.
- `MECHANISM_COVERAGE.md` already tracks issuer trust and root publication trust roots.

### Success Metrics And Red-Team Vectors

Success:

- stale or missing canaries are visible without exposing sensitive preimages;
- role rotation procedure can be rehearsed without changing production state;
- disputed evidence has a forked, reviewable packet rather than a silent overwrite.

Red-team:

- compromised auditor signs "alive" while leaking data;
- signer quorum colludes;
- false canary panic triggers censorship;
- evidence fork becomes a misinformation channel.

### Downsides And Mitigations

- Downside: canaries can create false comfort.
  Mitigation: treat them as liveness signals, not proof of honesty.
- Downside: rotation can centralize authority in emergency actors.
  Mitigation: require public minutes, timelock where safe, and post-incident review.
- Downside: evidence forks can confuse users.
  Mitigation: label canonical, disputed, and archived bundles clearly.

### Feasibility

Implement now as docs and local signed-bundle verifier. Defer any new contract authority until after governance review.

## 7. Paper Merkle Offline Claim Vouchers

### Refined Description And Exact Scope

Create printable offline claim vouchers that encode minimal Merkle proof fragments, claim scope, short authentication codes, and redemption instructions. They act as a companion to the continuity kit and proxy relay, not as bearer instruments.

Scope includes:

- printable voucher template;
- QR payload format;
- short MAC or checksum for transcription error detection;
- proxy redemption flow;
- paper retention and destruction guidance.

Scope excludes:

- granting transferable claims;
- bypassing Merkle root, cap, dispute, or recipient checks;
- printing PHI or raw credentials.

### Implementation Approach

- Tooling: future script emits printable synthetic vouchers from existing Merkle allocation fixtures.
- Docs: add paper voucher limits to `CARE_CONTINUITY.md`.
- Operations: vouchers are redeemed by participant or authorized proxy after online reconciliation.
- Privacy: voucher payload should use pseudonymous IDs and evidence hashes, not pharmacy names or patient data.

### Smallest Viable Experiment

In 1-2 weeks:

- generate sample paper vouchers from a synthetic Merkle tree;
- verify the voucher offline using static data;
- simulate proxy redemption in a dry-run log without touching contracts.

### Integration Points

- `tools/merkle/allocations.js` already produces Merkle allocation material.
- `scripts/verify-export.js` already verifies Merkle math offline.
- `scripts/export-portability.js` already exports receipt and proof material.
- Future proxy relay can accept paper voucher IDs and evidence hashes as intake references.

### Success Metrics And Red-Team Vectors

Success:

- a participant can verify a voucher offline against a known root;
- proxy intake can reject duplicate, expired, malformed, or tampered vouchers;
- printed material does not reveal raw patient or credential data.

Red-team:

- voucher photocopy replay;
- forged QR with valid-looking fields;
- payer obtains paper voucher and correlates timing/location;
- MAC key compromise;
- staff treats voucher as guaranteed physical inventory.

### Downsides And Mitigations

- Downside: paper vouchers may look like guaranteed payment or medicine access.
  Mitigation: label as proof material, not a guarantee, until redeemed through protocol authority.
- Downside: paper can be lost or copied.
  Mitigation: use short expiries, non-transferable recipient binding, and duplicate detection.
- Downside: QR payload can leak identity.
  Mitigation: pseudonymous IDs and minimum fields only.

### Feasibility

Implement now as synthetic tooling and templates. Defer real participant issuance until proxy authority, privacy, and redemption rules are ratified.

## Ready-To-Paste Documentation Suggestions

### `CARE_CONTINUITY.md`

Suggested addition under infrastructure degradation:

```markdown
### Offline Continuity Packet

Offline continuity tools are survival aids, not alternate settlement authority. A continuity packet may include printable Merkle proof receipts, signed emergency bundle hashes, operator contact paths, and an air-gapped verifier. It must not contain private keys, raw credentials, PHI, or stable wallet-to-pharmacy identity mappings.

Offline checks may verify structure, signatures, and Merkle math. They do not prove final on-chain settlement without later chain provenance verification.
```

### `OPERATIONAL_RUNBOOK.md`

Suggested new section:

```markdown
## Emergency Privacy And Continuity Interventions

Before public participant use, operators must rehearse compromised-issuer burns, power-loss recovery, proxy relay intake, helpdesk redaction, and auditor canary failure. These are operational controls unless and until a contract or circuit enforces them.

No emergency procedure may bypass existing treasury accounting, epoch caps, Merkle proof requirements, dispute evidence hashes, guardian/council separation, or patient-fund sink rules.
```

### `MECHANISM_COVERAGE.md`

Suggested rows for the Care Continuity table:

```markdown
| Compromised issuer/nullifier burn response exists | Docs-only (Proposed) | `PRIVACY_CONTINUITY_INTERVENTION_HANDOFF.md`, `ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md` | Add signed burn-bundle verifier and non-revocation design before ZK implementation |
| Paper/offline claim vouchers protect degraded operations | Not implemented | `CARE_CONTINUITY.md`, `PORTABILITY.md` | Build synthetic paper Merkle voucher generator and offline verifier fixtures |
| Proxy relay supports participants without stable wallets | Not implemented | `RETALIATION_AND_PRIVACY_THREAT_MODEL.md` | Define authority, receipts, rate limits, and privacy-safe intake before live use |
| Helpdesk flows avoid credential and PHI leakage | Not implemented | `PRODUCTION_READINESS_CHECKLIST.md`, `EVIDENCE_METADATA.md` | Add support-intake fixtures and forbidden-field scanner |
```

### New Helper Scripts

Candidate scripts, in recommended order:

```text
tools/credentials/burn-registry.mjs
tools/offline/continuity-kit.html
tools/proxy/proxy-intake-validate.mjs
tools/support/support-leakage-scan.mjs
tools/offline/paper-merkle-vouchers.mjs
tools/auditors/canary-bundle-verify.mjs
```

Each script should start with synthetic fixtures and local tests only. None should require network access for its first milestone.

## Feasibility Summary

| Intervention | Can start now | Defer until ZK/nullifier work | Do not do now |
|--------------|---------------|-------------------------------|---------------|
| Burn registry | Signed JSON/Merkle bundle docs and verifier | Circuit-enforced non-revocation | On-chain accumulator without design gate |
| Continuity kit | Static HTML sample verifier and paper checklist | ZK witness verification | Real participant data in offline kit |
| Proxy relay | Synthetic intake schema and dry-run validator | Nullifier-based proxy privacy | Live custodial proxy claims |
| Retaliation Mode | Runbook and offline batch format | Contract-level mode flag | Core balance/accounting changes |
| Helpdesk segregation | Fixtures, scanner, templates | Hosted support provider integration | Store real support records |
| Canary rotation | Signed bundle verifier and runbook | On-chain auditor registry | Automatic sanctions from canary failure |
| Paper Merkle vouchers | Synthetic voucher generator | Live proxy redemption with privacy controls | Bearer claim vouchers |

## Recommended Next Steps

1. Run the no-edits prompt in `REVIEW_ITERATION_PROCESS.md` against this handoff and the ZK requirements document.
2. Reconcile each finding against the live repo and classify it as confirmed defect, confirmed design risk, partially true, false, stale snapshot, or useful provocation.
3. Add the documentation snippets to `CARE_CONTINUITY.md`, `OPERATIONAL_RUNBOOK.md`, and `MECHANISM_COVERAGE.md` after reviewer approval.
4. Implement `tools/credentials/burn-registry.mjs` with synthetic fixtures and tests.
5. Implement a static continuity-kit prototype that reuses the offline Merkle verification concepts from `scripts/verify-export.js`.
6. Create a proxy intake schema and validator, but keep it synthetic until authority and privacy boundaries are ratified.

## ZK/Nullifier Adjustments

- Treat burn bundles as a precursor to non-revocation roots, not as a final ZK revocation design.
- Treat proxy relay as a test case for whether wallet identity can disappear from public flows.
- Treat paper vouchers and continuity-kit artifacts as degraded-mode witnesses; ensure they never contain witness secrets or raw credential material.
- Treat canary bundles as liveness and compromise signals for issuer/auditor trust roots.
- Include support/helpdesk leakage in the ZK threat model, because perfect circuits do not protect users who paste secrets into support channels.
