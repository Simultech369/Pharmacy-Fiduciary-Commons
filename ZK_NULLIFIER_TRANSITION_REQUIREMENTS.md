# ZK Nullifier Transition Requirements

## 1. Purpose

This document is a design gate for moving voter and claimant identity from stable credential hashes to scoped nullifiers. It does not specify a complete ZK implementation, and it should not be treated as approval to begin Circom, snarkjs, Solidity verifier integration, or dashboard changes.

The goal is to name the decisions that must be settled before implementation. The current repo remains a local/testnet prototype with public-wallet and stable-hash privacy limits.

## 2. Current Leakage Surfaces

- Stable credential hashes are part of both EIP-712 registration payloads and emitted events. The relayer derives `credentialHash` from the canonical credential, the dashboard submits it, and `RegistrationAuthorizationUsed` publishes it.
- Public wallet addresses remain central to registration and voting. `VoterRegistered`, `RegistrationAuthorizationUsed`, and `VoteCast` expose the participating address, so replacing only `credentialHash` with a nullifier would not achieve unlinkability.
- CLI output and dashboard workflows expose authorization material. The relayer prints the credential hash, signature, and authorization JSON; the dashboard expects users to paste that JSON.
- The local revocation registry is not an on-chain revocation source. `tools/credentials/revoked_credentials.json` can block future relayer-issued authorizations only when the relayer uses the updated file.
- Issuer and auditor custody can become a new correlation point. Even if on-chain data is shielded, issuer logs, support channels, credential issuance metadata, and witness-generation workflows can reveal participation.
- Public readiness remains blocked. The production checklist still contains unresolved controls for source maps, bundled assets, provider trust boundaries, row-level security, credential data, logs, support flows, and public participant privacy.
- Historical public event data cannot be made private retroactively. Any legacy round or deployment that emitted stable hashes or wallet activity must remain labeled as prototype/unsafe for real participants.

## 3. Corrected Revocation Model

- The contract has a council-controlled on-chain registration status path: `registerVoter(roundId, voter, status)`.
- Calling `registerVoter(roundId, voter, false)` clears `registeredVoters[roundId][voter]` and increments the registration nonce.
- That nonce bump invalidates outstanding relayer and trusted-issuer signatures for the same round and voter.
- `tools/credentials/revoked_credentials.json` does not automatically clear active on-chain rights. It only affects future off-chain credential verification in tools that load the updated file.
- The direct trusted-issuer path does not read the local revocation JSON in Solidity. It relies on issuer discipline, trusted issuer configuration, deadline, nonce, policy version, and the signed payload.
- Revocation does not erase prior event history. Previously emitted wallet addresses, credential hashes, deadlines, signatures, and transaction metadata remain public.

## 4. Decisions Required Before Circuits

- [ ] Participant unit: decide whether eligibility maps to wallet, credential, organization, physical pharmacy location, license, NPI/NCPDP identifier, owner group, or another unit.
- [ ] Anonymity set target: define the minimum population needed before a round, epoch, geography, or credential class can safely operate.
- [ ] Credential secret definition: define who generates the secret, how it is stored, how it rotates, and how it survives device loss.
- [ ] Nullifier domain separation: define separate domains for round voting, epoch claims, disputes, portability exports, migration, and any emergency workflows.
- [ ] Membership tree schema: define leaf contents, root publication cadence, issuer inclusion criteria, and how root updates are audited.
- [ ] Issuer trust and proof model: decide whether proofs attest to issuer signature, membership in an issuer-signed tree, delegated auditor approval, or another credential construction.
- [ ] Non-revocation model: choose short-lived credentials, accumulator proofs, Merkle non-membership, root freshness, or an explicit hybrid.
- [ ] Wallet/address privacy strategy: decide whether public wallet identity remains acceptable, becomes ephemeral, moves behind relayers/account abstraction, or is removed from privacy-sensitive events.
- [ ] Event schema: define the public audit fields that replace `credentialHash` and voter-indexed events.
- [ ] Legacy migration boundary: decide how old prototype rounds are labeled, frozen, migrated, or excluded from production privacy claims.
- [ ] Verifier and circuit governance: define who can deploy, pause, upgrade, or deprecate verifiers and how voters learn which verifier is authoritative.
- [ ] Proving key and witness handling: define where proofs are generated, what logs are forbidden, and how witness data is deleted or protected.
- [ ] Dashboard, CLI, and support redaction rules: define what must never appear in browser logs, screenshots, support tickets, shell history, or exported receipts.
- [ ] Care-continuity fallback: define what happens when privacy fails and a participant faces payer retaliation, supply exclusion, or network termination.

## 5. Minimal Verifier-Mock Milestone

Before real circuits, build a verifier-mock milestone that proves the desired contract and workflow semantics.

Implementation status after OpenClaude and Antigravity reconciliation: the first mock slice is implemented in `PatientFundParticipatoryBudgeting.sol` and covered by focused tests in `PatientFundParticipatoryBudgeting.test.js`. It adds explicit ZK-mode rounds, a rotatable mock verifier, per-round mock membership roots, verifier-version/root-bound attestations, per-round nullifier reuse protection, council revocation in ZK mode, and guards that reject legacy registration paths in ZK-mode rounds. This remains a semantic mock only; it does not provide production unlinkability because `msg.sender`, `VoteCast(..., voter)`, transaction gas source, timestamps, and RPC metadata remain public.

Required properties:

- A mock verifier interface accepts or rejects verifier-signed attestations without importing Circom or snarkjs.
- Registration uses a round-scoped nullifier and rejects nullifier reuse within the same round.
- Public events do not emit canonical credential hashes.
- Legacy and ZK rounds are explicitly separated so no one can mistake old stable-hash history for anonymized history.
- Tests fail if the privacy target requires unlinkability but registration or voting still emits a stable wallet identity.
- Tests cover verifier version rejection.
- Tests cover stale, missing, or intentionally rejected proof roots.
- Tests cover council revocation and verifier/root governance expectations.
- Dashboard and CLI fixtures demonstrate the post-ZK public payload shape without raw credentials, witness material, or stable hashes.

The mock milestone should answer the interface and auditability questions before the project pays the complexity cost of real proof generation.

## 6. Disruption Pass

1. Power-loss drill
   - Established pattern disrupted: assuming local-first work continues because internet is not required.
   - Hidden assumption attacked: a local node, laptop, wallet, and notes are available when needed.
   - Smallest experiment: stop mid-registration flow, resume from committed repo state and documented artifacts only.
   - Possible harm: wasted operator time or accidental duplicate state if recovery instructions are unclear.
   - Belongs in: operations and emergency procedure.

2. No-internet proof rehearsal
   - Established pattern disrupted: assuming hosted docs, package registries, RPC dashboards, or support channels can fill gaps.
   - Hidden assumption attacked: offline-safe means more than smart contracts compiling locally.
   - Smallest experiment: verify a credential, inspect a root, and explain participant status with networking disabled.
   - Possible harm: false confidence if the rehearsal uses cached dependencies without saying so.
   - Belongs in: operations, docs, and tests.

3. Hostile payer metadata table
   - Established pattern disrupted: focusing only on credential hash secrecy.
   - Hidden assumption attacked: removing one field removes the retaliation trail.
   - Smallest experiment: build a table of what a payer can infer from timestamps, wallet reuse, project support, RPC endpoint, UI logs, and support messages.
   - Possible harm: analysis may over-classify benign metadata as sensitive without a triage standard.
   - Belongs in: docs, governance, and UI.

4. Compromised issuer simulation
   - Established pattern disrupted: treating trusted issuers as outside the privacy threat model.
   - Hidden assumption attacked: issuer custody is benevolent, available, and non-coercive.
   - Smallest experiment: write the incident story for an issuer subpoena, insider leak, key compromise, or commercial pressure campaign.
   - Possible harm: too much issuer skepticism can make legitimate credential recovery impossible.
   - Belongs in: governance and operations.

5. Support-ticket leak test
   - Established pattern disrupted: treating support/helpdesk as separate from protocol privacy.
   - Hidden assumption attacked: users will never paste authorization JSON, screenshots, wallet addresses, or credential details into support.
   - Smallest experiment: draft a support flow that solves registration failure without collecting secrets or stable identifiers.
   - Possible harm: support may become less useful if redaction rules are too blunt.
   - Belongs in: operations, UI, and docs.

6. No-stable-wallet participant
   - Established pattern disrupted: designing eligibility around a stable public address.
   - Hidden assumption attacked: every pharmacy can safely maintain, recover, and publicly reuse a wallet.
   - Smallest experiment: model a participant who loses a wallet, must rotate devices, or cannot expose an address tied to their business.
   - Possible harm: account recovery can become an identity backdoor.
   - Belongs in: code, governance, and operations.

7. Retaliation continuity exercise
   - Established pattern disrupted: treating privacy breach as only a data-security incident.
   - Hidden assumption attacked: harm ends when the protocol warns users.
   - Smallest experiment: write the care-continuity response when a pharmacy is removed from a payer network after participating.
   - Possible harm: the project may imply it can provide remedies it has not resourced.
   - Belongs in: governance, docs, and emergency procedure.

8. Surveillance-aesthetic review
   - Established pattern disrupted: assuming UI is neutral if the cryptography is sound.
   - Hidden assumption attacked: participants trust interfaces that resemble compliance dashboards or institutional monitoring.
   - Smallest experiment: review the minimal panel for language, colors, labels, and status indicators that feel like surveillance instead of mutual aid.
   - Possible harm: aesthetic preference can distract from measurable security work if not kept bounded.
   - Belongs in: UI and docs.

9. Auditability budget
   - Established pattern disrupted: maximizing public transparency by default.
   - Hidden assumption attacked: every audit field is worth its correlation cost.
   - Smallest experiment: list each desired audit field and assign it to public event, aggregate report, private auditor record, participant-held receipt, or not collected.
   - Possible harm: under-publishing can weaken legitimacy if aggregate verification is not strong enough.
   - Belongs in: governance, code, and docs.

10. Luminary invariant pass
   - Established pattern disrupted: asking only whether the current plan is acceptable.
   - Hidden assumption attacked: the first architecture framing is the right one.
   - Smallest experiment: derive three invariants from nonstandard lenses: an Einstein lens asks what must remain invariant across migrations; a Tesla lens asks what infrastructure dependency fails first; a Da Vinci lens asks what the workflow diagram reveals before code exists.
   - Possible harm: visionary framing can become vague unless each lens produces a testable constraint.
   - Belongs in: docs and design review.

## 7. Tests That Define Done

Before transition:

- Prove the current stable credential hash is emitted and indexable.
- Prove the same credential produces the same hash across uses under the current canonicalization rules.
- Prove local JSON revocation blocks future relayer authorization generation.
- Prove local JSON revocation does not automatically clear active on-chain registration.
- Prove council revocation clears active registration and invalidates outstanding signatures through nonce changes.
- Prove direct trusted-issuer signatures are not checked against the local JSON revocation file by Solidity.
- Prove dashboard authorization JSON contains only the expected current fields and no raw credential payload.

Verifier-mock milestone:

- Reject reused round nullifiers.
- Reject invalid mock proofs and public self-computed proof bytes.
- Reject unsupported verifier or policy versions.
- Reject known-nullifier theft when the verifier attestation is bound to another voter.
- Emit only approved public fields.
- Keep legacy and ZK rounds separated in state, events, and tests.
- Fail tests if `credentialHash` appears in the ZK registration event path.
- Fail tests if wallet identity remains public in a path whose stated privacy target is unlinkability.

After real ZK integration:

- Same credential generates unlinkable round-scoped nullifiers across different rounds.
- Round, epoch, dispute, portability, and migration nullifiers are domain-separated.
- Revoked credentials cannot generate valid non-revocation proofs after the freshness window.
- Stale roots and unsupported circuits are rejected.
- Witness material, credential secrets, and raw credentials are not logged by CLI, dashboard, tests, or support fixtures.
- Verifier upgrades, pauses, and deprecations are governed and tested.
- Public readiness checks include ZK privacy, operational metadata, and support-flow redaction gates.

## 8. Non-Goals

- No Circom circuit should be written from this document alone.
- No snarkjs setup should begin until the missing design decisions are resolved.
- No Solidity verifier should be integrated before the verifier-mock milestone proves the contract interface.
- No dashboard ZK UX should claim production privacy before operational metadata and support flows are addressed.
- No public or mainnet participant flow should use real credentials or real pharmacy identities under the current stable-hash model.
- No migration should claim that legacy stable-hash history has been anonymized retroactively.

## 9. Recommended Next Step

The verifier-mock milestone is now the active code checkpoint. The next step is to run the full suite, review the patched mock verifier/root/version semantics, and decide whether the current mock is sufficient as a pre-circuit interface harness.

Before any real circuit work starts, run another no-edits reviewer loop in `REVIEW_ITERATION_PROCESS.md`. The review should attack remaining assumptions around wallet identity, issuer compromise, revocation freshness, support-flow leakage, degraded/offline operations, and whether each proposed milestone has a deterministic test or fixture gate.

## 10. Implemented ZK/Nullifier Design Fixture and Test Gate

A static ZK/nullifier design fixture and test gate has been implemented to make pre-circuit constraints on future public payloads, domain separation, governance lifecycles, and metadata leakage rules executable. This test gate is defined in `test/ZKNullifierFixtureGate.test.js` and asserts that:
- Any payload claiming the `unlinkable` privacy target must strictly omit all forbidden identifiers (wallet address, stable credential hash, NPI/NCPDP, credential secret, witness, and voter-nullifier co-exposure).
- Unique, domain-separated nullifiers are used across all workflows (voting, claims, disputes, portability, migration, emergency burn/revocation).
- Verifier and root lifecycle states (proposed, active, deprecated, emergency-paused, sunset) are defined with strict validation of quorum and upgrade pathways.
- The metadata leakage budget restricts the exposure of exact timestamps, gas payers, and raw RPC/ticket identifiers in privacy-claimed payloads.

### Remaining Open Design Decisions

The following key architectural decisions remain undecided and must be settled before any real circuit work:
1. **Participant Identity Unit**: What exact unit maps to eligibility (wallet, credential, pharmacy location, license, NPI/NCPDP, legal entity, or owner group)?
2. **Secret Custody, Recovery, Rotation, and Loss Model**: Who generates/stores/rotates secrets, and how are devices recovered without exposing backdoors?
3. **Verifier/Root/Non-Revocation Governance**: Who configures roots, rotates/deprecates verifiers, pauses compromised circuits, and validates revocation freshness?
4. **Hosted Auth/Database Provider Selection**: What SaaS/database boundaries are used, and how do we prevent hosted provider logs from deanonymizing the ZK layer?
5. **Metadata Leakage Mitigation**: How are transaction and network metadata leaks (batch timing, gas funding, RPC IP addresses) strictly eliminated?
