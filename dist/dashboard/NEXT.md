# Next

Pharmacy Fiduciary Commons is a local/testnet prototype. It is not audited, not deployed to mainnet, and not ready for real funds, public-wallet participants, PHI, or production custody.

This roadmap is intentionally credibility-first: every public claim should trace to code, tests, generated receipts, or an unresolved launch blocker.

## Current Public Posture

| Area | Current status | Boundary |
|------|----------------|----------|
| Treasury accounting | Solidity prototype with local tests and verifier receipts | Not an audit certificate or mainnet safety claim |
| Dashboard | Static prototype with synthetic fixtures and local/test Web3 paths | Not real PBM data, live funding, or production database proof |
| Formal checks | Off-chain Python/Z3/schema checks for project model logic | Verifier evidence only; not market truth or external audit replacement |
| ZK/nullifier work | Semantic mock and design-spec evidence | Not production unlinkability; wallet, gas, timing, RPC, and metadata linkage remain risks |
| Council and A2A tooling | Local/off-chain review and receipt infrastructure | Not autonomous on-chain authority or external execution permission |

## Immediate Handoff Focus

1. Seal the public UI/docs slice.
   - Keep it separate from the A2A/fraud-attestation dirty files.
   - Preserve the README, dashboard, onboarding, constitution, and security-policy edits as one public-trust checkpoint.
   - Include the regenerated static dashboard bundle only if the nested dashboard docs are committed with it.

2. Re-run the fast evidence ladder before any public announcement.
   - `npm.cmd run build:dashboard`
   - `npm.cmd run check:frontend`
   - `npm.cmd run check:readiness -- --env local`
   - `python scripts\index_dossier_tree.py`
   - `git diff --check`

3. After the tree is clean, run the full verifier.
   - `python scripts\verify_all.py`
   - Treat any new receipt as tied to the exact commit, dirty-tree state, timestamp, and test counts it reports.

## Community Roadmap

| Focus | Why it matters | Good first contributions |
|-------|----------------|--------------------------|
| Public trust and docs | Outside readers need to know what is real, local, synthetic, or blocked | Improve wording, link maps, glossary, contributor guide, and issue templates |
| Dashboard accessibility | A public financial dashboard must be usable without visual guesswork | Keyboard navigation, screen-reader labels, contrast review, reduced-motion checks |
| Solidity security review | Contract custody claims need independent scrutiny before any launch path | Review `PBMRebateTreasury`, `PharmacyMutualCredit`, dispute flows, recall paths, and cap invariants |
| Scanner triangulation | Slither, Solhint, Foundry, Aderyn, Mythril, and Echidna each see different risks | Convert scanner findings into documented false-positive, accepted-risk, or test-backed fix records |
| Formal verification | Local proofs should become more specific, reproducible, and narrow | Expand Forge invariants, SMT probes, and proof-harness fixtures without calling them audits |
| ZK/nullifier privacy | Privacy claims are dangerous unless metadata leakage is handled directly | Review circuit specs, relayer assumptions, nullifier scope, wallet/gas linkage, and migration boundaries |
| Data provenance | Omission claims require independent expected-deposit evidence | Design source metadata, methodology disclosures, dispute labels, and no-real-PBM demo safeguards |
| Governance ratification | A fiduciary commons needs more than code; it needs accountable procedures | Review role separation, ratification steps, appeal windows, and participant safety rules |
| Dependency and branch hygiene | Public contributors should not inherit stale maintenance noise | Triage Dependabot branches one at a time, then compare or delete `feature/roadmap-and-drafts` |

## What This Does Not Claim

- No mainnet deployment.
- No real-funds custody.
- No PHI or live patient data.
- No claim of external audit completion.
- No claim that local Council or A2A tools replace human governance, legal review, security review, or production operations.
- No public claims about named PBMs without independently sourced expected-deposit evidence and methodology notes.

## Review Queue

1. Public overclaim review: find any README, dashboard, docs, or handoff language that sounds audited, production-ready, or externally verified without evidence.
2. Dashboard proof-boundary review: confirm every panel labels synthetic fixtures, local checks, and non-claims plainly.
3. Security-policy review: confirm `SECURITY.md` names the system boundary, reportable findings, known limits, and audit blockers.
4. ZK/privacy review: confirm mock nullifier wording does not imply production privacy.
5. Dependency review: evaluate Dependabot branches with full test and scanner evidence before merging.

## Stop Rules

Stop and write a handoff instead of broadening scope when:

- a test failure repeats and the cause is not isolated;
- Git metadata writes are blocked;
- a proposed change would mix UI/docs work with Solidity, A2A, fraud-invariant, or dependency-update work;
- a public claim cannot be tied to a local file, test, receipt, or explicit unresolved risk.
