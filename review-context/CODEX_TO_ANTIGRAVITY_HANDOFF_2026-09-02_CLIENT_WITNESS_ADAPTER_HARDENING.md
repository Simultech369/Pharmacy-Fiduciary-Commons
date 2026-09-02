# Codex to Antigravity Handoff - Client Witness Adapter Hardening - 2026-09-02

## 1. Live Anchor

- Repository: `C:\Users\Josh\Desktop\PBMRebateTreasuryFinal`
- Branch observed: `main`
- HEAD observed before this working-tree slice: `410bd07f2ea843f49020174d358e9a5d5bda390c` (`feat(zk): build strict client witness adapter isolating local Circom inputs`)
- Local relation observed: `main...origin/main [ahead 4]` from the local remote-tracking ref; Codex did not fetch network state.
- Starting state: clean committed HEAD with `cache/verification_master_receipt.json` recording 9/9 passed, 433 Hardhat tests, 0 dirty files.
- Data freshness for this addendum: `[working tree]`
- This handoff is not committed.

## 2. Reconciliation Finding

Antigravity's Item 2 slice added `tools/zk/ClientWitnessAdapter.js` and `test/ClientWitnessAdapter.test.js`.

Codex verified the committed baseline, then inspected the adapter against:

- `circuits/vote_nullifier.circom`
- `test/ZKNullifierFixtureGate.test.js`
- `test/fixtures/metadataLeakageTable.json`
- `test/fixtures/projectScopedZKCircuitInterface.json`
- `docs/design/ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md`

The adapter was useful but thin:

- It did not require `nullifier`, even though the minimal Circom public input boundary includes it.
- It rejected forbidden side-channel fields only at the top level.
- Its forbidden list missed fields already named in the metadata leakage fixtures, including `witnessMaterial`, `gasPayerAddress`, `rawRpcIpAddress`, and `rawRpcApiKey`.
- It accepted malformed non-field values such as arbitrary strings for roots.

Weakest valid claim: this is local witness-adapter hardening for fixture and proof-input preparation. It is not production unlinkability, not a real prover, not a relayer privacy guarantee, and not an external audit.

## 3. Codex Repair

Updated `tools/zk/ClientWitnessAdapter.js`:

- Added `nullifier` to `REQUIRED_WITNESS_INPUTS`.
- Added recursive forbidden-field detection through ignored/nested payload fields.
- Added side-channel names from the metadata leakage fixture, including raw RPC IP/API key variants.
- Added Merkle path validation:
  - arrays required;
  - equal lengths required;
  - depth must be between 1 and 64;
  - path indices must be bits (`0` or `1`).
- Added BN254 scalar-field normalization for Circom-facing inputs.
- Requires `credentialSecret` and `nullifier` to be non-zero.
- Returns only the exact minimal circuit witness keys; harmless extra fields are ignored, forbidden extras are rejected.

Updated `test/ClientWitnessAdapter.test.js`:

- Expanded from 3 tests to 8 tests.
- Pins `nullifier` as a required input.
- Proves nested side-channel fields are rejected, not merely ignored.
- Proves malformed fields and zero nullifiers fail closed.
- Proves non-forbidden extras are stripped from the returned witness.
- Adds a drift guard comparing `FORBIDDEN_FIELDS` against `test/fixtures/metadataLeakageTable.json`, with `credentialSecret` allowed only as the explicit root private witness input.

## 4. Verification Completed By Codex

```powershell
npx.cmd --no-install hardhat test test\ClientWitnessAdapter.test.js test\ZKNullifierFixtureGate.test.js test\ZKNullifierCircuit.test.js --no-compile
```

Result: 43 passing.

```powershell
git diff --check -- tools\zk\ClientWitnessAdapter.js test\ClientWitnessAdapter.test.js
```

Result: passed; only expected LF-to-CRLF working-copy warnings.

```powershell
npx.cmd --no-install hardhat test --no-compile
```

Result: 438 passing in about 5 minutes.

```powershell
npm.cmd run check:frontend
python scripts\eval_constitutional_rubric.py --target reviews\rotational_swarm_review_dossier.md
python scripts\index_dossier_tree.py
python scripts\context_hygiene_audit.py
```

Results:

- Frontend / Brand Gate B: passed.
- Constitutional rubric: passed.
- PageIndex: 13 documents scanned, 2 dirty/untracked files detected before this handoff, 0 contradictory/stale/mismatched claims.
- Context hygiene: passed.

```powershell
python scripts\verify_all.py
```

Result: PASSED, 9/9 steps.

Receipt summary:

```text
timestamp: 2026-09-02T14:16:12Z
overall_status: PASSED
head_commit: 410bd07f2ea843f49020174d358e9a5d5bda390c
lineage_tag: [dirty working tree]
dirty_file_count: 3
Hardhat passing_tests: 438
claims_audited: 40
claim_violations: 0
PageIndex contradictions: 0
```

## 5. Master Receipt Boundary

At the start of this slice, `cache/verification_master_receipt.json` recorded:

```text
timestamp: 2026-09-02T13:51:39Z
overall_status: PASSED
head_commit: 410bd07f2ea843f49020174d358e9a5d5bda390c
lineage_tag: [committed HEAD]
dirty_file_count: 0
Hardhat passing_tests: 433
```

After this handoff was written and calibrated, Codex reran `python scripts\verify_all.py`. The receipt now records a dirty-tree master pass for the witness hardening patch:

```text
timestamp: 2026-09-02T14:16:12Z
overall_status: PASSED
head_commit: 410bd07f2ea843f49020174d358e9a5d5bda390c
lineage_tag: [dirty working tree]
dirty_file_count: 3
Hardhat passing_tests: 438
```

Weakest valid claim: this proves the working tree passed the master verifier. It is not yet a clean committed-HEAD receipt for the adapter hardening because the adapter patch and this handoff are not committed.

## 6. Recommended Commit Slice

Stage only these files:

```powershell
Set-Location -LiteralPath 'C:\Users\Josh\Desktop\PBMRebateTreasuryFinal'
git add -- `
  tools/zk/ClientWitnessAdapter.js `
  test/ClientWitnessAdapter.test.js `
  review-context/CODEX_TO_ANTIGRAVITY_HANDOFF_2026-09-02_CLIENT_WITNESS_ADAPTER_HARDENING.md
```

Suggested commit:

```powershell
git commit -m "fix(zk): harden client witness adapter side-channel isolation"
```

Then rerun:

```powershell
python scripts\verify_all.py
```

## 7. Next Frontier After This Slice

The next useful council lane is a privacy threat-model test for the full witness path:

- prove support/docs/examples never ask users for raw credentials, private witness JSON, RPC traces, wallet-to-pharmacy mappings, PHI, private keys, or authorization payloads;
- define whether the adapter should accept field-reduced decimal strings only, or whether a future host adapter performs deterministic bytes32-to-field reduction;
- document that `credentialSecret` is a local private witness input and must never appear in public payloads, support tickets, dashboard logs, external A2A envelopes, or generated receipts.
