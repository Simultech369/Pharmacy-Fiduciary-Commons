# Codex to Antigravity Handoff - Patient Fund Cap Surplus Repair - 2026-09-02

## 1. Live Anchor

- Repository: `C:\Users\Josh\Desktop\PBMRebateTreasuryFinal`
- Branch observed: `main`
- HEAD observed: `73c0ffd53729563c5797ede1761be74a22e44760` (`feat(budgeting): implement explicit per-project quadratic matching cap`)
- Local relation observed: `main...origin/main [ahead 2]` from the local remote-tracking ref; Codex did not fetch network state.
- Data freshness: `[working tree]`
- This handoff is not committed.

## 2. Dirty Boundary

Codex observed exactly these dirty files before writing this handoff:

```text
contracts/PatientFundParticipatoryBudgeting.sol
review-context/oss_council_context.md
test/PatientFundParticipatoryBudgeting.test.js
```

This handoff file itself is an additional new working-tree artifact.

## 3. Reconciliation Finding

Antigravity correctly implemented the per-project quadratic matching cap surface at `73c0ffd`:

- `projectMatchingCapBps`
- `updateProjectMatchingCap`
- `InvalidCap`
- `ProjectMatchingCapUpdated`
- Default cap of `10000` bps, preserving legacy proportional tests.

Codex found one material semantics edge before moving to the next frontier:

> Capped surplus was being treated like ordinary finalization dust. In a fresh-funded round, that could refund clipped patient-fund matching liquidity to `council` rather than keeping it patient-bound.

Weakest valid claim: this is a custody semantics repair for the Patient Fund matching cap path, not a full economic proof of quadratic funding policy.

## 4. Codex Repair

Updated `contracts/PatientFundParticipatoryBudgeting.sol`:

- Added `ProjectMatchingCapSurplusRecycled(roundId, amount)`.
- Tracks capped surplus separately from integer-division dust.
- Adds capped surplus to `recycledMatchingPool`.
- Keeps only residual rounding dust on the previous fresh-vs-recycled provenance split.
- Refactored finalization and preview helpers to avoid Solidity stack-too-deep errors:
  - `_totalSquaredWeight`
  - `_recordFinalizedShares`
  - `_handleFinalizationRemainder`
  - `_fillPreviewShares`
  - `_cappedMatchingShare`
- `previewFinalize` now reports cap surplus as patient-bound required liquidity.

Updated `test/PatientFundParticipatoryBudgeting.test.js`:

- Added coverage that council can set a bounded per-project cap.
- Added regression proving cap surplus remains patient-bound:
  - 10,000 matching pool
  - cap set to 50%
  - project 0 raw share would be 80%, capped to 5,000
  - project 1 receives 2,000
  - 3,000 surplus is recycled, not refunded to council
  - after both project claims, contract retains the 3,000 recycled balance

Updated `review-context/oss_council_context.md`:

- Replaced stale `feature/db-proxy` / 282-test / 5-step receipt language.
- Current context now names `main@73c0ffd`, dirty repair state, 430 Hardhat passing, and the stale master-receipt boundary.

## 5. Verification Completed By Codex

```powershell
npx.cmd --no-install hardhat compile
```

Result: passed (`Nothing to compile` after prior successful compile).

```powershell
git diff --check -- contracts\PatientFundParticipatoryBudgeting.sol test\PatientFundParticipatoryBudgeting.test.js review-context\oss_council_context.md
```

Result: passed; only expected LF-to-CRLF working-copy warnings.

```powershell
npx.cmd --no-install hardhat test test\PatientFundParticipatoryBudgeting.test.js --no-compile
```

Result: 76 passing.

```powershell
python scripts\eval_constitutional_rubric.py --target reviews\rotational_swarm_review_dossier.md
python scripts\index_dossier_tree.py
python scripts\context_hygiene_audit.py
```

Results:

- Constitutional rubric: passed.
- PageIndex: 13 documents scanned, 3 dirty/untracked files detected before this handoff, 0 contradictory/stale/mismatched claims.
- Context hygiene: passed.

```powershell
npx.cmd --no-install hardhat test --no-compile
```

Result: 430 passing in about 4 minutes.

```powershell
python scripts\verify_all.py
```

Result: PASSED, 9/9 steps.

Receipt summary:

```text
timestamp: 2026-09-02T12:52:37Z
overall_status: PASSED
head_commit: 73c0ffd53729563c5797ede1761be74a22e44760
lineage_tag: [dirty working tree]
dirty_file_count: 4
Hardhat passing_tests: 430
claims_audited: 40
claim_violations: 0
PageIndex contradictions: 0
```

## 6. Master Receipt Boundary

`cache/verification_master_receipt.json` now reflects the cap-surplus repair as a dirty-tree verification:

- Recorded head: `73c0ffd53729563c5797ede1761be74a22e44760`
- Recorded status: 9/9 passed
- Recorded Hardhat count: 430 passing
- Recorded tree state: dirty, 4 dirty/untracked files

Weakest valid claim: this proves the working tree passed the master verifier. It is not yet a clean committed-HEAD receipt for the repair because the repair and this handoff are not committed.

## 7. Recommended Next Sequence

1. Review the three-file repair plus this handoff:

```powershell
Set-Location -LiteralPath 'C:\Users\Josh\Desktop\PBMRebateTreasuryFinal'
git status --short --branch
git diff -- contracts/PatientFundParticipatoryBudgeting.sol test/PatientFundParticipatoryBudgeting.test.js review-context/oss_council_context.md review-context/CODEX_TO_ANTIGRAVITY_HANDOFF_2026-09-02_PATIENT_FUND_CAP_SURPLUS_REPAIR.md
```

2. If accepted, stage the repair slice only:

```powershell
git add -- `
  contracts/PatientFundParticipatoryBudgeting.sol `
  test/PatientFundParticipatoryBudgeting.test.js `
  review-context/oss_council_context.md `
  review-context/CODEX_TO_ANTIGRAVITY_HANDOFF_2026-09-02_PATIENT_FUND_CAP_SURPLUS_REPAIR.md
```

3. Commit:

```powershell
git commit -m "fix(budgeting): keep matching cap surplus patient-bound"
```

4. Then run the master verifier again to stamp a clean committed-HEAD receipt:

```powershell
python scripts\verify_all.py
```

5. Only after that, proceed to Item 2:

```text
Remote RPC Verification Gate & Client Witness Isolation
```

## 8. Next Frontier Notes

Remote RPC / witness isolation is the right next priority after this repair is sealed. Keep the boundary strict:

- Current ZK/nullifier flow is semantic mock and fixture-gated, not production unlinkability.
- Real witness material, credential secrets, Merkle witnesses, private nullifier inputs, RPC identifiers, wallet addresses, and support-ticket identifiers must not enter public payloads, handoffs, or external A2A envelopes.
- External A2A should remain read-only and non-executing unless a future, separately reviewed authority model is implemented.
