# Ring-1 Hardening Handoff (D-01 – D-06 + Anti-Spam #1 – #6)

> **Status: WORK IN PROGRESS.** The owner architecture decisions (D-01 – D-08) are still being worked on. Nothing here is a final governance ratification. `COMMONS_CONSTITUTION.md`, `server/`, and `supabase/` are out of scope (LRN-016).

Last updated: 2026-11-27 (Antigravity session handoff, from Gemini to Opus).

## 1. Where things stand

| Slice | Where it lives | State |
| :--- | :--- | :--- |
| CI / Foundry / D-04 extraction (`e607513`, `edfe649`, `78c14bc`) | `main` | Merged and green (Actions run `45919103811`). |
| Anti-Spam #4 — `PatientFundParticipatoryBudgeting` proposal limits | `main` (via the `feat/antispam-pb-pmc` PR) | Done and tested. |
| Anti-Spam #5 / #6 — `PharmacyMutualCredit` salted vouchers + poison-pill-safe batch release | `main` (via the `feat/antispam-pb-pmc` PR) | Done and tested. |
| D-01 network config (`optimism`, `optimismSepolia` in `hardhat.config.js`) | `main` (via the `feat/antispam-pb-pmc` PR) | Done (config only). |
| D-01 timing constants, D-02, D-03, D-05, D-06, Anti-Spam #1 – #3 in `PBMRebateTreasury.sol` | branch **`wip/ring1-treasury-hardening`** | **Does not compile yet.** Not merged. |

## 2. What is on `wip/ring1-treasury-hardening`

Files: `contracts/PBMRebateTreasury.sol` (heavy rewrite), `contracts/libraries/TreasuryVerifier.sol` (new), `hardhat.config.js` + `foundry.toml` (`optimizer.runs` 100 → 1, to save bytecode).

What the treasury changes are meant to do:

- **D-01:** `MIN_EPOCH_DURATION` goes from 1 day to 3 days and `ROOT_PROPOSAL_EXPIRY` from 3 days to 7 days.
- **D-02:** `claim()` and `resolveClaim()` no longer push the patient share. They add it to `accruedPatientFund`, and anyone can flush it with `withdrawPatientFund()`. That way a USDC freeze on `patientFund` can never block pharmacy claims. `solvencyCheck()` now counts `accruedPatientFund`, `_totalExclusionBonds`, and `_totalCarriedEscrow`.
- **D-03:** `claimWithAuthorization(ClaimAuth, proof, signature)` adds EIP-712 gas-relayer claims to a fresh `recipient` (works with EOAs and ERC-1271 accounts).
- **D-05 / Anti-Spam #1:** adds `disputeUsedInEpoch[epoch][account]`, which closes the `flagExclusion` → `DISMISS` re-spam loop. Also adds an exclusion-dispute bond and trusted-issuer credentials through `configureAntiSpam(...)` and `flagExclusionWithCredential(...)`, plus `DisputeResolution.DISMISS_RESTORE_CLAIM`.
- **Anti-Spam #2:** `depositRebate` rejects sanctioned callers and amounts below the configured minimum. Dust below `minimumEpochVolume / 1000` is no longer pushed into `rebateDeposits[]`.
- **Anti-Spam #3:** `appealSanction` rejects reasons over 256 bytes and allows only one pending appeal at a time.
- **D-06:** adds `allowPartial` claims, `DisputeResolution.RELEASE_PARTIAL`, `claimCarried(recipient, isExclusion)`, and `recallStaleCarryForward`. Settlements are partial and carried forward, and active caps are never exceeded.
- **Bytecode:** stateless crypto (EIP-712, ECDSA, ERC-1271, MerkleProof) moves into `TreasuryVerifier`, which the treasury constructor deploys. `SafeERC20` is replaced by a custom-error `_safeTransferCall`. Role modifiers become `_onlyRole(...)`.

## 3. Immediate next step (the blocker)

`npm run compile` fails:

```
CompilerError: Stack too deep.
  --> contracts/PBMRebateTreasury.sol: claimWithAuthorization (verifier.verifyClaimAuthorization(... auth.allowPartial, signature))
```

The 9-argument external call to `verifier.verifyClaimAuthorization` overflows the stack. Suggested fixes (pick one):

1. Move the `ClaimAuth` struct into `TreasuryVerifier` (or a shared file) and change the signature to `verifyClaimAuthorization(uint256 epoch, uint256 nonce, ClaimAuth calldata auth, bytes calldata sig)`. Pass `auth` straight through.
2. Or move the nonce check and verification into a separate `private` helper, `_consumeClaimAuth(ClaimAuth calldata auth, bytes calldata sig)`.

After that:

1. `npm run compile && npm run check:bytecode` — `PBMRebateTreasury` runtime must be **< 24,576 bytes** (EIP-170). At `78c14bc` it was already 24,277 B at `runs=1`. If it is still over, the next zero-linking lever is a compact `AccessControlEnumerable` replacement without `Strings` (saves about 3.5 KB). Tests match the substring `"AccessControl"` in revert reasons, so keep that in the error name. Do **not** use an external linked `library`, because it breaks `scripts/run_mythril_ci.py` (`--bin-runtime`).
2. Run Slither. `balanceBefore/After` moved into `_pullExactTokens`, so check whether the triaged `reentrancy-balance` element names in `scripts/check_slither_ci.py` and `docs/ops/SCANNER_TRIAGE.md` need updating.

## 4. Test updates the WIP branch still needs (LRN-015: update deliberately, never weaken)

- **3-day epoch / 7-day expiry:** update `scripts/validate-deployment-config.js` (L107-108, `259200` → `604800`) and `deployment/parameters.template.json` (L18). Update the time-warp constants in `test/PBMRebateTreasury.security.test.js` (L303, 416, 743, 1205, 1385, 1560, 1817), `test/PBMRebateTreasury.regressions.test.js` (L10), `test/PBMRebateTreasury.fuzz.test.js` (L13), `test/PBMRebateTreasury.dispute-timeout.test.js` (L6), and `test/PBMRebateTreasuryStaleRecovery.test.js` (L249, 361: 4 days → 8 days).
- **D-02 bucket sums:** update `test/PBMRebateTreasury.fuzz.test.js` (L121-126), `test/foundry/TreasurySolvencyInvariant.t.sol` (L61: the sink becomes `balanceOf(patientFund) + accruedPatientFund()`; L275-280 `sumBuckets`), `test/PBMRebateTreasury.security.test.js` (L543-641, 896-900, 1265-1269, 1320-1330, 1865-1875), and `test/ZeroDatabaseLiveness.test.js` (L298-313).
- **D-05:** `test/PBMRebateTreasury.security.test.js` around L856-861 currently asserts that re-flagging works (`exclusion-attacker-retry`). It must now expect a `DisputeAlreadyUsedInEpoch` revert.
- **New suite `test/Ring1AndAntiSpam.test.js`:**
  - D-02 with a blacklistable mock token.
  - D-03 with a relayed EOA and an ERC-1271 claimant.
  - D-05: bond refund vs. slash, credential path, and restore-claim.
  - Anti-Spam #2 / #3.
  - D-06: partial claims plus carry across emergency cap ratchets, with `solvencyCheck().delta == 0` throughout.
- **Still to do outside the contracts:**
  - `tools/merkle/allocations.js`: fixed-denomination tranches (`--tranche-size`) and co-op aggregation (D-03).
  - `docs/design/OWNER_ARCHITECTURE_DECISIONS.md` (mark it WIP).
  - `docs/ops/OP_MAINNET_L1_ESCAPE_HATCH.md` (D-01 `OptimismPortal.depositTransaction` runbook, D-08 rehearsal).

Full L2 proof before merge: `npm run compile && npm run check:bytecode`, `npm test`, `npm run test:formal`, `npm run lint:sol`, `npm run audit:slither`, `forge test --match-path "test/foundry/*.t.sol"`, `npm run demo:local && node scripts/check-readiness.js --env local && npm run check:deployment-template`, `npm run coverage`. Then confirm `git diff --stat -- COMMONS_CONSTITUTION.md server/ supabase/` is empty.

## 5. Explicitly deferred (do not implement in Ring 1)

- **D-07** ("Patients First" + reclaim tolling) is Ring 2 work.
- [SOLVENCY_OWNER_DECISION_WORKSHEET.md](../ops/SOLVENCY_OWNER_DECISION_WORKSHEET.md):
  - SD-01 – SD-06 are `DEFER / DO NOT IMPLEMENT YET` (owner, 2026-07-20).
  - **SD-07 – SD-09 still have blank owner selections.** They need an owner answer; this is not engineering work.
- `PatientFundParticipatoryBudgeting` solvency priority and reclaim behavior stay unchanged. They are protected by the tests at `test/PatientFundParticipatoryBudgeting.test.js` around L1661-1745.
- D-03 Option B (the full ZK nullifier pool) is Ring 2 and waits on a community trusted-setup ceremony.
