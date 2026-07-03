# Scanner Triage

This file records local scanner results and dispositions. It is not a formal audit and should be refreshed before any public deployment claim.

## Current Artifacts

- Slither: `C:\tmp\pbm-slither-report-a816e9e.json`
- Aderyn: `C:\tmp\pbm-aderyn-report-a816e9e.md`
- Mythril: `C:\tmp\pbm-mythril-patientfund-bytecode-excavated-triage.json`

The final Mythril run is a bounded PatientFund runtime-bytecode check, not full-project symbolic execution. It completed with 0 issues and empty stderr.

Live scanner refresh: Slither and Aderyn were refreshed for commit `a816e9e` on 2026-07-03 from the elevated WSL distro `Ubuntu-24.04`. Later commits include scanner-document updates and the `dryRunFinalize` view alias, so these artifacts remain useful triage evidence but should be refreshed before deployment claims. The normal, non-elevated Windows shell still cannot see registered WSL distros; use the elevated WSL context for scanner reruns on this host.

Post-excavation verification: `npm.cmd test` passed with 135 tests. After adding treasury callback and forced-ETH tests, `npm.cmd test -- test/PBMRebateTreasury.security.test.js` passed with 36 tests. Later dry-run finalization naming work added `dryRunFinalize` as a view alias for `previewFinalize`; scanner artifacts should be refreshed again before deployment claims because that alias landed after commit `a816e9e`.

## Slither Production Triage

Live Slither command:

`wsl.exe -d Ubuntu-24.04 -u root -- bash -lc "cd /mnt/c/Users/Josh/Desktop/PBMRebateTreasuryFinal && slither . --exclude-dependencies --filter-paths 'node_modules|contracts/mocks|artifacts|cache' --json /mnt/c/tmp/pbm-slither-report-a816e9e.json"`

Live Slither artifact count: 36 production-filtered detector entries.

Grouped count:

- 1 `arbitrary-send-eth` high
- 2 `incorrect-equality` medium
- 1 `reentrancy-no-eth` medium
- 2 `reentrancy-benign` low
- 18 `timestamp` low
- 3 `cyclomatic-complexity` informational
- 1 `low-level-calls` informational
- 8 `naming-convention` informational

Production high/medium entries:

- `arbitrary-send-eth`: `PBMRebateTreasury.sweepETH`.
  - Disposition: hardened and accepted residual forced-ETH recovery path.
  - Rationale: `receive()` and `fallback()` reject ordinary ETH, so ETH can only arrive by force-send mechanics such as `selfdestruct` or protocol-level balance changes. `sweepETH` now requires `EXECUTOR_ROLE` rather than `COUNCIL_ROLE`, and sends only to constructor/executor-validated `environmentalFund`.
  - Regression: `test/PBMRebateTreasury.security.test.js` deploys `ForceETH`, proves normal ETH transfer is rejected, force-sends ETH, proves council cannot sweep, and proves timelock execution sweeps exactly the forced ETH amount to `environmentalFund`.

- `incorrect-equality`: `PBMRebateTreasury.recallEligible` checks `publishedAt == 0`.
  - Disposition: accepted sentinel check.
  - Rationale: `epochPublishedTimestamp[epoch]` uses zero as the "no root published" sentinel throughout the contract. This is a view helper, not a payout path.

- `incorrect-equality`: `PBMRebateTreasury.sweepETH` checks `balance == 0`.
  - Disposition: accepted empty-balance guard.
  - Rationale: this is a direct no-op guard before a forced-ETH recovery sweep. It does not compare application state for randomness, authorization, or economic thresholds.

- `reentrancy-no-eth`: `PatientFundParticipatoryBudgeting.startRound`.
  - Disposition: mitigated and regression-tested. See StartRound Reentrancy Review below.

Production low/informational entries:

- `reentrancy-benign`: `PBMRebateTreasury.depositRebate` and `fundExclusionRemediation`.
  - Disposition: mitigated and regression-tested with `TreasuryReentrantToken`. During callbacks, accounting buckets remain unpublished until inbound transfers complete, and guarded value-moving reentry attempts fail.

- `timestamp`: expected governance/deadline/expiry logic across root proposals, epoch finalization, recall eligibility, credential deadlines, proposal support, matching reclaim grace periods, voucher expiry, issuer grace windows, and stale recovery.
  - Disposition: accepted design dependency. These flows need wall-clock deadlines. They do not use timestamps for randomness.

- `low-level-calls`: `PBMRebateTreasury.sweepETH`.
  - Disposition: accepted because sending ETH requires `.call{value: ...}`. The path is `nonReentrant`, executor-gated, and sends to validated `environmentalFund`.

- `cyclomatic-complexity`: `PBMRebateTreasury` constructor, `flagClaim`, and `resolveClaim`.
  - Disposition: accepted for now. These functions encode explicit governance and dispute checks; refactoring them would be readability work, not a scanner blocker.

- `naming-convention`: underscore-prefixed external parameters in sweep/environment setter helpers.
  - Disposition: accepted style noise. Names are local parameters only.

## StartRound Reentrancy Review

Slither continues to report `PatientFundParticipatoryBudgeting.startRound(uint256)` as `reentrancy-no-eth` because `token.safeTransferFrom(...)` occurs before `currentRound` and `rounds[roundId]` are written.

Disposition: mitigated and regression-tested residual warning.

Evidence:

- `startRound` now computes `roundId` locally and does not publish `currentRound` or the active round struct until after the fresh token pull succeeds.
- `recycledMatchingPool` is cleared before the external token call, with rollback on transfer failure.
- `nonReentrant` is the first modifier on `startRound`.
- `contracts/mocks/StartRoundReentrantToken.sol` deliberately reenters during `transferFrom`.
- `test/PatientFundParticipatoryBudgeting.test.js` grants the malicious token `COUNCIL_ROLE`, starts a second round after a finalized first round, and proves that during the callback:
  - `currentRound` still points to the previous finalized round;
  - the next round is still `Inactive`;
  - recursive `startRound` is blocked;
  - reentrant voter/project/proposal/vote mutations all fail;
  - `unexpectedSuccessCount == 0`.

The remaining Slither signal is therefore useful as a reminder that ERC-20 callbacks are possible, but the tested callback cannot publish or mutate the pending round.

Unfiltered exploratory Slither runs may also report reentrancy issues in `StartRoundReentrantToken`. Those are expected: the mock exists only to exercise adversarial callback behavior and is not deployable protocol code. The production-filtered artifact listed above excludes `contracts/mocks`.

## Treasury ERC-20 Callback Review

Aderyn H-1 reports `PBMRebateTreasury.depositRebate`, `fundExclusionRemediation`, and `claim` under an ETH-transfer detector, but these are payout-token flows. The residual security question is therefore ERC-20 callback/reentrancy behavior, not unchecked ETH delivery.

Disposition: tested with an adversarial payout token.

Evidence:

- `contracts/mocks/TreasuryReentrantToken.sol` reenters the treasury during both inbound `transferFrom` calls and outbound `transfer` calls.
- During `depositRebate`, the malicious token observes that `distributionPool`, `governanceReserve`, `totalRebateDeposited`, and `rebateDepositCount` are still unchanged while the token pull is in progress.
- During `fundExclusionRemediation`, the malicious token observes that `exclusionRemediationReserve` is still unchanged while the token pull is in progress.
- During `claim`, the malicious token observes that claim effects are already settled before payout transfer callbacks: `hasClaimed == true`, `epochEscrow == 0`, `totalEscrowed == 0`, and root/claim totals already include the gross claim.
- In each callback phase, the mock attempts the guarded value-moving entry points: `depositRebate`, `fundExclusionRemediation`, `claim`, `resolveClaim`, `recallUnclaimed`, `withdrawGovernanceReserve`, `recoverStaleDistributionPool`, `sweepETH`, and `sweep`.
- All guarded reentry attempts are blocked and `unexpectedSuccessCount == 0`.
- Focused verification: `npm.cmd test -- test/PBMRebateTreasury.security.test.js` passed with 36 tests.

## Aderyn High Issues

Live Aderyn command:

`wsl.exe -d Ubuntu-24.04 -u root -- bash -lc "cd /mnt/c/Users/Josh/Desktop/PBMRebateTreasuryFinal && aderyn . -x contracts/mocks,node_modules,artifacts,cache -o /mnt/c/tmp/pbm-aderyn-report-a816e9e.md"`

Live Aderyn count: 1 high, 6 lows.

### H-1: ETH transferred without address checks

Instances: `PBMRebateTreasury.depositRebate`, `fundExclusionRemediation`, and `claim`.

Disposition: accepted detector mismatch.

Rationale:

- `depositRebate` pulls the configured ERC-20 payout token from `msg.sender` to `address(this)` and does not send ETH.
- `fundExclusionRemediation` pulls the configured ERC-20 payout token from `msg.sender` to `address(this)` and does not send ETH.
- `claim` transfers the configured ERC-20 payout token to `patientFund` and `claimant`; `claimant` is `msg.sender` in the public entry point, and `patientFund` is constructor-validated.
- ETH is rejected by `receive()` and `fallback()`. The intentional ETH path is `sweepETH`, which is executor-gated, `nonReentrant`, and sends only to constructor/executor-validated `environmentalFund`.

### H-2: Storage Array Edited with Memory

Previous instance: `_registerProject(roundId, prop.title, prop.recipient)` in `PatientFundParticipatoryBudgeting.supportProposal`.

Disposition: fixed.

Rationale: the proposal title and recipient are now copied into local variables before setting `prop.registered` and calling `_registerProject`. The final Aderyn report no longer includes this high.

## Aderyn Low Issues

Fixed lows from the earlier report:

- `nonReentrant is Not the First Modifier`: fixed on protocol functions.
- `State Change Without Event`: fixed for basis-point setters and test mocks.
- `Address State Variable Set Without Checks`: fixed in mocks.
- `Unused Error`: removed unused errors.
- selected `Literal Instead of Constant`: replaced BP policy literals with named constants and mock signature literal with `INVALID_SIGNATURE`.
- `Public Function Not Used Internally`: changed `getRecoverableStaleAmount` to `external`.

Residual lows, excavated:

- `Centralization Risk` has 40 role-gated instances across `PBMRebateTreasury`, `PatientFundParticipatoryBudgeting`, and `PharmacyMutualCredit`.
  - `PBMRebateTreasury`: council proposes roots, resolves disputes, finalizes/recalls epochs, sweeps accidental tokens/ETH, and unpauses; root confirmer confirms roots and exclusions; executor changes caps/BP/environmental fund and recovers stale reserves; guardian can pause.
  - `PatientFundParticipatoryBudgeting`: council starts/finalizes rounds, manages voter/project eligibility, reclaims unclaimed shares, sweeps non-matching tokens, and unpauses; guardian can pause.
  - `PharmacyMutualCredit`: council registers participants/issuers, unpauses, and sweeps accidental tokens; guardian can pause.
  - Disposition: accepted governance surface, not ignored. Existing mitigations include constructor role-separation checks, root confirmer separation, executor/timelock deployment flow, guardian/council separation tests, and production-readiness gates for Safe/timelock setup. Remaining work is operational: real Safe membership, timelock ownership, runbooks, and deployment audit.

- `Costly operations inside loop` has 3 instances.
  - `PatientFundParticipatoryBudgeting.registerVotersBatch`: now bounded by `MAX_VOTERS_PER_BATCH = 200` and covered by a `BatchTooLarge` regression test.
  - `PatientFundParticipatoryBudgeting.finalizeRound`: bounded by `MAX_PROJECTS_PER_ROUND = 50`; this loop is core matching math and cannot be removed without changing the allocation design.
  - `PharmacyMutualCredit.releaseExpiredVouchersBatch`: now bounded by `MAX_VOUCHER_RELEASE_BATCH = 100` and covered by a `BatchTooLarge` regression test.

- `Large Numeric Literal` has 1 instance.
  - `PBMRebateTreasury.BP_DENOM = 10_000`.
  - Disposition: accepted. `10_000` is clearer for basis points than `1e4`, and the related policy literals were already moved into named constants.

- `PUSH0 Opcode` has 4 pragma instances.
  - All project Solidity files use `pragma solidity 0.8.20`.
  - Mitigation: Hardhat now explicitly sets `evmVersion: "paris"` and compile output confirms `evm target: paris`.
  - Residual: Aderyn reports `EVM version - prague`, so release deployment must continue verifying bytecode target per chain.

- `Loop Contains require/revert` has 2 instances.
  - `PatientFundParticipatoryBudgeting.registerVotersBatch`: intentionally atomic; malformed voter batches revert rather than silently partially registering eligibility. Now bounded by `MAX_VOTERS_PER_BATCH`.
  - `PharmacyMutualCredit.releaseExpiredVouchersBatch`: intentionally atomic; malformed cleanup batches revert rather than silently releasing a partial set of voucher reservations. Now bounded by `MAX_VOUCHER_RELEASE_BATCH`.

- `Unused Import` has 1 instance.
  - `OZTimelockControllerImport.sol` imports `TimelockController` solely to force a local Hardhat artifact used by deployment scripts and tests.
  - Disposition: accepted shim. Removing it breaks the local artifact lookup pattern unless scripts/tests are refactored to use fully-qualified OpenZeppelin names.

## Next Scanner Work

- Keep Aderyn, Slither, and targeted Mythril artifacts under `C:\tmp` for local review evidence.
- Before deployment, rerun scanners from a clean checkout and produce release-specific artifacts.
- Treat new high-confidence production-contract scanner findings as blockers unless fixed or accepted here with a concrete exploitability rationale and, where practical, a regression test.

## Roadmap Decisions From Residual Findings

- `PBMRebateTreasury.sweepETH`: no further contract change is needed for the current prototype. Promote the operational side to roadmap/release gates: executor must be a timelock-controlled address, `environmentalFund` rotation must remain executor-gated, and release rehearsals should include a forced-ETH recovery drill.
- Timestamp dependencies: no current contract patch is recommended because the flagged paths are deadline, expiry, and grace-period mechanics rather than randomness. Promote chain-specific deployment review to roadmap work: document timestamp tolerance, L2 sequencer assumptions, deadline boundary behavior, and operator notice windows before mainnet.
- `PBMRebateTreasury.resolveClaim` complexity: not a scanner blocker, but worth future readability work before a formal audit. Any refactor should extract internal helpers only after preserving the existing accounting invariant and dispute-resolution regression coverage.
- Aderyn centralization risk: accepted as a governance surface, not dismissed. Promote real Safe membership, separate root confirmer, separate guardian, timelocked executor ownership, and deployment-audit evidence to release blockers.
