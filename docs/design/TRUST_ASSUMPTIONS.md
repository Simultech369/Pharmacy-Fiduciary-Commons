# Trust Assumptions & Custody Boundaries

**Status:** Prototype Specification (Unaudited — Not Deployed to Mainnet)  
**Primary Contract:** [`contracts/PBMRebateTreasury.sol`](../../contracts/PBMRebateTreasury.sol)

`PBMRebateTreasury` is **publicly verifiable with bounded trust roots**, not "trustless." Every external reviewer and prospective participant should evaluate the system against the explicit trust assumptions below.

---

## 1. Merkle Root Proposal & Confirmation

- **Proposer (`COUNCIL_ROLE`)**: Intended to be a `3/5` Gnosis Safe. Calls `proposeRoot(bytes32 merkleRoot, uint256 totalAmount)` to stage an epoch allocation root against available unescrowed distribution liquidity.
- **Independent Confirmer (`ROOT_CONFIRMER_ROLE`)**: Intended to be a **separate** Safe or governance contract. Calls `confirmRoot()` to activate the root and lock `totalAmount` into `epochEscrow[epoch]`.
- **Enforced Separation**: Bytecode forbids any address from simultaneously holding `COUNCIL_ROLE` and `ROOT_CONFIRMER_ROLE`, including across future role rotations (`EXECUTOR_ROLE` timelock).
- **Residual Trust Assumption**: If both `COUNCIL_ROLE` and `ROOT_CONFIRMER_ROLE` collude or are compromised simultaneously, they can publish an inaccurate Merkle root up to `min(availableDistributionPool, dailyVolumeCap, hardAbsoluteVolumeCap)`. On-chain code verifies Merkle membership and arithmetic caps, **not** whether the off-chain dispensing inputs were truthful.

---

## 2. How Off-Chain Allocations Are Computed

1. **Inputs**: Validated pharmacy dispensing/reconciliation records (such as NCPDP claim summaries matched to epoch rebate schedules) are aggregated off-chain. No PHI or raw patient identifiers belong in allocation artifacts.
2. **Deterministic Leaf Construction**: `tools/merkle/allocations.js` builds double-hashed leaves matching `PBMRebateTreasury.sol`:
   ```solidity
   bytes32 leaf = keccak256(
       bytes.concat(keccak256(abi.encodePacked(pharmacy, grossAmount, eligibleCap)))
   );
   ```
3. **Verifiability**: Any pharmacy can independently recompute its leaf and verify inclusion against the on-chain `epochMerkleRoot[epoch]` and exported proof bundle (`scripts/export-portability.js`, `scripts/verify-export.js`).

---

## 3. Volume Caps & Permanent Downward-Only Hard Cap Ratchet

| Parameter | Initial Value | Who Can Change It | Direction Allowed After Deploy |
| :--- | :--- | :--- | :--- |
| `hardAbsoluteVolumeCap` | `10 * _initialDailyCap` (constructor) | `EXECUTOR_ROLE` (`TimelockController`) via `reduceHardCap(newCap)` | **Decrease only (`CanOnlyReduce`) — can NEVER increase after deploy.** Raising this ceiling requires deploying a new contract. |
| `dailyVolumeCap` *(legacy name: caps cumulative epoch volume)* | `_initialDailyCap` (constructor) | `EXECUTOR_ROLE` (`TimelockController`) via `updateDailyCap(newCap)` | **Increase or decrease**, strictly bounded by `minimumEpochVolume <= newCap <= hardAbsoluteVolumeCap`. |
| `patientClaimBP` | `1000` (`10%`) | `EXECUTOR_ROLE` via `updatePatientClaimBP(newBP)` | Bounded within `[500, 3000]` (`5%` to `30%`). |
| `governanceBP` | `100` (`1%`) | `EXECUTOR_ROLE` via `updateGovernanceBP(newBP)` | Bounded within `[0, 500]` (`0%` to `5%`). |

---

## 4. How Pharmacies Contest Allocations & Sanctions

1. **Included Leaf Dispute (`flagClaim`)**:
   - A claimant included in the epoch Merkle root calls `flagClaim(amount, eligibleCap, proof, reason, evidenceHash)` with a valid Merkle proof and non-zero `evidenceHash`.
   - `amount` is immediately reserved from `epochEscrow[epoch]` into `flaggedAmount[epoch][msg.sender]` and counted toward epoch volume caps so funds cannot be drained or recalled while contested.
   - `COUNCIL_ROLE` resolves via `resolveClaim(...)` (paying out or dismissing with a non-zero resolution `evidenceHash`), or the claimant can exercise timeout recovery if unaddressed past the contract dispute timeout.
2. **Omitted Pharmacy Contest (`flagExclusion`)**:
   - An unsanctioned pharmacy omitted from an epoch root calls `flagExclusion(epoch, amount, evidenceHash)`.
   - Paying an exclusion claim requires **two independent roles**: `ROOT_CONFIRMER_ROLE` must first approve the payout ceiling, and `COUNCIL_ROLE` executes resolution. Approved payouts draw exclusively from the separate `exclusionRemediationReserve` and never dilute root-backed pharmacy escrow.
3. **Sanction Appeal (`appealSanction`)**:
   - A sanctioned address can record `appealSanction(reason, evidenceHash)` on-chain even while sanctioned. The 14-day Council review SLA in [GOVERNANCE.md](../../GOVERNANCE.md) is **procedural**, not enforced by smart contract bytecode.

---

## 5. Who Controls the `patientFund` Address and Recovery Paths

- **Immutable Destination**: `patientFund` is declared `address public immutable patientFund` in `PBMRebateTreasury.sol`. **No role—not `COUNCIL_ROLE`, `EXECUTOR_ROLE`, `GUARDIAN_ROLE`, or a timelock—can change `patientFund` after deployment.**
- **Custody Architecture Choice at Deploy**: Operators must bind `_patientFund` at construction either to (a) a dedicated multi-signature patient-fund Safe, or (b) a deployed `PatientFundParticipatoryBudgeting` contract (see [OPERATIONAL_RUNBOOK.md](../ops/OPERATIONAL_RUNBOOK.md)). Trust in downstream patient-fund disbursement therefore rests on whichever contract/Safe occupies that immutable address.
- **Recovery & Sweep Sinks Routed Strictly to `patientFund`**:
  1. **Per-Claim Patient Share**: `10%` default (`patientClaimBP`) transferred automatically on every settled `claim()`.
  2. **Post-Epoch Unclaimed Recall (`recallUnclaimed`)**: After `finalizeEpoch()` plus `RECALL_DELAY` (`30 days`), `COUNCIL_ROLE` can transfer remaining unclaimed epoch escrow (excluding quarantined `flaggedAmount` disputes) **only** to `patientFund`.
  3. **Stale Unallocated Pool Recovery (`recoverStaleDistributionPool`)**: If an epoch sits `180 days` past `epochStartTimestamp` with no confirmed root and no unexpired pending root proposal, `EXECUTOR_ROLE` can recover unallocated distribution tokens—and bytecode reverts with `InvalidAddress()` unless `recipient == patientFund`.
  4. **Non-Payout ERC-20 Sweeps (`sweep`)**: Any ERC-20 other than the primary payout token accidentally transferred to the treasury is swept **only** to `patientFund` (the payout token itself cannot be swept).
