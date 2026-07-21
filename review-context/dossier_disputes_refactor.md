# Dossier: Dispute Resolution Refactoring and State Transition Analysis

This dossier provides a detailed analysis of the dispute resolution state transitions in the `PBMRebateTreasury` contract, focuses on the behavior of the system when a claim dispute is dismissed by the council, drafts a readability refactor for `resolveClaim`, and proposes a safe solution to reset the `hasClaimed` status for dismissed exclusion claims.

---

## 1. Scope and Grounding Context

*   **Target Contract**: `contracts/PBMRebateTreasury.sol`
*   **Key Functions Analysed**:
    *   `resolveClaim(...)` (Lines 994–1086)
    *   `flagClaim(...)` (Lines 827–874)
    *   `flagExclusion(...)` (Lines 888–909)
    *   `retractClaimDispute(...)` (Lines 935–980)
*   **Key State Variables**:
    *   `hasClaimed[epoch][pharmacy]` (mapping)
    *   `flaggedAmount[epoch][pharmacy]` (mapping)
    *   `isExclusionDispute[epoch][pharmacy]` (mapping)
    *   `exclusionApproved[epoch][pharmacy]` (mapping)
    *   `epochEscrow[epoch]` (mapping)
    *   `epochClaimedTotal[epoch]` (mapping)
    *   `epochVolume` (uint256)
*   **Existing Unit Test Coverage Reference**:
    *   `test/PBMRebateTreasury.security.test.js` (Lines 836–880: `handles flagExclusion and resolveClaim appropriately`)
    *   `test/PBMRebateTreasury.dispute-timeout.test.js` (Lines 312: testing resolution of claim disputes via dismissal)

---

## 2. State Transition Analysis: Dismissing a Dispute

When a dispute is dismissed via `resolveClaim(epoch, pharmacy, DisputeResolution.DISMISS, evidenceHash)`, the contract settles the claim without distributing payouts. The exact state transitions differ significantly between **Normal Disputes** (proof-backed claims that locked epoch escrow at flag time) and **Exclusion Disputes** (claims raised by pharmacies alleging they were omitted from the root, which locked no escrow at flag time).

### Transition Matrix for Dismissals

The following table tracks the exact state transitions for each dispute type upon dismissal:

| State Variable / Metric | Normal Dispute Dismissal (`isExclusion = false`) | Exclusion Dispute Dismissal (`isExclusion = true`) |
| :--- | :--- | :--- |
| `flaggedAmount[epoch][pharmacy]` | Reset to `0` | Reset to `0` |
| `disputeFlaggedTimestamp[epoch][pharmacy]` | Reset to `0` | Reset to `0` |
| `isExclusionDispute[epoch][pharmacy]` | Remains `false` | Reset to `false` |
| `exclusionApproved[epoch][pharmacy]` | Remains `false` | Reset to `false` |
| `totalFlaggedNormal` | Decreased by `amount` | No change |
| `totalFlaggedExclusion` | No change | Decreased by `amount` |
| `epochVolume` | Decreased by `amount` (if `epoch == currentEpoch`) | No change (no volume was recorded on flag) |
| `epochClaimedTotal[epoch]` | Decreased by `amount` | No change (no claimed total was recorded on flag) |
| `epochRootClaimedTotal[epoch]` | Decreased by `amount` | No change |
| `pharmacyClaimedThisEpoch[epoch][pharmacy]` | Decreased by `amount` | No change |
| `epochEscrow[epoch]` | **If epoch not recalled**: Restored (increased by `amount`).<br>**If epoch recalled**: Stays `0`. | No change (no escrow was reserved on flag) |
| `totalEscrowed` | **If epoch not recalled**: Restored (increased by `amount`).<br>**If epoch recalled**: Stays unchanged. | No change |
| `hasClaimed[epoch][pharmacy]` | **REMAINS `true`** | **REMAINS `true`** |

### The `hasClaimed` Deadlock Issue

> [!WARNING]
> Both Normal and Exclusion disputes leave the claimant's `hasClaimed` status set to `true` upon dismissal.
> 
> *   **For Normal Disputes**: The pharmacy was in the Merkle root. If their dispute is dismissed, their claimed volume is reverted, but because `hasClaimed` remains `true`, they cannot submit a regular claim for that epoch.
> *   **For Exclusion Disputes**: The pharmacy was omitted from the root. If their dispute is dismissed (e.g., due to a technical/formatting error or insufficient proof), `hasClaimed` remains `true`. This permanently deadlocks the address from ever filing a corrected exclusion dispute or claiming if a root is corrected or updated.

---

## 3. Proposal to Reset `hasClaimed` for Dismissed Exclusion Claims

To resolve the deadlock described above, we propose resetting `hasClaimed` to `false` when an exclusion dispute is dismissed by the council.

### Safety and Accounting Proof

1.  **No Financial Exposure**: Exclusion disputes lock no funds from the distribution pool or the exclusion reserve at flag time (`flagExclusion` only sets `hasClaimed = true`, `flaggedAmount = amount`, etc.).
2.  **No Double-Dipping Risk**: Because the dispute is dismissed, the pharmacy receives exactly `0` tokens. Resetting `hasClaimed` to `false` returns them to their pre-flag state, meaning they cannot claim any tokens unless they file a new claim that is approved and resolved under strict volume caps.
3.  **Consistency with Retraction**: If a pharmacy retracts their own unresolved exclusion dispute after `DISPUTE_TIMEOUT` via `retractClaimDispute`, the contract already resets `hasClaimed` to `false` (Line 949). Automatically resetting it on a council dismissal aligns the council-side resolution with the user-side retraction logic.

### Implementation Detail
In the `resolveClaim` function, under the `isExclusion` branch, when the resolution is `DISMISS`:
```solidity
} else { // DISMISS
    hasClaimed[epoch][pharmacy] = false; // Reset to allow corrected re-filing
    emit ClaimResolved(epoch, pharmacy, amount, resolution, isExclusion, evidenceHash);
}
```

---

## 4. Readability Refactor for `resolveClaim`

The original `resolveClaim` implementation is verbose, has deep nested conditionals, and repeats logic (such as patient share calculations and volume cap checks). 

The refactored version below uses a cleaner **Checks-Effects-Interactions** layout that:
1.  Consolidates validations/checks at the top of the function.
2.  Updates all storage state variables (effects) together.
3.  Performs external token transfers (interactions) cleanly at the bottom.
4.  Addresses the `hasClaimed` reset for dismissed exclusion claims.

### Refactored Code Block

```solidity
    /**
     * @notice Council resolves a flagged dispute.
     * @dev    Transfers are done after state updates and event emission to follow
     *         checks-effects-interactions. nonReentrant guards external calls.
     *         RELEASE_TO_PHARMACY: net-of-patient-share paid to pharmacy.
     *         SEND_TO_PATIENT_FUND applies only to proof-backed claims whose funds were reserved.
     *         Exclusion disputes may be released or dismissed, but cannot create a treasury-funded penalty.
     *
     * @param epoch      The epoch of the dispute.
     * @param pharmacy   The pharmacy whose dispute to resolve.
     * @param resolution RELEASE_TO_PHARMACY, SEND_TO_PATIENT_FUND, or DISMISS.
     * @param evidenceHash Hash binding off-chain resolution evidence/rationale.
     */
    function resolveClaim(
        uint256            epoch,
        address            pharmacy,
        DisputeResolution  resolution,
        bytes32            evidenceHash
    )
        external
        nonReentrant
        onlyRole(COUNCIL_ROLE)
        whenNotPaused
    {
        // --- 1. CHECKS ---
        if (evidenceHash == bytes32(0)) revert ZeroEvidenceHash();
        
        uint256 amount = flaggedAmount[epoch][pharmacy];
        if (amount == 0) revert NoFlaggedClaim();

        bool isExclusion = isExclusionDispute[epoch][pharmacy];

        if (isExclusion) {
            if (resolution == DisputeResolution.SEND_TO_PATIENT_FUND) {
                revert InvalidExclusionResolution();
            }
            if (resolution == DisputeResolution.RELEASE_TO_PHARMACY) {
                if (!exclusionApproved[epoch][pharmacy]) revert ExclusionApprovalRequired();
                
                uint256 newEpochTotal = epochClaimedTotal[epoch] + amount;
                if (newEpochTotal > dailyVolumeCap)        revert DailyCapExceeded();
                if (newEpochTotal > hardAbsoluteVolumeCap) revert HardCapExceeded();
                if (exclusionRemediationReserve < amount)  revert InsufficientExclusionReserve();
            }
        }

        // --- 2. EFFECTS ---
        flaggedAmount[epoch][pharmacy] = 0;
        disputeFlaggedTimestamp[epoch][pharmacy] = 0;

        if (isExclusion) {
            isExclusionDispute[epoch][pharmacy] = false;
            exclusionApproved[epoch][pharmacy] = false;
            totalFlaggedExclusion -= amount;

            if (resolution == DisputeResolution.RELEASE_TO_PHARMACY) {
                exclusionRemediationReserve -= amount;
                epochClaimedTotal[epoch] += amount;
                epochExclusionPaidTotal[epoch] += amount;
                pharmacyClaimedThisEpoch[epoch][pharmacy] += amount;
                if (epoch == currentEpoch) {
                    epochVolume += amount;
                }
            } else { // DISMISS
                // Reset hasClaimed to allow re-filing or normal claims in the future
                hasClaimed[epoch][pharmacy] = false;
            }
        } else { // Normal proof-backed dispute
            totalFlaggedNormal -= amount;

            if (resolution == DisputeResolution.DISMISS) {
                epochClaimedTotal[epoch] -= amount;
                epochRootClaimedTotal[epoch] -= amount;
                pharmacyClaimedThisEpoch[epoch][pharmacy] -= amount;
                if (epoch == currentEpoch) {
                    epochVolume -= amount;
                }

                if (!epochRecalled[epoch]) {
                    epochEscrow[epoch] += amount;
                    totalEscrowed      += amount;
                }
            }
        }

        emit ClaimResolved(epoch, pharmacy, amount, resolution, isExclusion, evidenceHash);

        // --- 3. INTERACTIONS ---
        if (resolution == DisputeResolution.RELEASE_TO_PHARMACY) {
            uint256 patientShare  = (amount * patientClaimBP) / BP_DENOM;
            uint256 netToPharmacy = amount - patientShare;

            token.safeTransfer(patientFund, patientShare);
            token.safeTransfer(pharmacy,    netToPharmacy);
        } else if (resolution == DisputeResolution.SEND_TO_PATIENT_FUND) {
            // This path only executes for normal disputes (exclusion revert in CHECKS)
            token.safeTransfer(patientFund, amount);
        } else if (resolution == DisputeResolution.DISMISS) {
            // If normal dispute was already recalled, transfer the dismissed amount to patientFund
            if (!isExclusion && epochRecalled[epoch]) {
                token.safeTransfer(patientFund, amount);
            }
        }
    }
```

---

## 5. Invariant Validation of Refactored Code

Here we verify that all core accounting invariants are strictly preserved by the refactoring:

### Invariant 1: Total Escrowed & Epoch Escrow consistency for Normal Disputes
*   **Original**: On `DISMISS`, if `!epochRecalled`, it executes:
    ```solidity
    epochEscrow[epoch] += amount;
    totalEscrowed      += amount;
    ```
*   **Refactored**: Line 77-80 under `!isExclusion && resolution == DisputeResolution.DISMISS` executes exactly the same addition.
*   **Status**: **Preserved**.

### Invariant 2: Exclusion Remediation Reserve
*   **Original**: On `RELEASE_TO_PHARMACY` for exclusion claims, it executes:
    ```solidity
    exclusionRemediationReserve -= amount;
    ```
*   **Refactored**: Line 59 under `isExclusion && resolution == DisputeResolution.RELEASE_TO_PHARMACY` executes exactly the same deduction.
*   **Status**: **Preserved**.

### Invariant 3: Reversion of Claim Volume Metrics on Normal Dispute Dismissal
*   **Original**: On `DISMISS` for normal claims, it executes:
    ```solidity
    epochClaimedTotal[epoch] -= amount;
    epochRootClaimedTotal[epoch] -= amount;
    pharmacyClaimedThisEpoch[epoch][pharmacy] -= amount;
    if (epoch == currentEpoch) epochVolume -= amount;
    ```
*   **Refactored**: Lines 71-75 under `!isExclusion && resolution == DisputeResolution.DISMISS` execute these exact subtractions.
*   **Status**: **Preserved**.

### Invariant 4: Token Payout and Share Allocation
*   **Original**: Releases `patientShare` to `patientFund` and `netToPharmacy` to `pharmacy` in both exclusion and normal branches.
*   **Refactored**: Evaluated at the bottom (Lines 91-97) for `DisputeResolution.RELEASE_TO_PHARMACY` regardless of the dispute type, executing identical transfer math.
*   **Status**: **Preserved**.

### Invariant 5: Dismissed Normal Dispute in a Recalled Epoch
*   **Original**: If `epochRecalled` is true, sends the normal dispute's reserved escrow `amount` to the `patientFund` immediately to prevent trapping.
*   **Refactored**: Line 102 under `interactions` performs `token.safeTransfer(patientFund, amount)` when `!isExclusion && epochRecalled[epoch]` on `DISMISS`.
*   **Status**: **Preserved**.
