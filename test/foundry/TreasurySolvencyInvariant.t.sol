// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "../../contracts/PBMRebateTreasury.sol";
import "../../contracts/mocks/MockERC20.sol";
import "@openzeppelin/contracts/governance/TimelockController.sol";

/**
 * @title TreasurySolvencyInvariant
 * @notice Stateful property invariant tests for PBMRebateTreasury.
 *         Verifies solvency check zero-delta, full balance bucket conservation,
 *         total escrow sum consistency, and total flagged normal sum consistency.
 */
contract TreasurySolvencyInvariant {
    PBMRebateTreasury public treasury;
    MockERC20 public token;
    TimelockController public timelock;

    address public council;
    address public rootConfirmer;
    address public guardian;
    address public patientFund;
    address public environmentalFund;
    address public depositor;

    uint256 public constant INITIAL_DAILY_CAP = 100_000 ether;
    uint256 public constant MINIMUM_EPOCH_VOLUME = 10 ether;

    // Ghost accounting variables for tracked sums across epochs and claimants
    uint256 public ghostSumEpochEscrow;
    uint256 public ghostSumFlaggedNormal;

    mapping(uint256 => uint256) public ghostEpochEscrow;
    mapping(uint256 => mapping(address => uint256)) public ghostFlaggedNormal;

    // Tracking active epochs and claimants
    uint256[] public trackedEpochs;
    address[] public trackedPharmacies;

    constructor() {
        council = address(0x1111);
        rootConfirmer = address(0x2222);
        guardian = address(0x3333);
        patientFund = address(0x4444);
        environmentalFund = address(0x5555);
        depositor = address(0x6666);

        token = new MockERC20("Mock DAI", "mDAI", 18);

        address[] memory proposers = new address[](1);
        proposers[0] = council;
        address[] memory executors = new address[](1);
        executors[0] = address(0);

        timelock = new TimelockController(1, proposers, executors, council);

        treasury = new PBMRebateTreasury(
            address(token),
            patientFund,
            environmentalFund,
            INITIAL_DAILY_CAP,
            MINIMUM_EPOCH_VOLUME,
            council,
            rootConfirmer,
            address(timelock),
            guardian
        );

        token.mint(depositor, 10_000_000 ether);
        token.mint(council, 1_000_000 ether);
    }

    // =========================================================
    // INVARIANT ASSERTIONS
    // =========================================================

    /**
     * @notice Invariant 1: solvencyCheck() must always return isSolvent == true with delta == 0.
     */
    function invariant_solvencyCheckZeroDelta() public view returns (bool) {
        (bool isSolvent, uint256 delta, uint256 expected, uint256 actual) = treasury.solvencyCheck();
        return isSolvent && (delta == 0) && (expected == actual);
    }

    /**
     * @notice Invariant 2: Contract ERC20 token balance must strictly equal the sum of all internal buckets.
     *         contractBalance == distributionPool + governanceReserve + exclusionRemediationReserve + totalEscrowed + totalFlaggedNormal
     */
    function invariant_bucketConservation() public view returns (bool) {
        uint256 balance = token.balanceOf(address(treasury));
        uint256 sumBuckets = treasury.distributionPool() +
            treasury.governanceReserve() +
            treasury.exclusionRemediationReserve() +
            treasury.totalEscrowed() +
            treasury.totalFlaggedNormal();

        return balance == sumBuckets;
    }

    /**
     * @notice Invariant 3: totalEscrowed must equal the sum of active epochEscrow across all epochs.
     */
    function invariant_totalEscrowMatchesSum() public view returns (bool) {
        uint256 currentEpoch = treasury.currentEpoch();
        uint256 calculatedSum = 0;
        for (uint256 i = 0; i <= currentEpoch; i++) {
            calculatedSum += treasury.epochEscrow(i);
        }
        return treasury.totalEscrowed() == calculatedSum;
    }

    /**
     * @notice Invariant 4: totalFlaggedNormal must equal the sum of flaggedAmount for non-exclusion disputes.
     */
    function invariant_totalFlaggedNormalMatchesSum(address[] memory pharmacies) public view returns (bool) {
        uint256 currentEpoch = treasury.currentEpoch();
        uint256 calculatedSum = 0;
        for (uint256 e = 0; e <= currentEpoch; e++) {
            for (uint256 p = 0; p < pharmacies.length; p++) {
                address pharmacy = pharmacies[p];
                if (!treasury.isExclusionDispute(e, pharmacy)) {
                    calculatedSum += treasury.flaggedAmount(e, pharmacy);
                }
            }
        }
        return treasury.totalFlaggedNormal() == calculatedSum;
    }
}
