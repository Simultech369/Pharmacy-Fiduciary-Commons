// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "../../contracts/PBMRebateTreasury.sol";
import "../../contracts/mocks/MockERC20.sol";
import "@openzeppelin/contracts/governance/TimelockController.sol";

interface Vm {
    function prank(address msgSender) external;
    function warp(uint256 newTimestamp) external;
}

/**
 * @title TreasuryFuzzHandler
 * @notice Bounded stateful action handler driving multi-epoch deposits, dual-Safe
 *         Merkle roots, claims, proof-backed disputes, recalls, and cap ratchets.
 */
contract TreasuryFuzzHandler {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    PBMRebateTreasury public immutable treasury;
    MockERC20 public immutable token;
    TimelockController public immutable timelock;

    address public immutable council;
    address public immutable rootConfirmer;
    address public immutable depositor;
    address public immutable pharmacyA;
    address public immutable pharmacyB;

    uint256 public nonceCounter;
    uint256 public lastPatientFundBalance;
    bool public patientFundMonotonicBroken;

    mapping(uint256 => uint256) public epochLeafAmountA;
    mapping(uint256 => uint256) public epochLeafAmountB;
    mapping(uint256 => bytes32) public epochSiblingForA;
    mapping(uint256 => bytes32) public epochSiblingForB;

    constructor(
        PBMRebateTreasury _treasury,
        MockERC20 _token,
        TimelockController _timelock,
        address _council,
        address _rootConfirmer,
        address _depositor,
        address _pharmacyA,
        address _pharmacyB
    ) {
        treasury = _treasury;
        token = _token;
        timelock = _timelock;
        council = _council;
        rootConfirmer = _rootConfirmer;
        depositor = _depositor;
        pharmacyA = _pharmacyA;
        pharmacyB = _pharmacyB;
    }

    function _checkPatientFundMonotonic() internal {
        uint256 currentBal = token.balanceOf(treasury.patientFund());
        if (currentBal < lastPatientFundBalance) {
            patientFundMonotonicBroken = true;
        }
        lastPatientFundBalance = currentBal;
    }

    function _leaf(address account, uint256 amount) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encodePacked(account, amount, amount))));
    }

    function actDeposit(uint96 rawAmount) external {
        uint256 amount = (uint256(rawAmount) % 50_000 ether) + 100 ether;
        if (token.balanceOf(depositor) < amount) return;

        vm.prank(depositor);
        token.approve(address(treasury), amount);
        vm.prank(depositor);
        treasury.depositRebate(amount, "foundry-fuzz");
        _checkPatientFundMonotonic();
    }

    function actPublishTwoLeafRoot(uint64 rawA, uint64 rawB) external {
        uint256 epoch = treasury.currentEpoch();
        if (treasury.epochMerkleRoot(epoch) != bytes32(0)) return;

        uint256 pool = treasury.distributionPool();
        uint256 cap = treasury.dailyVolumeCap();
        uint256 maxBudget = pool < cap ? pool : cap;
        if (maxBudget < 100 ether) return;

        uint256 amtA = (uint256(rawA) % (maxBudget / 2)) + 30 ether;
        uint256 amtB = (uint256(rawB) % (maxBudget / 2)) + 30 ether;
        if (amtA + amtB > maxBudget) {
            amtB = maxBudget - amtA;
        }
        if (amtB == 0) return;

        bytes32 lA = _leaf(pharmacyA, amtA);
        bytes32 lB = _leaf(pharmacyB, amtB);
        bytes32 root = uint256(lA) <= uint256(lB)
            ? keccak256(abi.encodePacked(lA, lB))
            : keccak256(abi.encodePacked(lB, lA));

        vm.prank(council);
        try treasury.proposeRoot(root, amtA + amtB) {
            vm.prank(rootConfirmer);
            treasury.confirmRoot(epoch);
            epochLeafAmountA[epoch] = amtA;
            epochLeafAmountB[epoch] = amtB;
            epochSiblingForA[epoch] = lB;
            epochSiblingForB[epoch] = lA;
        } catch {}
        _checkPatientFundMonotonic();
    }

    function actClaimA() external {
        uint256 epoch = treasury.currentEpoch();
        uint256 amt = epochLeafAmountA[epoch];
        if (amt == 0 || treasury.hasClaimed(epoch, pharmacyA)) return;

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = epochSiblingForA[epoch];
        vm.prank(pharmacyA);
        try treasury.claim(amt, amt, proof) {} catch {}
        _checkPatientFundMonotonic();
    }

    function actFlagAndResolveB(uint8 resolutionSeed) external {
        uint256 epoch = treasury.currentEpoch();
        uint256 amt = epochLeafAmountB[epoch];
        if (amt == 0 || treasury.hasClaimed(epoch, pharmacyB)) return;

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = epochSiblingForB[epoch];
        vm.prank(pharmacyB);
        try treasury.flagClaim(epoch, amt, amt, proof, keccak256("flag-b")) {
            PBMRebateTreasury.DisputeResolution res = PBMRebateTreasury.DisputeResolution(resolutionSeed % 3);
            vm.prank(council);
            treasury.resolveClaim(epoch, pharmacyB, res, keccak256("resolve-b"));
        } catch {}
        _checkPatientFundMonotonic();
    }

    function actFinalizeAndRecall() external {
        uint256 epoch = treasury.currentEpoch();
        if (treasury.epochMerkleRoot(epoch) == bytes32(0)) return;

        vm.warp(block.timestamp + 31 days);
        vm.prank(council);
        if (treasury.epochVolume() >= treasury.minimumEpochVolume()) {
            try treasury.finalizeEpoch() {} catch {}
        } else {
            try treasury.finalizeStaleEpochForRecall() {} catch {}
        }

        if (treasury.currentEpoch() > epoch && treasury.epochEscrow(epoch) > 0) {
            vm.warp(block.timestamp + 31 days);
            vm.prank(council);
            try treasury.recallUnclaimed(epoch) {} catch {}
        }
        _checkPatientFundMonotonic();
    }

    function actRatchetHardCapDown(uint64 deltaSeed) external {
        uint256 currentHard = treasury.hardAbsoluteVolumeCap();
        uint256 currentDaily = treasury.dailyVolumeCap();
        if (currentHard <= currentDaily + 1 ether) return;

        uint256 cut = (uint256(deltaSeed) % (currentHard - currentDaily)) + 1;
        uint256 newHard = currentHard - cut;
        if (newHard < currentDaily) newHard = currentDaily;

        nonceCounter += 1;
        bytes32 salt = bytes32(nonceCounter);
        bytes memory data = abi.encodeWithSelector(PBMRebateTreasury.reduceHardCap.selector, newHard);

        vm.prank(council);
        timelock.schedule(address(treasury), 0, data, bytes32(0), salt, 1);
        vm.warp(block.timestamp + 2);
        timelock.execute(address(treasury), 0, data, bytes32(0), salt);
        _checkPatientFundMonotonic();
    }
}

/**
 * @title TreasurySolvencyInvariant
 * @notice Stateful property invariant tests for PBMRebateTreasury covering
 *         zero-delta solvency, bucket conservation, epoch escrow/recall math,
 *         dispute accounting, and downward-only hard-cap bounds.
 */
contract TreasurySolvencyInvariant {
    PBMRebateTreasury public treasury;
    MockERC20 public token;
    TimelockController public timelock;
    TreasuryFuzzHandler public handler;

    address public council;
    address public rootConfirmer;
    address public guardian;
    address public patientFund;
    address public environmentalFund;
    address public depositor;
    address public pharmacyA;
    address public pharmacyB;

    uint256 public constant INITIAL_DAILY_CAP = 100_000 ether;
    uint256 public constant INITIAL_HARD_CAP = INITIAL_DAILY_CAP * 10;
    uint256 public constant MINIMUM_EPOCH_VOLUME = 10 ether;

    address[] private trackedClaimants;
    address[] private targetContractsList;

    function setUp() public {
        council = address(0x1111);
        rootConfirmer = address(0x2222);
        guardian = address(0x3333);
        patientFund = address(0x4444);
        environmentalFund = address(0x5555);
        depositor = address(0x6666);
        pharmacyA = address(0x7777);
        pharmacyB = address(0x8888);

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

        handler = new TreasuryFuzzHandler(
            treasury,
            token,
            timelock,
            council,
            rootConfirmer,
            depositor,
            pharmacyA,
            pharmacyB
        );

        trackedClaimants.push(pharmacyA);
        trackedClaimants.push(pharmacyB);
        targetContractsList.push(address(handler));
    }

    function targetContracts() public view returns (address[] memory) {
        return targetContractsList;
    }

    function invariant_solvencyCheckZeroDelta() public view {
        (bool isSolvent, uint256 delta, uint256 expected, uint256 actual) = treasury.solvencyCheck();
        require(isSolvent && delta == 0 && expected == actual, "Solvency delta mismatch");
    }

    function invariant_bucketConservation() public view {
        uint256 balance = token.balanceOf(address(treasury));
        uint256 sumBuckets = treasury.distributionPool() +
            treasury.governanceReserve() +
            treasury.exclusionRemediationReserve() +
            treasury.totalEscrowed() +
            treasury.totalFlaggedNormal();

        require(balance == sumBuckets, "Bucket conservation violated");
    }

    function invariant_totalEscrowMatchesSum() public view {
        uint256 currentEpoch = treasury.currentEpoch();
        uint256 calculatedSum = 0;
        for (uint256 i = 0; i <= currentEpoch; i++) {
            calculatedSum += treasury.epochEscrow(i);
            if (treasury.epochRecalled(i)) {
                require(treasury.epochEscrow(i) == 0, "Non-zero escrow after recall");
            }
        }
        require(treasury.totalEscrowed() == calculatedSum, "Total escrow mismatch");
    }

    function invariant_totalFlaggedNormalMatchesSum() public view {
        uint256 currentEpoch = treasury.currentEpoch();
        uint256 calculatedSum = 0;
        for (uint256 e = 0; e <= currentEpoch; e++) {
            for (uint256 p = 0; p < trackedClaimants.length; p++) {
                address pharmacy = trackedClaimants[p];
                if (!treasury.isExclusionDispute(e, pharmacy)) {
                    calculatedSum += treasury.flaggedAmount(e, pharmacy);
                }
            }
        }
        require(treasury.totalFlaggedNormal() == calculatedSum, "Flagged normal mismatch");
    }

    function invariant_capHierarchyAndPatientFundSink() public view {
        uint256 dailyCap = treasury.dailyVolumeCap();
        uint256 hardCap = treasury.hardAbsoluteVolumeCap();
        require(dailyCap >= treasury.minimumEpochVolume(), "Daily cap below minimum");
        require(dailyCap <= hardCap, "Daily cap exceeds hard cap");
        require(hardCap <= INITIAL_HARD_CAP, "Hard cap increased past deployment ceiling");
        require(!handler.patientFundMonotonicBroken(), "Patient fund balance decreased");
    }
}
