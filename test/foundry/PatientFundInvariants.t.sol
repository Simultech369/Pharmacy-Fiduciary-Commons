// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "../../contracts/PatientFundParticipatoryBudgeting.sol";
import "../../contracts/mocks/MockERC20.sol";

interface VmPB {
    function prank(address msgSender) external;
    function warp(uint256 newTimestamp) external;
}

/**
 * @title PatientFundFuzzHandler
 * @notice Bounded stateful action handler driving multi-round matching pools,
 *         external patient-fund routing, squared-vote allocations, zero-vote
 *         recycling, 90-day grace reclaims, and underfunded solvency debt tracking.
 */
contract PatientFundFuzzHandler {
    VmPB private constant vm = VmPB(address(uint160(uint256(keccak256("hevm cheat code")))));

    PatientFundParticipatoryBudgeting public immutable pb;
    MockERC20 public immutable token;

    address public immutable council;
    address public immutable patientSink;
    address public immutable voterA;
    address public immutable voterB;
    address public immutable projectRecipientA;
    address public immutable projectRecipientB;

    bool public underfundedDebtDecreased;
    bool public zeroVoteCouncilLeakDetected;

    mapping(uint256 => uint256) public lastObservedRoundDeficit;

    constructor(
        PatientFundParticipatoryBudgeting _pb,
        MockERC20 _token,
        address _council,
        address _patientSink,
        address _voterA,
        address _voterB,
        address _projectRecipientA,
        address _projectRecipientB
    ) {
        pb = _pb;
        token = _token;
        council = _council;
        patientSink = _patientSink;
        voterA = _voterA;
        voterB = _voterB;
        projectRecipientA = _projectRecipientA;
        projectRecipientB = _projectRecipientB;
    }

    function _recordRoundDeficitMonotonic(uint256 roundId) internal {
        if (roundId == 0) return;
        uint256 currentDeficit = pb.roundDeficit(roundId);
        if (currentDeficit < lastObservedRoundDeficit[roundId]) {
            underfundedDebtDecreased = true;
        }
        lastObservedRoundDeficit[roundId] = currentDeficit;
    }

    function actStartRound(uint96 rawMatchingPool) external {
        uint256 current = pb.currentRound();
        if (current > 0) {
            (, PatientFundParticipatoryBudgeting.RoundState state, , , , ) = pb.rounds(current);
            if (state != PatientFundParticipatoryBudgeting.RoundState.Finalized) return;
        }

        uint256 freshAmount = (uint256(rawMatchingPool) % 25_000 ether) + 10 ether;
        if (token.balanceOf(council) < freshAmount) return;

        vm.prank(council);
        token.approve(address(pb), freshAmount);
        vm.prank(council);
        try pb.startRound(freshAmount) {
            uint256 nextRound = pb.currentRound();
            vm.prank(council);
            pb.registerProject(nextRound, "Community Insulin Access", projectRecipientA);
            vm.prank(council);
            pb.registerProject(nextRound, "Mobile Rural Clinic", projectRecipientB);
            vm.prank(council);
            pb.registerVoter(nextRound, voterA, true);
            vm.prank(council);
            pb.registerVoter(nextRound, voterB, true);
            _recordRoundDeficitMonotonic(nextRound);
        } catch {}
    }

    function actRouteExternalPatientFunds(uint96 rawAmount) external {
        uint256 amount = (uint256(rawAmount) % 10_000 ether) + 1 ether;
        if (token.balanceOf(patientSink) < amount) return;

        vm.prank(patientSink);
        token.transfer(address(pb), amount);
        pb.refreshSolvencyDebt();
        _recordRoundDeficitMonotonic(pb.currentRound());
    }

    function actCastVotes(uint8 voteMask) external {
        uint256 roundId = pb.currentRound();
        if (roundId == 0) return;
        (, PatientFundParticipatoryBudgeting.RoundState state, uint256 projectCount, , , ) = pb.rounds(roundId);
        if (state != PatientFundParticipatoryBudgeting.RoundState.Active || projectCount < 2) return;

        if ((voteMask & 1) != 0 && !pb.hasVoted(roundId, voterA, 0)) {
            vm.prank(voterA);
            try pb.castVote(roundId, 0) {} catch {}
        }
        if ((voteMask & 2) != 0 && !pb.hasVoted(roundId, voterA, 1)) {
            vm.prank(voterA);
            try pb.castVote(roundId, 1) {} catch {}
        }
        if ((voteMask & 4) != 0 && !pb.hasVoted(roundId, voterB, 0)) {
            vm.prank(voterB);
            try pb.castVote(roundId, 0) {} catch {}
        }
    }

    function actSimulateUnderfundedDepletion(uint64 rawBurn) external {
        uint256 bal = token.balanceOf(address(pb));
        if (bal <= 1 ether) return;

        uint256 burnAmount = (uint256(rawBurn) % (bal / 2)) + 1;
        uint256 debtBefore = pb.totalDebt();
        uint256 shortfallBefore = pb.currentSolvencyShortfall();

        token.burn(address(pb), burnAmount);
        uint256 debtAfter = pb.refreshSolvencyDebt();

        if (shortfallBefore > 0 && debtAfter < debtBefore) {
            underfundedDebtDecreased = true;
        }
        _recordRoundDeficitMonotonic(pb.currentRound());
    }

    function actFinalizeRound() external {
        uint256 roundId = pb.currentRound();
        if (roundId == 0) return;
        (, PatientFundParticipatoryBudgeting.RoundState state, , , uint256 freshMatchingPool, ) = pb.rounds(roundId);
        if (state != PatientFundParticipatoryBudgeting.RoundState.Active) return;

        uint256 councilBefore = token.balanceOf(council);
        vm.prank(council);
        try pb.finalizeRound(roundId) {
            uint256 councilAfter = token.balanceOf(council);
            uint256 refundedCouncil = councilAfter >= councilBefore ? councilAfter - councilBefore : 0;
            if (refundedCouncil > freshMatchingPool) {
                zeroVoteCouncilLeakDetected = true;
            }
            _recordRoundDeficitMonotonic(roundId);
        } catch {}
    }

    function actClaimOrReclaim(uint8 roundSeed, uint8 projectSeed, bool reclaimAfterGrace) external {
        uint256 maxRound = pb.currentRound();
        if (maxRound == 0) return;

        uint256 roundId = (uint256(roundSeed) % maxRound) + 1;
        (, PatientFundParticipatoryBudgeting.RoundState state, uint256 projectCount, , , ) = pb.rounds(roundId);
        if (state != PatientFundParticipatoryBudgeting.RoundState.Finalized || projectCount == 0) return;

        uint256 projectId = uint256(projectSeed) % projectCount;
        if (pb.roundProjectShares(roundId, projectId) == 0) return;

        if (reclaimAfterGrace) {
            vm.warp(block.timestamp + 91 days);
            vm.prank(council);
            try pb.reclaimUnclaimedMatchShare(roundId, projectId) {
                _recordRoundDeficitMonotonic(roundId);
            } catch {}
        } else {
            try pb.claimMatchShare(roundId, projectId) {
                _recordRoundDeficitMonotonic(roundId);
            } catch {}
        }
    }
}

/**
 * @title PatientFundInvariants
 * @notice Stateful property invariant tests for PatientFundParticipatoryBudgeting.
 *         Verifies balance reserves, solvency debt non-negativity, and zero-vote
 *         patient-fund sink retention under Foundry invariant fuzzing.
 */
contract PatientFundInvariants {
    PatientFundParticipatoryBudgeting public pb;
    MockERC20 public token;
    PatientFundFuzzHandler public handler;

    address public council;
    address public guardian;
    address public patientSink;
    address public voterA;
    address public voterB;
    address public projectRecipientA;
    address public projectRecipientB;

    address[] private targetContractsList;

    function setUp() public {
        council = address(0xA111);
        guardian = address(0xA222);
        patientSink = address(0xA333);
        voterA = address(0xA444);
        voterB = address(0xA555);
        projectRecipientA = address(0xA666);
        projectRecipientB = address(0xA777);

        token = new MockERC20("Mock USDC", "mUSDC", 18);
        pb = new PatientFundParticipatoryBudgeting(address(token), council, guardian);

        token.mint(council, 10_000_000 ether);
        token.mint(patientSink, 5_000_000 ether);

        handler = new PatientFundFuzzHandler(
            pb,
            token,
            council,
            patientSink,
            voterA,
            voterB,
            projectRecipientA,
            projectRecipientB
        );

        targetContractsList.push(address(handler));
    }

    function targetContracts() public view returns (address[] memory) {
        return targetContractsList;
    }

    // Invariant 1: Total recorded debt tracks current shortfall and never decreases during depletion
    function invariant_total_debt_non_negative() public view {
        require(!handler.underfundedDebtDecreased(), "Solvency debt decreased during depletion");
        require(pb.totalDebt() == pb.currentSolvencyShortfall(), "Synced debt diverges from shortfall");
    }

    // Invariant 2: Contract balance plus recorded solvency debt covers all unclaimed shares and active obligations
    function invariant_balance_covers_shares_or_debt() public view {
        uint256 contractBalance = token.balanceOf(address(pb));
        uint256 recordedDebt = pb.totalDebt();
        require(
            contractBalance + recordedDebt >= pb.totalUnclaimedShares(),
            "Balance + debt below unclaimed shares"
        );
        require(
            contractBalance + recordedDebt >= pb.requiredSolvencyBalance(),
            "Balance + debt below required solvency balance"
        );
    }

    // Invariant 3: Recycled and externally routed patient funds never leak to council on zero-vote or dust refunds
    function invariant_zero_vote_recycled_funds_stay_in_sink() public view {
        require(!handler.zeroVoteCouncilLeakDetected(), "Council refund exceeded fresh contribution");
    }
}
