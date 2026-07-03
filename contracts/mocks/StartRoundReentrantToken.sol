// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

interface IStartRoundReentryTarget {
    function currentRound() external view returns (uint256);
    function rounds(uint256 roundId)
        external
        view
        returns (uint256 matchingPool, uint8 state, uint256 projectCount, uint256 finalizedAt);
    function startRound(uint256 matchingPoolAmount) external;
    function registerVoter(uint256 roundId, address voter, bool status) external;
    function registerVotersBatch(uint256 roundId, address[] calldata voters) external;
    function registerProject(uint256 roundId, string calldata title, address recipient) external;
    function proposeProject(uint256 roundId, string calldata title, address recipient) external;
    function supportProposal(uint256 roundId, uint256 proposalId) external;
    function castVote(uint256 roundId, uint256 projectId) external;
}

contract StartRoundReentrantToken is ERC20 {
    error InvalidAddress();

    IStartRoundReentryTarget public target;
    bool public attackEnabled;
    bool private entered;

    uint256 public callbackCount;
    uint256 public observedCurrentRound;
    uint8 public observedNextRoundState;
    uint256 public observedNextRoundProjectCount;
    uint256 public unexpectedSuccessCount;

    bool public recursiveStartRoundBlocked;
    bool public registerVoterBlocked;
    bool public registerVotersBatchBlocked;
    bool public registerProjectBlocked;
    bool public proposeProjectBlocked;
    bool public supportProposalBlocked;
    bool public castVoteBlocked;

    event TargetUpdated(address indexed target);
    event AttackEnabledUpdated(bool enabled);

    constructor() ERC20("StartRound Reentrant Token", "SRT") {}

    function setTarget(address target_) external {
        if (target_ == address(0)) revert InvalidAddress();
        target = IStartRoundReentryTarget(target_);
        emit TargetUpdated(target_);
    }

    function setAttackEnabled(bool enabled) external {
        attackEnabled = enabled;
        emit AttackEnabledUpdated(enabled);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        if (attackEnabled && !entered && msg.sender == address(target)) {
            entered = true;
            _probeStartRoundCallback();
            entered = false;
        }

        return super.transferFrom(from, to, amount);
    }

    function _probeStartRoundCallback() private {
        callbackCount += 1;
        observedCurrentRound = target.currentRound();
        uint256 nextRound = observedCurrentRound + 1;
        (, uint8 state, uint256 projectCount,) = target.rounds(nextRound);
        observedNextRoundState = state;
        observedNextRoundProjectCount = projectCount;

        try target.startRound(1) {
            unexpectedSuccessCount += 1;
        } catch {
            recursiveStartRoundBlocked = true;
        }

        try target.registerVoter(nextRound, address(this), true) {
            unexpectedSuccessCount += 1;
        } catch {
            registerVoterBlocked = true;
        }

        address[] memory voters = new address[](1);
        voters[0] = address(this);
        try target.registerVotersBatch(nextRound, voters) {
            unexpectedSuccessCount += 1;
        } catch {
            registerVotersBatchBlocked = true;
        }

        try target.registerProject(nextRound, "callback project", address(this)) {
            unexpectedSuccessCount += 1;
        } catch {
            registerProjectBlocked = true;
        }

        try target.proposeProject(nextRound, "callback project", address(this)) {
            unexpectedSuccessCount += 1;
        } catch {
            proposeProjectBlocked = true;
        }

        try target.supportProposal(nextRound, 0) {
            unexpectedSuccessCount += 1;
        } catch {
            supportProposalBlocked = true;
        }

        try target.castVote(nextRound, 0) {
            unexpectedSuccessCount += 1;
        } catch {
            castVoteBlocked = true;
        }
    }
}
