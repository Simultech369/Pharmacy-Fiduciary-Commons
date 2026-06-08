// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title  PatientFundParticipatoryBudgeting
 * @author Pharmacy Fiduciary Commons
 * @notice Governs the allocation of the Patient Fund matching pool using Quadratic Funding.
 *         Sybil-resistant voting enables community members to vote on local health projects.
 */
contract PatientFundParticipatoryBudgeting is AccessControl {
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    bytes32 public constant COUNCIL_ROLE = keccak256("COUNCIL_ROLE");

    enum RoundState { Inactive, Active, Finalized }

    struct Project {
        string title;
        address recipient;
        uint256 voteCount;
        bool active;
    }

    struct Round {
        uint256 matchingPool;
        RoundState state;
        uint256 projectCount;
    }

    IERC20 public immutable token;
    uint256 public currentRound;
    address public relayerVerifier;

    // roundId -> Round details
    mapping(uint256 => Round) public rounds;
    
    // roundId => projectId => Project details
    mapping(uint256 => mapping(uint256 => Project)) public roundProjects;
    
    // roundId => voter => isRegistered
    mapping(uint256 => mapping(address => bool)) public registeredVoters;
    
    // roundId => voter => projectId => hasVoted
    mapping(uint256 => mapping(address => mapping(uint256 => bool))) public hasVoted;

    // =========================================================
    // EVENTS
    // =========================================================
    event RoundStarted(uint256 indexed roundId, uint256 matchingPool);
    event RoundFinalized(uint256 indexed roundId, uint256 totalWeight);
    event ProjectRegistered(uint256 indexed roundId, uint256 indexed projectId, string title, address recipient);
    event VoterRegistered(uint256 indexed roundId, address indexed voter, bool status);
    event VoteCast(uint256 indexed roundId, uint256 indexed projectId, address indexed voter);
    event MatchDistributed(uint256 indexed roundId, uint256 indexed projectId, address indexed recipient, uint256 amount);
    event RelayerVerifierUpdated(address indexed newVerifier);

    // =========================================================
    // CUSTOM ERRORS
    // =========================================================
    error InvalidAddress();
    error ZeroAmount();
    error NotActive();
    error AlreadyFinalized();
    error AlreadyVoted();
    error ProjectInactive();
    error Unauthorized();
    error WrongRoundState();
    error ArrayEmpty();

    // =========================================================
    // CONSTRUCTOR
    // =========================================================
    constructor(address _token, address _council) {
        if (_token == address(0)) revert InvalidAddress();
        if (_council == address(0)) revert InvalidAddress();

        token = IERC20(_token);
        _grantRole(DEFAULT_ADMIN_ROLE, _council);
        _grantRole(COUNCIL_ROLE, _council);
    }

    // =========================================================
    // ROUND ADMINISTRATION (COUNCIL ONLY)
    // =========================================================

    function startRound(uint256 matchingPoolAmount) external onlyRole(COUNCIL_ROLE) {
        if (matchingPoolAmount == 0) revert ZeroAmount();

        currentRound += 1;
        uint256 roundId = currentRound;

        token.safeTransferFrom(msg.sender, address(this), matchingPoolAmount);

        rounds[roundId] = Round({
            matchingPool: matchingPoolAmount,
            state: RoundState.Active,
            projectCount: 0
        });

        emit RoundStarted(roundId, matchingPoolAmount);
    }

    function setRelayerVerifier(address _newVerifier) external onlyRole(COUNCIL_ROLE) {
        if (_newVerifier == address(0)) revert InvalidAddress();
        relayerVerifier = _newVerifier;
        emit RelayerVerifierUpdated(_newVerifier);
    }

    function registerVoter(uint256 roundId, address voter, bool status) external onlyRole(COUNCIL_ROLE) {
        if (voter == address(0)) revert InvalidAddress();
        if (rounds[roundId].state != RoundState.Active) revert WrongRoundState();

        registeredVoters[roundId][voter] = status;
        emit VoterRegistered(roundId, voter, status);
    }

    function registerVotersBatch(uint256 roundId, address[] calldata voters) external onlyRole(COUNCIL_ROLE) {
        if (voters.length == 0) revert ArrayEmpty();
        if (rounds[roundId].state != RoundState.Active) revert WrongRoundState();

        for (uint256 i = 0; i < voters.length; i++) {
            address voter = voters[i];
            if (voter == address(0)) revert InvalidAddress();
            registeredVoters[roundId][voter] = true;
            emit VoterRegistered(roundId, voter, true);
        }
    }

    function registerVoterWithSignature(uint256 roundId, address voter, bytes calldata signature) external {
        if (voter == address(0)) revert InvalidAddress();
        if (msg.sender != voter) revert Unauthorized();
        if (rounds[roundId].state != RoundState.Active) revert WrongRoundState();
        if (relayerVerifier == address(0)) revert InvalidAddress();

        bytes32 messageHash = keccak256(abi.encodePacked(roundId, voter, address(this)));
        address signer = messageHash.toEthSignedMessageHash().recover(signature);
        if (signer != relayerVerifier) revert Unauthorized();

        registeredVoters[roundId][voter] = true;
        emit VoterRegistered(roundId, voter, true);
    }

    function registerProject(uint256 roundId, string calldata title, address recipient) external onlyRole(COUNCIL_ROLE) {
        if (recipient == address(0)) revert InvalidAddress();
        if (bytes(title).length == 0) revert InvalidAddress();
        if (rounds[roundId].state != RoundState.Active) revert WrongRoundState();

        Round storage r = rounds[roundId];
        uint256 projectId = r.projectCount;

        roundProjects[roundId][projectId] = Project({
            title: title,
            recipient: recipient,
            voteCount: 0,
            active: true
        });

        r.projectCount += 1;

        emit ProjectRegistered(roundId, projectId, title, recipient);
    }

    // =========================================================
    // VOTING (REGISTERED VOTERS ONLY)
    // =========================================================

    function castVote(uint256 roundId, uint256 projectId) external {
        if (!registeredVoters[roundId][msg.sender]) revert Unauthorized();
        
        Round storage r = rounds[roundId];
        if (r.state != RoundState.Active) revert NotActive();
        if (projectId >= r.projectCount) revert ProjectInactive();

        Project storage p = roundProjects[roundId][projectId];
        if (!p.active) revert ProjectInactive();
        if (hasVoted[roundId][msg.sender][projectId]) revert AlreadyVoted();

        hasVoted[roundId][msg.sender][projectId] = true;
        p.voteCount += 1;

        emit VoteCast(roundId, projectId, msg.sender);
    }

    // =========================================================
    // FINALIZATION & PROPORTIONAL QF PAYOUT
    // =========================================================

    /**
     * @notice Finalizes the voting round, calculates quadratic weights, and distributes matching pool.
     * @dev    Weight of project i is (votes_i)^2. Proportional share is Weight_i / TotalWeight.
     *         If totalWeight is 0, the matching pool is returned to the council address to prevent locking.
     */
    function finalizeRound(uint256 roundId) external onlyRole(COUNCIL_ROLE) {
        Round storage r = rounds[roundId];
        if (r.state != RoundState.Active) revert WrongRoundState();

        uint256 count = r.projectCount;
        uint256 totalWeight = 0;

        // 1. Calculate weights for all projects
        uint256[] memory weights = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            uint256 votes = roundProjects[roundId][i].voteCount;
            uint256 weight = votes * votes; // QF weight
            weights[i] = weight;
            totalWeight += weight;
        }

        uint256 pool = r.matchingPool;
        r.state = RoundState.Finalized;

        // 2. Handle zero vote edge case
        if (totalWeight == 0) {
            token.safeTransfer(msg.sender, pool);
            emit RoundFinalized(roundId, 0);
            return;
        }

        // 3. Distribute matching pool proportionally
        uint256 distributed = 0;
        for (uint256 i = 0; i < count; i++) {
            if (weights[i] > 0) {
                // Calculate proportional share
                uint256 share = (pool * weights[i]) / totalWeight;
                if (share > 0) {
                    address recipient = roundProjects[roundId][i].recipient;
                    token.safeTransfer(recipient, share);
                    distributed += share;
                    emit MatchDistributed(roundId, i, recipient, share);
                }
            }
        }

        // Refund any tiny division dust left over to the council
        if (pool > distributed) {
            uint256 dust = pool - distributed;
            token.safeTransfer(msg.sender, dust);
        }

        emit RoundFinalized(roundId, totalWeight);
    }
}
