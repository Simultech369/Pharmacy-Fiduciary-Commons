// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title  PatientFundParticipatoryBudgeting
 * @author Pharmacy Fiduciary Commons
 * @notice Governs the allocation of the Patient Fund matching pool using squared vote weights.
 *         Credential-gated voting enables community members to vote on local health projects.
 */
contract PatientFundParticipatoryBudgeting is AccessControl, EIP712, Pausable {
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    bytes32 public constant COUNCIL_ROLE = keccak256("COUNCIL_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    uint256 public constant MAX_PROJECTS_PER_ROUND = 50;
    bytes32 public constant REGISTRATION_TYPEHASH = keccak256(
        "VoterRegistration(uint256 roundId,address voter,uint256 nonce,bytes32 credentialHash,bytes32 policyVersion,uint256 deadline)"
    );
    bytes32 public constant ACCEPTED_CREDENTIAL_POLICY_VERSION = keccak256(
        "fiduciary-credential-policy-v1"
    );

    enum RoundState { Inactive, Active, Finalized }

    struct Project {
        string title;
        address recipient;
        uint256 voteCount;
        bool active;
    }

    struct ProjectProposal {
        string title;
        address recipient;
        uint256 supportCount;
        bool registered;
    }

    struct Round {
        uint256 matchingPool;
        RoundState state;
        uint256 projectCount;
    }

    IERC20 public immutable token;
    address public immutable council;
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

    // roundId => voter => next relayer authorization nonce
    mapping(uint256 => mapping(address => uint256)) public registrationNonces;

    // roundId => projectId => matching share amount
    mapping(uint256 => mapping(uint256 => uint256)) public roundProjectShares;

    // issuerAddress => isTrusted
    mapping(address => bool) public trustedCredentialIssuers;

    uint256 public projectSupportThreshold = 3;

    // roundId => proposalId => ProjectProposal details
    mapping(uint256 => mapping(uint256 => ProjectProposal)) public roundProposals;
    // roundId => proposalCount
    mapping(uint256 => uint256) public roundProposalCount;
    // roundId => proposalId => voter => hasSupported
    mapping(uint256 => mapping(uint256 => mapping(address => bool))) public hasSupportedProposal;

    // =========================================================
    // EVENTS
    // =========================================================
    event TrustedCredentialIssuerUpdated(address indexed issuer, bool status);
    event RoundStarted(uint256 indexed roundId, uint256 matchingPool);
    event RoundFinalized(uint256 indexed roundId, uint256 totalWeight);
    event ProjectRegistered(uint256 indexed roundId, uint256 indexed projectId, string title, address recipient);
    event VoterRegistered(uint256 indexed roundId, address indexed voter, bool status);
    event RegistrationAuthorizationUsed(
        uint256 indexed roundId,
        address indexed voter,
        bytes32 indexed credentialHash,
        bytes32 policyVersion,
        uint256 deadline
    );
    event VoteCast(uint256 indexed roundId, uint256 indexed projectId, address indexed voter);
    event MatchDistributed(uint256 indexed roundId, uint256 indexed projectId, address indexed recipient, uint256 amount);
    event RelayerVerifierUpdated(address indexed newVerifier);
    event Sweep(address indexed tokenAddr, address indexed recipient, uint256 amount);
    event ProjectProposed(uint256 indexed roundId, uint256 indexed proposalId, string title, address indexed recipient);
    event ProposalSupported(uint256 indexed roundId, uint256 indexed proposalId, address indexed supporter, uint256 currentSupport);
    event ProjectSupportThresholdUpdated(uint256 newThreshold);

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
    error AuthorizationExpired();
    error InvalidAuthorizationMetadata();
    error UnsupportedCredentialPolicy();
    error ProjectLimitReached();
    error RoundAlreadyActive();
    error CannotSweepMatchingToken();
    error GuardianMustDifferFromCouncil();
    error ProposalAlreadyRegistered();
    error AlreadySupported();
    error ProposalDoesNotExist();

    // =========================================================
    // CONSTRUCTOR
    // =========================================================
    constructor(address _token, address _council, address _guardian)
        EIP712("Pharmacy Fiduciary Commons", "1")
    {
        if (_token == address(0)) revert InvalidAddress();
        if (_council == address(0)) revert InvalidAddress();
        if (_guardian == address(0)) revert InvalidAddress();
        if (_guardian == _council) revert GuardianMustDifferFromCouncil();

        token = IERC20(_token);
        council = _council;
        _grantRole(DEFAULT_ADMIN_ROLE, _council);
        _grantRole(COUNCIL_ROLE, _council);
        _grantRole(GUARDIAN_ROLE, _guardian);
    }

    // =========================================================
    // ROUND ADMINISTRATION (COUNCIL ONLY)
    // =========================================================

    function startRound(uint256 matchingPoolAmount) external onlyRole(COUNCIL_ROLE) whenNotPaused {
        if (matchingPoolAmount == 0) revert ZeroAmount();
        if (currentRound > 0 && rounds[currentRound].state != RoundState.Finalized) {
            revert RoundAlreadyActive();
        }

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

    function setRelayerVerifier(address _newVerifier) external onlyRole(COUNCIL_ROLE) whenNotPaused {
        if (_newVerifier == address(0)) revert InvalidAddress();
        relayerVerifier = _newVerifier;
        emit RelayerVerifierUpdated(_newVerifier);
    }

    function setTrustedCredentialIssuer(address issuer, bool status) external onlyRole(COUNCIL_ROLE) whenNotPaused {
        if (issuer == address(0)) revert InvalidAddress();
        trustedCredentialIssuers[issuer] = status;
        emit TrustedCredentialIssuerUpdated(issuer, status);
    }

    function registerVoter(uint256 roundId, address voter, bool status) external onlyRole(COUNCIL_ROLE) whenNotPaused {
        if (voter == address(0)) revert InvalidAddress();
        if (rounds[roundId].state != RoundState.Active) revert WrongRoundState();

        registeredVoters[roundId][voter] = status;
        registrationNonces[roundId][voter] += 1;
        emit VoterRegistered(roundId, voter, status);
    }

    function registerVotersBatch(uint256 roundId, address[] calldata voters) external onlyRole(COUNCIL_ROLE) whenNotPaused {
        if (voters.length == 0) revert ArrayEmpty();
        if (rounds[roundId].state != RoundState.Active) revert WrongRoundState();

        for (uint256 i = 0; i < voters.length; i++) {
            address voter = voters[i];
            if (voter == address(0)) revert InvalidAddress();
            registeredVoters[roundId][voter] = true;
            registrationNonces[roundId][voter] += 1;
            emit VoterRegistered(roundId, voter, true);
        }
    }

    function registerVoterWithSignature(
        uint256 roundId,
        address voter,
        bytes32 credentialHash,
        bytes32 policyVersion,
        uint256 deadline,
        bytes calldata signature
    ) external whenNotPaused {
        if (voter == address(0)) revert InvalidAddress();
        if (msg.sender != voter) revert Unauthorized();
        if (rounds[roundId].state != RoundState.Active) revert WrongRoundState();
        if (relayerVerifier == address(0)) revert InvalidAddress();
        if (credentialHash == bytes32(0) || policyVersion == bytes32(0)) {
            revert InvalidAuthorizationMetadata();
        }
        if (policyVersion != ACCEPTED_CREDENTIAL_POLICY_VERSION) {
            revert UnsupportedCredentialPolicy();
        }
        if (block.timestamp > deadline) revert AuthorizationExpired();

        // EIP-712 binds the authorization to this deployment and chain through the
        // domain separator while keeping the policy fields readable to wallets.
        uint256 nonce = registrationNonces[roundId][voter];
        bytes32 structHash = keccak256(
            abi.encode(
                REGISTRATION_TYPEHASH,
                roundId,
                voter,
                nonce,
                credentialHash,
                policyVersion,
                deadline
            )
        );
        address signer = _hashTypedDataV4(structHash).recover(signature);
        if (signer != relayerVerifier) revert Unauthorized();

        registrationNonces[roundId][voter] = nonce + 1;
        registeredVoters[roundId][voter] = true;
        emit VoterRegistered(roundId, voter, true);
        emit RegistrationAuthorizationUsed(roundId, voter, credentialHash, policyVersion, deadline);
    }

    /**
     * @notice Allows a voter to self-register by presenting a credential signed by a trusted issuer.
     * @dev Issuer signatures bind chain ID, contract address, voter, round,
     *      current nonce, credential hash, policy version, and deadline. Council
     *      registration/revocation advances the nonce and invalidates outstanding
     *      issuer signatures.
     */
    function registerVoterWithCredential(
        uint256 roundId,
        bytes32 credentialHash,
        bytes32 policyVersion,
        uint256 deadline,
        bytes calldata issuerSignature
    ) external whenNotPaused {
        if (rounds[roundId].state != RoundState.Active) revert WrongRoundState();
        if (credentialHash == bytes32(0) || policyVersion == bytes32(0)) {
            revert InvalidAuthorizationMetadata();
        }
        if (policyVersion != ACCEPTED_CREDENTIAL_POLICY_VERSION) {
            revert UnsupportedCredentialPolicy();
        }
        if (block.timestamp > deadline) revert AuthorizationExpired();

        // Reconstruct the issuer authorization. The nonce and deadline keep direct
        // issuer signatures from becoming reusable stale credentials, while chain
        // and contract binding prevent cross-deployment replay.
        uint256 nonce = registrationNonces[roundId][msg.sender];
        bytes32 messageHash = keccak256(
            abi.encodePacked(block.chainid, address(this), msg.sender, roundId, nonce, credentialHash, policyVersion, deadline)
        );
        bytes32 ethSignedMessageHash = ECDSA.toEthSignedMessageHash(messageHash);
        address issuer = ethSignedMessageHash.recover(issuerSignature);

        if (!trustedCredentialIssuers[issuer]) revert Unauthorized();

        registeredVoters[roundId][msg.sender] = true;
        registrationNonces[roundId][msg.sender] = nonce + 1;
        emit VoterRegistered(roundId, msg.sender, true);
        emit RegistrationAuthorizationUsed(roundId, msg.sender, credentialHash, policyVersion, deadline);
    }

    function setProjectSupportThreshold(uint256 threshold) external onlyRole(COUNCIL_ROLE) whenNotPaused {
        projectSupportThreshold = threshold;
        emit ProjectSupportThresholdUpdated(threshold);
    }

    /**
     * @notice Allows a registered voter to propose a new project for the active round.
     */
    function proposeProject(uint256 roundId, string calldata title, address recipient) external whenNotPaused {
        if (!registeredVoters[roundId][msg.sender]) revert Unauthorized();
        if (rounds[roundId].state != RoundState.Active) revert WrongRoundState();
        if (recipient == address(0)) revert InvalidAddress();
        if (bytes(title).length == 0) revert InvalidAddress();

        uint256 proposalId = roundProposalCount[roundId];
        roundProposals[roundId][proposalId] = ProjectProposal({
            title: title,
            recipient: recipient,
            supportCount: 0,
            registered: false
        });

        roundProposalCount[roundId] += 1;

        emit ProjectProposed(roundId, proposalId, title, recipient);
    }

    /**
     * @notice Allows a registered voter to support a proposed project.
     *         Once a proposal reaches the projectSupportThreshold, it is registered.
     */
    function supportProposal(uint256 roundId, uint256 proposalId) external whenNotPaused {
        if (!registeredVoters[roundId][msg.sender]) revert Unauthorized();
        if (rounds[roundId].state != RoundState.Active) revert WrongRoundState();
        if (proposalId >= roundProposalCount[roundId]) revert ProposalDoesNotExist();

        ProjectProposal storage prop = roundProposals[roundId][proposalId];
        if (prop.registered) revert ProposalAlreadyRegistered();
        if (hasSupportedProposal[roundId][proposalId][msg.sender]) revert AlreadySupported();

        hasSupportedProposal[roundId][proposalId][msg.sender] = true;
        prop.supportCount += 1;

        emit ProposalSupported(roundId, proposalId, msg.sender, prop.supportCount);

        if (prop.supportCount >= projectSupportThreshold) {
            prop.registered = true;
            _registerProject(roundId, prop.title, prop.recipient);
        }
    }

    function registerProject(uint256 roundId, string calldata title, address recipient) external onlyRole(COUNCIL_ROLE) whenNotPaused {
        if (recipient == address(0)) revert InvalidAddress();
        if (bytes(title).length == 0) revert InvalidAddress();
        if (rounds[roundId].state != RoundState.Active) revert WrongRoundState();

        _registerProject(roundId, title, recipient);
    }

    function _registerProject(uint256 roundId, string memory title, address recipient) internal {
        Round storage r = rounds[roundId];
        if (r.projectCount >= MAX_PROJECTS_PER_ROUND) revert ProjectLimitReached();
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

    function castVote(uint256 roundId, uint256 projectId) external whenNotPaused {
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
    // FINALIZATION & SQUARED VOTE-WEIGHT PAYOUT
    // =========================================================

    /**
     * @notice Finalizes the voting round, calculates squared vote weights, and distributes matching pool.
     * @dev    Weight of project i is (votes_i)^2. Proportional share is Weight_i / TotalWeight.
     *         If totalWeight is 0, the matching pool is returned to the council address to prevent locking.
     */
    function finalizeRound(uint256 roundId) external onlyRole(COUNCIL_ROLE) whenNotPaused {
        Round storage r = rounds[roundId];
        if (r.state != RoundState.Active) revert WrongRoundState();

        uint256 count = r.projectCount;
        uint256 totalWeight = 0;

        // 1. Calculate weights for all projects
        uint256[] memory weights = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            uint256 votes = roundProjects[roundId][i].voteCount;
            uint256 weight = votes * votes;
            weights[i] = weight;
            totalWeight += weight;
        }

        uint256 pool = r.matchingPool;
        r.state = RoundState.Finalized;

        // 2. Handle zero vote edge case
        if (totalWeight == 0) {
            token.safeTransfer(council, pool);
            emit RoundFinalized(roundId, 0);
            return;
        }

        // 3. Record matching shares proportionally
        uint256 distributed = 0;
        for (uint256 i = 0; i < count; i++) {
            if (weights[i] > 0) {
                // Calculate proportional share
                uint256 share = (pool * weights[i]) / totalWeight;
                if (share > 0) {
                    roundProjectShares[roundId][i] = share;
                    distributed += share;
                }
            }
        }

        // Refund any tiny division dust left over to the council
        if (pool > distributed) {
            uint256 dust = pool - distributed;
            token.safeTransfer(council, dust);
        }

        emit RoundFinalized(roundId, totalWeight);
    }

    /**
     * @notice Allows claiming calculated matching pool shares for a finalized round.
     * @dev    Enforces pull-payment pattern to prevent gas exhaustion.
     */
    function claimMatchShare(uint256 roundId, uint256 projectId) external whenNotPaused {
        Round storage r = rounds[roundId];
        if (r.state != RoundState.Finalized) revert WrongRoundState();

        uint256 share = roundProjectShares[roundId][projectId];
        if (share == 0) revert ZeroAmount();

        roundProjectShares[roundId][projectId] = 0;
        address recipient = roundProjects[roundId][projectId].recipient;
        token.safeTransfer(recipient, share);

        emit MatchDistributed(roundId, projectId, recipient, share);
    }

    // =========================================================
    // EMERGENCY CONTROL
    // =========================================================

    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(COUNCIL_ROLE) {
        _unpause();
    }

    // =========================================================
    // RECOVERY
    // =========================================================

    function sweep(address _token, uint256 _amount) external onlyRole(COUNCIL_ROLE) {
        if (_token == address(0)) revert InvalidAddress();
        if (_amount == 0) revert ZeroAmount();
        if (_token == address(token)) revert CannotSweepMatchingToken();
        IERC20(_token).safeTransfer(msg.sender, _amount);
        emit Sweep(_token, msg.sender, _amount);
    }
}
