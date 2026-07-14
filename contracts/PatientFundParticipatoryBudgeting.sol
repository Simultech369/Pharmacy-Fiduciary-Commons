// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title  PatientFundParticipatoryBudgeting
 * @author Pharmacy Fiduciary Commons
 * @notice Governs the allocation of the Patient Fund matching pool using squared vote weights.
 *         Credential-gated voting enables community members to vote on local health projects.
 */
contract PatientFundParticipatoryBudgeting is AccessControl, EIP712, Pausable, ReentrancyGuard {
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    bytes32 public constant COUNCIL_ROLE = keccak256("COUNCIL_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    uint256 public constant MAX_PROJECTS_PER_ROUND = 50;
    uint256 public constant MAX_VOTERS_PER_BATCH = 200;
    uint256 public constant MATCH_RECLAIM_GRACE_PERIOD = 90 days;
    bytes32 public constant REGISTRATION_TYPEHASH = keccak256(
        "VoterRegistration(uint256 roundId,address voter,uint256 nonce,bytes32 credentialHash,bytes32 policyVersion,uint256 deadline)"
    );
    bytes32 public constant CREDENTIAL_TYPEHASH = keccak256(
        "VoterCredential(uint256 roundId,address voter,uint256 nonce,bytes32 credentialHash,bytes32 policyVersion,uint256 deadline)"
    );
    bytes32 public constant ACCEPTED_CREDENTIAL_POLICY_VERSION = keccak256(
        "fiduciary-credential-policy-v1"
    );
    bytes32 public constant MOCK_ZK_PROOF_DOMAIN = keccak256(
        "fiduciary-mock-zk-proof-v1"
    );
    bytes32 public constant MOCK_ZK_VERIFIER_VERSION = keccak256(
        "fiduciary-mock-zk-verifier-v1"
    );
    bytes32 public constant MOCK_ZK_REGISTRATION_TYPEHASH = keccak256(
        "MockZKRegistration(uint256 roundId,address voter,bytes32 nullifier,bytes32 verifierVersion,bytes32 root)"
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
        uint256 finalizedAt;
        uint256 freshMatchingPool;
        bool isZKMode;
    }

    IERC20 public immutable token;
    address public immutable council;
    uint256 public currentRound;
    address public relayerVerifier;
    address public mockZKVerifier;
    uint256 public recycledMatchingPool;
    uint256 public totalUnclaimedShares;

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

    // roundId => nullifier => consumed in mock ZK-mode registration
    mapping(uint256 => mapping(bytes32 => bool)) public roundNullifiersUsed;

    // roundId => mock credential membership root accepted for ZK-mode registration
    mapping(uint256 => bytes32) public roundMockZKRoots;

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
    event MockZKRegistrationUsed(uint256 indexed roundId, bytes32 indexed nullifier);
    event VoteCast(uint256 indexed roundId, uint256 indexed projectId, address indexed voter);
    event MatchDistributed(uint256 indexed roundId, uint256 indexed projectId, address indexed recipient, uint256 amount);
    event MatchShareReclaimed(uint256 indexed roundId, uint256 indexed projectId, address indexed recipient, uint256 amount);
    event RecycledMatchingPoolApplied(uint256 indexed roundId, uint256 amount);
    event ExternalPatientFundsApplied(uint256 indexed roundId, uint256 amount);
    event RelayerVerifierUpdated(address indexed newVerifier);
    event MockZKVerifierUpdated(address indexed newVerifier);
    event MockZKRootUpdated(uint256 indexed roundId, bytes32 indexed root);
    event Sweep(address indexed tokenAddr, address indexed recipient, uint256 amount);
    event ProjectProposed(uint256 indexed roundId, uint256 indexed proposalId, string title, address indexed recipient);
    event ProposalSupported(uint256 indexed roundId, uint256 indexed proposalId, address indexed supporter, uint256 currentSupport);
    event ProjectSupportThresholdUpdated(uint256 newThreshold);
    event LowBalanceDetected(uint256 requested, uint256 actual);

    // =========================================================
    // CUSTOM ERRORS
    // =========================================================
    error InvalidAddress();
    error ZeroAmount();
    error NotActive();
    error AlreadyVoted();
    error ProjectInactive();
    error Unauthorized();
    error WrongRoundState();
    error ArrayEmpty();
    error BatchTooLarge();
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
    error ReclaimGracePeriodNotElapsed();
    error InsufficientContractBalance(uint256 requested, uint256 actual);
    error InsufficientSolvencyBalance(uint256 required, uint256 actual);
    error TokenTransferAmountMismatch(uint256 expected, uint256 actual);
    error GovernanceRoleSeparationViolation();
    error RoundModeMismatch();
    error NullifierAlreadyUsed();
    error InvalidProof();

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

    function _grantRole(bytes32 role, address account) internal override {
        if (
            (role == GUARDIAN_ROLE && (hasRole(COUNCIL_ROLE, account) || hasRole(DEFAULT_ADMIN_ROLE, account))) ||
            ((role == COUNCIL_ROLE || role == DEFAULT_ADMIN_ROLE) && hasRole(GUARDIAN_ROLE, account))
        ) {
            revert GovernanceRoleSeparationViolation();
        }
        super._grantRole(role, account);
    }

    function _hasReachedDelay(uint256 startedAt, uint256 delaySeconds) private view returns (bool) {
        if (block.timestamp < startedAt) return false;
        return block.timestamp - startedAt >= delaySeconds;
    }

    // =========================================================
    // ROUND ADMINISTRATION (COUNCIL ONLY)
    // =========================================================

    function startRound(uint256 matchingPoolAmount) external nonReentrant onlyRole(COUNCIL_ROLE) whenNotPaused {
        _startRound(matchingPoolAmount, false);
    }

    function startZKRound(uint256 matchingPoolAmount) external nonReentrant onlyRole(COUNCIL_ROLE) whenNotPaused {
        _startRound(matchingPoolAmount, true);
    }

    function _startRound(uint256 matchingPoolAmount, bool isZKMode) internal {
        uint256 recycled = recycledMatchingPool;
        uint256 recordedRecycled = recycled;
        if (currentRound > 0 && rounds[currentRound].state != RoundState.Finalized) {
            revert RoundAlreadyActive();
        }

        uint256 roundId = currentRound + 1;
        uint256 requiredExisting = totalUnclaimedShares + recycled;
        uint256 actualBefore = token.balanceOf(address(this));
        if (actualBefore < requiredExisting) {
            revert InsufficientSolvencyBalance(requiredExisting, actualBefore);
        }

        uint256 externalSurplus = actualBefore - requiredExisting;
        if (externalSurplus > 0) {
            recycled += externalSurplus;
            emit ExternalPatientFundsApplied(roundId, externalSurplus);
        }
        if (matchingPoolAmount == 0 && recycled == 0) revert ZeroAmount();

        recycledMatchingPool = 0;

        // Pull fresh funds before publishing the round so callbacks cannot observe a half-open round.
        if (matchingPoolAmount > 0) {
            uint256 balanceBefore = actualBefore;
            token.safeTransferFrom(msg.sender, address(this), matchingPoolAmount);
            uint256 balanceAfter = token.balanceOf(address(this));
            uint256 received = balanceAfter >= balanceBefore ? balanceAfter - balanceBefore : 0;
            if (received != matchingPoolAmount) {
                revert TokenTransferAmountMismatch(matchingPoolAmount, received);
            }
        }
        uint256 totalMatchingPool = matchingPoolAmount + recycled;
        currentRound = roundId;
        if (recordedRecycled > 0) {
            emit RecycledMatchingPoolApplied(roundId, recordedRecycled);
        }

        rounds[roundId] = Round({
            matchingPool: totalMatchingPool,
            state: RoundState.Active,
            projectCount: 0,
            finalizedAt: 0,
            freshMatchingPool: matchingPoolAmount,
            isZKMode: isZKMode
        });

        emit RoundStarted(roundId, totalMatchingPool);
    }

    function setRelayerVerifier(address _newVerifier) external onlyRole(COUNCIL_ROLE) whenNotPaused {
        if (_newVerifier == address(0)) revert InvalidAddress();
        relayerVerifier = _newVerifier;
        emit RelayerVerifierUpdated(_newVerifier);
    }

    function setMockZKVerifier(address _newVerifier) external onlyRole(COUNCIL_ROLE) whenNotPaused {
        if (_newVerifier == address(0)) revert InvalidAddress();
        mockZKVerifier = _newVerifier;
        emit MockZKVerifierUpdated(_newVerifier);
    }

    function setRoundMockZKRoot(uint256 roundId, bytes32 root) external onlyRole(COUNCIL_ROLE) whenNotPaused {
        if (rounds[roundId].state != RoundState.Active) revert WrongRoundState();
        if (!rounds[roundId].isZKMode) revert RoundModeMismatch();
        if (root == bytes32(0)) revert InvalidAuthorizationMetadata();
        roundMockZKRoots[roundId] = root;
        emit MockZKRootUpdated(roundId, root);
    }

    function setTrustedCredentialIssuer(address issuer, bool status) external onlyRole(COUNCIL_ROLE) whenNotPaused {
        if (issuer == address(0)) revert InvalidAddress();
        trustedCredentialIssuers[issuer] = status;
        emit TrustedCredentialIssuerUpdated(issuer, status);
    }

    function registerVoter(uint256 roundId, address voter, bool status) external onlyRole(COUNCIL_ROLE) whenNotPaused {
        if (voter == address(0)) revert InvalidAddress();
        if (rounds[roundId].state != RoundState.Active) revert WrongRoundState();
        if (rounds[roundId].isZKMode && status) revert RoundModeMismatch();

        registeredVoters[roundId][voter] = status;
        registrationNonces[roundId][voter] += 1;
        emit VoterRegistered(roundId, voter, status);
    }

    function registerVotersBatch(uint256 roundId, address[] calldata voters) external onlyRole(COUNCIL_ROLE) whenNotPaused {
        uint256 count = voters.length;
        if (count == 0) revert ArrayEmpty();
        if (count > MAX_VOTERS_PER_BATCH) revert BatchTooLarge();
        if (rounds[roundId].state != RoundState.Active) revert WrongRoundState();
        if (rounds[roundId].isZKMode) revert RoundModeMismatch();

        for (uint256 i = 0; i < count; i++) {
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
        if (rounds[roundId].isZKMode) revert RoundModeMismatch();
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
        bytes32 digest = _hashTypedDataV4(structHash);
        if (!SignatureChecker.isValidSignatureNow(relayerVerifier, digest, signature)) {
            revert Unauthorized();
        }

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
        if (rounds[roundId].isZKMode) revert RoundModeMismatch();
        if (credentialHash == bytes32(0) || policyVersion == bytes32(0)) {
            revert InvalidAuthorizationMetadata();
        }
        if (policyVersion != ACCEPTED_CREDENTIAL_POLICY_VERSION) {
            revert UnsupportedCredentialPolicy();
        }
        if (block.timestamp > deadline) revert AuthorizationExpired();

        // EIP-712 binds the authorization to this deployment and chain through the
        // domain separator while keeping the policy fields readable to wallets.
        uint256 nonce = registrationNonces[roundId][msg.sender];
        bytes32 structHash = keccak256(
            abi.encode(
                CREDENTIAL_TYPEHASH,
                roundId,
                msg.sender,
                nonce,
                credentialHash,
                policyVersion,
                deadline
            )
        );
        address issuer = _hashTypedDataV4(structHash).recover(issuerSignature);

        if (!trustedCredentialIssuers[issuer]) revert Unauthorized();

        registeredVoters[roundId][msg.sender] = true;
        registrationNonces[roundId][msg.sender] = nonce + 1;
        emit VoterRegistered(roundId, msg.sender, true);
        emit RegistrationAuthorizationUsed(roundId, msg.sender, credentialHash, policyVersion, deadline);
    }

    /**
     * @notice Mock ZK registration path used to prove nullifier-mode semantics before real circuits.
     * @dev This does not provide production privacy: msg.sender and transaction metadata remain public.
     *      The mock proof only anchors the expected public input shape for tests and future verifier design.
     */
    function registerVoterWithMockZK(
        uint256 roundId,
        bytes32 nullifier,
        bytes calldata proof
    ) external whenNotPaused {
        if (rounds[roundId].state != RoundState.Active) revert WrongRoundState();
        if (!rounds[roundId].isZKMode) revert RoundModeMismatch();
        if (nullifier == bytes32(0)) revert InvalidAuthorizationMetadata();
        if (mockZKVerifier == address(0)) revert InvalidAddress();
        if (roundMockZKRoots[roundId] == bytes32(0)) revert InvalidAuthorizationMetadata();
        if (roundNullifiersUsed[roundId][nullifier]) revert NullifierAlreadyUsed();
        if (!_isValidMockZKProof(roundId, msg.sender, nullifier, proof)) revert InvalidProof();

        roundNullifiersUsed[roundId][nullifier] = true;
        registeredVoters[roundId][msg.sender] = true;
        emit MockZKRegistrationUsed(roundId, nullifier);
    }

    function _isValidMockZKProof(
        uint256 roundId,
        address voter,
        bytes32 nullifier,
        bytes calldata proof
    ) internal view returns (bool) {
        bytes32 expectedProofHash = keccak256(
            abi.encode(
                MOCK_ZK_REGISTRATION_TYPEHASH,
                roundId,
                voter,
                nullifier,
                MOCK_ZK_VERIFIER_VERSION,
                roundMockZKRoots[roundId]
            )
        );
        bytes32 digest = _hashTypedDataV4(expectedProofHash);
        return SignatureChecker.isValidSignatureNow(mockZKVerifier, digest, proof);
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
            string memory title = prop.title;
            address recipient = prop.recipient;
            prop.registered = true;
            _registerProject(roundId, title, recipient);
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
     *         If totalWeight is 0, only fresh council-funded liquidity is returned to council; recycled
     *         and externally routed patient-fund liquidity remains patient-bound for future rounds.
     */
    function finalizeRound(uint256 roundId) external nonReentrant onlyRole(COUNCIL_ROLE) whenNotPaused {
        Round storage r = rounds[roundId];
        if (r.state != RoundState.Active) revert WrongRoundState();

        uint256 pool = r.matchingPool;
        uint256 required = totalUnclaimedShares + pool;
        uint256 actual = token.balanceOf(address(this));
        if (actual < required) revert InsufficientSolvencyBalance(required, actual);

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

        r.state = RoundState.Finalized;
        r.finalizedAt = block.timestamp;

        // 2. Handle zero vote edge case
        if (totalWeight == 0) {
            uint256 fresh = r.freshMatchingPool;
            uint256 recycled = pool - fresh;
            if (recycled > 0) {
                recycledMatchingPool += recycled;
            }
            if (fresh > 0) {
                token.safeTransfer(council, fresh);
            }
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
        totalUnclaimedShares += distributed;

        // Split tiny division dust according to provenance: fresh dust returns to council, while
        // recycled or externally routed patient-fund dust remains patient-bound for future rounds.
        if (pool > distributed) {
            uint256 dust = pool - distributed;
            uint256 freshLimit = r.freshMatchingPool;
            uint256 councilRefund = (dust * freshLimit) / pool;
            uint256 recycledRefund = dust - councilRefund;
            if (recycledRefund > 0) {
                recycledMatchingPool += recycledRefund;
            }
            if (councilRefund > 0) {
                token.safeTransfer(council, councilRefund);
            }
        }

        emit RoundFinalized(roundId, totalWeight);
    }

    /**
     * @notice Allows claiming calculated matching pool shares for a finalized round.
     * @dev    Enforces pull-payment pattern to prevent gas exhaustion.
     */
    function claimMatchShare(uint256 roundId, uint256 projectId) external nonReentrant whenNotPaused {
        Round storage r = rounds[roundId];
        if (r.state != RoundState.Finalized) revert WrongRoundState();
        if (projectId >= r.projectCount) revert ProjectInactive();

        uint256 share = roundProjectShares[roundId][projectId];
        if (share == 0) revert ZeroAmount();

        address recipient = roundProjects[roundId][projectId].recipient;
        if (recipient == address(0)) revert ProjectInactive();
        roundProjectShares[roundId][projectId] = 0;
        totalUnclaimedShares -= share;

        uint256 balance = token.balanceOf(address(this));
        if (balance < share) {
            emit LowBalanceDetected(share, balance);
            revert InsufficientContractBalance(share, balance);
        }

        token.safeTransfer(recipient, share);

        emit MatchDistributed(roundId, projectId, recipient, share);
    }

    /**
     * @notice Reclaims an unclaimed finalized project share after a 90-day grace period.
     * @dev    This makes finalized shares claimable until the deadline, not perpetual debts.
     *         Reclaimed funds remain in the contract and are applied by `startRound` to the
     *         next matching round rather than entering council custody.
     */
    function reclaimUnclaimedMatchShare(uint256 roundId, uint256 projectId)
        external
        nonReentrant
        onlyRole(COUNCIL_ROLE)
        whenNotPaused
    {
        Round storage r = rounds[roundId];
        if (r.state != RoundState.Finalized) revert WrongRoundState();
        if (projectId >= r.projectCount) revert ProjectInactive();
        if (!_hasReachedDelay(r.finalizedAt, MATCH_RECLAIM_GRACE_PERIOD)) {
            revert ReclaimGracePeriodNotElapsed();
        }

        uint256 share = roundProjectShares[roundId][projectId];
        if (share == 0) revert ZeroAmount();

        address recipient = roundProjects[roundId][projectId].recipient;
        if (recipient == address(0)) revert ProjectInactive();
        roundProjectShares[roundId][projectId] = 0;
        totalUnclaimedShares -= share;
        recycledMatchingPool += share;

        uint256 balance = token.balanceOf(address(this));
        if (balance < share) {
            emit LowBalanceDetected(share, balance);
            // We do NOT revert on low balance because reclaims are purely accounting-based
            // and we want to allow recycling recorded commitments under depletion.
        }

        emit MatchShareReclaimed(roundId, projectId, recipient, share);
    }

    /**
     * @notice Previews the finalization of a round, calculating the expected project shares,
     *         and checking if the contract has sufficient token balance to cover them plus outstanding shares.
     * @param roundId The ID of the active round to preview.
     * @return projects An array of project recipient addresses.
     * @return expectedShares An array of expected matching shares for each project.
     * @return actualBalance The current actual token balance of the contract.
     * @return totalRequiredAfterFinalize The total required tokens in the contract after finalization.
     * @return isSufficient Whether the actual balance is sufficient.
     */
    function previewFinalize(uint256 roundId)
        external
        view
        returns (
            address[] memory projects,
            uint256[] memory expectedShares,
            uint256 actualBalance,
            uint256 totalRequiredAfterFinalize,
            bool isSufficient
        )
    {
        return _previewFinalize(roundId);
    }

    /**
     * @notice Dry-runs finalization with the same output as `previewFinalize`.
     * @dev    Alias kept for operator-facing dashboards and runbooks.
     */
    function dryRunFinalize(uint256 roundId)
        external
        view
        returns (
            address[] memory projects,
            uint256[] memory expectedShares,
            uint256 actualBalance,
            uint256 totalRequiredAfterFinalize,
            bool isSufficient
        )
    {
        return _previewFinalize(roundId);
    }

    function _previewFinalize(uint256 roundId)
        internal
        view
        returns (
            address[] memory projects,
            uint256[] memory expectedShares,
            uint256 actualBalance,
            uint256 totalRequiredAfterFinalize,
            bool isSufficient
        )
    {
        Round storage r = rounds[roundId];
        if (r.state != RoundState.Active) revert WrongRoundState();

        uint256 count = r.projectCount;
        projects = new address[](count);
        expectedShares = new uint256[](count);

        uint256 totalWeight = 0;
        uint256[] memory weights = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            projects[i] = roundProjects[roundId][i].recipient;
            uint256 votes = roundProjects[roundId][i].voteCount;
            uint256 weight = votes * votes;
            weights[i] = weight;
            totalWeight += weight;
        }

        uint256 pool = r.matchingPool;
        uint256 distributed = 0;
        if (totalWeight > 0) {
            for (uint256 i = 0; i < count; i++) {
                if (weights[i] > 0) {
                    uint256 share = (pool * weights[i]) / totalWeight;
                    expectedShares[i] = share;
                    distributed += share;
                }
            }
        }

        actualBalance = token.balanceOf(address(this));
        totalRequiredAfterFinalize = totalUnclaimedShares + distributed;
        isSufficient = actualBalance >= totalUnclaimedShares + pool;
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

    function sweep(address _token, uint256 _amount) external nonReentrant onlyRole(COUNCIL_ROLE) {
        if (_token == address(0)) revert InvalidAddress();
        if (_amount == 0) revert ZeroAmount();
        if (_token == address(token)) revert CannotSweepMatchingToken();
        IERC20(_token).safeTransfer(msg.sender, _amount);
        emit Sweep(_token, msg.sender, _amount);
    }
}
