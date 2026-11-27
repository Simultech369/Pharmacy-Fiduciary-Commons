// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import { Pausable } from "@openzeppelin/contracts/security/Pausable.sol";
import { AccessControlEnumerable } from "@openzeppelin/contracts/access/AccessControlEnumerable.sol";
import { TreasuryVerifier } from "./libraries/TreasuryVerifier.sol";

/**
 * @title  PBMRebateTreasury
 * @author Pharmacy Fiduciary Commons
 * @notice Transparent on-chain rebate capture and distribution engine.
 *         Routes PBM rebates back to independent pharmacies and patients -
 *         auditable, ungameable, and publicly verifiable.
 */
contract PBMRebateTreasury is
    AccessControlEnumerable,
    ReentrancyGuard,
    Pausable
{
    // =========================================================
    // CUSTOM ERRORS
    // =========================================================

    error ZeroAmount();
    error InvalidSource();
    error InvalidAddress();
    error ZeroCap();
    error Sanctioned();
    error AlreadyClaimed();
    error NoRootForEpoch();
    error InvalidProof();
    error PharmacyCapExceeded();
    error DailyCapExceeded();
    error HardCapExceeded();
    error RootTotalExceeded();
    error DistributionPoolDepleted();
    error RootAlreadyLive();
    error ProposalPendingOrNotExpired();
    error InvalidRoot();
    error ZeroTotal();
    error InsufficientDistributionPool();
    error InsufficientExclusionReserve();
    error WrongEpoch();
    error NoPendingRoot();
    error ProposalExpired();
    error NotExpired();
    error CanOnlyReduce();
    error BelowDailyCap();
    error ExceedsHardCap();
    error NoFlaggedClaim();
    error CanOnlyFlagCurrentEpoch();
    error AlreadyFlagged();
    error EpochNotFinalized();
    error AlreadyRecalled();
    error NoRootPublished();
    error RecallDelayNotElapsed();
    error NothingToRecall();
    error ExceedsReserve();
    error NoETH();
    error ETHTransferFailed();
    error ETHNotAccepted();
    error NoFallback();
    error CannotSweepPayoutToken();
    error OutOfRange();
    error EpochTooShort();
    error EpochVolumeTooLow();
    error EpochVolumeMeetsMinimum();
    error RecoveryDelayNotElapsed();
    error GuardianMustDifferFromCouncil();
    error RootConfirmerMustDifferFromCouncil();
    error NotSanctioned();
    error ExclusionApprovalRequired();
    error NotExclusionDispute();
    error InvalidExclusionResolution();
    error MinimumEpochVolumeExceedsDailyCap();
    error GovernanceRoleSeparationViolation();
    error ZeroEvidenceHash();
    error DisputeTimeoutNotElapsed();
    error TokenTransferAmountMismatch(uint256 expected, uint256 actual);
    error TokenTransferFailed();
    error DepositBelowMinimum();
    error DisputeAlreadyUsedInEpoch();
    error ExclusionCredentialRequired();
    error ExclusionBondTooHigh();
    error AuthorizationExpired();
    error InvalidSignature();
    error InvalidAppealReason();
    error AppealAlreadyPending();
    error InvalidDisputeResolution();
    error NothingToCarrySettle();
    error CarryEpochNotAdvanced();

    // =========================================================
    // ROLES & CONSTANTS
    // =========================================================

    bytes32 private constant COUNCIL_ROLE        = keccak256("COUNCIL_ROLE");
    bytes32 private constant EXECUTOR_ROLE       = keccak256("EXECUTOR_ROLE");
    bytes32 private constant ROOT_CONFIRMER_ROLE = keccak256("ROOT_CONFIRMER_ROLE");
    bytes32 private constant GUARDIAN_ROLE       = keccak256("GUARDIAN_ROLE");

    uint256 private constant BP_DENOM = 10_000;
    uint256 private constant MIN_PATIENT_CLAIM_BP = 500;
    uint256 private constant MAX_PATIENT_CLAIM_BP = 3_000;
    uint256 private constant MAX_GOVERNANCE_BP = 500;
    uint256 private constant MAX_APPEAL_REASON_LENGTH = 256;

    uint256 public governanceBP = 100;
    uint256 public patientClaimBP = 1_000;

    uint256 private constant MIN_EPOCH_DURATION = 3 days;
    uint256 public immutable minimumEpochVolume;

    uint256 private constant RECALL_DELAY = 30 days;
    uint256 public constant DISPUTE_TIMEOUT = 30 days;
    uint256 private constant ROOT_PROPOSAL_EXPIRY = 7 days;
    uint256 private constant STALE_DISTRIBUTION_RECOVERY_DELAY = 180 days;

    // =========================================================
    // IMMUTABLE CORE
    // =========================================================

    IERC20  public immutable token;
    address public immutable patientFund;
    TreasuryVerifier public immutable verifier;

    // =========================================================
    // MUTABLE (executor-governed)
    // =========================================================

    address public environmentalFund;

    // =========================================================
    // TREASURY BUCKET BALANCES
    // =========================================================

    uint256 public distributionPool;
    uint256 public governanceReserve;
    uint256 public exclusionRemediationReserve;
    uint256 public accruedPatientFund;
    uint256 private _totalExclusionBonds;
    uint256 private _totalCarriedEscrow;
    uint256 public totalEscrowed;
    uint256 public totalFlaggedNormal;
    uint256 public totalFlaggedExclusion;

    // =========================================================
    // CAPS & ANTI-SPAM PARAMETERS
    // =========================================================

    uint256 public dailyVolumeCap;
    uint256 public hardAbsoluteVolumeCap;
    uint256 private _minimumDepositAmount;
    uint256 private _exclusionDisputeBond;
    bool private _requireExclusionCredential;

    // =========================================================
    // EPOCH & AUTHORIZATION STATE
    // =========================================================

    uint256 public currentEpoch;
    uint256 public epochVolume;
    uint256 public epochStartTimestamp;
    uint256 public lastDepositTimestamp;

    mapping(uint256 => bytes32) public epochMerkleRoot;
    mapping(uint256 => uint256) public epochRootTotal;
    mapping(uint256 => uint256) public epochPublishedTimestamp;
    mapping(uint256 => uint256) public epochClaimedTotal;
    mapping(uint256 => uint256) public epochRootClaimedTotal;
    mapping(uint256 => uint256) public epochExclusionPaidTotal;
    mapping(uint256 => bool)    public epochRecalled;
    mapping(uint256 => mapping(address => bool))    public hasClaimed;
    mapping(uint256 => mapping(address => uint256)) public pharmacyClaimedThisEpoch;
    mapping(uint256 => uint256) public epochEscrow;
    mapping(uint256 => mapping(address => bool)) public isExclusionDispute;

    mapping(address => bool) public sanctioned;
    mapping(address => bool) private _appealPending;
    mapping(address => uint256) public authNonces;
    mapping(address => bool) private _trustedCredentialIssuers;

    // =========================================================
    // PENDING ROOT (co-sign gate)
    // =========================================================

    struct PendingRoot {
        bytes32 root;
        uint256 totalAmount;
        address proposer;
        uint256 proposedAt;
    }

    mapping(uint256 => PendingRoot) public pendingRoot;

    // =========================================================
    // DISPUTE RESOLUTION & CARRY-FORWARD SETTLEMENT
    // =========================================================

    mapping(uint256 => mapping(address => uint256)) public flaggedAmount;
    mapping(uint256 => mapping(address => uint256)) public disputeFlaggedTimestamp;
    mapping(uint256 => mapping(address => bool)) public exclusionApproved;
    mapping(uint256 => mapping(address => bool)) public disputeUsedInEpoch;
    mapping(uint256 => mapping(address => uint256)) private _exclusionBonds;

    mapping(address => uint256) private _carriedRootAmount;
    mapping(address => uint256) private _carriedRootEpoch;
    mapping(address => uint256) private _carriedRootSince;

    mapping(address => uint256) private _carriedExclusionAmount;
    mapping(address => uint256) private _carriedExclusionEpoch;

    enum DisputeResolution {
        RELEASE_TO_PHARMACY,
        SEND_TO_PATIENT_FUND,
        DISMISS,
        DISMISS_RESTORE_CLAIM,
        RELEASE_PARTIAL
    }

    // =========================================================
    // REBATE DEPOSIT TRACKING
    // =========================================================

    struct RebateDeposit {
        address depositor;
        uint256 amount;
        uint256 timestamp;
        string  source;
    }

    RebateDeposit[] public rebateDeposits;
    uint256 public totalRebateDeposited;

    // =========================================================
    // EVENTS
    // =========================================================

    event RebateDeposited(
        uint256 indexed depositId,
        address indexed depositor,
        uint256 amount,
        uint256 distributionAmount,
        uint256 governanceAmount,
        string  source
    );

    event RootProposed(
        uint256 indexed epoch,
        bytes32 indexed root,
        uint256 total,
        address indexed proposer,
        uint256 expiresAt
    );

    event RootConfirmed(
        uint256 indexed epoch,
        bytes32 indexed root,
        uint256 total,
        address indexed confirmer
    );

    event RootProposalExpired(uint256 indexed epoch);

    event Claimed(
        uint256 indexed epoch,
        address indexed pharmacy,
        uint256 grossAmount,
        uint256 netToPharmacy,
        uint256 patientShare
    );

    event ClaimRouted(
        uint256 indexed epoch,
        address indexed claimant,
        address indexed recipient,
        uint256 netToPharmacy
    );

    event PatientFundAccrued(uint256 indexed epoch, uint256 amount);
    event PatientFundWithdrawn(address indexed recipient, uint256 amount, address indexed caller);

    event EpochFinalized(uint256 indexed epoch, uint256 totalVolume, uint256 remainingEscrow, uint256 timestamp);
    event StaleEpochFinalizedForRecall(uint256 indexed epoch, uint256 totalVolume, uint256 remainingEscrow, uint256 timestamp);
    event EpochStarted(uint256 indexed epoch, uint256 timestamp);

    event HardCapReduced(uint256 indexed oldCap, uint256 indexed newCap);
    event DailyCapUpdated(uint256 indexed oldCap, uint256 indexed newCap);
    event PatientClaimBPUpdated(uint256 indexed oldBP, uint256 indexed newBP);
    event GovernanceBPUpdated(uint256 indexed oldBP, uint256 indexed newBP);
    event AntiSpamConfigured(uint256 minDeposit, uint256 bondAmount, bool requireCredential);
    event TrustedCredentialIssuerUpdated(address indexed issuer, bool status);

    event SanctionUpdated(address indexed account, bool status, string reason);
    event SanctionAppealed(address indexed account, string reason, bytes32 indexed evidenceHash);

    event EpochRecalled(uint256 indexed epoch, uint256 amount);

    event ClaimFlagged(uint256 indexed epoch, address indexed pharmacy, uint256 amount, bytes32 indexed evidenceHash);
    event ExclusionClaimFlagged(uint256 indexed epoch, address indexed pharmacy, uint256 amount, bytes32 indexed evidenceHash);
    event ExclusionClaimApproved(uint256 indexed epoch, address indexed pharmacy, uint256 amount, address approver);
    event ClaimDisputeRetracted(
        uint256 indexed epoch,
        address indexed pharmacy,
        uint256 amount,
        bool isExclusion,
        bool epochWasRecalled
    );
    event ClaimResolved(
        uint256 indexed epoch,
        address indexed pharmacy,
        uint256 amount,
        DisputeResolution resolution,
        bool isExclusion,
        bytes32 indexed evidenceHash
    );
    event PartialSettlementRecorded(
        uint256 indexed epoch,
        address indexed pharmacy,
        uint256 paidGross,
        uint256 carriedGross,
        bool isExclusion
    );
    event CarriedSettlementPaid(
        uint256 indexed epoch,
        address indexed pharmacy,
        address indexed recipient,
        uint256 paidGross,
        uint256 remainingCarry,
        bool isExclusion
    );
    event StaleCarryForwardRecalled(address indexed pharmacy, uint256 amount);

    event GovernanceReserveWithdrawn(address indexed recipient, uint256 amount);
    event StaleDistributionPoolRecovered(address indexed recipient, uint256 amount);
    event ExclusionRemediationFunded(address indexed funder, uint256 amount);
    event StaleUnrootedEpochSkipped(uint256 indexed skippedEpoch, address indexed executor, uint256 timestamp);

    event Sweep(address indexed tokenAddr, address indexed recipient, uint256 amount);
    event EnvironmentalFundUpdated(address indexed oldFund, address indexed newFund);

    // =========================================================
    // CONSTRUCTOR & SHARED HELPERS
    // =========================================================

    constructor(
        address _token,
        address _patientFund,
        address _environmentalFund,
        uint256 _initialDailyCap,
        uint256 _minimumEpochVolume,
        address _council,
        address _rootConfirmer,
        address _executor,
        address _guardian
    ) {
        if (_token             == address(0)) revert InvalidAddress();
        if (_patientFund       == address(0)) revert InvalidAddress();
        if (_environmentalFund == address(0)) revert InvalidAddress();
        if (_council           == address(0)) revert InvalidAddress();
        if (_rootConfirmer     == address(0)) revert InvalidAddress();
        if (_executor          == address(0)) revert InvalidAddress();
        if (_guardian          == address(0)) revert InvalidAddress();
        if (_guardian          == _council)   revert GuardianMustDifferFromCouncil();
        if (_initialDailyCap   == 0)          revert ZeroCap();
        if (_minimumEpochVolume == 0)         revert ZeroAmount();
        if (_minimumEpochVolume > _initialDailyCap) revert MinimumEpochVolumeExceedsDailyCap();
        if (_rootConfirmer     == _council)   revert RootConfirmerMustDifferFromCouncil();
        if (_rootConfirmer     == _guardian)  revert GovernanceRoleSeparationViolation();

        token             = IERC20(_token);
        patientFund       = _patientFund;
        environmentalFund = _environmentalFund;
        verifier          = new TreasuryVerifier(address(this));

        dailyVolumeCap        = _initialDailyCap;
        hardAbsoluteVolumeCap = _initialDailyCap * 10;
        minimumEpochVolume    = _minimumEpochVolume;

        epochStartTimestamp = block.timestamp;
        lastDepositTimestamp = block.timestamp;

        _setRoleAdmin(EXECUTOR_ROLE, EXECUTOR_ROLE);
        _setRoleAdmin(ROOT_CONFIRMER_ROLE, EXECUTOR_ROLE);
        _grantRole(DEFAULT_ADMIN_ROLE, _council);
        _grantRole(COUNCIL_ROLE,       _council);
        _grantRole(ROOT_CONFIRMER_ROLE, _rootConfirmer);
        _grantRole(EXECUTOR_ROLE,      _executor);
        _grantRole(GUARDIAN_ROLE,      _guardian);

        emit EpochStarted(currentEpoch, block.timestamp);
    }

    function _onlyRole(bytes32 role) private view {
        _checkRole(role);
    }

    function _safeTransferCall(IERC20 tok, bytes memory callData) private {
        address target = address(tok);
        if (target.code.length == 0) revert InvalidAddress();
        (bool ok, bytes memory ret) = target.call(callData);
        if (!ok) {
            if (ret.length > 0) {
                assembly {
                    revert(add(ret, 32), mload(ret))
                }
            }
            revert TokenTransferFailed();
        }
        if (ret.length > 0 && !abi.decode(ret, (bool))) {
            revert TokenTransferFailed();
        }
    }

    function _safeTransfer(IERC20 tok, address to, uint256 amt) private {
        _safeTransferCall(tok, abi.encodeWithSelector(IERC20.transfer.selector, to, amt));
    }

    function _grantRole(bytes32 role, address account) internal override {
        if (
            (role == ROOT_CONFIRMER_ROLE && hasRole(COUNCIL_ROLE, account)) ||
            (role == ROOT_CONFIRMER_ROLE && hasRole(GUARDIAN_ROLE, account)) ||
            (role == COUNCIL_ROLE && hasRole(ROOT_CONFIRMER_ROLE, account)) ||
            (role == GUARDIAN_ROLE && (hasRole(COUNCIL_ROLE, account) || hasRole(DEFAULT_ADMIN_ROLE, account))) ||
            (role == GUARDIAN_ROLE && hasRole(ROOT_CONFIRMER_ROLE, account)) ||
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

    function _hasPassedDelay(uint256 startedAt, uint256 delaySeconds) private view returns (bool) {
        if (block.timestamp <= startedAt) return false;
        return block.timestamp - startedAt > delaySeconds;
    }

    function _deadlineAt(uint256 startedAt, uint256 delaySeconds) private pure returns (uint256) {
        if (startedAt > type(uint256).max - delaySeconds) return type(uint256).max;
        return startedAt + delaySeconds;
    }

    function _pullExactTokens(address from, uint256 amount) private {
        uint256 balanceBefore = token.balanceOf(address(this));
        _safeTransferCall(
            token,
            abi.encodeWithSelector(IERC20.transferFrom.selector, from, address(this), amount)
        );
        uint256 balanceAfter = token.balanceOf(address(this));
        uint256 received = balanceAfter >= balanceBefore ? balanceAfter - balanceBefore : 0;
        if (received != amount) {
            revert TokenTransferAmountMismatch(amount, received);
        }
    }

    function _accruePatientShare(uint256 epoch, uint256 grossAmount) private returns (uint256 patientShare, uint256 netToPharmacy) {
        patientShare = (grossAmount * patientClaimBP) / BP_DENOM;
        netToPharmacy = grossAmount - patientShare;
        if (patientShare > 0) {
            accruedPatientFund += patientShare;
            emit PatientFundAccrued(epoch, patientShare);
        }
    }

    receive()  external payable { revert ETHNotAccepted(); }
    fallback() external payable { revert NoFallback(); }

    // =========================================================
    // REBATE DEPOSIT
    // =========================================================

    function depositRebate(uint256 amount, string calldata source)
        external
        nonReentrant
    {
        _requireNotPaused();
        if (sanctioned[msg.sender]) revert Sanctioned();
        if (amount == 0) revert ZeroAmount();
        if (amount < _minimumDepositAmount) revert DepositBelowMinimum();
        uint256 srcLen = bytes(source).length;
        if (srcLen == 0 || srcLen > 256) revert InvalidSource();

        _pullExactTokens(msg.sender, amount);

        uint256 forGovernance   = (amount * governanceBP) / BP_DENOM;
        uint256 forDistribution = amount - forGovernance;

        governanceReserve    += forGovernance;
        distributionPool     += forDistribution;
        totalRebateDeposited += amount;
        lastDepositTimestamp  = block.timestamp;

        uint256 minIndexed = minimumEpochVolume / 1_000;
        if (minIndexed == 0) minIndexed = 1;

        uint256 depositId = type(uint256).max;
        if (amount >= minIndexed) {
            depositId = rebateDeposits.length;
            rebateDeposits.push(RebateDeposit({
                depositor: msg.sender,
                amount:    amount,
                timestamp: block.timestamp,
                source:    source
            }));
        }

        emit RebateDeposited(depositId, msg.sender, amount, forDistribution, forGovernance, source);
    }

    function fundExclusionRemediation(uint256 amount)
        external
        nonReentrant
    {
        _requireNotPaused();
        if (sanctioned[msg.sender]) revert Sanctioned();
        if (amount == 0) revert ZeroAmount();
        _pullExactTokens(msg.sender, amount);
        exclusionRemediationReserve += amount;
        emit ExclusionRemediationFunded(msg.sender, amount);
    }

    // =========================================================
    // ROOT PUBLICATION - CO-SIGN GATE
    // =========================================================

    function proposeRoot(bytes32 root, uint256 totalAmount) external {
        _onlyRole(COUNCIL_ROLE);
        _requireNotPaused();
        uint256 epoch = currentEpoch;
        if (epochMerkleRoot[epoch] != bytes32(0)) revert RootAlreadyLive();

        PendingRoot storage pr = pendingRoot[epoch];
        if (pr.proposedAt != 0 && !_hasPassedDelay(pr.proposedAt, ROOT_PROPOSAL_EXPIRY)) {
            revert ProposalPendingOrNotExpired();
        }
        if (root == bytes32(0))  revert InvalidRoot();
        if (totalAmount == 0)    revert ZeroTotal();
        if (totalAmount > dailyVolumeCap)        revert DailyCapExceeded();
        if (totalAmount > hardAbsoluteVolumeCap) revert HardCapExceeded();
        if (distributionPool < totalAmount)      revert InsufficientDistributionPool();

        pendingRoot[epoch] = PendingRoot({
            root:        root,
            totalAmount: totalAmount,
            proposer:    msg.sender,
            proposedAt:  block.timestamp
        });

        emit RootProposed(epoch, root, totalAmount, msg.sender, _deadlineAt(block.timestamp, ROOT_PROPOSAL_EXPIRY));
    }

    function confirmRoot(uint256 epoch) external {
        _onlyRole(ROOT_CONFIRMER_ROLE);
        _requireNotPaused();
        if (epoch != currentEpoch) revert WrongEpoch();

        PendingRoot storage pr = pendingRoot[epoch];
        if (pr.proposedAt == 0)            revert NoPendingRoot();
        if (_hasPassedDelay(pr.proposedAt, ROOT_PROPOSAL_EXPIRY)) revert ProposalExpired();
        if (epochMerkleRoot[epoch] != bytes32(0)) revert RootAlreadyLive();

        if (pr.totalAmount > dailyVolumeCap)        revert DailyCapExceeded();
        if (pr.totalAmount > hardAbsoluteVolumeCap) revert HardCapExceeded();
        if (distributionPool < pr.totalAmount)      revert InsufficientDistributionPool();

        bytes32 confirmedRoot   = pr.root;
        uint256 confirmedTotal  = pr.totalAmount;

        epochMerkleRoot[epoch]         = confirmedRoot;
        epochRootTotal[epoch]          = confirmedTotal;
        epochPublishedTimestamp[epoch] = block.timestamp;

        distributionPool     -= confirmedTotal;
        epochEscrow[epoch]    = confirmedTotal;
        totalEscrowed        += confirmedTotal;

        delete pendingRoot[epoch];

        emit RootConfirmed(epoch, confirmedRoot, confirmedTotal, msg.sender);
    }

    function clearExpiredProposal(uint256 epoch) external {
        PendingRoot storage pr = pendingRoot[epoch];
        if (pr.proposedAt == 0) revert NoPendingRoot();
        if (!_hasPassedDelay(pr.proposedAt, ROOT_PROPOSAL_EXPIRY)) revert NotExpired();
        delete pendingRoot[epoch];
        emit RootProposalExpired(epoch);
    }

    // =========================================================
    // CLAIM & PATIENT FUND PULL ISOLATION
    // =========================================================

    function withdrawPatientFund() external nonReentrant returns (uint256 amount) {
        amount = accruedPatientFund;
        if (amount == 0) revert ZeroAmount();

        accruedPatientFund = 0;
        emit PatientFundWithdrawn(patientFund, amount, msg.sender);

        _safeTransfer(token, patientFund, amount);
    }

    function claim(
        uint256 amount,
        uint256 eligibleCap,
        bytes32[] calldata proof
    )
        external
        nonReentrant
    {
        _requireNotPaused();
        _executeMerkleClaim(msg.sender, msg.sender, amount, eligibleCap, proof, false);
    }

    struct ClaimAuth {
        address claimant;
        address recipient;
        uint256 amount;
        uint256 eligibleCap;
        uint256 deadline;
        bool allowPartial;
    }

    /**
     * @notice Unified routed, gas-relayer EIP-712 (D-03), and cap-bounded partial/carry-forward (D-06) claim.
     * @dev    When msg.sender == auth.claimant and signature.length == 0, executes directly without signature overhead.
     */
    function claimWithAuthorization(
        ClaimAuth calldata auth,
        bytes32[] calldata proof,
        bytes calldata signature
    )
        external
        nonReentrant
        returns (uint256 paidGross, uint256 carriedGross)
    {
        _requireNotPaused();
        if (auth.claimant == address(0) || auth.recipient == address(0)) revert InvalidAddress();
        if (block.timestamp > auth.deadline) revert AuthorizationExpired();

        if (msg.sender != auth.claimant || signature.length > 0) {
            uint256 nonce = authNonces[auth.claimant];
            if (
                !verifier.verifyClaimAuthorization(
                    currentEpoch,
                    auth.claimant,
                    auth.recipient,
                    auth.amount,
                    auth.eligibleCap,
                    nonce,
                    auth.deadline,
                    auth.allowPartial,
                    signature
                )
            ) {
                revert InvalidSignature();
            }
            authNonces[auth.claimant] = nonce + 1;
        }

        return _executeMerkleClaim(
            auth.claimant,
            auth.recipient,
            auth.amount,
            auth.eligibleCap,
            proof,
            auth.allowPartial
        );
    }

    function _verifyRootLeaf(
        uint256 epoch,
        address claimant,
        uint256 amount,
        uint256 eligibleCap,
        bytes32[] calldata proof
    ) private view returns (uint256 newRootClaimed) {
        if (hasClaimed[epoch][claimant])         revert AlreadyClaimed();
        if (flaggedAmount[epoch][claimant] != 0) revert AlreadyFlagged();

        bytes32 root = epochMerkleRoot[epoch];
        if (root == bytes32(0)) revert NoRootForEpoch();

        if (!verifier.verifyMerkleLeaf(root, claimant, amount, eligibleCap, proof)) {
            revert InvalidProof();
        }

        if (pharmacyClaimedThisEpoch[epoch][claimant] + amount > eligibleCap) {
            revert PharmacyCapExceeded();
        }

        newRootClaimed = epochRootClaimedTotal[epoch] + amount;
        if (newRootClaimed > epochRootTotal[epoch]) revert RootTotalExceeded();
        if (epochEscrow[epoch] < amount) revert DistributionPoolDepleted();
    }

    function _executeMerkleClaim(
        address claimant,
        address recipient,
        uint256 amount,
        uint256 eligibleCap,
        bytes32[] calldata proof,
        bool allowPartial
    )
        private
        returns (uint256 paidGross, uint256 carriedGross)
    {
        if (recipient == address(0)) revert InvalidAddress();
        if (sanctioned[claimant] || sanctioned[recipient]) revert Sanctioned();

        uint256 epoch = currentEpoch;
        uint256 newRootClaimed = _verifyRootLeaf(epoch, claimant, amount, eligibleCap, proof);

        if (allowPartial) {
            uint256 capRoom = _remainingEpochCapRoom();
            paidGross = amount <= capRoom ? amount : capRoom;
            carriedGross = amount - paidGross;
        } else {
            if (epochVolume + amount > dailyVolumeCap)        revert DailyCapExceeded();
            if (epochVolume + amount > hardAbsoluteVolumeCap) revert HardCapExceeded();
            paidGross = amount;
        }

        hasClaimed[epoch][claimant]                = true;
        pharmacyClaimedThisEpoch[epoch][claimant] += amount;
        epochVolume                                += paidGross;
        epochClaimedTotal[epoch]                  += paidGross;
        epochRootClaimedTotal[epoch]               = newRootClaimed;
        epochEscrow[epoch]                         -= amount;
        totalEscrowed                              -= amount;

        if (carriedGross > 0) {
            _carriedRootAmount[claimant] += carriedGross;
            _totalCarriedEscrow          += carriedGross;
            _carriedRootEpoch[claimant]   = epoch;
            if (_carriedRootSince[claimant] == 0) {
                _carriedRootSince[claimant] = block.timestamp;
            }
        }

        (uint256 patientShare, uint256 netToPharmacy) = _accruePatientShare(epoch, paidGross);

        emit Claimed(epoch, claimant, paidGross, netToPharmacy, patientShare);
        if (allowPartial) {
            emit PartialSettlementRecorded(epoch, claimant, paidGross, carriedGross, false);
        } else if (recipient != claimant) {
            emit ClaimRouted(epoch, claimant, recipient, netToPharmacy);
        }

        _safeTransfer(token, recipient, netToPharmacy);
    }

    function claimCarried(address recipient, bool isExclusion)
        external
        nonReentrant
        returns (uint256 paidGross, uint256 remainingCarry)
    {
        _requireNotPaused();
        if (recipient == address(0)) revert InvalidAddress();
        if (sanctioned[msg.sender] || sanctioned[recipient]) revert Sanctioned();

        uint256 owed = isExclusion ? _carriedExclusionAmount[msg.sender] : _carriedRootAmount[msg.sender];
        if (owed == 0) revert NothingToCarrySettle();

        uint256 epoch = currentEpoch;
        uint256 lastEpoch = isExclusion ? _carriedExclusionEpoch[msg.sender] : _carriedRootEpoch[msg.sender];
        if (epoch <= lastEpoch) revert CarryEpochNotAdvanced();

        uint256 capRoom = _remainingEpochCapRoom();
        if (isExclusion) {
            if (exclusionRemediationReserve == 0) revert InsufficientExclusionReserve();
            if (exclusionRemediationReserve < capRoom) {
                capRoom = exclusionRemediationReserve;
            }
        }

        paidGross = owed <= capRoom ? owed : capRoom;
        remainingCarry = owed - paidGross;

        if (isExclusion) {
            _carriedExclusionAmount[msg.sender] = remainingCarry;
            _carriedExclusionEpoch[msg.sender]  = epoch;
            exclusionRemediationReserve -= paidGross;
            epochExclusionPaidTotal[epoch] += paidGross;
            pharmacyClaimedThisEpoch[epoch][msg.sender] += paidGross;
        } else {
            _carriedRootAmount[msg.sender] = remainingCarry;
            _carriedRootEpoch[msg.sender]  = epoch;
            if (remainingCarry == 0) {
                _carriedRootSince[msg.sender] = 0;
            }
            _totalCarriedEscrow -= paidGross;
        }

        epochVolume              += paidGross;
        epochClaimedTotal[epoch] += paidGross;

        (, uint256 netToPharmacy) = _accruePatientShare(epoch, paidGross);

        emit CarriedSettlementPaid(epoch, msg.sender, recipient, paidGross, remainingCarry, isExclusion);
        _safeTransfer(token, recipient, netToPharmacy);
    }

    function recallStaleCarryForward(address pharmacy)
        external
        nonReentrant
    {
        _onlyRole(COUNCIL_ROLE);
        uint256 owed = _carriedRootAmount[pharmacy];
        if (owed == 0) revert NothingToRecall();
        if (!_hasReachedDelay(_carriedRootSince[pharmacy], STALE_DISTRIBUTION_RECOVERY_DELAY)) {
            revert RecoveryDelayNotElapsed();
        }

        _carriedRootAmount[pharmacy] = 0;
        _carriedRootSince[pharmacy]  = 0;
        _totalCarriedEscrow         -= owed;
        accruedPatientFund          += owed;

        emit StaleCarryForwardRecalled(pharmacy, owed);
    }

    function _remainingEpochCapRoom() private view returns (uint256) {
        if (epochVolume >= dailyVolumeCap) revert DailyCapExceeded();
        if (epochVolume >= hardAbsoluteVolumeCap) revert HardCapExceeded();
        uint256 dailyRoom = dailyVolumeCap - epochVolume;
        uint256 hardRoom = hardAbsoluteVolumeCap - epochVolume;
        return dailyRoom <= hardRoom ? dailyRoom : hardRoom;
    }

    // =========================================================
    // DISPUTE RESOLUTION
    // =========================================================

    function flagClaim(
        uint256 epoch,
        uint256 amount,
        uint256 eligibleCap,
        bytes32[] calldata proof,
        bytes32 evidenceHash
    )
        external
    {
        _requireNotPaused();
        if (evidenceHash == bytes32(0))           revert ZeroEvidenceHash();
        if (epoch != currentEpoch)                revert CanOnlyFlagCurrentEpoch();
        if (sanctioned[msg.sender])               revert Sanctioned();
        if (disputeUsedInEpoch[epoch][msg.sender]) revert DisputeAlreadyUsedInEpoch();
        if (amount == 0)                          revert ZeroAmount();
        if (hasClaimed[epoch][msg.sender])        revert AlreadyClaimed();
        if (flaggedAmount[epoch][msg.sender] != 0) revert AlreadyFlagged();
        if (epochEscrow[epoch] < amount)          revert DistributionPoolDepleted();

        uint256 newRootClaimed = _verifyRootLeaf(epoch, msg.sender, amount, eligibleCap, proof);

        uint256 newVolume = epochVolume + amount;
        if (newVolume > dailyVolumeCap)        revert DailyCapExceeded();
        if (newVolume > hardAbsoluteVolumeCap) revert HardCapExceeded();

        disputeUsedInEpoch[epoch][msg.sender]        = true;
        hasClaimed[epoch][msg.sender]                = true;
        pharmacyClaimedThisEpoch[epoch][msg.sender] += amount;
        epochVolume                                   = newVolume;
        epochClaimedTotal[epoch]                    += amount;
        epochRootClaimedTotal[epoch]                 = newRootClaimed;
        flaggedAmount[epoch][msg.sender]             = amount;
        disputeFlaggedTimestamp[epoch][msg.sender]   = block.timestamp;
        epochEscrow[epoch]                           -= amount;
        totalEscrowed                                -= amount;
        totalFlaggedNormal                           += amount;

        emit ClaimFlagged(epoch, msg.sender, amount, evidenceHash);
    }

    function flagExclusion(uint256 epoch, uint256 amount, bytes32 evidenceHash)
        external
        nonReentrant
    {
        _requireNotPaused();
        uint256 bond = _exclusionDisputeBond;
        if (bond == 0 && _requireExclusionCredential) {
            revert ExclusionCredentialRequired();
        }
        _recordExclusionFlag(epoch, msg.sender, amount, evidenceHash, bond);
    }

    function flagExclusionWithCredential(
        uint256 epoch,
        uint256 amount,
        bytes32 evidenceHash,
        address issuer,
        uint256 deadline,
        bytes calldata issuerSignature
    )
        external
        nonReentrant
    {
        _requireNotPaused();
        if (!_trustedCredentialIssuers[issuer]) revert InvalidSignature();
        if (block.timestamp > deadline) revert AuthorizationExpired();

        uint256 nonce = authNonces[msg.sender];
        if (
            !verifier.verifyExclusionCredential(
                issuer,
                epoch,
                msg.sender,
                nonce,
                evidenceHash,
                deadline,
                issuerSignature
            )
        ) {
            revert InvalidSignature();
        }

        authNonces[msg.sender] = nonce + 1;
        _recordExclusionFlag(epoch, msg.sender, amount, evidenceHash, 0);
    }

    function _recordExclusionFlag(
        uint256 epoch,
        address pharmacy,
        uint256 amount,
        bytes32 evidenceHash,
        uint256 bond
    )
        private
    {
        if (evidenceHash == bytes32(0))         revert ZeroEvidenceHash();
        if (epoch != currentEpoch)              revert CanOnlyFlagCurrentEpoch();
        if (sanctioned[pharmacy])               revert Sanctioned();
        if (disputeUsedInEpoch[epoch][pharmacy]) revert DisputeAlreadyUsedInEpoch();
        if (hasClaimed[epoch][pharmacy])        revert AlreadyClaimed();
        if (flaggedAmount[epoch][pharmacy] != 0) revert AlreadyFlagged();
        if (amount == 0)                        revert ZeroAmount();
        if (epochMerkleRoot[epoch] == bytes32(0)) revert NoRootForEpoch();
        if (amount > dailyVolumeCap)            revert DailyCapExceeded();
        if (amount > hardAbsoluteVolumeCap)     revert HardCapExceeded();

        if (bond > 0) {
            _pullExactTokens(pharmacy, bond);
            _exclusionBonds[epoch][pharmacy] = bond;
            _totalExclusionBonds            += bond;
        }

        disputeUsedInEpoch[epoch][pharmacy]      = true;
        hasClaimed[epoch][pharmacy]              = true;
        flaggedAmount[epoch][pharmacy]           = amount;
        disputeFlaggedTimestamp[epoch][pharmacy] = block.timestamp;
        isExclusionDispute[epoch][pharmacy]      = true;
        totalFlaggedExclusion                   += amount;

        emit ExclusionClaimFlagged(epoch, pharmacy, amount, evidenceHash);
    }

    function approveExclusionClaim(uint256 epoch, address pharmacy) external {
        _onlyRole(ROOT_CONFIRMER_ROLE);
        uint256 amount = flaggedAmount[epoch][pharmacy];
        if (amount == 0) revert NoFlaggedClaim();
        if (!isExclusionDispute[epoch][pharmacy]) revert NotExclusionDispute();

        exclusionApproved[epoch][pharmacy] = true;
        emit ExclusionClaimApproved(epoch, pharmacy, amount, msg.sender);
    }

    function retractClaimDispute(uint256 epoch)
        external
        nonReentrant
    {
        _requireNotPaused();
        address pharmacy = msg.sender;
        uint256 amount = flaggedAmount[epoch][pharmacy];
        if (amount == 0) revert NoFlaggedClaim();

        uint256 flaggedAt = disputeFlaggedTimestamp[epoch][pharmacy];
        if (!_hasReachedDelay(flaggedAt, DISPUTE_TIMEOUT)) revert DisputeTimeoutNotElapsed();

        bool isExclusion = isExclusionDispute[epoch][pharmacy];

        hasClaimed[epoch][pharmacy] = false;
        flaggedAmount[epoch][pharmacy] = 0;
        disputeFlaggedTimestamp[epoch][pharmacy] = 0;

        if (isExclusion) {
            isExclusionDispute[epoch][pharmacy] = false;
            exclusionApproved[epoch][pharmacy] = false;
            totalFlaggedExclusion -= amount;

            uint256 bond = _exclusionBonds[epoch][pharmacy];
            if (bond > 0) {
                _exclusionBonds[epoch][pharmacy] = 0;
                _totalExclusionBonds -= bond;
            }

            emit ClaimDisputeRetracted(epoch, pharmacy, amount, true, false);
            if (bond > 0) {
                _safeTransfer(token, pharmacy, bond);
            }
            return;
        }

        epochClaimedTotal[epoch] -= amount;
        epochRootClaimedTotal[epoch] -= amount;
        pharmacyClaimedThisEpoch[epoch][pharmacy] -= amount;
        if (epoch == currentEpoch) {
            epochVolume -= amount;
        }
        totalFlaggedNormal -= amount;

        bool wasRecalled = epochRecalled[epoch];
        if (wasRecalled) {
            emit ClaimDisputeRetracted(epoch, pharmacy, amount, false, true);
            _safeTransfer(token, patientFund, amount);
        } else {
            epochEscrow[epoch] += amount;
            totalEscrowed += amount;
            emit ClaimDisputeRetracted(epoch, pharmacy, amount, false, false);
        }
    }

    function resolveClaim(
        uint256            epoch,
        address            pharmacy,
        DisputeResolution  resolution,
        bytes32            evidenceHash
    )
        external
        nonReentrant
    {
        _onlyRole(COUNCIL_ROLE);
        _requireNotPaused();
        if (evidenceHash == bytes32(0)) revert ZeroEvidenceHash();

        uint256 amount = flaggedAmount[epoch][pharmacy];
        if (amount == 0) revert NoFlaggedClaim();

        bool isExclusion = isExclusionDispute[epoch][pharmacy];

        if (isExclusion) {
            if (
                resolution == DisputeResolution.SEND_TO_PATIENT_FUND ||
                resolution == DisputeResolution.DISMISS_RESTORE_CLAIM
            ) {
                revert InvalidExclusionResolution();
            }
            if (
                resolution == DisputeResolution.RELEASE_TO_PHARMACY ||
                resolution == DisputeResolution.RELEASE_PARTIAL
            ) {
                _settleExclusionRelease(
                    epoch,
                    pharmacy,
                    amount,
                    evidenceHash,
                    resolution == DisputeResolution.RELEASE_PARTIAL
                );
                return;
            }
        } else {
            if (resolution == DisputeResolution.RELEASE_PARTIAL) {
                revert NotExclusionDispute();
            }
            if (resolution == DisputeResolution.DISMISS_RESTORE_CLAIM && epochRecalled[epoch]) {
                revert InvalidDisputeResolution();
            }
        }

        flaggedAmount[epoch][pharmacy] = 0;
        disputeFlaggedTimestamp[epoch][pharmacy] = 0;

        if (isExclusion) {
            isExclusionDispute[epoch][pharmacy] = false;
            exclusionApproved[epoch][pharmacy] = false;
            totalFlaggedExclusion -= amount;
            hasClaimed[epoch][pharmacy] = false;

            uint256 bond = _exclusionBonds[epoch][pharmacy];
            if (bond > 0) {
                _exclusionBonds[epoch][pharmacy] = 0;
                _totalExclusionBonds -= bond;
                accruedPatientFund += bond;
                emit PatientFundAccrued(epoch, bond);
            }
        } else {
            totalFlaggedNormal -= amount;

            if (
                resolution == DisputeResolution.DISMISS ||
                resolution == DisputeResolution.DISMISS_RESTORE_CLAIM
            ) {
                epochClaimedTotal[epoch] -= amount;
                epochRootClaimedTotal[epoch] -= amount;
                pharmacyClaimedThisEpoch[epoch][pharmacy] -= amount;
                if (epoch == currentEpoch) {
                    epochVolume -= amount;
                }

                if (resolution == DisputeResolution.DISMISS_RESTORE_CLAIM) {
                    hasClaimed[epoch][pharmacy] = false;
                }

                if (!epochRecalled[epoch]) {
                    epochEscrow[epoch] += amount;
                    totalEscrowed      += amount;
                }
            }
        }

        uint256 netToPharmacy = 0;
        if (resolution == DisputeResolution.RELEASE_TO_PHARMACY) {
            (, netToPharmacy) = _accruePatientShare(epoch, amount);
        } else if (resolution == DisputeResolution.SEND_TO_PATIENT_FUND) {
            accruedPatientFund += amount;
            emit PatientFundAccrued(epoch, amount);
        }

        emit ClaimResolved(epoch, pharmacy, amount, resolution, isExclusion, evidenceHash);

        if (resolution == DisputeResolution.RELEASE_TO_PHARMACY) {
            _safeTransfer(token, pharmacy, netToPharmacy);
        } else if (resolution == DisputeResolution.DISMISS && !isExclusion && epochRecalled[epoch]) {
            _safeTransfer(token, patientFund, amount);
        }
    }

    function _settleExclusionRelease(
        uint256 epoch,
        address pharmacy,
        uint256 amount,
        bytes32 evidenceHash,
        bool allowPartial
    )
        private
    {
        if (!exclusionApproved[epoch][pharmacy]) revert ExclusionApprovalRequired();

        uint256 paidGross;
        uint256 carriedGross;

        if (allowPartial) {
            if (exclusionRemediationReserve == 0) revert InsufficientExclusionReserve();
            uint256 activeCapUsed = epoch == currentEpoch ? epochVolume : epochClaimedTotal[epoch];
            if (activeCapUsed >= dailyVolumeCap) revert DailyCapExceeded();
            if (activeCapUsed >= hardAbsoluteVolumeCap) revert HardCapExceeded();

            uint256 dailyRoom = dailyVolumeCap - activeCapUsed;
            uint256 hardRoom = hardAbsoluteVolumeCap - activeCapUsed;
            uint256 capRoom = dailyRoom <= hardRoom ? dailyRoom : hardRoom;
            if (exclusionRemediationReserve < capRoom) {
                capRoom = exclusionRemediationReserve;
            }
            paidGross = amount <= capRoom ? amount : capRoom;
            carriedGross = amount - paidGross;
        } else {
            uint256 newEpochTotal = epochClaimedTotal[epoch] + amount;
            if (newEpochTotal > dailyVolumeCap)        revert DailyCapExceeded();
            if (newEpochTotal > hardAbsoluteVolumeCap) revert HardCapExceeded();
            if (exclusionRemediationReserve < amount)  revert InsufficientExclusionReserve();
            paidGross = amount;
        }

        flaggedAmount[epoch][pharmacy] = 0;
        disputeFlaggedTimestamp[epoch][pharmacy] = 0;
        isExclusionDispute[epoch][pharmacy] = false;
        exclusionApproved[epoch][pharmacy] = false;
        totalFlaggedExclusion -= amount;

        uint256 refundBond = _exclusionBonds[epoch][pharmacy];
        if (refundBond > 0) {
            _exclusionBonds[epoch][pharmacy] = 0;
            _totalExclusionBonds -= refundBond;
        }

        exclusionRemediationReserve -= paidGross;
        epochClaimedTotal[epoch] += paidGross;
        epochExclusionPaidTotal[epoch] += paidGross;
        pharmacyClaimedThisEpoch[epoch][pharmacy] += paidGross;
        if (epoch == currentEpoch) {
            epochVolume += paidGross;
        }

        if (carriedGross > 0) {
            _carriedExclusionAmount[pharmacy] += carriedGross;
            _carriedExclusionEpoch[pharmacy]   = currentEpoch;
        }

        (, uint256 netToPharmacy) = _accruePatientShare(epoch, paidGross);

        emit ClaimResolved(
            epoch,
            pharmacy,
            paidGross,
            allowPartial ? DisputeResolution.RELEASE_PARTIAL : DisputeResolution.RELEASE_TO_PHARMACY,
            true,
            evidenceHash
        );
        if (allowPartial) {
            emit PartialSettlementRecorded(epoch, pharmacy, paidGross, carriedGross, true);
        }

        _safeTransfer(token, pharmacy, netToPharmacy + refundBond);
    }

    // =========================================================
    // EPOCH MANAGEMENT
    // =========================================================

    function finalizeEpoch() external {
        _onlyRole(COUNCIL_ROLE);
        _requireNotPaused();
        uint256 epoch = currentEpoch;
        if (epochMerkleRoot[epoch] == bytes32(0)) revert NoRootPublished();
        if (!_hasReachedDelay(epochStartTimestamp, MIN_EPOCH_DURATION)) revert EpochTooShort();
        if (epochVolume < minimumEpochVolume) revert EpochVolumeTooLow();

        emit EpochFinalized(epoch, epochVolume, epochEscrow[epoch], block.timestamp);

        unchecked { currentEpoch = epoch + 1; }
        epochVolume         = 0;
        epochStartTimestamp = block.timestamp;

        emit EpochStarted(currentEpoch, block.timestamp);
    }

    function finalizeStaleEpochForRecall() external {
        _onlyRole(COUNCIL_ROLE);
        _requireNotPaused();
        uint256 epoch = currentEpoch;
        uint256 publishedAt = epochPublishedTimestamp[epoch];
        if (publishedAt == 0) revert NoRootPublished();
        if (!_hasReachedDelay(epochStartTimestamp, MIN_EPOCH_DURATION)) revert EpochTooShort();
        if (epochVolume >= minimumEpochVolume) revert EpochVolumeMeetsMinimum();
        if (!_hasReachedDelay(publishedAt, RECALL_DELAY)) revert RecallDelayNotElapsed();

        emit StaleEpochFinalizedForRecall(epoch, epochVolume, epochEscrow[epoch], block.timestamp);
        emit EpochFinalized(epoch, epochVolume, epochEscrow[epoch], block.timestamp);

        unchecked { currentEpoch = epoch + 1; }
        epochVolume         = 0;
        epochStartTimestamp = block.timestamp;

        emit EpochStarted(currentEpoch, block.timestamp);
    }

    // =========================================================
    // RECALL UNCLAIMED
    // =========================================================

    function recallUnclaimed(uint256 epoch) external nonReentrant {
        _onlyRole(COUNCIL_ROLE);
        if (epoch >= currentEpoch)  revert EpochNotFinalized();
        if (epochRecalled[epoch])   revert AlreadyRecalled();

        uint256 publishedAt = epochPublishedTimestamp[epoch];
        if (publishedAt == 0) revert NoRootPublished();
        if (!_hasReachedDelay(publishedAt, RECALL_DELAY)) revert RecallDelayNotElapsed();

        uint256 unclaimed = epochEscrow[epoch];
        if (unclaimed == 0) revert NothingToRecall();

        epochRecalled[epoch] = true;
        epochEscrow[epoch]   = 0;
        totalEscrowed       -= unclaimed;

        _safeTransfer(token, patientFund, unclaimed);

        emit EpochRecalled(epoch, unclaimed);
    }

    // =========================================================
    // GOVERNANCE RESERVE
    // =========================================================

    function withdrawGovernanceReserve(address recipient, uint256 amount) external nonReentrant {
        _onlyRole(EXECUTOR_ROLE);
        if (recipient == address(0)) revert InvalidAddress();
        if (amount == 0)             revert ZeroAmount();
        if (governanceReserve < amount) revert ExceedsReserve();

        governanceReserve -= amount;
        _safeTransfer(token, recipient, amount);

        emit GovernanceReserveWithdrawn(recipient, amount);
    }

    function recoverStaleDistributionPool(address recipient, uint256 amount) external nonReentrant {
        _onlyRole(EXECUTOR_ROLE);
        if (recipient == address(0)) revert InvalidAddress();
        if (recipient != patientFund) revert InvalidAddress();
        if (amount == 0)             revert ZeroAmount();
        if (epochMerkleRoot[currentEpoch] != bytes32(0)) revert RootAlreadyLive();
        if (!_hasReachedDelay(epochStartTimestamp, STALE_DISTRIBUTION_RECOVERY_DELAY)) {
            revert RecoveryDelayNotElapsed();
        }

        PendingRoot storage pr = pendingRoot[currentEpoch];
        if (pr.proposedAt != 0 && !_hasPassedDelay(pr.proposedAt, ROOT_PROPOSAL_EXPIRY)) {
            revert ProposalPendingOrNotExpired();
        }

        if (distributionPool < amount) revert InsufficientDistributionPool();

        distributionPool -= amount;
        _safeTransfer(token, recipient, amount);

        emit StaleDistributionPoolRecovered(recipient, amount);
    }

    function skipStaleUnrootedEpoch() external nonReentrant {
        _onlyRole(EXECUTOR_ROLE);
        uint256 epoch = currentEpoch;
        if (epochMerkleRoot[epoch] != bytes32(0)) revert RootAlreadyLive();
        if (epochEscrow[epoch] != 0) revert InvalidAddress();
        if (!_hasReachedDelay(epochStartTimestamp, STALE_DISTRIBUTION_RECOVERY_DELAY)) {
            revert RecoveryDelayNotElapsed();
        }

        PendingRoot storage pr = pendingRoot[epoch];
        if (pr.proposedAt != 0 && !_hasPassedDelay(pr.proposedAt, ROOT_PROPOSAL_EXPIRY)) {
            revert ProposalPendingOrNotExpired();
        }

        delete pendingRoot[epoch];

        emit StaleUnrootedEpochSkipped(epoch, msg.sender, block.timestamp);
        emit EpochFinalized(epoch, epochVolume, 0, block.timestamp);

        unchecked { currentEpoch = epoch + 1; }
        epochVolume         = 0;
        epochStartTimestamp = block.timestamp;

        emit EpochStarted(currentEpoch, block.timestamp);
    }

    // =========================================================
    // GOVERNANCE - PARAMETER MANAGEMENT
    // =========================================================

    function reduceHardCap(uint256 newCap) external {
        _onlyRole(EXECUTOR_ROLE);
        if (newCap >= hardAbsoluteVolumeCap) revert CanOnlyReduce();
        if (newCap < dailyVolumeCap)         revert BelowDailyCap();

        uint256 oldCap        = hardAbsoluteVolumeCap;
        hardAbsoluteVolumeCap = newCap;

        emit HardCapReduced(oldCap, newCap);
    }

    function updateDailyCap(uint256 newCap) external {
        _onlyRole(EXECUTOR_ROLE);
        if (newCap == 0)                    revert ZeroCap();
        if (newCap < minimumEpochVolume)    revert MinimumEpochVolumeExceedsDailyCap();
        if (newCap > hardAbsoluteVolumeCap) revert ExceedsHardCap();

        uint256 oldCap = dailyVolumeCap;
        dailyVolumeCap = newCap;

        emit DailyCapUpdated(oldCap, newCap);
    }

    function updatePatientClaimBP(uint256 newBP) external {
        _onlyRole(EXECUTOR_ROLE);
        if (newBP < MIN_PATIENT_CLAIM_BP || newBP > MAX_PATIENT_CLAIM_BP) revert OutOfRange();
        uint256 oldBP = patientClaimBP;
        patientClaimBP = newBP;
        emit PatientClaimBPUpdated(oldBP, newBP);
    }

    function updateGovernanceBP(uint256 newBP) external {
        _onlyRole(EXECUTOR_ROLE);
        if (newBP > MAX_GOVERNANCE_BP) revert OutOfRange();
        uint256 oldBP = governanceBP;
        governanceBP = newBP;
        emit GovernanceBPUpdated(oldBP, newBP);
    }

    /**
     * @notice Configures deposit floor, exclusion anti-spam bond/credential gate, and optional trusted issuer.
     */
    function configureAntiSpam(
        uint256 minDeposit,
        uint256 bondAmount,
        bool requireCredWhenUnbonded,
        address credentialIssuer,
        bool issuerStatus
    ) external {
        if (!hasRole(COUNCIL_ROLE, msg.sender) && !hasRole(EXECUTOR_ROLE, msg.sender)) {
            revert InvalidAddress();
        }
        if (minDeposit > minimumEpochVolume) revert OutOfRange();
        if (bondAmount > dailyVolumeCap / 20) revert ExclusionBondTooHigh();

        _minimumDepositAmount = minDeposit;
        _exclusionDisputeBond = bondAmount;
        _requireExclusionCredential = requireCredWhenUnbonded;
        emit AntiSpamConfigured(minDeposit, bondAmount, requireCredWhenUnbonded);

        if (credentialIssuer != address(0)) {
            _trustedCredentialIssuers[credentialIssuer] = issuerStatus;
            emit TrustedCredentialIssuerUpdated(credentialIssuer, issuerStatus);
        }
    }

    function updateSanction(address account, bool status, string calldata reason) external {
        _onlyRole(COUNCIL_ROLE);
        _requireNotPaused();
        sanctioned[account] = status;
        _appealPending[account] = false;
        emit SanctionUpdated(account, status, reason);
    }

    function appealSanction(string calldata reason, bytes32 evidenceHash) external {
        if (evidenceHash == bytes32(0)) revert ZeroEvidenceHash();
        if (!sanctioned[msg.sender]) revert NotSanctioned();
        uint256 rLen = bytes(reason).length;
        if (rLen == 0 || rLen > MAX_APPEAL_REASON_LENGTH) revert InvalidAppealReason();
        if (_appealPending[msg.sender]) revert AppealAlreadyPending();
        _appealPending[msg.sender] = true;
        emit SanctionAppealed(msg.sender, reason, evidenceHash);
    }

    function setEnvironmentalFund(address _newFund) external {
        _onlyRole(EXECUTOR_ROLE);
        if (_newFund == address(0)) revert InvalidAddress();
        address oldFund   = environmentalFund;
        environmentalFund = _newFund;
        emit EnvironmentalFundUpdated(oldFund, _newFund);
    }

    // =========================================================
    // SWEEP
    // =========================================================

    function sweepETH() external nonReentrant {
        _onlyRole(EXECUTOR_ROLE);
        uint256 balance = address(this).balance;
        if (balance == 0) revert NoETH();
        (bool ok, ) = environmentalFund.call{value: balance}("");
        if (!ok) revert ETHTransferFailed();
        emit Sweep(address(0), environmentalFund, balance);
    }

    function sweep(address _token, uint256 _amount) external nonReentrant {
        _onlyRole(COUNCIL_ROLE);
        if (_token == address(0))     revert InvalidAddress();
        if (_amount == 0)             revert ZeroAmount();
        if (_token == address(token)) revert CannotSweepPayoutToken();
        _safeTransfer(IERC20(_token), patientFund, _amount);
        emit Sweep(_token, patientFund, _amount);
    }

    // =========================================================
    // EMERGENCY
    // =========================================================

    function pause()   external { _onlyRole(GUARDIAN_ROLE); _pause(); }
    function unpause() external { _onlyRole(COUNCIL_ROLE);  _unpause(); }

    // =========================================================
    // VIEW HELPERS - dashboard and watchdog primitives
    // =========================================================

    struct Ring1State {
        uint256 minDeposit;
        uint256 exclusionBond;
        bool requireCredential;
        uint256 totalBonds;
        uint256 totalCarried;
        uint256 carriedRoot;
        uint256 carriedExclusion;
        bool appealOpen;
        bool trustedIssuer;
    }

    function ring1State(address account)
        external
        view
        returns (Ring1State memory state)
    {
        state.minDeposit = _minimumDepositAmount;
        state.exclusionBond = _exclusionDisputeBond;
        state.requireCredential = _requireExclusionCredential;
        state.totalBonds = _totalExclusionBonds;
        state.totalCarried = _totalCarriedEscrow;
        state.carriedRoot = _carriedRootAmount[account];
        state.carriedExclusion = _carriedExclusionAmount[account];
        state.appealOpen = _appealPending[account];
        state.trustedIssuer = _trustedCredentialIssuers[account];
    }

    function unclaimedForEpoch(uint256 epoch)
        external
        view
        returns (uint256)
    {
        return epochEscrow[epoch];
    }

    function recallEligible(uint256 epoch)
        external
        view
        returns (bool)
    {
        if (epoch >= currentEpoch)   return false;
        if (epochRecalled[epoch])    return false;

        uint256 publishedAt = epochPublishedTimestamp[epoch];
        if (publishedAt == 0)        return false;
        if (!_hasReachedDelay(publishedAt, RECALL_DELAY)) return false;

        return epochEscrow[epoch] > 0;
    }

    function epochStats(uint256 epoch)
        external
        view
        returns (
            uint256 rootTotal,
            uint256 claimed,
            uint256 unclaimed,
            bool    recalled,
            uint256 publishedAt
        )
    {
        rootTotal   = epochRootTotal[epoch];
        claimed     = epochRootClaimedTotal[epoch];
        unclaimed   = epochEscrow[epoch];
        recalled    = epochRecalled[epoch];
        publishedAt = epochPublishedTimestamp[epoch];
    }

    function epochAccounting(uint256 epoch)
        external
        view
        returns (
            uint256 rootAllocated,
            uint256 rootClaimed,
            uint256 exclusionPaid,
            uint256 escrowUnclaimed,
            uint256 totalClaimed
        )
    {
        rootAllocated   = epochRootTotal[epoch];
        rootClaimed     = epochRootClaimedTotal[epoch];
        exclusionPaid   = epochExclusionPaidTotal[epoch];
        escrowUnclaimed = epochEscrow[epoch];
        totalClaimed    = epochClaimedTotal[epoch];
    }

    function globalAccounting()
        external
        view
        returns (
            uint256 escrowed,
            uint256 flaggedNormal,
            uint256 flaggedExclusion
        )
    {
        return (totalEscrowed, totalFlaggedNormal, totalFlaggedExclusion);
    }

    function solvencyCheck()
        external
        view
        returns (
            bool isSolvent,
            uint256 delta,
            uint256 expectedBalance,
            uint256 actualBalance
        )
    {
        actualBalance = token.balanceOf(address(this));
        expectedBalance = distributionPool +
            governanceReserve +
            exclusionRemediationReserve +
            accruedPatientFund +
            _totalExclusionBonds +
            _totalCarriedEscrow +
            totalEscrowed +
            totalFlaggedNormal;

        if (actualBalance >= expectedBalance) {
            isSolvent = true;
            delta = actualBalance - expectedBalance;
        } else {
            isSolvent = false;
            delta = expectedBalance - actualBalance;
        }
    }

    /// @notice How much a pharmacy has claimed in a given epoch.
    /// @param epoch    The epoch to query.
    /// @param pharmacy The pharmacy address.
    /// @return Total tokens claimed by the pharmacy in that epoch.
    function pharmacyEpochClaimed(uint256 epoch, address pharmacy)
        external
        view
        returns (uint256)
    {
        return pharmacyClaimedThisEpoch[epoch][pharmacy];
    }

    /// @notice Total number of rebate deposits ever made.
    /// @return Length of the rebateDeposits array.
    function rebateDepositCount()
        external
        view
        returns (uint256)
    {
        return rebateDeposits.length;
    }

    /// @notice Returns a single rebate deposit record by index.
    /// @param index Array index into rebateDeposits.
    function getRebateDeposit(uint256 index)
        external
        view
        returns (
            address depositor,
            uint256 amount,
            uint256 timestamp,
            string memory source
        )
    {
        if (index >= rebateDeposits.length) revert OutOfRange();
        RebateDeposit storage d = rebateDeposits[index];
        return (d.depositor, d.amount, d.timestamp, d.source);
    }

    /// @notice Pending root proposal state for any epoch.
    /// @param epoch The epoch to inspect.
    function getPendingRoot(uint256 epoch)
        external
        view
        returns (
            bytes32 root,
            uint256 totalAmount,
            address proposer,
            uint256 proposedAt,
            uint256 expiresAt,
            bool    expired
        )
    {
        PendingRoot storage pr = pendingRoot[epoch];
        root        = pr.root;
        totalAmount = pr.totalAmount;
        proposer    = pr.proposer;
        proposedAt  = pr.proposedAt;
        expiresAt   = pr.proposedAt > 0 ? _deadlineAt(pr.proposedAt, ROOT_PROPOSAL_EXPIRY) : 0;
        expired     = pr.proposedAt > 0 && _hasPassedDelay(pr.proposedAt, ROOT_PROPOSAL_EXPIRY);
    }

    /// @notice Current bucket balances.
    /// @return distribution   Current distributionPool balance.
    /// @return governance     Current governanceReserve balance.
    /// @return exclusion      Current exclusionRemediationReserve balance.
    /// @return totalDeposited Cumulative total ever deposited.
    function bucketBalances()
        external
        view
        returns (
            uint256 distribution,
            uint256 governance,
            uint256 exclusion,
            uint256 totalDeposited
        )
    {
        return (distributionPool, governanceReserve, exclusionRemediationReserve, totalRebateDeposited);
    }

    // =========================================================
    // ROLE GETTERS (public visibility for off-chain tooling)
    // =========================================================

    /// @notice Returns the COUNCIL_ROLE identifier.
    function councilRole()   external pure returns (bytes32) { return COUNCIL_ROLE; }
    function rootConfirmerRole() external pure returns (bytes32) { return ROOT_CONFIRMER_ROLE; }

    /// @notice Returns the EXECUTOR_ROLE identifier.
    function executorRole()  external pure returns (bytes32) { return EXECUTOR_ROLE; }

    /// @notice Returns the GUARDIAN_ROLE identifier.
    function guardianRole()  external pure returns (bytes32) { return GUARDIAN_ROLE; }

    /**
     * @notice Returns the amount of unallocated distribution pool tokens eligible for stale recovery.
     * @dev    Mirrors recoverStaleDistributionPool() eligibility checks so off-chain
     *         monitors do not report funds as recoverable while a current root is live
     *         or a pending root proposal remains unexpired.
     */
    function getRecoverableStaleAmount() external view returns (uint256) {
        if (epochMerkleRoot[currentEpoch] != bytes32(0)) {
            return 0;
        }

        PendingRoot storage pr = pendingRoot[currentEpoch];
        if (pr.proposedAt != 0 && !_hasPassedDelay(pr.proposedAt, ROOT_PROPOSAL_EXPIRY)) {
            return 0;
        }

        if (_hasReachedDelay(epochStartTimestamp, STALE_DISTRIBUTION_RECOVERY_DELAY)) {
            return distributionPool;
        }
        return 0;
    }
}
