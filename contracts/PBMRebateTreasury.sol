// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControlEnumerable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/**
 * @title  PBMRebateTreasury
 * @author Pharmacy Fiduciary Commons
 * @notice Transparent on-chain rebate capture and distribution engine.
 *         Routes PBM rebates back to independent pharmacies and patients -
 *         auditable, ungameable, and publicly verifiable.
 *
 * @dev    Designed to sit behind a TimelockController (EXECUTOR_ROLE) for
 *         sensitive parameter changes. COUNCIL_ROLE is a 3/5 Gnosis Safe and
 *         ROOT_CONFIRMER_ROLE is held by a separate Safe or governance address.
 *         GUARDIAN_ROLE is a separate faster-response address for emergency pause.
 *
 *         ACCESS CONTROL NOTE: DEFAULT_ADMIN_ROLE is granted to the council Safe
 *         for council and guardian membership. EXECUTOR_ROLE is self-administered
 *         by the TimelockController, and it administers ROOT_CONFIRMER_ROLE.
 *         Council and root-confirmer membership are mutually exclusive on every
 *         role grant, preserving separate proposal and approval trust roots.
 *
 * MISSION:
 * Pharmacy Benefit Managers (PBMs) negotiate rebates from drug manufacturers
 * but routinely retain them instead of passing savings to pharmacies or patients.
 * Independent pharmacies are further extracted via DIR fee clawbacks applied
 * retroactively after dispensing. This contract makes rebate flows permanently
 * visible on-chain and routes captured value back to independent pharmacies
 * and patients. Absence from this voluntary ledger is only meaningful when
 * paired with independent expected-deposit evidence.
 *
 * LIFECYCLE:
 * 1. PBM (or any party) calls depositRebate() - funds enter escrow, source logged forever.
 * 2. Council proposes Merkle root via proposeRoot().
 * 3. A separately configured root confirmer calls confirmRoot() - root becomes active.
 * 4. Pharmacies call claim() directly with Merkle proofs.
 * 5. Council calls finalizeEpoch() to close epoch and open the next.
 * 6. After RECALL_DELAY, unclaimed funds recalled to patientFund.
 *
 * TREASURY BUCKETS (split at deposit time):
 * - Distribution pool  - 99% - pharmacy Merkle claims draw from here.
 * - Governance reserve -  1% - council operations; EXECUTOR_ROLE access only.
 *
 * PATIENT FUND allocation:
 * - 10% of every gross claim (PATIENT_CLAIM_BP) -> patientFund at claim time.
 * - All unclaimed epoch funds after RECALL_DELAY -> patientFund.
 * - Non-payout token sweeps -> patientFund.
 * - Patient fund is NOT funded at deposit time - allocation is claim-aligned.
 *
 * DISPUTE RESOLUTION:
 * - Pharmacies may flag a disputed claim via flagClaim().
 * - A valid Merkle proof must be supplied at flag time - griefing protection.
 * - Disputed amount is held in reserve in flaggedAmount[epoch][pharmacy].
 * - Council resolves proof-backed disputes via resolveClaim().
 * - Root-exclusion payouts additionally require ROOT_CONFIRMER_ROLE approval and cap checks.
 *
 * SECURITY PROPERTIES:
 * - Hard cap enforced at root proposal + claim
 * - Daily cap enforced at root proposal + claim
 * - Root total enforced at claim
 * - Per-pharmacy cap enforced at claim via Merkle leaf encoding
 * - Double-hash leaf (second-preimage protection)
 * - Root publication requires separate council proposal and confirmer approval
 * - Hard cap monotonic decrease only (ratchet)
 * - Daily cap bounded by hard cap
 * - Recall only after RECALL_DELAY, only unclaimed amount, sent to patientFund
 * - Payout token cannot be swept
 * - Non-payout tokens swept to patientFund (not general fund)
 * - GUARDIAN_ROLE is a separate address from COUNCIL_ROLE - faster emergency response
 * - flagClaim requires valid Merkle proof - prevents pool-draining griefing
 * - flagClaim increments epochClaimedTotal + epochVolume + hasClaimed - caps and recall math fully consistent
 * - ETH rejected via receive() and fallback()
 * - No upgradeability
 */
contract PBMRebateTreasury is
    AccessControlEnumerable,
    ReentrancyGuard,
    Pausable
{
    using SafeERC20 for IERC20;

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

    // =========================================================
    // ROLES
    // =========================================================

    /// @notice 3/5 Gnosis Safe - epoch management, root co-sign, recall, sanctions.
    bytes32 private constant COUNCIL_ROLE  = keccak256("COUNCIL_ROLE");

    /// @notice TimelockController - sensitive parameter changes (caps, env fund).
    bytes32 private constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    /// @notice Separate Safe or governance address that confirms council root proposals.
    bytes32 private constant ROOT_CONFIRMER_ROLE = keccak256("ROOT_CONFIRMER_ROLE");

    /// @notice Separate fast-response address - emergency pause only.
    ///         Cannot unpause. Cannot publish roots. Cannot access funds.
    bytes32 private constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    // =========================================================
    // CONSTANTS
    // =========================================================

    uint256 private constant BP_DENOM = 10_000;
    uint256 private constant MIN_PATIENT_CLAIM_BP = 500;
    uint256 private constant MAX_PATIENT_CLAIM_BP = 3_000;
    uint256 private constant MAX_GOVERNANCE_BP = 500;

    /// @notice Governance reserve taken at deposit time (1%).
    uint256 public governanceBP = 100;

    /// @notice Patient share taken from gross claim amount at claim time (10%).
    ///         Draws from distributionPool. patientFund receives this on every claim.
    uint256 public patientClaimBP = 1_000;

    uint256 private constant MIN_EPOCH_DURATION = 1 days;
    /// @notice Minimum gross claim volume required to finalize an epoch, in token base units.
    uint256 public immutable minimumEpochVolume;

    /// @notice Minimum delay after root publish before council may recall unclaimed funds.
    uint256 private constant RECALL_DELAY = 30 days;

    /// @notice Delay after which a claimant may retract an unresolved dispute.
    uint256 public constant DISPUTE_TIMEOUT = 30 days;

    /// @notice Proposed roots expire if not co-signed within this window.
    uint256 private constant ROOT_PROPOSAL_EXPIRY = 3 days;

    /// @notice Long inactivity window before timelock may recover unallocated distribution liquidity.
    uint256 private constant STALE_DISTRIBUTION_RECOVERY_DELAY = 180 days;

    // =========================================================
    // IMMUTABLE CORE
    // =========================================================

    /// @notice The ERC-20 payout token (DAI or USDC).
    IERC20  public immutable token;

    /// @notice Receives 10% of every gross claim and all unclaimed recalled funds.
    ///         Funds free/low-cost drug access for patients in need.
    ///         NOT funded at deposit time - allocation is claim-aligned.
    address public immutable patientFund;

    // =========================================================
    // MUTABLE (executor-governed)
    // =========================================================

    /// @notice Receives forced/accidentally sent ETH. Non-payout token sweeps go to patientFund.
    address public environmentalFund;

    // =========================================================
    // TREASURY BUCKET BALANCES
    // =========================================================

    /// @notice Pharmacy distribution pool - Merkle claims draw from this.
    uint256 public distributionPool;

    /// @notice Council operational reserve - gas, legal, admin.
    ///         Withdrawable only by EXECUTOR_ROLE.
    uint256 public governanceReserve;

    /// @notice Explicitly funded reserve for approved root-exclusion remediation.
    ///         This reserve cannot be sourced from root distribution liquidity.
    uint256 public exclusionRemediationReserve;

    /// @notice Aggregate of all currently escrowed funds across active and finalized epochs.
    uint256 public totalEscrowed;

    /// @notice Aggregate of all currently flagged proof-backed claims.
    uint256 public totalFlaggedNormal;

    /// @notice Aggregate of all currently flagged root-exclusion claims.
    uint256 public totalFlaggedExclusion;

    // =========================================================
    // CAPS
    // =========================================================

    /// @notice Maximum tokens claimable per epoch rolling window.
    uint256 public dailyVolumeCap;

    /// @notice Absolute upper bound on total epoch claim volume. Ratchet: can only decrease.
    uint256 public hardAbsoluteVolumeCap;

    // =========================================================
    // EPOCH STATE
    // =========================================================

    /// @notice The current active epoch index.
    uint256 public currentEpoch;

    /// @notice Total tokens claimed in the current epoch.
    uint256 public epochVolume;

    /// @notice Timestamp when the current epoch started.
    uint256 public epochStartTimestamp;

    /// @notice Timestamp of the latest rebate deposit.
    /// @dev Informational deposit metadata only. Stale distribution recovery is gated by
    ///      epochStartTimestamp so dust deposits cannot extend the recovery delay.
    uint256 public lastDepositTimestamp;

    /// @notice merkleRoot[epoch] - zero if not yet published.
    mapping(uint256 => bytes32) public epochMerkleRoot;

    /// @notice Total gross allocation in the published root for each epoch.
    mapping(uint256 => uint256) public epochRootTotal;

    /// @notice Timestamp at which the root for each epoch was confirmed and published.
    mapping(uint256 => uint256) public epochPublishedTimestamp;

    /// @notice Total tokens successfully claimed in each epoch.
    mapping(uint256 => uint256) public epochClaimedTotal;

    /// @notice Root-backed claims consumed from epoch escrow, including proof-backed disputes.
    mapping(uint256 => uint256) public epochRootClaimedTotal;

    /// @notice Approved root-exclusion payouts funded outside the epoch's root escrow.
    mapping(uint256 => uint256) public epochExclusionPaidTotal;

    /// @notice Whether unclaimed funds for an epoch have been recalled.
    mapping(uint256 => bool)    public epochRecalled;

    /// @notice hasClaimed[epoch][pharmacy] - true once a pharmacy has claimed for an epoch.
    mapping(uint256 => mapping(address => bool))    public hasClaimed;

    /// @notice pharmacyClaimedThisEpoch[epoch][pharmacy] - total claimed by pharmacy in epoch.
    mapping(uint256 => mapping(address => uint256)) public pharmacyClaimedThisEpoch;

    /// @notice epochEscrow[epoch] - total tokens currently escrowed for the epoch.
    mapping(uint256 => uint256) public epochEscrow;

    /// @notice isExclusionDispute[epoch][pharmacy] - true if dispute is for root exclusion.
    mapping(uint256 => mapping(address => bool)) public isExclusionDispute;

    /// @notice sanctioned[address] - true if address is barred from claiming.
    mapping(address => bool) public sanctioned;

    // =========================================================
    // PENDING ROOT (co-sign gate)
    // =========================================================

    struct PendingRoot {
        bytes32 root;
        uint256 totalAmount;
        address proposer;
        uint256 proposedAt;
    }

    /// @notice Proposed root awaiting independent confirmer approval. One pending root per epoch.
    mapping(uint256 => PendingRoot) public pendingRoot;

    // =========================================================
    // DISPUTE RESOLUTION
    // =========================================================

    /// @notice Amount held in reserve for disputed claims.
    ///         flaggedAmount[epoch][pharmacy] > 0 means a dispute is open.
    mapping(uint256 => mapping(address => uint256)) public flaggedAmount;

    /// @notice Timestamp when each dispute was raised, used for claimant timeout retraction.
    mapping(uint256 => mapping(address => uint256)) public disputeFlaggedTimestamp;

    /// @notice Independent approval required before an exclusion dispute can receive funds.
    mapping(uint256 => mapping(address => bool)) public exclusionApproved;

    enum DisputeResolution { RELEASE_TO_PHARMACY, SEND_TO_PATIENT_FUND, DISMISS }

    // =========================================================
    // REBATE DEPOSIT TRACKING
    // =========================================================

    struct RebateDeposit {
        address depositor;
        uint256 amount;
        uint256 timestamp;
        string  source;
    }

    /// @notice Permanent public log of every rebate deposit - the Ledger of Omissions.
    ///         Missing entries are ledger absences, not standalone proof of off-chain nonpayment.
    RebateDeposit[] public rebateDeposits;

    /// @notice Cumulative total of all rebate tokens ever deposited.
    uint256 public totalRebateDeposited;

    // =========================================================
    // EVENTS
    // =========================================================

    /// @notice Emitted on every rebate deposit - core transparency primitive.
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

    event EpochFinalized(uint256 indexed epoch, uint256 totalVolume, uint256 remainingEscrow, uint256 timestamp);
    event StaleEpochFinalizedForRecall(uint256 indexed epoch, uint256 totalVolume, uint256 remainingEscrow, uint256 timestamp);
    event EpochStarted(uint256 indexed epoch, uint256 timestamp);

    event HardCapReduced(uint256 indexed oldCap, uint256 indexed newCap);
    event DailyCapUpdated(uint256 indexed oldCap, uint256 indexed newCap);
    event PatientClaimBPUpdated(uint256 indexed oldBP, uint256 indexed newBP);
    event GovernanceBPUpdated(uint256 indexed oldBP, uint256 indexed newBP);

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

    event GovernanceReserveWithdrawn(address indexed recipient, uint256 amount);
    event StaleDistributionPoolRecovered(address indexed recipient, uint256 amount);
    event ExclusionRemediationFunded(address indexed funder, uint256 amount);
    event StaleUnrootedEpochSkipped(uint256 indexed skippedEpoch, address indexed executor, uint256 timestamp);

    event Sweep(address indexed tokenAddr, address indexed recipient, uint256 amount);
    event EnvironmentalFundUpdated(address indexed oldFund, address indexed newFund);

    // =========================================================
    // CONSTRUCTOR
    // =========================================================

    /**
     * @notice Deploys the treasury and wires up all roles and initial parameters.
     * @param _token             DAI (or USDC) contract address.
     * @param _patientFund       Immutable patient access fund address.
     * @param _environmentalFund Receives accidentally sent ETH.
     * @param _initialDailyCap   Starting daily volume cap (hard cap set to 10x).
     * @param _minimumEpochVolume Minimum claimed volume required to finalize, in token base units.
     * @param _council           3/5 Gnosis Safe - receives COUNCIL_ROLE and DEFAULT_ADMIN_ROLE.
     * @param _rootConfirmer     Separate Safe or governance address that confirms roots.
     * @param _executor          TimelockController - receives EXECUTOR_ROLE.
     * @param _guardian          Separate fast-response EOA or 2/3 Safe - GUARDIAN_ROLE only.
     * @dev  GUARDIAN_ROLE, ROOT_CONFIRMER_ROLE, and council must be separate controllers.
     */
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

    /**
     * @dev Keeps root proposal and confirmation authority mutually exclusive across
     *      constructor setup and all future AccessControl role rotations.
     */
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

    receive()  external payable { revert ETHNotAccepted(); }
    fallback() external payable { revert NoFallback(); }

    // =========================================================
    // REBATE DEPOSIT
    // =========================================================

    /**
     * @notice Deposits rebate funds into escrow with public source attribution.
     * @dev    Anyone may deposit - a PBM settlement, a DAO contribution, a grant.
     *         Every deposit is permanently logged on-chain with caller and source string.
     *         Funds split at deposit time into two buckets:
     *         99% -> distributionPool (pharmacy Merkle claims)
     *          1% -> governanceReserve (council operations)
     *
     *         Patient fund is NOT funded at deposit time. It receives 10% of every
     *         gross claim at claim time, and all unclaimed recalled funds. This keeps
     *         the deposit event clean - the full deposited amount is visible as
     *         entering the system, with deductions occurring only at verified distribution.
     *
     *         This is the core transparency primitive. Treat non-deposit as an
     *         omission only when paired with independently sourced expected-deposit evidence.
     *
     * @param amount Amount of `token` to deposit.
     * @param source Human-readable source label (1-256 bytes).
     *               Example: "OptumRx - Respiratory - Q1 2026 - UFCW Drug Trust"
     */
    function depositRebate(uint256 amount, string calldata source)
        external
        nonReentrant
        whenNotPaused
    {
        if (amount == 0) revert ZeroAmount();
        uint256 srcLen = bytes(source).length;
        if (srcLen == 0 || srcLen > 256) revert InvalidSource();

        uint256 balanceBefore = token.balanceOf(address(this));
        token.safeTransferFrom(msg.sender, address(this), amount);
        uint256 balanceAfter = token.balanceOf(address(this));
        uint256 received = balanceAfter >= balanceBefore ? balanceAfter - balanceBefore : 0;
        if (received != amount) {
            revert TokenTransferAmountMismatch(amount, received);
        }

        uint256 forGovernance   = (amount * governanceBP) / BP_DENOM;
        uint256 forDistribution = amount - forGovernance;

        governanceReserve    += forGovernance;
        distributionPool     += forDistribution;
        totalRebateDeposited += amount;
        lastDepositTimestamp  = block.timestamp;

        uint256 depositId = rebateDeposits.length;
        rebateDeposits.push(RebateDeposit({
            depositor: msg.sender,
            amount:    amount,
            timestamp: block.timestamp,
            source:    source
        }));

        emit RebateDeposited(depositId, msg.sender, amount, forDistribution, forGovernance, source);
    }

    /**
     * @notice Funds the dedicated reserve used only for approved root-exclusion claims.
     * @dev This is separate from rebate deposits so remediation cannot consume
     *      liquidity intended for current or future Merkle roots.
     */
    function fundExclusionRemediation(uint256 amount)
        external
        nonReentrant
        whenNotPaused
    {
        if (amount == 0) revert ZeroAmount();
        uint256 balanceBefore = token.balanceOf(address(this));
        token.safeTransferFrom(msg.sender, address(this), amount);
        uint256 balanceAfter = token.balanceOf(address(this));
        uint256 received = balanceAfter >= balanceBefore ? balanceAfter - balanceBefore : 0;
        if (received != amount) {
            revert TokenTransferAmountMismatch(amount, received);
        }
        exclusionRemediationReserve += amount;
        emit ExclusionRemediationFunded(msg.sender, amount);
    }

    // =========================================================
    // ROOT PUBLICATION - CO-SIGN GATE
    // =========================================================

    /**
     * @notice First council member proposes a Merkle root for the current epoch.
     * @dev    Root does not go live until a member with ROOT_CONFIRMER_ROLE
     *         calls confirmRoot(). This is the highest-stakes action in the contract -
     *         the root determines who gets paid.
     *
     *         Proposal expires after ROOT_PROPOSAL_EXPIRY if not confirmed.
     *         Only one pending root per epoch.
     *
     * @param root        The Merkle root of pharmacy allocations.
     * @param totalAmount Sum of all leaf gross allocations.
     *
     * @dev Leaf encoding:
     *      keccak256(keccak256(abi.encodePacked(pharmacy, grossAmount, eligibleCap)))
     */
    function proposeRoot(bytes32 root, uint256 totalAmount)
        external
        onlyRole(COUNCIL_ROLE)
        whenNotPaused
    {
        uint256 epoch = currentEpoch; // cache SLOAD
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

    /**
     * @notice Separate root confirmer approves a pending root, making it live.
     * @dev    The confirmer role is configured independently from the council.
     *         Proposal must not have expired.
     *         Once confirmed, root is immutable for this epoch.
     *         Caps and pool balance are re-verified at confirmation time.
     *
     * @param epoch The epoch whose pending root to confirm. Must equal currentEpoch.
     */
    function confirmRoot(uint256 epoch)
        external
        onlyRole(ROOT_CONFIRMER_ROLE)
        whenNotPaused
    {
        if (epoch != currentEpoch) revert WrongEpoch();

        PendingRoot storage pr = pendingRoot[epoch];
        if (pr.proposedAt == 0)            revert NoPendingRoot();
        if (_hasPassedDelay(pr.proposedAt, ROOT_PROPOSAL_EXPIRY)) revert ProposalExpired();
        if (epochMerkleRoot[epoch] != bytes32(0)) revert RootAlreadyLive();

        // Re-verify caps and escrow at confirmation time - conditions may have changed
        if (pr.totalAmount > dailyVolumeCap)        revert DailyCapExceeded();
        if (pr.totalAmount > hardAbsoluteVolumeCap) revert HardCapExceeded();
        if (distributionPool < pr.totalAmount)      revert InsufficientDistributionPool();

        bytes32 confirmedRoot   = pr.root;
        uint256 confirmedTotal  = pr.totalAmount;

        epochMerkleRoot[epoch]         = confirmedRoot;
        epochRootTotal[epoch]          = confirmedTotal;
        epochPublishedTimestamp[epoch] = block.timestamp;

        // Partition pool to epoch escrow
        distributionPool     -= confirmedTotal;
        epochEscrow[epoch]    = confirmedTotal;
        totalEscrowed        += confirmedTotal;

        delete pendingRoot[epoch];

        emit RootConfirmed(epoch, confirmedRoot, confirmedTotal, msg.sender);
    }

    /**
     * @notice Clears an expired root proposal, allowing a new one to be proposed.
     * @dev    Callable by anyone - no gatekeeping on cleanup.
     * @param epoch The epoch whose expired proposal to clear.
     */
    function clearExpiredProposal(uint256 epoch) external {
        PendingRoot storage pr = pendingRoot[epoch];
        if (pr.proposedAt == 0) revert NoPendingRoot();
        if (!_hasPassedDelay(pr.proposedAt, ROOT_PROPOSAL_EXPIRY)) revert NotExpired();
        delete pendingRoot[epoch];
        emit RootProposalExpired(epoch);
    }

    // =========================================================
    // CLAIM
    // =========================================================

    /**
     * @notice Claims allocated rebate for the current epoch.
     * @dev    Leaf: keccak256(keccak256(abi.encodePacked(msg.sender, amount, eligibleCap)))
     *         `amount`      - gross allocation this epoch.
     *         `eligibleCap` - per-pharmacy maximum; enforced on-chain.
     *         Claimant receives amount * 90%. Patient fund receives 10%.
     *         Draws from the current epoch's confirmed escrow - not from the raw contract balance.
     *
     * @param amount      Gross allocated amount.
     * @param eligibleCap Per-pharmacy cap encoded in the Merkle leaf.
     * @param proof       Merkle proof.
     */
    function claim(
        uint256 amount,
        uint256 eligibleCap,
        bytes32[] calldata proof
    )
        external
        nonReentrant
        whenNotPaused
    {
        _processClaim(msg.sender, amount, eligibleCap, proof);
    }

    /**
     * @dev Internal claim logic for claim().
     *      Leaf encoding uses abi.encodePacked for gas efficiency - safe because
     *      all three fields (address, uint256, uint256) are fixed-size types.
     */
    function _processClaim(
        address claimant,
        uint256 amount,
        uint256 eligibleCap,
        bytes32[] memory proof
    )
        internal
    {
        uint256 epoch = currentEpoch; // cache SLOAD - used 6x below

        if (sanctioned[claimant])                revert Sanctioned();
        if (hasClaimed[epoch][claimant])         revert AlreadyClaimed();
        if (flaggedAmount[epoch][claimant] != 0) revert AlreadyFlagged();

        bytes32 root = epochMerkleRoot[epoch];
        if (root == bytes32(0)) revert NoRootForEpoch();

        // Double-hash leaf - second-preimage protection
        // abi.encodePacked is safe here: all fields are fixed-size (address + uint256 + uint256)
        bytes32 leaf = keccak256(
            bytes.concat(keccak256(abi.encodePacked(claimant, amount, eligibleCap)))
        );
        if (!MerkleProof.verify(proof, root, leaf)) revert InvalidProof();

        // Per-pharmacy cap enforcement
        uint256 alreadyClaimed = pharmacyClaimedThisEpoch[epoch][claimant];
        if (alreadyClaimed + amount > eligibleCap) revert PharmacyCapExceeded();

        uint256 newVolume = epochVolume + amount;
        if (newVolume > dailyVolumeCap)        revert DailyCapExceeded();
        if (newVolume > hardAbsoluteVolumeCap) revert HardCapExceeded();
        if (newVolume > epochRootTotal[epoch]) revert RootTotalExceeded();
        if (epochEscrow[epoch] < amount)       revert DistributionPoolDepleted();

        // Effects
        hasClaimed[epoch][claimant]                = true;
        pharmacyClaimedThisEpoch[epoch][claimant] += amount;
        epochVolume                                 = newVolume;
        epochClaimedTotal[epoch]                  += amount;
        epochRootClaimedTotal[epoch]              += amount;
        epochEscrow[epoch]                         -= amount;
        totalEscrowed                              -= amount;

        uint256 patientShare  = (amount * patientClaimBP) / BP_DENOM;
        uint256 netToPharmacy = amount - patientShare;

        // Interactions
        token.safeTransfer(patientFund, patientShare);
        token.safeTransfer(claimant,    netToPharmacy);

        emit Claimed(epoch, claimant, amount, netToPharmacy, patientShare);
    }

    // =========================================================
    // DISPUTE RESOLUTION
    // =========================================================

    /**
     * @notice Pharmacy flags a disputed allocation for council review.
     * @dev    Requires a valid Merkle proof of the claimed amount - this prevents
     *         arbitrary pool-draining griefing. The proof anchors the flagged amount
     *         to a leaf that the council actually published.
     *
     *         Flags the pharmacy's hasClaimed entry and holds the disputed amount
     *         in reserve. The pharmacy cannot claim while a dispute is open.
     *         Council must call resolveClaim() to settle.
     *
     *         Use case: pharmacy believes Merkle root incorrectly excluded or
     *         undercounted their allocation for the epoch.
     *
     * @param epoch       The epoch being disputed (must be currentEpoch).
     * @param amount      Amount the pharmacy believes it is owed (must match leaf).
     * @param eligibleCap Per-pharmacy cap as encoded in the leaf.
     * @param proof       Merkle proof authenticating the leaf.
     * @param evidenceHash Hash binding off-chain dispute evidence to this on-chain flag.
     */
    function flagClaim(
        uint256 epoch,
        uint256 amount,
        uint256 eligibleCap,
        bytes32[] calldata proof,
        bytes32 evidenceHash
    )
        external
        whenNotPaused
    {
        if (evidenceHash == bytes32(0)) revert ZeroEvidenceHash();
        if (epoch != currentEpoch)                revert CanOnlyFlagCurrentEpoch();
        if (sanctioned[msg.sender])               revert Sanctioned();
        if (hasClaimed[epoch][msg.sender])        revert AlreadyClaimed();
        if (flaggedAmount[epoch][msg.sender] != 0) revert AlreadyFlagged();
        if (amount == 0)                          revert ZeroAmount();
        if (epochEscrow[epoch] < amount)          revert DistributionPoolDepleted();

        // Require valid Merkle proof to prevent griefing / arbitrary pool lock
        bytes32 root = epochMerkleRoot[epoch];
        if (root == bytes32(0)) revert NoRootForEpoch();
        bytes32 leaf = keccak256(
            bytes.concat(keccak256(abi.encodePacked(msg.sender, amount, eligibleCap)))
        );
        if (!MerkleProof.verify(proof, root, leaf)) revert InvalidProof();

        // Enforce the same cap boundaries as claim() before reserving.
        uint256 alreadyClaimed = pharmacyClaimedThisEpoch[epoch][msg.sender];
        if (alreadyClaimed + amount > eligibleCap) revert PharmacyCapExceeded();

        uint256 newVolume = epochVolume + amount;
        if (newVolume > dailyVolumeCap)        revert DailyCapExceeded();
        if (newVolume > hardAbsoluteVolumeCap) revert HardCapExceeded();
        if (newVolume > epochRootTotal[epoch]) revert RootTotalExceeded();

        hasClaimed[epoch][msg.sender]                = true;
        pharmacyClaimedThisEpoch[epoch][msg.sender] += amount;
        epochVolume                                   = newVolume;
        epochClaimedTotal[epoch]                    += amount;
        epochRootClaimedTotal[epoch]                += amount;
        flaggedAmount[epoch][msg.sender]             = amount;
        disputeFlaggedTimestamp[epoch][msg.sender]   = block.timestamp;
        epochEscrow[epoch]                           -= amount;
        totalEscrowed                                -= amount;
        totalFlaggedNormal                           += amount;

        emit ClaimFlagged(epoch, msg.sender, amount, evidenceHash);
    }

    /**
     * @notice Pharmacy flags a dispute for exclusion from the Merkle root.
     * @dev    Does not require a Merkle proof since the pharmacy is claiming they were omitted.
     *         No funds are locked from the remediation reserve at flag time.
     *         A root confirmer must approve before council can release funds, and the payout
     *         remains bounded by epoch volume caps at resolution time.
     *         Sets hasClaimed to true to prevent double-dipping or regular claims on the same epoch.
     *
     * @param epoch  The epoch being disputed (must be currentEpoch).
     * @param amount The gross amount being claimed.
     * @param evidenceHash Hash binding off-chain omission evidence to this on-chain flag.
     */
    function flagExclusion(uint256 epoch, uint256 amount, bytes32 evidenceHash)
        external
        whenNotPaused
    {
        if (evidenceHash == bytes32(0)) revert ZeroEvidenceHash();
        if (epoch != currentEpoch)                 revert CanOnlyFlagCurrentEpoch();
        if (sanctioned[msg.sender])                revert Sanctioned();
        if (hasClaimed[epoch][msg.sender])         revert AlreadyClaimed();
        if (flaggedAmount[epoch][msg.sender] != 0) revert AlreadyFlagged();
        if (amount == 0)                           revert ZeroAmount();
        if (epochMerkleRoot[epoch] == bytes32(0))  revert NoRootForEpoch();
        if (amount > dailyVolumeCap)               revert DailyCapExceeded();
        if (amount > hardAbsoluteVolumeCap)        revert HardCapExceeded();

        hasClaimed[epoch][msg.sender]         = true;
        flaggedAmount[epoch][msg.sender]      = amount;
        disputeFlaggedTimestamp[epoch][msg.sender] = block.timestamp;
        isExclusionDispute[epoch][msg.sender] = true;
        totalFlaggedExclusion                += amount;

        emit ExclusionClaimFlagged(epoch, msg.sender, amount, evidenceHash);
    }

    /**
     * @notice Independently approves a root-exclusion claim for council resolution.
     * @dev Approval does not transfer or reserve funds. Caps and reserve availability are
     *      enforced again when the council resolves the claim.
     */
    function approveExclusionClaim(uint256 epoch, address pharmacy)
        external
        onlyRole(ROOT_CONFIRMER_ROLE)
    {
        uint256 amount = flaggedAmount[epoch][pharmacy];
        if (amount == 0) revert NoFlaggedClaim();
        if (!isExclusionDispute[epoch][pharmacy]) revert NotExclusionDispute();

        exclusionApproved[epoch][pharmacy] = true;
        emit ExclusionClaimApproved(epoch, pharmacy, amount, msg.sender);
    }

    /**
     * @notice Allows a pharmacy to retract an unresolved dispute after the timeout.
     * @dev Normal disputes reverse claim-volume accounting. If the epoch has already
     *      been recalled, the quarantined funds follow the recall destination.
     *
     * @param epoch The epoch whose unresolved dispute should be retracted.
     */
    function retractClaimDispute(uint256 epoch)
        external
        nonReentrant
        whenNotPaused
    {
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

            emit ClaimDisputeRetracted(epoch, pharmacy, amount, true, false);
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
            token.safeTransfer(patientFund, amount);
        } else {
            epochEscrow[epoch] += amount;
            totalEscrowed += amount;
            emit ClaimDisputeRetracted(epoch, pharmacy, amount, false, false);
        }
    }

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
     * @param resolution RELEASE_TO_PHARMACY or SEND_TO_PATIENT_FUND.
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

    // =========================================================
    // EPOCH MANAGEMENT
    // =========================================================

    /**
     * @notice Finalizes current epoch and begins a new one.
     * @dev    Cannot rotate during pause. Minimum epoch duration and volume enforced.
     */
    function finalizeEpoch()
        external
        onlyRole(COUNCIL_ROLE)
        whenNotPaused
    {
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

    /**
     * @notice Finalizes a below-minimum-volume epoch after the recall window has elapsed.
     * @dev    Normal finalization still requires minimumEpochVolume. This liveness path
     *         exists only so inactive or low-participation epochs cannot permanently
     *         trap root escrow by blocking recallUnclaimed().
     */
    function finalizeStaleEpochForRecall()
        external
        onlyRole(COUNCIL_ROLE)
        whenNotPaused
    {
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

    /**
     * @notice After RECALL_DELAY, council sends unclaimed epoch funds to patientFund.
     * @dev    Prevents permanent token lock. Unclaimed funds benefit patients, not council.
     *         Only unclaimed amount recalled - claimed funds already transferred.
     *
     * @param epoch The finalized epoch to recall from.
     */
    function recallUnclaimed(uint256 epoch)
        external
        nonReentrant
        onlyRole(COUNCIL_ROLE)
    {
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

        token.safeTransfer(patientFund, unclaimed);

        emit EpochRecalled(epoch, unclaimed);
    }

    // =========================================================
    // GOVERNANCE RESERVE
    // =========================================================

    /**
     * @notice EXECUTOR_ROLE withdraws from governance reserve for council operations.
     * @dev    Should be called via TimelockController. Cannot exceed reserve balance.
     *
     * @param recipient Address to send reserve funds to.
     * @param amount    Amount to withdraw.
     */
    function withdrawGovernanceReserve(address recipient, uint256 amount)
        external
        nonReentrant
        onlyRole(EXECUTOR_ROLE)
    {
        if (recipient == address(0)) revert InvalidAddress();
        if (amount == 0)             revert ZeroAmount();
        if (governanceReserve < amount) revert ExceedsReserve();

        governanceReserve -= amount;
        token.safeTransfer(recipient, amount);

        emit GovernanceReserveWithdrawn(recipient, amount);
    }

    /**
     * @notice Timelocked recovery for distribution liquidity never assigned to a root.
     * @dev    This does not touch epoch escrow or the payout token sweep guard. It only
     *         reduces unallocated distributionPool after a long period with no confirmed
     *         root for the current epoch, preventing indefinite lock if root publication
     *         governance stalls.
     *
     * @param recipient Address to receive recovered distribution liquidity.
     * @param amount    Amount to recover from the unallocated distribution pool.
     */
    function recoverStaleDistributionPool(address recipient, uint256 amount)
        external
        nonReentrant
        onlyRole(EXECUTOR_ROLE)
    {
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
        token.safeTransfer(recipient, amount);

        emit StaleDistributionPoolRecovered(recipient, amount);
    }

    /**
     * @notice Timelocked emergency path to skip a stale epoch for which no Merkle root was ever proposed/published,
     *         preventing a permanent freeze of the state machine.
     * @dev    Gated by EXECUTOR_ROLE (timelock controller). Requires STALE_DISTRIBUTION_RECOVERY_DELAY to have elapsed.
     */
    function skipStaleUnrootedEpoch()
        external
        nonReentrant
        onlyRole(EXECUTOR_ROLE)
    {
        uint256 epoch = currentEpoch;
        if (epochMerkleRoot[epoch] != bytes32(0)) revert RootAlreadyLive();
        if (epochEscrow[epoch] != 0) revert InvalidAddress(); // Defensive check: unrooted epoch must have 0 escrowed
        if (!_hasReachedDelay(epochStartTimestamp, STALE_DISTRIBUTION_RECOVERY_DELAY)) {
            revert RecoveryDelayNotElapsed();
        }

        PendingRoot storage pr = pendingRoot[epoch];
        if (pr.proposedAt != 0 && !_hasPassedDelay(pr.proposedAt, ROOT_PROPOSAL_EXPIRY)) {
            revert ProposalPendingOrNotExpired();
        }

        // Tidy up any expired pending root data
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

    /**
     * @notice Permanently reduces the absolute hard cap (ratchet - cannot increase).
     * @dev    Should be called via EXECUTOR_ROLE / TimelockController.
     *         newCap must be strictly less than current cap and >= dailyVolumeCap.
     *
     * @param newCap The new, lower hard cap.
     */
    function reduceHardCap(uint256 newCap)
        external
        onlyRole(EXECUTOR_ROLE)
    {
        if (newCap >= hardAbsoluteVolumeCap) revert CanOnlyReduce();
        if (newCap < dailyVolumeCap)         revert BelowDailyCap();

        uint256 oldCap        = hardAbsoluteVolumeCap;
        hardAbsoluteVolumeCap = newCap;

        emit HardCapReduced(oldCap, newCap);
    }

    /**
     * @notice Adjusts the daily volume cap within hard cap bounds.
     * @dev    Can increase or decrease. Cannot exceed hardAbsoluteVolumeCap.
     *
     * @param newCap The new daily volume cap.
     */
    function updateDailyCap(uint256 newCap)
        external
        onlyRole(EXECUTOR_ROLE)
    {
        if (newCap == 0)                    revert ZeroCap();
        if (newCap < minimumEpochVolume)    revert MinimumEpochVolumeExceedsDailyCap();
        if (newCap > hardAbsoluteVolumeCap) revert ExceedsHardCap();

        uint256 oldCap = dailyVolumeCap;
        dailyVolumeCap = newCap;

        emit DailyCapUpdated(oldCap, newCap);
    }

    /**
     * @notice Updates the patient fund claim basis points (safeguarded).
     * @dev    Must be executed by EXECUTOR_ROLE via TimelockController.
     *         Enforces safety boundaries: new value must be between 5% (500 BP) and 30% (3000 BP).
     * @param newBP The new basis points value.
     */
    function updatePatientClaimBP(uint256 newBP)
        external
        onlyRole(EXECUTOR_ROLE)
    {
        if (newBP < MIN_PATIENT_CLAIM_BP || newBP > MAX_PATIENT_CLAIM_BP) revert OutOfRange();
        uint256 oldBP = patientClaimBP;
        patientClaimBP = newBP;
        emit PatientClaimBPUpdated(oldBP, newBP);
    }

    /**
     * @notice Updates the governance reserve deposit basis points (downward-ratchet cap).
     * @dev    Must be executed by EXECUTOR_ROLE via TimelockController.
     *         Enforces safety cap limit: new value cannot exceed 5% (500 BP).
     * @param newBP The new basis points value.
     */
    function updateGovernanceBP(uint256 newBP)
        external
        onlyRole(EXECUTOR_ROLE)
    {
        if (newBP > MAX_GOVERNANCE_BP) revert OutOfRange();
        uint256 oldBP = governanceBP;
        governanceBP = newBP;
        emit GovernanceBPUpdated(oldBP, newBP);
    }

    /**
     * @notice Updates sanction status for an address.
     * @param account The address to sanction or unsanction.
     * @param status  True to sanction, false to lift sanction.
     */
    function updateSanction(address account, bool status, string calldata reason)
        external
        onlyRole(COUNCIL_ROLE)
        whenNotPaused
    {
        sanctioned[account] = status;
        emit SanctionUpdated(account, status, reason);
    }

    /**
     * @notice Allows a sanctioned address to submit an on-chain appeal.
     * @param reason The justification for the appeal.
     * @param evidenceHash Hash binding off-chain appeal evidence to this on-chain appeal.
     */
    function appealSanction(string calldata reason, bytes32 evidenceHash) external {
        if (evidenceHash == bytes32(0)) revert ZeroEvidenceHash();
        if (!sanctioned[msg.sender]) revert NotSanctioned();
        emit SanctionAppealed(msg.sender, reason, evidenceHash);
    }

    /**
     * @notice Updates environmental fund address.
     * @dev    Should be called via EXECUTOR_ROLE / TimelockController.
     * @param _newFund The new environmental fund address.
     */
    function setEnvironmentalFund(address _newFund)
        external
        onlyRole(EXECUTOR_ROLE)
    {
        if (_newFund == address(0)) revert InvalidAddress();
        address oldFund   = environmentalFund;
        environmentalFund = _newFund;
        emit EnvironmentalFundUpdated(oldFund, _newFund);
    }

    // =========================================================
    // SWEEP
    // =========================================================

    /**
     * @notice Timelocked recovery for forced/accidentally sent ETH to environmentalFund.
     */
    function sweepETH() external nonReentrant onlyRole(EXECUTOR_ROLE) {
        uint256 balance = address(this).balance;
        if (balance == 0) revert NoETH();
        (bool ok, ) = environmentalFund.call{value: balance}("");
        if (!ok) revert ETHTransferFailed();
        emit Sweep(address(0), environmentalFund, balance);
    }

    /**
     * @notice Recovers non-payout tokens sent accidentally.
     * @dev    Swept to patientFund - not general fund. Recovered value benefits patients.
     * @param _token  The ERC-20 token to recover (must not be the payout token).
     * @param _amount Amount to recover.
     */
    function sweep(address _token, uint256 _amount)
        external
        nonReentrant
        onlyRole(COUNCIL_ROLE)
    {
        if (_token == address(0))     revert InvalidAddress();
        if (_amount == 0)             revert ZeroAmount();
        if (_token == address(token)) revert CannotSweepPayoutToken();
        IERC20(_token).safeTransfer(patientFund, _amount);
        emit Sweep(_token, patientFund, _amount);
    }

    // =========================================================
    // EMERGENCY
    // =========================================================

    /// @notice GUARDIAN_ROLE can pause faster than the council multisig.
    function pause()   external onlyRole(GUARDIAN_ROLE) { _pause(); }

    /// @notice Only COUNCIL_ROLE can unpause - guardian cannot re-enable the system.
    function unpause() external onlyRole(COUNCIL_ROLE)  { _unpause(); }

    // =========================================================
    // VIEW HELPERS - dashboard and watchdog primitives
    // =========================================================

    /// @notice Total unclaimed allocation for a given epoch.
    /// @param epoch The epoch to query.
    /// @return Unclaimed token amount, or zero if fully claimed.
    function unclaimedForEpoch(uint256 epoch)
        external
        view
        returns (uint256)
    {
        return epochEscrow[epoch];
    }

    /// @notice Whether a past epoch is eligible for recall.
    /// @param epoch The epoch to check.
    /// @return True if the epoch can be recalled right now.
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

    /// @notice Full epoch summary - dashboard and journalist friendly.
    /// @param epoch The epoch to summarize.
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

    /// @notice Provenance-aware epoch accounting for dashboards and watchdogs.
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

    /// @notice Global aggregate accounting for dashboards and watchdogs.
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

    /**
     * @notice Performs an atomic on-chain solvency balance check.
     * @dev Compares actual ERC-20 token balance held by the contract against the sum of
     *      all accounting obligations: distributionPool + governanceReserve +
     *      exclusionRemediationReserve + totalEscrowed + totalFlaggedNormal.
     * @return isSolvent True if actual token balance >= total accounting obligations.
     * @return delta The surplus (or deficit if insolvent) in token base units.
     * @return expectedBalance Sum of all accounting bucket obligations.
     * @return actualBalance Real ERC-20 balance held by this contract.
     */
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
