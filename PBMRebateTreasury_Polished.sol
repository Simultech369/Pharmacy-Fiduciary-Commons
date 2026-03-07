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
 *         sensitive parameter changes. COUNCIL_ROLE is a 3/5 Gnosis Safe.
 *         GUARDIAN_ROLE is a separate faster-response address for emergency pause.
 *
 *         ACCESS CONTROL NOTE: DEFAULT_ADMIN_ROLE is intentionally granted to
 *         the _council (Gnosis Safe) so that role membership can be updated if
 *         signers rotate. This is a deliberate governance decision - the council
 *         Safe is the trust root. Mitigated by: (a) council is a 3/5 multisig,
 *         (b) EXECUTOR_ROLE is a TimelockController adding time-delay on
 *         parameter changes, (c) GUARDIAN_ROLE is a separate address that can
 *         pause faster than any multisig action.
 *
 * MISSION:
 * Pharmacy Benefit Managers (PBMs) negotiate rebates from drug manufacturers
 * but routinely retain them instead of passing savings to pharmacies or patients.
 * Independent pharmacies are further extracted via DIR fee clawbacks applied
 * retroactively after dispensing. This contract makes rebate flows permanently
 * visible on-chain and routes captured value back to independent pharmacies
 * and patients. PBM silence is the evidence.
 *
 * LIFECYCLE:
 * 1. PBM (or any party) calls depositRebate() - funds enter escrow, source logged forever.
 * 2. Council proposes Merkle root via proposeRoot() - requires co-sign from second
 *    council member before going live. This is the highest-stakes action.
 * 3. Second council member calls confirmRoot() - root becomes active.
 * 4. Pharmacies (or delegated claims agent) call claim() or claimBatch().
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
 * - Council resolves via resolveClaim() - releases to pharmacy or patientFund.
 *
 * SECURITY PROPERTIES:
 * - Hard cap enforced at root proposal + claim
 * - Daily cap enforced at root proposal + claim
 * - Root total enforced at claim
 * - Per-pharmacy cap enforced at claim via Merkle leaf encoding
 * - Double-hash leaf (second-preimage protection)
 * - Root publication requires co-sign from two distinct COUNCIL_ROLE members
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
    error WrongEpoch();
    error NoPendingRoot();
    error ProposerCannotConfirm();
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
    error PoolMismatch();
    error ExceedsReserve();
    error NoETH();
    error ETHTransferFailed();
    error ETHNotAccepted();
    error NoFallback();
    error CannotSweepPayoutToken();
    error OutOfRange();
    error EmptyBatch();
    error ArrayMismatchCaps();
    error ArrayMismatchProofs();
    error SingleClaimPerEpoch();
    error EpochTooShort();
    error EpochVolumeTooLow();
    error GuardianMustDifferFromCouncil();

    // =========================================================
    // ROLES
    // =========================================================

    /// @notice 3/5 Gnosis Safe - epoch management, root co-sign, recall, sanctions.
    bytes32 private constant COUNCIL_ROLE  = keccak256("COUNCIL_ROLE");

    /// @notice TimelockController - sensitive parameter changes (caps, env fund).
    bytes32 private constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    /// @notice Separate fast-response address - emergency pause only.
    ///         Cannot unpause. Cannot publish roots. Cannot access funds.
    bytes32 private constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    // =========================================================
    // CONSTANTS
    // =========================================================

    uint256 private constant BP_DENOM = 10_000;

    /// @notice Governance reserve taken at deposit time (1%).
    uint256 private constant GOVERNANCE_BP    = 100;

    /// @notice Patient share taken from gross claim amount at claim time (10%).
    ///         Draws from distributionPool. patientFund receives this on every claim.
    uint256 private constant PATIENT_CLAIM_BP = 1_000;

    uint256 private constant MIN_EPOCH_DURATION = 1 days;
    uint256 private constant MIN_EPOCH_VOLUME   = 1e18;

    /// @notice Minimum delay after root publish before council may recall unclaimed funds.
    uint256 private constant RECALL_DELAY = 30 days;

    /// @notice Proposed roots expire if not co-signed within this window.
    uint256 private constant ROOT_PROPOSAL_EXPIRY = 3 days;

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

    /// @notice Receives accidentally sent ETH. Non-payout token sweeps go to patientFund.
    address public environmentalFund;

    // =========================================================
    // TREASURY BUCKET BALANCES
    // =========================================================

    /// @notice Pharmacy distribution pool - Merkle claims draw from this.
    uint256 public distributionPool;

    /// @notice Council operational reserve - gas, legal, admin.
    ///         Withdrawable only by EXECUTOR_ROLE.
    uint256 public governanceReserve;

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

    /// @notice merkleRoot[epoch] - zero if not yet published.
    mapping(uint256 => bytes32) public epochMerkleRoot;

    /// @notice Total gross allocation in the published root for each epoch.
    mapping(uint256 => uint256) public epochRootTotal;

    /// @notice Timestamp at which the root for each epoch was confirmed and published.
    mapping(uint256 => uint256) public epochPublishedTimestamp;

    /// @notice Total tokens successfully claimed in each epoch.
    mapping(uint256 => uint256) public epochClaimedTotal;

    /// @notice Whether unclaimed funds for an epoch have been recalled.
    mapping(uint256 => bool)    public epochRecalled;

    /// @notice hasClaimed[epoch][pharmacy] - true once a pharmacy has claimed for an epoch.
    mapping(uint256 => mapping(address => bool))    public hasClaimed;

    /// @notice pharmacyClaimedThisEpoch[epoch][pharmacy] - total claimed by pharmacy in epoch.
    mapping(uint256 => mapping(address => uint256)) public pharmacyClaimedThisEpoch;

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

    /// @notice Proposed root awaiting second council co-sign. One pending root per epoch.
    mapping(uint256 => PendingRoot) public pendingRoot;

    // =========================================================
    // DISPUTE RESOLUTION
    // =========================================================

    /// @notice Amount held in reserve for disputed claims.
    ///         flaggedAmount[epoch][pharmacy] > 0 means a dispute is open.
    mapping(uint256 => mapping(address => uint256)) public flaggedAmount;

    enum DisputeResolution { RELEASE_TO_PHARMACY, SEND_TO_PATIENT_FUND }

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
    ///         PBM silence is the evidence. Every zero quarter is a documented omission.
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

    event EpochFinalized(uint256 indexed epoch, uint256 totalVolume);
    event EpochStarted(uint256 indexed epoch, uint256 timestamp);

    event HardCapReduced(uint256 indexed oldCap, uint256 indexed newCap);
    event DailyCapUpdated(uint256 indexed oldCap, uint256 indexed newCap);

    event SanctionUpdated(address indexed account, bool status);

    event EpochRecalled(uint256 indexed epoch, uint256 amount);

    event ClaimFlagged(uint256 indexed epoch, address indexed pharmacy, uint256 amount);
    event ClaimResolved(
        uint256 indexed epoch,
        address indexed pharmacy,
        uint256 amount,
        DisputeResolution resolution
    );

    event GovernanceReserveWithdrawn(address indexed recipient, uint256 amount);

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
     * @param _council           3/5 Gnosis Safe - receives COUNCIL_ROLE and DEFAULT_ADMIN_ROLE.
     * @param _executor          TimelockController - receives EXECUTOR_ROLE.
     * @param _guardian          Separate fast-response EOA or 2/3 Safe - GUARDIAN_ROLE only.
     * @dev  GUARDIAN_ROLE must be a different address from _council.
     *       This separation is the point - guardian can pause faster than multisig.
     */
    constructor(
        address _token,
        address _patientFund,
        address _environmentalFund,
        uint256 _initialDailyCap,
        address _council,
        address _executor,
        address _guardian
    ) {
        if (_token             == address(0)) revert InvalidAddress();
        if (_patientFund       == address(0)) revert InvalidAddress();
        if (_environmentalFund == address(0)) revert InvalidAddress();
        if (_council           == address(0)) revert InvalidAddress();
        if (_executor          == address(0)) revert InvalidAddress();
        if (_guardian          == address(0)) revert InvalidAddress();
        if (_guardian          == _council)   revert GuardianMustDifferFromCouncil();
        if (_initialDailyCap   == 0)          revert ZeroCap();

        token             = IERC20(_token);
        patientFund       = _patientFund;
        environmentalFund = _environmentalFund;

        dailyVolumeCap        = _initialDailyCap;
        hardAbsoluteVolumeCap = _initialDailyCap * 10;

        epochStartTimestamp = block.timestamp;

        _grantRole(DEFAULT_ADMIN_ROLE, _council);
        _grantRole(COUNCIL_ROLE,       _council);
        _grantRole(EXECUTOR_ROLE,      _executor);
        _grantRole(GUARDIAN_ROLE,      _guardian);

        emit EpochStarted(currentEpoch, block.timestamp);
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
     *         This is the core transparency primitive. A PBM that receives rebates
     *         and does not call this function is creating a documented omission.
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

        token.safeTransferFrom(msg.sender, address(this), amount);

        uint256 forGovernance   = (amount * GOVERNANCE_BP) / BP_DENOM;
        uint256 forDistribution = amount - forGovernance;

        governanceReserve    += forGovernance;
        distributionPool     += forDistribution;
        totalRebateDeposited += amount;

        uint256 depositId = rebateDeposits.length;
        rebateDeposits.push(RebateDeposit({
            depositor: msg.sender,
            amount:    amount,
            timestamp: block.timestamp,
            source:    source
        }));

        emit RebateDeposited(depositId, msg.sender, amount, forDistribution, forGovernance, source);
    }

    // =========================================================
    // ROOT PUBLICATION - CO-SIGN GATE
    // =========================================================

    /**
     * @notice First council member proposes a Merkle root for the current epoch.
     * @dev    Root does not go live until a second, distinct COUNCIL_ROLE member
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
        if (pr.proposedAt != 0 && block.timestamp <= pr.proposedAt + ROOT_PROPOSAL_EXPIRY) {
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

        emit RootProposed(epoch, root, totalAmount, msg.sender, block.timestamp + ROOT_PROPOSAL_EXPIRY);
    }

    /**
     * @notice Second council member confirms a pending root, making it live.
     * @dev    Confirmer must be a different address from the proposer.
     *         Proposal must not have expired.
     *         Once confirmed, root is immutable for this epoch.
     *         Caps and pool balance are re-verified at confirmation time.
     *
     * @param epoch The epoch whose pending root to confirm. Must equal currentEpoch.
     */
    function confirmRoot(uint256 epoch)
        external
        onlyRole(COUNCIL_ROLE)
        whenNotPaused
    {
        if (epoch != currentEpoch) revert WrongEpoch();

        PendingRoot storage pr = pendingRoot[epoch];
        if (pr.proposedAt == 0)            revert NoPendingRoot();
        if (pr.proposer == msg.sender)     revert ProposerCannotConfirm();
        if (block.timestamp > pr.proposedAt + ROOT_PROPOSAL_EXPIRY) revert ProposalExpired();
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
        if (block.timestamp <= pr.proposedAt + ROOT_PROPOSAL_EXPIRY) revert NotExpired();
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
     *         Draws from distributionPool - not from the raw contract balance.
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
     * @notice Compatibility wrapper for integrators expecting an array-based claim interface.
     * @dev    This contract enforces one claim per pharmacy per epoch. Arrays must contain
     *         exactly one entry - use claim() directly if calling from your own code.
     *         The len == 1 constraint is explicit rather than relying on the AlreadyClaimed
     *         revert from _processClaim, so callers get a clear error at the array boundary.
     *
     * @param amounts      Single-element array: gross allocated amount.
     * @param eligibleCaps Single-element array: per-pharmacy cap encoded in the Merkle leaf.
     * @param proofs       Single-element array: Merkle proof.
     */
    function claimBatch(
        uint256[]   calldata amounts,
        uint256[]   calldata eligibleCaps,
        bytes32[][] calldata proofs
    )
        external
        nonReentrant
        whenNotPaused
    {
        uint256 len = amounts.length;
        if (len == 0)                    revert EmptyBatch();
        if (len != eligibleCaps.length)  revert ArrayMismatchCaps();
        if (len != proofs.length)        revert ArrayMismatchProofs();
        if (len != 1)                    revert SingleClaimPerEpoch();

        _processClaim(msg.sender, amounts[0], eligibleCaps[0], proofs[0]);
    }

    /**
     * @dev Internal claim logic shared by claim() and claimBatch().
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
        if (distributionPool < amount)         revert DistributionPoolDepleted();

        // Effects
        hasClaimed[epoch][claimant]                = true;
        pharmacyClaimedThisEpoch[epoch][claimant] += amount;
        epochVolume                                 = newVolume;
        epochClaimedTotal[epoch]                  += amount;
        distributionPool                           -= amount;

        uint256 patientShare  = (amount * PATIENT_CLAIM_BP) / BP_DENOM;
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
     */
    function flagClaim(
        uint256 epoch,
        uint256 amount,
        uint256 eligibleCap,
        bytes32[] calldata proof
    )
        external
        whenNotPaused
    {
        if (epoch != currentEpoch)                revert CanOnlyFlagCurrentEpoch();
        if (sanctioned[msg.sender])               revert Sanctioned();
        if (hasClaimed[epoch][msg.sender])        revert AlreadyClaimed();
        if (flaggedAmount[epoch][msg.sender] != 0) revert AlreadyFlagged();
        if (amount == 0)                          revert ZeroAmount();
        if (distributionPool < amount)            revert DistributionPoolDepleted();

        // Require valid Merkle proof to prevent griefing / arbitrary pool lock
        bytes32 root = epochMerkleRoot[epoch];
        if (root == bytes32(0)) revert NoRootForEpoch();
        bytes32 leaf = keccak256(
            bytes.concat(keccak256(abi.encodePacked(msg.sender, amount, eligibleCap)))
        );
        if (!MerkleProof.verify(proof, root, leaf)) revert InvalidProof();

        // Enforce the same cap boundaries as claim() before reserving.
        // Full claim accounting is applied at flag time so that:
        //   (a) epochVolume / cap checks cannot be bypassed via flag + claim combination,
        //   (b) recall math (epochRootTotal - epochClaimedTotal) stays consistent, and
        //   (c) hasClaimed prevents a pharmacy from double-dipping after SEND_TO_PATIENT_FUND.
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
        flaggedAmount[epoch][msg.sender]             = amount;
        distributionPool                            -= amount;

        emit ClaimFlagged(epoch, msg.sender, amount);
    }

    /**
     * @notice Council resolves a flagged dispute.
     * @dev    Transfers are done after state updates and event emission to follow
     *         checks-effects-interactions. nonReentrant guards external calls.
     *         RELEASE_TO_PHARMACY: net-of-patient-share paid to pharmacy.
     *         SEND_TO_PATIENT_FUND: full amount sent to patientFund as invalid-flag penalty.
     *
     * @param epoch      The epoch of the dispute.
     * @param pharmacy   The pharmacy whose dispute to resolve.
     * @param resolution RELEASE_TO_PHARMACY or SEND_TO_PATIENT_FUND.
     */
    function resolveClaim(
        uint256            epoch,
        address            pharmacy,
        DisputeResolution  resolution
    )
        external
        onlyRole(COUNCIL_ROLE)
        nonReentrant
    {
        uint256 amount = flaggedAmount[epoch][pharmacy];
        if (amount == 0) revert NoFlaggedClaim();

        // Effects first. All claim accounting (hasClaimed, epochVolume, epochClaimedTotal)
        // was applied at flag time - only the reservation needs clearing here.
        flaggedAmount[epoch][pharmacy] = 0;

        // Interactions after state is settled
        if (resolution == DisputeResolution.RELEASE_TO_PHARMACY) {
            uint256 patientShare  = (amount * PATIENT_CLAIM_BP) / BP_DENOM;
            uint256 netToPharmacy = amount - patientShare;
            emit ClaimResolved(epoch, pharmacy, amount, resolution);
            token.safeTransfer(patientFund, patientShare);
            token.safeTransfer(pharmacy,    netToPharmacy);
        } else {
            emit ClaimResolved(epoch, pharmacy, amount, resolution);
            token.safeTransfer(patientFund, amount);
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
        if (block.timestamp < epochStartTimestamp + MIN_EPOCH_DURATION) revert EpochTooShort();
        if (epochVolume < MIN_EPOCH_VOLUME) revert EpochVolumeTooLow();

        emit EpochFinalized(epoch, epochVolume);

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
        onlyRole(COUNCIL_ROLE)
        nonReentrant
    {
        if (epoch >= currentEpoch)  revert EpochNotFinalized();
        if (epochRecalled[epoch])   revert AlreadyRecalled();

        uint256 publishedAt = epochPublishedTimestamp[epoch];
        if (publishedAt == 0) revert NoRootPublished();
        if (block.timestamp < publishedAt + RECALL_DELAY) revert RecallDelayNotElapsed();

        uint256 totalAllocated = epochRootTotal[epoch];
        uint256 totalClaimed   = epochClaimedTotal[epoch];
        if (totalAllocated <= totalClaimed) revert NothingToRecall();

        uint256 unclaimed = totalAllocated - totalClaimed;
        if (distributionPool < unclaimed) revert PoolMismatch();

        epochRecalled[epoch] = true;
        distributionPool    -= unclaimed;

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
        onlyRole(EXECUTOR_ROLE)
        nonReentrant
    {
        if (recipient == address(0)) revert InvalidAddress();
        if (amount == 0)             revert ZeroAmount();
        if (governanceReserve < amount) revert ExceedsReserve();

        governanceReserve -= amount;
        token.safeTransfer(recipient, amount);

        emit GovernanceReserveWithdrawn(recipient, amount);
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
        if (newCap > hardAbsoluteVolumeCap) revert ExceedsHardCap();

        uint256 oldCap = dailyVolumeCap;
        dailyVolumeCap = newCap;

        emit DailyCapUpdated(oldCap, newCap);
    }

    /**
     * @notice Updates sanction status for an address.
     * @param account The address to sanction or unsanction.
     * @param status  True to sanction, false to lift sanction.
     */
    function updateSanction(address account, bool status)
        external
        onlyRole(COUNCIL_ROLE)
    {
        sanctioned[account] = status;
        emit SanctionUpdated(account, status);
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
     * @notice Sweeps accidentally sent ETH to environmentalFund.
     */
    function sweepETH() external onlyRole(COUNCIL_ROLE) {
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
    /// @inheritdoc Pausable
    function pause()   external onlyRole(GUARDIAN_ROLE) { _pause(); }

    /// @notice Only COUNCIL_ROLE can unpause - guardian cannot re-enable the system.
    /// @inheritdoc Pausable
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
        uint256 allocated = epochRootTotal[epoch];
        uint256 claimed   = epochClaimedTotal[epoch];
        if (allocated <= claimed) return 0;
        return allocated - claimed;
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
        if (block.timestamp < publishedAt + RECALL_DELAY) return false;

        return epochRootTotal[epoch] > epochClaimedTotal[epoch];
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
        claimed     = epochClaimedTotal[epoch];
        unclaimed   = rootTotal > claimed ? rootTotal - claimed : 0;
        recalled    = epochRecalled[epoch];
        publishedAt = epochPublishedTimestamp[epoch];
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
        expiresAt   = pr.proposedAt > 0 ? pr.proposedAt + ROOT_PROPOSAL_EXPIRY : 0;
        expired     = pr.proposedAt > 0 && block.timestamp > pr.proposedAt + ROOT_PROPOSAL_EXPIRY;
    }

    /// @notice Current bucket balances.
    /// @return distribution   Current distributionPool balance.
    /// @return governance     Current governanceReserve balance.
    /// @return totalDeposited Cumulative total ever deposited.
    function bucketBalances()
        external
        view
        returns (
            uint256 distribution,
            uint256 governance,
            uint256 totalDeposited
        )
    {
        return (distributionPool, governanceReserve, totalRebateDeposited);
    }

    // =========================================================
    // ROLE GETTERS (public visibility for off-chain tooling)
    // =========================================================

    /// @notice Returns the COUNCIL_ROLE identifier.
    function councilRole()   external pure returns (bytes32) { return COUNCIL_ROLE; }

    /// @notice Returns the EXECUTOR_ROLE identifier.
    function executorRole()  external pure returns (bytes32) { return EXECUTOR_ROLE; }

    /// @notice Returns the GUARDIAN_ROLE identifier.
    function guardianRole()  external pure returns (bytes32) { return GUARDIAN_ROLE; }
}
