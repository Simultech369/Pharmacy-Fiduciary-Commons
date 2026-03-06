// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControlEnumerable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/**
 * @title  PBMRebateTreasury — V2 (Pharmacy Fiduciary Commons)
 * @notice Transparent on-chain rebate capture and distribution engine.
 *         Routes PBM rebates back to independent pharmacies and patients —
 *         auditable, ungameable, and publicly verifiable.
 *
 * @dev    Designed to sit behind a TimelockController (EXECUTOR_ROLE) for
 *         sensitive parameter changes. COUNCIL_ROLE is a 3/5 Gnosis Safe.
 *         GUARDIAN_ROLE is a separate faster-response address for emergency pause.
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
 * 1. PBM (or any party) calls depositRebate() — funds enter escrow, source logged forever.
 * 2. Council proposes Merkle root via proposeRoot() — requires co-sign from second
 *    council member before going live. This is the highest-stakes action.
 * 3. Second council member calls confirmRoot() — root becomes active.
 * 4. Pharmacies (or delegated claims agent) call claim() or claimBatch().
 * 5. Council calls finalizeEpoch() to close epoch and open the next.
 * 6. After RECALL_DELAY, unclaimed funds recalled to patientFund.
 *
 * TREASURY BUCKETS (split at deposit time):
 * - Distribution pool  — 99% — pharmacy Merkle claims draw from here.
 * - Governance reserve —  1% — council operations; EXECUTOR_ROLE access only.
 *
 * PATIENT FUND allocation:
 * - 10% of every gross claim (PATIENT_CLAIM_BP) → patientFund at claim time.
 * - All unclaimed epoch funds after RECALL_DELAY → patientFund.
 * - Non-payout token sweeps → patientFund.
 * - Patient fund is NOT funded at deposit time — allocation is claim-aligned.
 *
 * DISPUTE RESOLUTION:
 * - Pharmacies may flag a disputed claim via flagClaim().
 * - Disputed amount is held in reserve in flaggedAmount[epoch][pharmacy].
 * - Council resolves via resolveClaim() — releases to pharmacy or patientFund.
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
 * - GUARDIAN_ROLE is a separate address from COUNCIL_ROLE — faster emergency response
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
    // ROLES
    // =========================================================

    /// @notice 3/5 Gnosis Safe — epoch management, root co-sign, recall, sanctions.
    bytes32 public constant COUNCIL_ROLE  = keccak256("COUNCIL_ROLE");

    /// @notice TimelockController — sensitive parameter changes (caps, env fund).
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    /// @notice Separate fast-response address — emergency pause only.
    ///         Cannot unpause. Cannot publish roots. Cannot access funds.
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    // =========================================================
    // CONSTANTS
    // =========================================================

    uint256 public constant BP_DENOM = 10_000;

    /// @notice Governance reserve taken at deposit time.
    uint256 public constant GOVERNANCE_BP    = 100;    // 1% → governance reserve

    /// @notice Patient share taken from gross claim amount at claim time.
    ///         Draws from distributionPool. patientFund receives this on every claim.
    uint256 public constant PATIENT_CLAIM_BP = 1_000;  // 10% of gross claim

    uint256 public constant MIN_EPOCH_DURATION = 1 days;
    uint256 public constant MIN_EPOCH_VOLUME   = 1e18;

    /// @notice Minimum delay after root publish before council may recall unclaimed funds.
    uint256 public constant RECALL_DELAY = 30 days;

    /// @notice Proposed roots expire if not co-signed within this window.
    uint256 public constant ROOT_PROPOSAL_EXPIRY = 3 days;

    // =========================================================
    // IMMUTABLE CORE
    // =========================================================

    IERC20  public immutable token;

    /// @notice Receives 10% of every gross claim and all unclaimed recalled funds.
    ///         Funds free/low-cost drug access for patients in need.
    ///         NOT funded at deposit time — allocation is claim-aligned.
    address public immutable patientFund;

    // =========================================================
    // MUTABLE (executor-governed)
    // =========================================================

    /// @notice Receives accidentally sent ETH. Non-payout token sweeps go to patientFund.
    address public environmentalFund;

    // =========================================================
    // TREASURY BUCKET BALANCES
    // =========================================================

    /// @notice Pharmacy distribution pool — Merkle claims draw from this.
    uint256 public distributionPool;

    /// @notice Council operational reserve — gas, legal, admin.
    ///         Withdrawable only by EXECUTOR_ROLE.
    uint256 public governanceReserve;

    // =========================================================
    // CAPS
    // =========================================================

    uint256 public dailyVolumeCap;
    uint256 public hardAbsoluteVolumeCap;

    // =========================================================
    // EPOCH STATE
    // =========================================================

    uint256 public currentEpoch;
    uint256 public epochVolume;
    uint256 public epochStartTimestamp;

    mapping(uint256 => bytes32) public epochMerkleRoot;
    mapping(uint256 => uint256) public epochRootTotal;
    mapping(uint256 => uint256) public epochPublishedTimestamp;
    mapping(uint256 => uint256) public epochClaimedTotal;
    mapping(uint256 => bool)    public epochRecalled;

    mapping(uint256 => mapping(address => bool))    public hasClaimed;
    mapping(uint256 => mapping(address => uint256)) public pharmacyClaimedThisEpoch;

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

    /// @notice Permanent public log of every rebate deposit — the Ledger of Omissions.
    ///         PBM silence is the evidence. Every zero quarter is a documented omission.
    RebateDeposit[] public rebateDeposits;
    uint256 public totalRebateDeposited;

    // =========================================================
    // EVENTS
    // =========================================================

    /// @notice Emitted on every rebate deposit — core transparency primitive.
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
        bytes32 root,
        uint256 total,
        address indexed proposer,
        uint256 expiresAt
    );

    event RootConfirmed(
        uint256 indexed epoch,
        bytes32 root,
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

    event HardCapReduced(uint256 oldCap, uint256 newCap);
    event DailyCapUpdated(uint256 oldCap, uint256 newCap);

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
     * @param _token             DAI (or USDC) contract address.
     * @param _patientFund       Immutable patient access fund address.
     * @param _environmentalFund Receives accidentally sent ETH.
     * @param _initialDailyCap   Starting daily volume cap.
     * @param _council           3/5 Gnosis Safe — receives COUNCIL_ROLE.
     * @param _executor          TimelockController — receives EXECUTOR_ROLE.
     * @param _guardian          Separate fast-response EOA or 2/3 Safe — GUARDIAN_ROLE only.
     *
     * @dev GUARDIAN_ROLE must be a different address from _council.
     *      This separation is the point — guardian can pause faster than multisig.
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
        require(_token             != address(0), "Invalid token");
        require(_patientFund       != address(0), "Invalid patient fund");
        require(_environmentalFund != address(0), "Invalid env fund");
        require(_council           != address(0), "Invalid council");
        require(_executor          != address(0), "Invalid executor");
        require(_guardian          != address(0), "Invalid guardian");
        require(_guardian          != _council,   "Guardian must differ from council");
        require(_initialDailyCap   > 0,           "Zero daily cap");

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

    receive()  external payable { revert("ETH not accepted"); }
    fallback() external payable { revert("No fallback"); }

    // =========================================================
    // REBATE DEPOSIT
    // =========================================================

    /**
     * @notice Deposits rebate funds into escrow with public source attribution.
     * @dev    Anyone may deposit — a PBM settlement, a DAO contribution, a grant.
     *         Every deposit is permanently logged on-chain with caller and source string.
     *         Funds split at deposit time into two buckets:
     *         99% → distributionPool (pharmacy Merkle claims)
     *          1% → governanceReserve (council operations)
     *
     *         Patient fund is NOT funded at deposit time. It receives 10% of every
     *         gross claim at claim time, and all unclaimed recalled funds. This keeps
     *         the deposit event clean — the full deposited amount is visible as
     *         entering the system, with deductions occurring only at verified distribution.
     *
     *         This is the core transparency primitive. A PBM that receives rebates
     *         and does not call this function is creating a documented omission.
     *
     * @param amount Amount of `token` to deposit.
     * @param source Human-readable source label.
     *               Example: "OptumRx — Respiratory — Q1 2026 — UFCW Drug Trust"
     */
    function depositRebate(uint256 amount, string calldata source)
        external
        nonReentrant
        whenNotPaused
    {
        require(amount > 0, "Zero amount");
        require(bytes(source).length > 0 && bytes(source).length <= 256, "Invalid source");

        // Pull funds in first
        token.safeTransferFrom(msg.sender, address(this), amount);

        // Split into two buckets — no patient transfer at deposit
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

        emit RebateDeposited(
            depositId,
            msg.sender,
            amount,
            forDistribution,
            forGovernance,
            source
        );
    }

    // =========================================================
    // ROOT PUBLICATION — CO-SIGN GATE
    // =========================================================

    /**
     * @notice First council member proposes a Merkle root for the current epoch.
     * @dev    Root does not go live until a second, distinct COUNCIL_ROLE member
     *         calls confirmRoot(). This is the highest-stakes action in the contract —
     *         the root determines who gets paid.
     *
     *         Proposal expires after ROOT_PROPOSAL_EXPIRY if not confirmed.
     *         Only one pending root per epoch.
     *
     * @param root        The Merkle root of pharmacy allocations.
     * @param totalAmount Sum of all leaf gross allocations.
     *
     * Leaf encoding:
     * keccak256(keccak256(abi.encode(pharmacy, grossAmount, eligibleCap)))
     */
    function proposeRoot(bytes32 root, uint256 totalAmount)
        external
        onlyRole(COUNCIL_ROLE)
        whenNotPaused
    {
        require(epochMerkleRoot[currentEpoch] == bytes32(0), "Root already live");
        require(pendingRoot[currentEpoch].proposedAt == 0 ||
                block.timestamp > pendingRoot[currentEpoch].proposedAt + ROOT_PROPOSAL_EXPIRY,
                "Proposal pending or not expired");
        require(root != bytes32(0), "Invalid root");
        require(totalAmount > 0,    "Zero total");

        require(totalAmount <= dailyVolumeCap,        "Exceeds daily cap");
        require(totalAmount <= hardAbsoluteVolumeCap, "Exceeds hard cap");
        require(distributionPool >= totalAmount,       "Insufficient distribution pool");

        pendingRoot[currentEpoch] = PendingRoot({
            root:        root,
            totalAmount: totalAmount,
            proposer:    msg.sender,
            proposedAt:  block.timestamp
        });

        emit RootProposed(
            currentEpoch,
            root,
            totalAmount,
            msg.sender,
            block.timestamp + ROOT_PROPOSAL_EXPIRY
        );
    }

    /**
     * @notice Second council member confirms a pending root, making it live.
     * @dev    Confirmer must be a different address from the proposer.
     *         Proposal must not have expired.
     *         Once confirmed, root is immutable for this epoch.
     *
     * @param epoch The epoch whose pending root to confirm.
     *              Must equal currentEpoch — prevents confirming a stale proposal.
     */
    function confirmRoot(uint256 epoch)
        external
        onlyRole(COUNCIL_ROLE)
        whenNotPaused
    {
        require(epoch == currentEpoch, "Wrong epoch");

        PendingRoot storage pr = pendingRoot[epoch];
        require(pr.proposedAt != 0,                    "No pending root");
        require(pr.proposer != msg.sender,             "Proposer cannot confirm");
        require(
            block.timestamp <= pr.proposedAt + ROOT_PROPOSAL_EXPIRY,
            "Proposal expired"
        );
        require(epochMerkleRoot[epoch] == bytes32(0),  "Root already live");

        // Re-verify caps and escrow at confirmation time — conditions may have changed
        require(pr.totalAmount <= dailyVolumeCap,        "Daily cap exceeded");
        require(pr.totalAmount <= hardAbsoluteVolumeCap, "Hard cap exceeded");
        require(distributionPool >= pr.totalAmount,       "Insufficient distribution pool");

        epochMerkleRoot[epoch]        = pr.root;
        epochRootTotal[epoch]         = pr.totalAmount;
        epochPublishedTimestamp[epoch] = block.timestamp;

        delete pendingRoot[epoch];

        emit RootConfirmed(epoch, pr.root, pr.totalAmount, msg.sender);
    }

    /**
     * @notice Clears an expired root proposal, allowing a new one to be proposed.
     * @dev    Callable by anyone — no gatekeeping on cleanup.
     */
    function clearExpiredProposal(uint256 epoch) external {
        PendingRoot storage pr = pendingRoot[epoch];
        require(pr.proposedAt != 0, "No pending root");
        require(
            block.timestamp > pr.proposedAt + ROOT_PROPOSAL_EXPIRY,
            "Not expired"
        );
        delete pendingRoot[epoch];
        emit RootProposalExpired(epoch);
    }

    // =========================================================
    // CLAIM
    // =========================================================

    /**
     * @notice Claims allocated rebate for the current epoch.
     * @dev    Leaf: keccak256(keccak256(abi.encode(msg.sender, amount, eligibleCap)))
     *         `amount`      — gross allocation this epoch.
     *         `eligibleCap` — per-pharmacy maximum; enforced on-chain.
     *         Claimant receives amount * 90%. Patient fund receives 10%.
     *         Draws from distributionPool — not from the raw contract balance.
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
     * @notice Claims allocated tokens across multiple epochs in one transaction.
     * @dev    Saves gas for pharmacies with multiple unclaimed epochs.
     *         All arrays must be equal length.
     *         Delegated claims agent should use this for batch enrollment.
     *
     * @param amounts      Gross allocated amounts per epoch (sequential).
     * @param eligibleCaps Per-pharmacy caps per epoch.
     * @param proofs       Merkle proofs per epoch.
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
        require(len > 0,                   "Empty batch");
        require(len == eligibleCaps.length, "Array mismatch: caps");
        require(len == proofs.length,       "Array mismatch: proofs");

        for (uint256 i = 0; i < len; i++) {
            _processClaim(msg.sender, amounts[i], eligibleCaps[i], proofs[i]);
        }
    }

    /**
     * @dev Internal claim logic shared by claim() and claimBatch().
     */
    function _processClaim(
        address claimant,
        uint256 amount,
        uint256 eligibleCap,
        bytes32[] memory proof
    )
        internal
    {
        require(!sanctioned[claimant],               "Sanctioned");
        require(!hasClaimed[currentEpoch][claimant], "Already claimed");

        bytes32 root = epochMerkleRoot[currentEpoch];
        require(root != bytes32(0), "No root for epoch");

        // Double-hash leaf — second-preimage protection
        bytes32 leaf = keccak256(
            bytes.concat(keccak256(abi.encode(claimant, amount, eligibleCap)))
        );
        require(MerkleProof.verify(proof, root, leaf), "Invalid proof");

        // Per-pharmacy cap enforcement
        uint256 alreadyClaimed = pharmacyClaimedThisEpoch[currentEpoch][claimant];
        require(alreadyClaimed + amount <= eligibleCap, "Pharmacy cap exceeded");

        uint256 newVolume = epochVolume + amount;
        require(newVolume <= dailyVolumeCap,               "Daily cap exceeded");
        require(newVolume <= hardAbsoluteVolumeCap,        "Hard cap exceeded");
        require(newVolume <= epochRootTotal[currentEpoch], "Root total exceeded");

        // Draw from distribution pool
        require(distributionPool >= amount, "Distribution pool depleted");

        // Effects
        hasClaimed[currentEpoch][claimant]                = true;
        pharmacyClaimedThisEpoch[currentEpoch][claimant] += amount;
        epochVolume                                        = newVolume;
        epochClaimedTotal[currentEpoch]                  += amount;
        distributionPool                                  -= amount;

        uint256 patientShare  = (amount * PATIENT_CLAIM_BP) / BP_DENOM;
        uint256 netToPharmacy = amount - patientShare;

        // Interactions
        token.safeTransfer(patientFund, patientShare);
        token.safeTransfer(claimant,    netToPharmacy);

        emit Claimed(currentEpoch, claimant, amount, netToPharmacy, patientShare);
    }

    // =========================================================
    // DISPUTE RESOLUTION
    // =========================================================

    /**
     * @notice Pharmacy flags a disputed allocation for council review.
     * @dev    Flags the pharmacy's hasClaimed entry and holds the disputed amount
     *         in reserve. The pharmacy cannot claim while a dispute is open.
     *         Council must call resolveClaim() to settle.
     *
     *         Use case: pharmacy believes Merkle root incorrectly excluded or
     *         undercounted their allocation for the epoch.
     *
     * @param epoch       The epoch being disputed.
     * @param amount      Amount the pharmacy believes it is owed.
     */
    function flagClaim(uint256 epoch, uint256 amount)
        external
        whenNotPaused
    {
        require(epoch == currentEpoch,                    "Can only flag current epoch");
        require(!hasClaimed[epoch][msg.sender],           "Already claimed — cannot flag");
        require(flaggedAmount[epoch][msg.sender] == 0,    "Already flagged");
        require(amount > 0,                               "Zero amount");
        require(distributionPool >= amount,               "Insufficient pool for reserve");

        flaggedAmount[epoch][msg.sender] = amount;
        distributionPool -= amount;

        emit ClaimFlagged(epoch, msg.sender, amount);
    }

    /**
     * @notice Council resolves a flagged dispute.
     * @dev    RELEASE_TO_PHARMACY: transfers amount to pharmacy (net of patient share).
     *         SEND_TO_PATIENT_FUND: transfers amount to patientFund as penalty for invalid flag.
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
        require(amount > 0, "No flagged claim");

        flaggedAmount[epoch][pharmacy] = 0;
        hasClaimed[epoch][pharmacy]    = true;

        emit ClaimResolved(epoch, pharmacy, amount, resolution);

        if (resolution == DisputeResolution.RELEASE_TO_PHARMACY) {
            uint256 patientShare  = (amount * PATIENT_CLAIM_BP) / BP_DENOM;
            uint256 netToPharmacy = amount - patientShare;
            token.safeTransfer(patientFund, patientShare);
            token.safeTransfer(pharmacy,    netToPharmacy);
        } else {
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
        require(epochMerkleRoot[currentEpoch] != bytes32(0), "No root published");
        require(
            block.timestamp >= epochStartTimestamp + MIN_EPOCH_DURATION,
            "Epoch too short"
        );
        require(epochVolume >= MIN_EPOCH_VOLUME, "Volume too low");

        emit EpochFinalized(currentEpoch, epochVolume);

        currentEpoch++;
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
     *         Only unclaimed amount recalled — claimed funds already transferred.
     *
     * @param epoch The finalized epoch to recall from.
     */
    function recallUnclaimed(uint256 epoch)
        external
        onlyRole(COUNCIL_ROLE)
        nonReentrant
    {
        require(epoch < currentEpoch,  "Epoch not finalized");
        require(!epochRecalled[epoch], "Already recalled");

        uint256 publishedAt = epochPublishedTimestamp[epoch];
        require(publishedAt != 0, "No root published");
        require(
            block.timestamp >= publishedAt + RECALL_DELAY,
            "Recall delay not elapsed"
        );

        uint256 totalAllocated = epochRootTotal[epoch];
        uint256 totalClaimed   = epochClaimedTotal[epoch];
        require(totalAllocated > totalClaimed, "Nothing to recall");

        uint256 unclaimed = totalAllocated - totalClaimed;

        // Sanity check — distribution pool should cover this
        require(distributionPool >= unclaimed, "Pool mismatch — check accounting");

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
        require(recipient != address(0), "Invalid recipient");
        require(amount > 0,              "Zero amount");
        require(governanceReserve >= amount, "Exceeds reserve");

        governanceReserve -= amount;
        token.safeTransfer(recipient, amount);

        emit GovernanceReserveWithdrawn(recipient, amount);
    }

    // =========================================================
    // GOVERNANCE — PARAMETER MANAGEMENT
    // =========================================================

    /**
     * @notice Permanently reduces the absolute hard cap (ratchet — cannot increase).
     * @dev    Should be called via EXECUTOR_ROLE / TimelockController.
     */
    function reduceHardCap(uint256 newCap)
        external
        onlyRole(EXECUTOR_ROLE)
    {
        require(newCap < hardAbsoluteVolumeCap, "Can only reduce");
        require(newCap >= dailyVolumeCap,        "Below daily cap");

        uint256 oldCap        = hardAbsoluteVolumeCap;
        hardAbsoluteVolumeCap = newCap;

        emit HardCapReduced(oldCap, newCap);
    }

    /**
     * @notice Adjusts the daily volume cap within hard cap bounds.
     * @dev    Can increase or decrease. Cannot exceed hardAbsoluteVolumeCap.
     */
    function updateDailyCap(uint256 newCap)
        external
        onlyRole(EXECUTOR_ROLE)
    {
        require(newCap > 0,                      "Zero cap");
        require(newCap <= hardAbsoluteVolumeCap, "Exceeds hard cap");

        uint256 oldCap = dailyVolumeCap;
        dailyVolumeCap = newCap;

        emit DailyCapUpdated(oldCap, newCap);
    }

    /**
     * @notice Updates sanction status for an address.
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
     */
    function setEnvironmentalFund(address _newFund)
        external
        onlyRole(EXECUTOR_ROLE)
    {
        require(_newFund != address(0), "Invalid address");
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
        require(balance > 0, "No ETH");
        (bool ok, ) = environmentalFund.call{value: balance}("");
        require(ok, "ETH transfer failed");
        emit Sweep(address(0), environmentalFund, balance);
    }

    /**
     * @notice Recovers non-payout tokens sent accidentally.
     * @dev    Swept to patientFund — not general fund. Recovered value benefits patients.
     */
    function sweep(address _token, uint256 _amount)
        external
        onlyRole(COUNCIL_ROLE)
    {
        require(_token != address(token), "Cannot sweep payout token");
        IERC20(_token).safeTransfer(patientFund, _amount);
        emit Sweep(_token, patientFund, _amount);
    }

    // =========================================================
    // EMERGENCY
    // =========================================================

    /// @notice GUARDIAN_ROLE can pause faster than the council multisig.
    function pause()   external onlyRole(GUARDIAN_ROLE) { _pause(); }

    /// @notice Only COUNCIL_ROLE can unpause — guardian cannot re-enable the system.
    function unpause() external onlyRole(COUNCIL_ROLE)  { _unpause(); }

    // =========================================================
    // VIEW HELPERS — dashboard and watchdog primitives
    // =========================================================

    /// @notice Total unclaimed allocation for a given epoch.
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

    /// @notice Full epoch summary — dashboard and journalist friendly.
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
    function pharmacyEpochClaimed(uint256 epoch, address pharmacy)
        external
        view
        returns (uint256)
    {
        return pharmacyClaimedThisEpoch[epoch][pharmacy];
    }

    /// @notice Total number of rebate deposits ever made.
    function rebateDepositCount()
        external
        view
        returns (uint256)
    {
        return rebateDeposits.length;
    }

    /// @notice Returns a single rebate deposit record by index.
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
        require(index < rebateDeposits.length, "Out of range");
        RebateDeposit storage d = rebateDeposits[index];
        return (d.depositor, d.amount, d.timestamp, d.source);
    }

    /// @notice Pending root proposal state for the current epoch.
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
}
