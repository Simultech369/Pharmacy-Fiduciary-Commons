// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title  PharmacyMutualCredit
 * @author Pharmacy Fiduciary Commons
 * @notice Zero-sum mutual credit clearing ledger and community health voucher engine.
 *         Stabilizes independent pharmacy liquidity during reimbursement delays.
 */
contract PharmacyMutualCredit is AccessControl, Pausable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    bytes32 public constant COUNCIL_ROLE = keccak256("COUNCIL_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    uint256 public constant ISSUER_GRACE_PERIOD = 30 days;
    uint256 public constant MAX_VOUCHER_RELEASE_BATCH = 100;
    uint256 public constant MAX_VOUCHER_LIFETIME = 90 days;

    struct Voucher {
        address issuer;
        address recipient;
        uint256 amount;
        bool redeemed;
        uint256 expiry;
        uint256 createdAt;
    }

    // Zero-sum balance ledger. The sum of all balances in the system is always 0.
    mapping(address => int256) public balances;
    
    // Limits how far below zero a participant's balance can go.
    mapping(address => uint256) public creditLimits;
    
    mapping(address => bool) public registered;
    mapping(address => bool) public authorizedIssuers;
    mapping(address => uint256) public issuerDeregistrationTimestamp;

    // Credit capacity committed to valid, unexpired vouchers but not yet settled.
    mapping(address => uint256) public reservedVoucherCredit;

    // voucherId -> Voucher details
    mapping(bytes32 => Voucher) public vouchers;
    mapping(bytes32 => bool) public voucherReservationReleased;

    // =========================================================
    // EVENTS
    // =========================================================
    event ParticipantRegistered(address indexed participant, uint256 creditLimit);
    event CreditLimitUpdated(address indexed participant, uint256 newLimit);
    event IssuerStatusUpdated(address indexed issuer, bool status);
    event CreditTransferred(address indexed sender, address indexed recipient, uint256 amount);
    event VoucherCreated(bytes32 indexed voucherId, address indexed issuer, address indexed recipient, uint256 amount, uint256 expiry);
    event VoucherRedeemed(bytes32 indexed voucherId, address indexed redeemer, address indexed issuer, uint256 amount);
    event VoucherReservationReleased(bytes32 indexed voucherId, address indexed issuer, uint256 amount);
    event Sweep(address indexed tokenAddr, address indexed recipient, uint256 amount);

    // =========================================================
    // CUSTOM ERRORS
    // =========================================================
    error NotRegistered();
    error AlreadyRegistered();
    error CreditLimitExceeded();
    error ZeroAmount();
    error VoucherExpired();
    error VoucherAlreadyRedeemed();
    error VoucherDoesNotExist();
    error Unauthorized();
    error InvalidAddress();
    error VoucherNotExpired();
    error GuardianMustDifferFromCouncil();
    error BatchTooLarge();
    error VoucherExpiryTooLong();
    error GovernanceRoleSeparationViolation();

    // =========================================================
    // CONSTRUCTOR
    // =========================================================
    constructor(address _council, address _guardian) {
        if (_council == address(0)) revert InvalidAddress();
        if (_guardian == address(0)) revert InvalidAddress();
        if (_guardian == _council) revert GuardianMustDifferFromCouncil();
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

    // =========================================================
    // GOVERNANCE SETTERS
    // =========================================================
    
    function registerParticipant(address participant, uint256 initialCreditLimit)
        external
        onlyRole(COUNCIL_ROLE)
        whenNotPaused
    {
        if (participant == address(0)) revert InvalidAddress();
        if (registered[participant]) revert AlreadyRegistered();

        registered[participant] = true;
        creditLimits[participant] = initialCreditLimit;

        emit ParticipantRegistered(participant, initialCreditLimit);
    }

    function updateCreditLimit(address participant, uint256 newCreditLimit)
        external
        onlyRole(COUNCIL_ROLE)
        whenNotPaused
    {
        if (!registered[participant]) revert NotRegistered();
        if (!_capacityCovers(participant, 0, newCreditLimit)) revert CreditLimitExceeded();
        
        creditLimits[participant] = newCreditLimit;
        emit CreditLimitUpdated(participant, newCreditLimit);
    }

    function updateIssuerStatus(address issuer, bool status)
        external
        onlyRole(COUNCIL_ROLE)
        whenNotPaused
    {
        if (issuer == address(0)) revert InvalidAddress();
        if (!registered[issuer]) revert NotRegistered();
        bool wasAuthorized = authorizedIssuers[issuer];
        authorizedIssuers[issuer] = status;
        if (status) {
            issuerDeregistrationTimestamp[issuer] = 0;
        } else if (wasAuthorized) {
            issuerDeregistrationTimestamp[issuer] = block.timestamp;
        }
        emit IssuerStatusUpdated(issuer, status);
    }

    // =========================================================
    // MUTUAL CREDIT TRANSFERS
    // =========================================================

    /**
     * @notice Transfer credit from caller to recipient.
     * @dev    Enforces that the sender's balance does not drop below their negative creditLimit.
     */
    function transferCredit(address recipient, uint256 amount) external whenNotPaused {
        if (!registered[msg.sender]) revert NotRegistered();
        if (!registered[recipient]) revert NotRegistered();
        if (amount == 0) revert ZeroAmount();

        if (!_capacityCovers(msg.sender, amount, creditLimits[msg.sender])) revert CreditLimitExceeded();

        balances[msg.sender] -= int256(amount);
        balances[recipient] += int256(amount);

        emit CreditTransferred(msg.sender, recipient, amount);
    }

    // =========================================================
    // VOUCHER SYSTEM
    // =========================================================

    /**
     * @notice Registers a new voucher that can be redeemed at a pharmacy.
     */
    function createVoucher(bytes32 voucherId, address recipient, uint256 amount, uint256 expiry) external whenNotPaused {
        if (!registered[msg.sender]) revert NotRegistered();
        if (!authorizedIssuers[msg.sender]) revert Unauthorized();
        if (recipient == address(0)) revert InvalidAddress();
        if (!registered[recipient]) revert NotRegistered();
        if (vouchers[voucherId].issuer != address(0)) revert AlreadyRegistered();
        if (amount == 0) revert ZeroAmount();
        if (expiry <= block.timestamp) revert VoucherExpired();
        if (expiry > block.timestamp + MAX_VOUCHER_LIFETIME) revert VoucherExpiryTooLong();
        if (!_capacityCovers(msg.sender, amount, creditLimits[msg.sender])) revert CreditLimitExceeded();

        reservedVoucherCredit[msg.sender] += amount;
        vouchers[voucherId] = Voucher({
            issuer: msg.sender,
            recipient: recipient,
            amount: amount,
            redeemed: false,
            expiry: expiry,
            createdAt: block.timestamp
        });

        emit VoucherCreated(voucherId, msg.sender, recipient, amount, expiry);
    }

    /**
     * @notice Redeems a registered voucher, debiting the issuer and crediting the pharmacy.
     * @dev    Creation reserves issuer capacity, so valid vouchers clear without a second credit decision.
     */
    function redeemVoucher(bytes32 voucherId) external whenNotPaused {
        if (!registered[msg.sender]) revert NotRegistered();
        
        Voucher storage v = vouchers[voucherId];
        if (v.issuer == address(0)) revert VoucherDoesNotExist();
        if (v.redeemed) revert VoucherAlreadyRedeemed();
        if (block.timestamp > v.expiry) revert VoucherExpired();
        if (voucherReservationReleased[voucherId]) revert VoucherExpired();
        if (msg.sender != v.recipient) revert Unauthorized();

        address issuer = v.issuer;
        uint256 amount = v.amount;

        if (!registered[issuer]) revert NotRegistered();
        if (!authorizedIssuers[issuer]) {
            uint256 deregTime = issuerDeregistrationTimestamp[issuer];
            if (
                deregTime == 0 ||
                v.createdAt >= deregTime ||
                block.timestamp > deregTime + ISSUER_GRACE_PERIOD
            ) {
                revert Unauthorized();
            }
        }

        v.redeemed = true;
        reservedVoucherCredit[issuer] -= amount;
        voucherReservationReleased[voucherId] = true;
        balances[issuer] -= int256(amount);
        balances[msg.sender] += int256(amount);

        emit VoucherRedeemed(voucherId, msg.sender, issuer, amount);
    }

    /**
     * @notice Releases capacity reserved by an expired, unredeemed voucher.
     * @dev Anyone may perform expiry cleanup; no value is transferred.
     */
    function releaseExpiredVoucher(bytes32 voucherId) external whenNotPaused {
        Voucher storage v = vouchers[voucherId];
        if (v.issuer == address(0)) revert VoucherDoesNotExist();
        if (v.redeemed) revert VoucherAlreadyRedeemed();
        if (block.timestamp <= v.expiry) revert VoucherNotExpired();
        if (voucherReservationReleased[voucherId]) revert VoucherExpired();

        voucherReservationReleased[voucherId] = true;
        reservedVoucherCredit[v.issuer] -= v.amount;
        emit VoucherReservationReleased(voucherId, v.issuer, v.amount);
    }

    /**
     * @notice Releases capacity reserved by multiple expired, unredeemed vouchers in batch.
     * @dev Anyone may perform expiry cleanup; no value is transferred.
     */
    function releaseExpiredVouchersBatch(bytes32[] calldata voucherIds) external whenNotPaused {
        uint256 count = voucherIds.length;
        if (count > MAX_VOUCHER_RELEASE_BATCH) revert BatchTooLarge();

        for (uint256 i = 0; i < count; i++) {
            bytes32 voucherId = voucherIds[i];
            Voucher storage v = vouchers[voucherId];
            if (v.issuer == address(0)) revert VoucherDoesNotExist();
            if (v.redeemed) revert VoucherAlreadyRedeemed();
            if (block.timestamp <= v.expiry) revert VoucherNotExpired();
            if (voucherReservationReleased[voucherId]) revert VoucherExpired();

            voucherReservationReleased[voucherId] = true;
            reservedVoucherCredit[v.issuer] -= v.amount;
            emit VoucherReservationReleased(voucherId, v.issuer, v.amount);
        }
    }

    function _capacityCovers(address participant, uint256 additional, uint256 limit)
        internal
        view
        returns (bool)
    {
        if (
            additional > uint256(type(int256).max) ||
            reservedVoucherCredit[participant] > uint256(type(int256).max) - additional ||
            limit > uint256(type(int256).max)
        ) {
            return false;
        }

        int256 committed = int256(reservedVoucherCredit[participant] + additional);
        // Rewrite `balance - committed >= -limit` to `balance >= committed - limit` to prevent underflow.
        // Since both committed and limit are non-negative int256 values, committed - limit is safe from overflow/underflow.
        return balances[participant] >= committed - int256(limit);
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

    /**
     * @notice Recovers non-ledger ERC-20 tokens accidentally sent to this contract.
     */
    function sweep(address _token, uint256 _amount) external nonReentrant onlyRole(COUNCIL_ROLE) {
        if (_token == address(0)) revert InvalidAddress();
        if (_amount == 0) revert ZeroAmount();
        IERC20(_token).safeTransfer(msg.sender, _amount);
        emit Sweep(_token, msg.sender, _amount);
    }
}
