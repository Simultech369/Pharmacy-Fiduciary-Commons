// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title  PharmacyMutualCredit
 * @author Pharmacy Fiduciary Commons
 * @notice Zero-sum mutual credit clearing ledger and community health voucher engine.
 *         Stabilizes independent pharmacy liquidity during reimbursement delays.
 */
contract PharmacyMutualCredit is AccessControl {

    bytes32 public constant COUNCIL_ROLE = keccak256("COUNCIL_ROLE");

    struct Voucher {
        address issuer;
        uint256 amount;
        bool redeemed;
        uint256 expiry;
    }

    // Zero-sum balance ledger. The sum of all balances in the system is always 0.
    mapping(address => int256) public balances;
    
    // Limits how far below zero a participant's balance can go.
    mapping(address => uint256) public creditLimits;
    
    mapping(address => bool) public registered;
    mapping(address => bool) public authorizedIssuers;

    // voucherId -> Voucher details
    mapping(bytes32 => Voucher) public vouchers;

    // =========================================================
    // EVENTS
    // =========================================================
    event ParticipantRegistered(address indexed participant, uint256 creditLimit);
    event CreditLimitUpdated(address indexed participant, uint256 newLimit);
    event IssuerStatusUpdated(address indexed issuer, bool status);
    event CreditTransferred(address indexed sender, address indexed recipient, uint256 amount);
    event VoucherCreated(bytes32 indexed voucherId, address indexed issuer, uint256 amount, uint256 expiry);
    event VoucherRedeemed(bytes32 indexed voucherId, address indexed redeemer, address indexed issuer, uint256 amount);

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

    // =========================================================
    // CONSTRUCTOR
    // =========================================================
    constructor(address _council) {
        if (_council == address(0)) revert InvalidAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, _council);
        _grantRole(COUNCIL_ROLE, _council);
    }

    // =========================================================
    // GOVERNANCE SETTERS
    // =========================================================
    
    function registerParticipant(address participant, uint256 initialCreditLimit)
        external
        onlyRole(COUNCIL_ROLE)
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
    {
        if (!registered[participant]) revert NotRegistered();
        
        creditLimits[participant] = newCreditLimit;
        emit CreditLimitUpdated(participant, newCreditLimit);
    }

    function updateIssuerStatus(address issuer, bool status)
        external
        onlyRole(COUNCIL_ROLE)
    {
        if (issuer == address(0)) revert InvalidAddress();
        if (!registered[issuer]) revert NotRegistered();
        
        authorizedIssuers[issuer] = status;
        emit IssuerStatusUpdated(issuer, status);
    }

    // =========================================================
    // MUTUAL CREDIT TRANSFERS
    // =========================================================

    /**
     * @notice Transfer credit from caller to recipient.
     * @dev    Enforces that the sender's balance does not drop below their negative creditLimit.
     */
    function transferCredit(address recipient, uint256 amount) external {
        if (!registered[msg.sender]) revert NotRegistered();
        if (!registered[recipient]) revert NotRegistered();
        if (amount == 0) revert ZeroAmount();

        int256 creditLimitVal = int256(creditLimits[msg.sender]);
        if (balances[msg.sender] - int256(amount) < -creditLimitVal) {
            revert CreditLimitExceeded();
        }

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
    function createVoucher(bytes32 voucherId, uint256 amount, uint256 expiry) external {
        if (!registered[msg.sender]) revert NotRegistered();
        if (!authorizedIssuers[msg.sender]) revert Unauthorized();
        if (vouchers[voucherId].issuer != address(0)) revert AlreadyRegistered();
        if (amount == 0) revert ZeroAmount();
        if (expiry <= block.timestamp) revert VoucherExpired();

        vouchers[voucherId] = Voucher({
            issuer: msg.sender,
            amount: amount,
            redeemed: false,
            expiry: expiry
        });

        emit VoucherCreated(voucherId, msg.sender, amount, expiry);
    }

    /**
     * @notice Redeems a registered voucher, debiting the issuer and crediting the pharmacy.
     * @dev    Enforces that the voucher is valid and that the issuer stays within their credit lines.
     */
    function redeemVoucher(bytes32 voucherId) external {
        if (!registered[msg.sender]) revert NotRegistered();
        
        Voucher storage v = vouchers[voucherId];
        if (v.issuer == address(0)) revert VoucherDoesNotExist();
        if (v.redeemed) revert VoucherAlreadyRedeemed();
        if (block.timestamp > v.expiry) revert VoucherExpired();

        address issuer = v.issuer;
        uint256 amount = v.amount;

        if (!registered[issuer]) revert NotRegistered();

        int256 creditLimitVal = int256(creditLimits[issuer]);
        if (balances[issuer] - int256(amount) < -creditLimitVal) {
            revert CreditLimitExceeded();
        }

        v.redeemed = true;
        balances[issuer] -= int256(amount);
        balances[msg.sender] += int256(amount);

        emit VoucherRedeemed(voucherId, msg.sender, issuer, amount);
    }
}
