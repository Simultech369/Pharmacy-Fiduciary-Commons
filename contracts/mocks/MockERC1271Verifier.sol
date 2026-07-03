// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/interfaces/IERC1271.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract MockERC1271Verifier is IERC1271 {
    using ECDSA for bytes32;

    error InvalidAddress();

    bytes4 private constant INVALID_SIGNATURE = 0xffffffff;

    address public signer;
    bool public approvalsEnabled = true;

    event SignerUpdated(address indexed signer);
    event ApprovalsEnabledUpdated(bool enabled);

    constructor(address _signer) {
        if (_signer == address(0)) revert InvalidAddress();
        signer = _signer;
    }

    function setSigner(address _signer) external {
        if (_signer == address(0)) revert InvalidAddress();
        signer = _signer;
        emit SignerUpdated(_signer);
    }

    function setApprovalsEnabled(bool _enabled) external {
        approvalsEnabled = _enabled;
        emit ApprovalsEnabledUpdated(_enabled);
    }

    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4) {
        if (!approvalsEnabled) {
            return INVALID_SIGNATURE;
        }

        return hash.recover(signature) == signer ? IERC1271.isValidSignature.selector : INVALID_SIGNATURE;
    }
}
