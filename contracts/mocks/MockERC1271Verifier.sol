// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/interfaces/IERC1271.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract MockERC1271Verifier is IERC1271 {
    using ECDSA for bytes32;

    address public signer;
    bool public approvalsEnabled = true;

    constructor(address _signer) {
        signer = _signer;
    }

    function setSigner(address _signer) external {
        signer = _signer;
    }

    function setApprovalsEnabled(bool _enabled) external {
        approvalsEnabled = _enabled;
    }

    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4) {
        if (!approvalsEnabled) {
            return 0xffffffff;
        }

        return hash.recover(signature) == signer ? IERC1271.isValidSignature.selector : bytes4(0xffffffff);
    }
}
