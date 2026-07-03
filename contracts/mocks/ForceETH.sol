// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract ForceETH {
    constructor() payable {}

    function forceSend(address payable target) external {
        selfdestruct(target);
    }
}
