// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockFeeOnTransferERC20 is ERC20 {
    uint256 public constant FEE_BASIS_POINTS = 100;
    uint256 public constant BASIS_POINTS_DENOMINATOR = 10_000;

    constructor() ERC20("Mock Fee Token", "mFEE") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function _transfer(address from, address to, uint256 amount) internal override {
        uint256 fee = (amount * FEE_BASIS_POINTS) / BASIS_POINTS_DENOMINATOR;
        uint256 netAmount = amount - fee;

        if (fee > 0) {
            _burn(from, fee);
        }
        super._transfer(from, to, netAmount);
    }
}
