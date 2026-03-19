// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

// This file exists to ensure Hardhat compiles TimelockController into local artifacts
// so deployment scripts/tests can deploy it without relying on fully-qualified names.
import "@openzeppelin/contracts/governance/TimelockController.sol";

