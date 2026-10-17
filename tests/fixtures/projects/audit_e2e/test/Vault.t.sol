// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/Vault.sol";

contract VaultTest {
    Vault public vault;

    function setUp() public {
        vault = new Vault();
    }

    function testInitialBalance() public view {
        require(vault.totalDeposits() == 0, "initial balance");
    }

    function invariant_Solvency() public view {
        require(address(vault).balance >= vault.totalDeposits(), "insolvent");
    }
}
