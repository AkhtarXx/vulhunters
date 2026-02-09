// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableBank
 * @notice A deliberately vulnerable contract for testing VulnHunter
 * @dev Contains multiple vulnerabilities for demonstration
 */
contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    // VULNERABILITY 1: Reentrancy
    // The balance is updated AFTER the external call
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Vulnerable: external call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // State update after external call = reentrancy vulnerability
        balances[msg.sender] -= amount;
    }
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    // VULNERABILITY 2: Missing access control
    // Anyone can call this function and drain all funds
    function emergencyWithdraw() external {
        // Missing: require(msg.sender == owner)
        payable(msg.sender).transfer(address(this).balance);
    }
    
    // VULNERABILITY 3: Unchecked return value
    function unsafeTransfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        
        // Vulnerability: not checking return value
        payable(to).send(amount);
    }
    
    // VULNERABILITY 4: Integer overflow (in unchecked block)
    function addReward(address user, uint256 reward) external {
        unchecked {
            // This can overflow in unchecked block
            balances[user] += reward;
        }
    }
    
    // VULNERABILITY 5: Denial of Service
    // If receiver is a contract that reverts, this blocks everyone
    address[] public receivers;
    
    function addReceiver(address receiver) external {
        receivers.push(receiver);
    }
    
    function distributeRewards() external {
        uint256 share = address(this).balance / receivers.length;
        for (uint256 i = 0; i < receivers.length; i++) {
            // If one fails, all fail
            payable(receivers[i]).transfer(share);
        }
    }
    
    receive() external payable {}
}
