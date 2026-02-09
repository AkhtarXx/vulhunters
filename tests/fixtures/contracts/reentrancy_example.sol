// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ReentrancyExample
 * @dev Classic reentrancy vulnerability patterns
 */

// Pattern 1: ETH reentrancy via call
contract EthReentrancy {
    mapping(address => uint256) public balances;
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    // VULNERABLE: Classic ETH reentrancy
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // External call BEFORE state update
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // State update AFTER call - can be re-entered!
        balances[msg.sender] -= amount;
    }
}

// Pattern 2: ERC20 reentrancy via token callback
interface IERC20Callback {
    function onTokenReceived(address from, uint256 amount) external;
}

contract TokenReentrancy {
    mapping(address => uint256) public balances;
    
    function deposit(uint256 amount) external {
        balances[msg.sender] += amount;
    }
    
    // VULNERABLE: Callback reentrancy
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Callback BEFORE state update
        if (isContract(msg.sender)) {
            IERC20Callback(msg.sender).onTokenReceived(address(this), amount);
        }
        
        balances[msg.sender] -= amount;
    }
    
    function isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
}

// Pattern 3: Cross-function reentrancy
contract CrossFunctionReentrancy {
    mapping(address => uint256) public balances;
    mapping(address => bool) public hasWithdrawn;
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    // Function A: vulnerable external call
    function withdrawAll() external {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");
        
        (bool success,) = msg.sender.call{value: balance}("");
        require(success);
        
        hasWithdrawn[msg.sender] = true;
        balances[msg.sender] = 0;
    }
    
    // Function B: can be called during reentrancy
    // Before balances is set to 0, attacker can call this
    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}

// Pattern 4: Read-only reentrancy
interface IPool {
    function getSharePrice() external view returns (uint256);
}

contract ReadOnlyReentrancy {
    IPool public pool;
    mapping(address => uint256) public deposits;
    
    constructor(address _pool) {
        pool = IPool(_pool);
    }
    
    // Uses pool's share price which can be manipulated during callback
    function withdraw(uint256 shares) external {
        uint256 value = shares * pool.getSharePrice() / 1e18;
        
        // During this call, attacker manipulates pool's share price
        (bool success,) = msg.sender.call{value: value}("");
        require(success);
        
        deposits[msg.sender] -= shares;
    }
}

// SAFE: Using checks-effects-interactions pattern
contract SafeWithdraw {
    mapping(address => uint256) public balances;
    bool private locked;
    
    modifier noReentrant() {
        require(!locked, "Reentrancy");
        locked = true;
        _;
        locked = false;
    }
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    // SAFE: State update BEFORE external call
    function withdraw(uint256 amount) external noReentrant {
        require(balances[msg.sender] >= amount, "Insufficient");
        
        // State update FIRST
        balances[msg.sender] -= amount;
        
        // External call LAST
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}
