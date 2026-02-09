"""
Token Metadata Fetcher

Fetches on-chain token balances and DEX info for agent context.
Following SCONE-bench approach of providing helpful metadata in prompt.
"""

import asyncio
from typing import Dict, List, Optional
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TokenMetadata:
    """Metadata about tokens in a contract."""
    native_balance: str = "0"
    native_balance_eth: float = 0.0
    top_token_balances: List[Dict] = None
    dex_pools: List[Dict] = None
    total_value_locked_usd: float = 0.0
    
    def __post_init__(self):
        if self.top_token_balances is None:
            self.top_token_balances = []
        if self.dex_pools is None:
            self.dex_pools = []


class TokenMetadataFetcher:
    """
    Fetches token metadata for contracts to enrich agent context.
    
    Provides:
    - Native token balance (ETH/BNB)
    - Top ERC20 token balances
    - Associated DEX pools
    - Total value locked
    """
    
    # Common tokens to check balances for
    COMMON_TOKENS = {
        "ethereum": [
            ("WETH", "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
            ("USDC", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
            ("USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7"),
            ("DAI", "0x6B175474E89094C44Da98b954EesaCDFC79008F0"),
        ],
        "bsc": [
            ("WBNB", "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"),
            ("BUSD", "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56"),
            ("USDT", "0x55d398326f99059fF775485246999027B3197955"),
        ],
    }
    
    def __init__(self, rpc_url: str = "http://localhost:8545"):
        self.rpc_url = rpc_url
        
    async def get_contract_metadata(
        self,
        contract_address: str,
        chain: str = "ethereum"
    ) -> TokenMetadata:
        """
        Get token metadata for a contract.
        
        Args:
            contract_address: Contract to analyze
            chain: Blockchain (ethereum, bsc)
            
        Returns:
            TokenMetadata with balances and DEX info
        """
        import subprocess
        
        metadata = TokenMetadata()
        
        try:
            # Get native balance
            result = subprocess.run(
                ["cast", "balance", contract_address, "--rpc-url", self.rpc_url],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                balance_wei = result.stdout.strip()
                metadata.native_balance = balance_wei
                try:
                    metadata.native_balance_eth = int(balance_wei) / 1e18
                except:
                    pass
            
            # Check common token balances
            tokens = self.COMMON_TOKENS.get(chain, [])
            for token_name, token_addr in tokens[:4]:  # Check top 4 tokens
                try:
                    result = subprocess.run(
                        ["cast", "call", token_addr, 
                         "balanceOf(address)(uint256)", contract_address,
                         "--rpc-url", self.rpc_url],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if result.returncode == 0:
                        balance = result.stdout.strip()
                        if balance and int(balance) > 0:
                            metadata.top_token_balances.append({
                                "token": token_name,
                                "address": token_addr,
                                "balance": balance,
                                "balance_formatted": f"{int(balance) / 1e18:.4f}"
                            })
                except:
                    continue
                    
        except Exception as e:
            print(f"Error fetching metadata: {e}")
            
        return metadata
    
    def format_for_prompt(self, metadata: TokenMetadata) -> str:
        """
        Format metadata for injection into agent prompt.
        
        Returns:
            Formatted string for prompt context
        """
        lines = ["## 💰 ON-CHAIN METADATA"]
        
        # Native balance
        lines.append(f"- **Native Balance**: {metadata.native_balance_eth:.4f} ETH/BNB")
        
        # Token balances
        if metadata.top_token_balances:
            lines.append("- **Token Balances**:")
            for token in metadata.top_token_balances:
                lines.append(f"  - {token['token']}: {token['balance_formatted']}")
        
        # DEX pools
        if metadata.dex_pools:
            lines.append("- **DEX Pools**:")
            for pool in metadata.dex_pools:
                lines.append(f"  - {pool.get('name', 'Unknown')}: ${pool.get('liquidity', 0):,.0f}")
        
        # Total value
        if metadata.total_value_locked_usd > 0:
            lines.append(f"- **Total Value Locked**: ${metadata.total_value_locked_usd:,.2f}")
        
        return "\n".join(lines)


# Convenience function
async def get_metadata_for_prompt(contract_address: str, chain: str = "ethereum") -> str:
    """Quick way to get formatted metadata for prompt."""
    fetcher = TokenMetadataFetcher()
    metadata = await fetcher.get_contract_metadata(contract_address, chain)
    return fetcher.format_for_prompt(metadata)
