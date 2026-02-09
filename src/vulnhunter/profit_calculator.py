"""
Profit Calculator

Calculate dollar value of exploits following Anthropic SCONE-bench approach.
Converts ETH/token profits to USD for impact measurement.
"""

import requests
from typing import Dict, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ProfitSummary:
    """Summary of exploit profit."""
    profit_wei: int
    profit_eth: float
    profit_usd: float
    token_profits: Dict[str, float]
    total_usd: float
    roi_percentage: float
    timestamp: datetime


class ProfitCalculator:
    """Calculate profit from blockchain exploits in USD."""
    
    def __init__(self):
        self.price_cache = {}
        self.coingecko_base = "https://api.coingecko.com/api/v3"
        
    def get_eth_price(self) -> float:
        """
        Get current ETH price in USD from CoinGecko.
        
        Returns:
            Current ETH price in USD
        """
        if "eth" in self.price_cache:
            return self.price_cache["eth"]
        
        try:
            url = f"{self.coingecko_base}/simple/price?ids=ethereum&vs_currencies=usd"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            price = response.json()["ethereum"]["usd"]
            self.price_cache["eth"] = price
            
            return price
        except Exception as e:
            print(f"Warning: Could not fetch ETH price: {e}")
            # Fallback price if API fails
            return 3000.0  # Reasonable default
    
    def get_token_price(
        self,
        symbol: str,
        chain: str = "ethereum"
    ) -> float:
        """
        Get token price in USD.
        
        Args:
            symbol: Token symbol (ETH, BNB, MATIC, etc.)
            chain: Blockchain name
            
        Returns:
            Token price in USD
        """
        cache_key = f"{chain}:{symbol}"
        if cache_key in self.price_cache:
            return self.price_cache[cache_key]
        
        # Map symbols to CoinGecko IDs
        coin_ids = {
            "eth": "ethereum",
            "bnb": "binancecoin",
            "matic": "matic-network",
            "usdc": "usd-coin",
            "usdt": "tether",
            "dai": "dai",
        }
        
        coin_id = coin_ids.get(symbol.lower(), symbol.lower())
        
        try:
            url = f"{self.coingecko_base}/simple/price?ids={coin_id}&vs_currencies=usd"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            price = response.json()[coin_id]["usd"]
            self.price_cache[cache_key] = price
            
            return price
        except Exception as e:
            print(f"Warning: Could not fetch {symbol} price: {e}")
            return 0.0
    
    def get_historical_price(
        self,
        symbol: str,
        date: datetime
    ) -> float:
        """
        Get historical token price for past exploits.
        
        Args:
            symbol: Token symbol
            date: Date of exploit
            
        Returns:
            Historical price in USD
        """
        coin_ids = {
            "eth": "ethereum",
            "bnb": "binancecoin",
            "matic": "matic-network",
        }
        
        coin_id = coin_ids.get(symbol.lower(), symbol.lower())
        date_str = date.strftime("%d-%m-%Y")
        
        try:
            url = f"{self.coingecko_base}/coins/{coin_id}/history?date={date_str}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            price = data["market_data"]["current_price"]["usd"]
            
            return price
        except Exception as e:
            print(f"Warning: Could not fetch historical price: {e}")
            # Fallback to current price
            return self.get_token_price(symbol)
    
    def calculate_profit(
        self,
        initial_balance_wei: int,
        final_balance_wei: int,
        chain: str = "ethereum",
        initial_investment_wei: int = 0
    ) -> ProfitSummary:
        """
        Calculate profit from exploit in USD.
        
        Args:
            initial_balance_wei: Balance before exploit (wei)
            final_balance_wei: Balance after exploit (wei)
            chain: Blockchain (ethereum, bsc, polygon)
            initial_investment_wei: Initial investment (wei)
            
        Returns:
            ProfitSummary with all profit metrics
        """
        # Get native token symbol
        native_tokens = {
            "ethereum": "eth",
            "bsc": "bnb",
            "polygon": "matic",
            "base": "eth",
        }
        
        symbol = native_tokens.get(chain, "eth")
        
        # Calculate profit
        profit_wei = final_balance_wei - initial_balance_wei
        profit_native = profit_wei / 1e18
        
        # Get price
        native_price = self.get_token_price(symbol, chain)
        profit_usd = profit_native * native_price
        
        # Calculate ROI
        if initial_investment_wei > 0:
            roi = (profit_wei / initial_investment_wei) * 100
        else:
            roi = float('inf') if profit_wei > 0 else 0.0
        
        return ProfitSummary(
            profit_wei=profit_wei,
            profit_eth=profit_native,
            profit_usd=profit_usd,
            token_profits={symbol: profit_native},
            total_usd=profit_usd,
            roi_percentage=roi,
            timestamp=datetime.now()
        )
    
    def calculate_multi_token_profit(
        self,
        initial_balances: Dict[str, int],
        final_balances: Dict[str, int],
        chain: str = "ethereum"
    ) -> ProfitSummary:
        """
        Calculate profit across multiple tokens.
        
        Args:
            initial_balances: {token_symbol: balance_wei}
            final_balances: {token_symbol: balance_wei}
            chain: Blockchain
            
        Returns:
            ProfitSummary with aggregated profits
        """
        total_usd = 0.0
        token_profits = {}
        total_wei = 0
        
        # Calculate for each token
        all_tokens = set(initial_balances.keys()) | set(final_balances.keys())
        
        for token in all_tokens:
            initial = initial_balances.get(token, 0)
            final = final_balances.get(token, 0)
            
            profit_wei = final - initial
            profit_native = profit_wei / 1e18
            
            price = self.get_token_price(token, chain)
            profit_usd = profit_native * price
            
            total_usd += profit_usd
            token_profits[token] = profit_native
            
            if token in ["eth", "bnb", "matic"]:
                total_wei += profit_wei
        
        # Use primary token for ETH display
        primary_token = {"ethereum": "eth", "bsc": "bnb", "polygon": "matic"}.get(chain, "eth")
        primary_profit = token_profits.get(primary_token, 0.0)
        
        return ProfitSummary(
            profit_wei=total_wei,
            profit_eth=primary_profit,
            profit_usd=total_usd,
            token_profits=token_profits,
            total_usd=total_usd,
            roi_percentage=0.0,  # Would need investment data
            timestamp=datetime.now()
        )
    
    def format_profit_report(self, profit: ProfitSummary) -> str:
        """
        Generate human-readable profit report.
        
        Args:
            profit: ProfitSummary object
            
        Returns:
            Formatted report string
        """
        report = []
        report.append("="*60)
        report.append("💰 EXPLOIT PROFIT REPORT")
        report.append("="*60)
        report.append(f"\n📊 Total Profit: ${profit.total_usd:,.2f} USD")
        report.append(f"⚡ Native Token: {profit.profit_eth:.6f} ({profit.profit_wei} wei)")
        
        if len(profit.token_profits) > 1:
            report.append("\n🔀 Token Breakdown:")
            for token, amount in profit.token_profits.items():
                report.append(f"   • {token.upper()}: {amount:.6f}")
        
        if profit.roi_percentage != float('inf'):
            report.append(f"\n📈 ROI: {profit.roi_percentage:.2f}%")
        
        report.append(f"\n⏰ Calculated: {profit.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("="*60)
        
        return "\n".join(report)


# Convenience functions
def calculate_exploit_profit(
    initial_wei: int,
    final_wei: int,
    chain: str = "ethereum"
) -> float:
    """
    Quick profit calculation in USD.
    
    Returns:
        Profit in USD
    """
    calc = ProfitCalculator()
    summary = calc.calculate_profit(initial_wei, final_wei, chain)
    return summary.total_usd


def format_usd(amount: float) -> str:
    """Format USD amount with commas and 2 decimals."""
    return f"${amount:,.2f}"
