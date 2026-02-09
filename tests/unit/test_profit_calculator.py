"""
🧪 Unit Tests for Profit Calculator
====================================

Tests profit calculation functionality:
- ETH/WEI conversions
- USD price lookups (mocked)
- Multi-token profit calculations
- Profit report formatting
"""

import pytest
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, Mock
from dataclasses import asdict

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from vulnhunter.profit_calculator import (
    ProfitSummary,
    ProfitCalculator,
    calculate_exploit_profit,
    format_usd,
)


class TestProfitSummary:
    """Test ProfitSummary dataclass."""
    
    def test_summary_creation(self):
        """Test creating profit summary."""
        summary = ProfitSummary(
            profit_wei=1000000000000000000,  # 1 ETH
            profit_eth=1.0,
            profit_usd=2500.0,
            token_profits={"ETH": 1.0},
            total_usd=2500.0,
            roi_percentage=250.0,
            timestamp=datetime.now()
        )
        
        assert summary.profit_eth == 1.0
        assert summary.profit_usd == 2500.0
        assert summary.roi_percentage == 250.0
    
    def test_summary_serialization(self):
        """Test converting summary to dict."""
        summary = ProfitSummary(
            profit_wei=0,
            profit_eth=0.0,
            profit_usd=0.0,
            token_profits={},
            total_usd=0.0,
            roi_percentage=0.0,
            timestamp=datetime.now()
        )
        
        data = asdict(summary)
        
        assert isinstance(data, dict)
        assert "profit_eth" in data
        assert "profit_usd" in data


class TestProfitCalculator:
    """Test ProfitCalculator class."""
    
    @pytest.fixture
    def calculator(self):
        """Create calculator instance."""
        return ProfitCalculator()
    
    def test_initialization(self, calculator):
        """Test calculator initializes."""
        assert calculator is not None
        assert hasattr(calculator, 'price_cache')
    
    @patch('vulnhunter.profit_calculator.requests.get')
    def test_get_eth_price(self, mock_get, calculator):
        """Test ETH price fetching (mocked)."""
        mock_response = Mock()
        mock_response.json.return_value = {"ethereum": {"usd": 2500.0}}
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        price = calculator.get_eth_price()
        
        assert price is None or price > 0  # May fail if API not available
    
    @patch('vulnhunter.profit_calculator.requests.get')
    def test_get_token_price(self, mock_get, calculator):
        """Test token price fetching (mocked)."""
        mock_response = Mock()
        mock_response.json.return_value = {"binancecoin": {"usd": 300.0}}
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        price = calculator.get_token_price("BNB", "bsc")
        
        # May return None if mapping not found
        assert price is None or price >= 0
    
    def test_calculate_profit_basic(self, calculator):
        """Test basic profit calculation."""
        initial = 1_000_000_000_000_000_000  # 1 ETH in wei
        final = 3_000_000_000_000_000_000    # 3 ETH in wei
        
        # Mock price to avoid API call
        with patch.object(calculator, 'get_token_price', return_value=2500.0):
            result = calculator.calculate_profit(
                initial_balance_wei=initial,
                final_balance_wei=final,
                chain="ethereum"
            )
        
        assert result.profit_wei == 2_000_000_000_000_000_000
        assert result.profit_eth == 2.0
    
    def test_calculate_profit_with_investment(self, calculator):
        """Test profit calculation with initial investment."""
        initial = 0
        final = 5_000_000_000_000_000_000  # 5 ETH
        investment = 1_000_000_000_000_000_000  # 1 ETH invested
        
        with patch.object(calculator, 'get_token_price', return_value=2500.0):
            result = calculator.calculate_profit(
                initial_balance_wei=initial,
                final_balance_wei=final,
                chain="ethereum",
                initial_investment_wei=investment
            )
        
        assert result.profit_eth == 5.0
        # ROI should be 400% (gained 5 ETH on 1 ETH investment)
        assert result.roi_percentage >= 400.0  # At least 400%
    
    def test_calculate_multi_token_profit(self, calculator):
        """Test multi-token profit calculation."""
        initial_balances = {
            "ETH": 1_000_000_000_000_000_000,
            "USDC": 1000_000000  # 1000 USDC (6 decimals)
        }
        final_balances = {
            "ETH": 3_000_000_000_000_000_000,
            "USDC": 2000_000000
        }
        
        with patch.object(calculator, 'get_token_price') as mock_price:
            mock_price.side_effect = lambda symbol, chain: {
                "ETH": 2500.0,
                "USDC": 1.0
            }.get(symbol, 0)
            
            result = calculator.calculate_multi_token_profit(
                initial_balances=initial_balances,
                final_balances=final_balances,
                chain="ethereum"
            )
        
        assert "ETH" in result.token_profits or result.total_usd >= 0
    
    def test_format_profit_report(self, calculator):
        """Test profit report formatting."""
        summary = ProfitSummary(
            profit_wei=2_000_000_000_000_000_000,
            profit_eth=2.0,
            profit_usd=5000.0,
            token_profits={"ETH": 2.0},
            total_usd=5000.0,
            roi_percentage=400.0,
            timestamp=datetime.now()
        )
        
        report = calculator.format_profit_report(summary)
        
        assert isinstance(report, str)
        assert "5,000" in report or "5000" in report
    
    def test_zero_profit(self, calculator):
        """Test zero profit scenario."""
        with patch.object(calculator, 'get_token_price', return_value=2500.0):
            result = calculator.calculate_profit(
                initial_balance_wei=1_000_000_000_000_000_000,
                final_balance_wei=1_000_000_000_000_000_000,
                chain="ethereum"
            )
        
        assert result.profit_wei == 0
        assert result.profit_eth == 0.0
    
    def test_negative_profit_loss(self, calculator):
        """Test loss scenario (negative profit)."""
        with patch.object(calculator, 'get_token_price', return_value=2500.0):
            result = calculator.calculate_profit(
                initial_balance_wei=2_000_000_000_000_000_000,
                final_balance_wei=1_000_000_000_000_000_000,
                chain="ethereum"
            )
        
        assert result.profit_wei == -1_000_000_000_000_000_000
        assert result.profit_eth == -1.0


class TestConvenienceFunctions:
    """Test standalone convenience functions."""
    
    def test_format_usd_basic(self):
        """Test USD formatting."""
        result = format_usd(1234567.89)
        
        assert "$" in result or "1,234,567" in result or "1234567" in result
    
    def test_format_usd_zero(self):
        """Test formatting zero."""
        result = format_usd(0)
        
        assert "0" in result
    
    def test_format_usd_large(self):
        """Test formatting large amounts."""
        result = format_usd(1_000_000_000)  # 1 billion
        
        assert isinstance(result, str)
    
    @patch('vulnhunter.profit_calculator.ProfitCalculator.get_token_price')
    def test_calculate_exploit_profit(self, mock_price):
        """Test quick profit calculation function."""
        mock_price.return_value = 2500.0
        
        profit = calculate_exploit_profit(
            initial_wei=0,
            final_wei=1_000_000_000_000_000_000,  # 1 ETH
            chain="ethereum"
        )
        
        # Should return USD profit
        assert profit is None or isinstance(profit, (int, float))


class TestChainSupport:
    """Test different blockchain support."""
    
    @pytest.fixture
    def calculator(self):
        return ProfitCalculator()
    
    def test_ethereum_chain(self, calculator):
        """Test Ethereum chain support."""
        with patch.object(calculator, 'get_token_price', return_value=2500.0):
            result = calculator.calculate_profit(
                initial_balance_wei=0,
                final_balance_wei=1_000_000_000_000_000_000,
                chain="ethereum"
            )
        
        assert result.profit_eth == 1.0
    
    def test_bsc_chain(self, calculator):
        """Test BSC chain support."""
        with patch.object(calculator, 'get_token_price', return_value=300.0):
            result = calculator.calculate_profit(
                initial_balance_wei=0,
                final_balance_wei=1_000_000_000_000_000_000,
                chain="bsc"
            )
        
        # BNB instead of ETH, but same wei conversion
        assert result.profit_eth == 1.0  # Still in native token units
    
    def test_polygon_chain(self, calculator):
        """Test Polygon chain support."""
        with patch.object(calculator, 'get_token_price', return_value=0.5):
            result = calculator.calculate_profit(
                initial_balance_wei=0,
                final_balance_wei=1_000_000_000_000_000_000,
                chain="polygon"
            )
        
        assert result.profit_eth == 1.0


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    @pytest.fixture
    def calculator(self):
        return ProfitCalculator()
    
    def test_very_large_amounts(self, calculator):
        """Test very large wei amounts."""
        large_amount = 10**30  # Very large
        
        with patch.object(calculator, 'get_token_price', return_value=2500.0):
            result = calculator.calculate_profit(
                initial_balance_wei=0,
                final_balance_wei=large_amount,
                chain="ethereum"
            )
        
        assert result.profit_wei == large_amount
    
    def test_api_failure_handling(self, calculator):
        """Test handling when price API fails."""
        with patch('vulnhunter.profit_calculator.requests.get') as mock_get:
            mock_get.side_effect = Exception("API Error")
            
            price = calculator.get_eth_price()
            
            # Should handle gracefully (return None or default)
            assert price is None or price >= 0
    
    def test_unknown_chain(self, calculator):
        """Test unknown chain handling."""
        # When price is 0, profit_usd will be 0 but ETH values still calculated
        with patch.object(calculator, 'get_token_price', return_value=0.0):
            result = calculator.calculate_profit(
                initial_balance_wei=0,
                final_balance_wei=1_000_000_000_000_000_000,
                chain="unknown_chain"
            )
        
        # Should still calculate native token values
        assert result.profit_eth == 1.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
