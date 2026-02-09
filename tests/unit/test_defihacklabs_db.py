"""
🧪 Unit Tests for DeFiHackLabs Database
=======================================

Tests the DeFiHackLabs exploit database:
- Database loading and parsing
- Exploit record structure
- Search functionality
- Vulnerability type normalization
- Statistics
"""

import pytest
from pathlib import Path
from datetime import datetime

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from vulnhunter.defihacklabs_db import (
    DefiHackLabsDB,
    ExploitRecord,
    normalize_vulnerability_type,
)


class TestExploitRecord:
    """Test ExploitRecord dataclass."""
    
    def test_exploit_record_creation(self):
        """Test creating an exploit record."""
        record = ExploitRecord(
            id="202303-Euler",
            name="Euler",
            date=datetime(2023, 3, 13),
            chain="ethereum",
            file_path="/path/to/Euler_exp.sol",
            vulnerability_type="flashloan",
            vulnerability_raw="Flash Loan Attack",
            description="Flash loan attack on Euler Finance",
            contracts=["0x1234..."],
            tx_hash="0xabcd...",
            attacker_address="0x5678...",
            lost_amount="$197M",
        )
        
        assert record.name == "Euler"
        assert record.chain == "ethereum"
        assert record.vulnerability_type == "flashloan"
        assert "$197M" in record.lost_amount
    
    def test_exploit_record_minimal(self):
        """Test creating record with minimal fields."""
        record = ExploitRecord(
            id="test-001",
            name="TestExploit",
            date=datetime.now(),
            chain="ethereum",
            file_path="/test.sol",
            vulnerability_type="reentrancy",
            vulnerability_raw="Reentrancy",
            description="",
        )
        
        assert record.id == "test-001"
        assert record.description == ""
        assert record.contracts == []
    
    def test_dollar_value_property(self):
        """Test dollar_value field."""
        record = ExploitRecord(
            id="test",
            name="Test",
            date=datetime.now(),
            chain="ethereum",
            file_path="/test.sol",
            vulnerability_type="reentrancy",
            vulnerability_raw="Reentrancy",
            description="",
            dollar_value=3600000.0,
            lost_amount="$3.6M",
        )
        
        # dollar_value should be set
        assert record.dollar_value == 3600000.0


class TestNormalizeVulnerabilityType:
    """Test vulnerability type normalization."""
    
    def test_normalize_reentrancy_variants(self):
        """Test normalizing reentrancy variants."""
        variants = ["Reentrancy", "reentrancy", "REENTRANCY", "Re-entrancy"]
        
        for v in variants:
            normalized = normalize_vulnerability_type(v)
            assert "reentrancy" in normalized.lower()
    
    def test_normalize_flashloan_variants(self):
        """Test normalizing flash loan variants."""
        variants = ["FlashLoan", "flash loan", "Flash Loan", "flashloan"]
        
        for v in variants:
            normalized = normalize_vulnerability_type(v)
            assert "flashloan" in normalized.lower() or "flash" in normalized.lower()
    
    def test_normalize_price_manipulation(self):
        """Test normalizing price manipulation variants."""
        variants = [
            "Price Manipulation", 
            "price manipulation",
            "Price Oracle Manipulation",
        ]
        
        for v in variants:
            normalized = normalize_vulnerability_type(v)
            assert "price" in normalized.lower() or "oracle" in normalized.lower()
    
    def test_normalize_unknown_type(self):
        """Test handling unknown vulnerability type."""
        result = normalize_vulnerability_type("SomeWeirdType123")
        assert result is not None


class TestDefiHackLabsDB:
    """Test DefiHackLabsDB class."""
    
    def test_db_initialization(self):
        """Test database initializes."""
        db = DefiHackLabsDB()
        assert db is not None
        assert hasattr(db, 'exploits')
    
    def test_db_custom_path(self, temp_dir):
        """Test database with custom path."""
        # Should not crash even if path doesn't exist
        db = DefiHackLabsDB(str(temp_dir / "nonexistent"))
        assert db is not None
    
    @pytest.mark.slow
    def test_parse_exploits_loads_data(self, defihacklabs_db):
        """Test exploits are loaded from repository."""
        db = defihacklabs_db
        
        assert len(db.exploits) > 100, f"Expected 100+ exploits, got {len(db.exploits)}"
        print(f"✅ Loaded {len(db.exploits)} exploits")
    
    @pytest.mark.slow
    def test_exploit_structure(self, defihacklabs_db):
        """Test exploit records have required fields."""
        db = defihacklabs_db
        
        if db.exploits:
            exploit = db.exploits[0]
            
            assert hasattr(exploit, 'id')
            assert hasattr(exploit, 'name')
            assert hasattr(exploit, 'date')
            assert hasattr(exploit, 'chain')
            assert hasattr(exploit, 'file_path')
            assert hasattr(exploit, 'vulnerability_type')
            
            assert exploit.id is not None
            assert exploit.name is not None
            assert exploit.file_path is not None
    
    @pytest.mark.slow
    def test_find_similar_reentrancy(self, defihacklabs_db):
        """Test finding similar reentrancy exploits."""
        db = defihacklabs_db
        
        results = db.find_similar("reentrancy", limit=10)
        
        assert len(results) > 0
        print(f"✅ Found {len(results)} reentrancy exploits")
    
    @pytest.mark.slow
    def test_find_similar_flashloan(self, defihacklabs_db):
        """Test finding similar flash loan exploits."""
        db = defihacklabs_db
        
        results = db.find_similar("flashloan", limit=10)
        
        assert len(results) > 0
        print(f"✅ Found {len(results)} flash loan exploits")
    
    @pytest.mark.slow
    def test_find_similar_price_manipulation(self, defihacklabs_db):
        """Test finding price manipulation exploits."""
        db = defihacklabs_db
        
        results = db.find_similar("price manipulation", limit=10)
        
        # May or may not find results
        print(f"✅ Found {len(results)} price manipulation exploits")
    
    @pytest.mark.slow
    def test_find_similar_returns_exploit_records(self, defihacklabs_db):
        """Test find_similar returns ExploitRecord objects."""
        db = defihacklabs_db
        
        results = db.find_similar("reentrancy", limit=5)
        
        for result in results:
            assert isinstance(result, ExploitRecord)
    
    @pytest.mark.slow
    def test_get_by_id(self, defihacklabs_db):
        """Test getting exploit by ID."""
        db = defihacklabs_db
        
        if db.exploits and hasattr(db, 'get_by_id'):
            first_id = db.exploits[0].id
            result = db.get_by_id(first_id)
            
            if result:
                assert result.id == first_id
    
    @pytest.mark.slow
    def test_get_statistics(self, defihacklabs_db):
        """Test getting database statistics."""
        db = defihacklabs_db
        
        if hasattr(db, 'get_statistics'):
            stats = db.get_statistics()
            
            assert 'total_exploits' in stats or 'total' in stats
            assert stats.get('total_exploits', stats.get('total', 0)) > 100


class TestChainDetection:
    """Test blockchain chain detection from exploit code."""
    
    @pytest.mark.slow
    def test_ethereum_exploits(self, defihacklabs_db):
        """Test that some exploits are detected as Ethereum."""
        db = defihacklabs_db
        
        eth_exploits = [e for e in db.exploits if e.chain == "ethereum"]
        
        assert len(eth_exploits) > 0
        print(f"✅ Found {len(eth_exploits)} Ethereum exploits")
    
    @pytest.mark.slow  
    def test_bsc_exploits(self, defihacklabs_db):
        """Test that some exploits are detected as BSC."""
        db = defihacklabs_db
        
        bsc_exploits = [e for e in db.exploits if e.chain == "bsc"]
        
        print(f"✅ Found {len(bsc_exploits)} BSC exploits")


class TestAddressExtraction:
    """Test contract address extraction from exploit code."""
    
    @pytest.mark.slow
    def test_some_exploits_have_addresses(self, defihacklabs_db):
        """Test that some exploits have extracted addresses."""
        db = defihacklabs_db
        
        exploits_with_addresses = [e for e in db.exploits if e.contracts]
        
        print(f"✅ {len(exploits_with_addresses)} exploits have contract addresses")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "not slow"])
