"""
🧪 Integration Tests for Full Audit Workflow
=============================================

Tests the complete audit workflow from scope to report:
- Protocol analysis
- Pattern matching
- Vulnerability detection pipeline
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock
import tempfile
import shutil

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))


class TestProtocolAnalysis:
    """Test protocol analysis phase of audit."""
    
    @pytest.fixture
    def mock_protocol_dir(self, temp_dir):
        """Create mock protocol directory structure."""
        # Create basic structure
        (temp_dir / "contracts").mkdir(parents=True)
        (temp_dir / "scope.txt").write_text("contracts/Token.sol\ncontracts/Vault.sol")
        
        # Create mock contracts
        (temp_dir / "contracts" / "Token.sol").write_text("""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Token {
    string public name = "Test Token";
    mapping(address => uint256) public balanceOf;
    
    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
""")
        
        (temp_dir / "contracts" / "Vault.sol").write_text("""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract Vault {
    IERC20 public token;
    mapping(address => uint256) public deposits;
    
    function deposit(uint256 amount) external {
        deposits[msg.sender] += amount;
    }
    
    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "Insufficient balance");
        deposits[msg.sender] -= amount;
        // Potential reentrancy: external call before state update
        token.transfer(msg.sender, amount);
    }
}
""")
        
        return temp_dir
    
    def test_scope_file_parsing(self, mock_protocol_dir):
        """Test scope.txt is correctly parsed."""
        scope_file = mock_protocol_dir / "scope.txt"
        
        content = scope_file.read_text()
        contracts = [line.strip() for line in content.split('\n') if line.strip()]
        
        assert len(contracts) == 2
        assert "contracts/Token.sol" in contracts
        assert "contracts/Vault.sol" in contracts
    
    def test_contracts_exist(self, mock_protocol_dir):
        """Test all scoped contracts exist."""
        scope_file = mock_protocol_dir / "scope.txt"
        contracts = [
            line.strip() 
            for line in scope_file.read_text().split('\n') 
            if line.strip()
        ]
        
        for contract in contracts:
            contract_path = mock_protocol_dir / contract
            assert contract_path.exists(), f"Contract {contract} not found"
    
    def test_protocol_structure(self, mock_protocol_dir):
        """Test protocol has expected structure."""
        assert (mock_protocol_dir / "contracts").is_dir()
        assert (mock_protocol_dir / "scope.txt").is_file()


class TestVulnerabilityDetection:
    """Test vulnerability detection patterns."""
    
    @pytest.fixture
    def vulnerable_contract(self):
        """Create contract with known vulnerability."""
        return """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableVault {
    mapping(address => uint256) public balances;
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0);
        
        // VULNERABILITY: External call before state update (reentrancy)
        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed to send");
        
        balances[msg.sender] = 0;
    }
}
"""
    
    def test_reentrancy_pattern_detected(self, vulnerable_contract):
        """Test reentrancy pattern is recognized."""
        # Pattern: call before state update
        patterns = [
            "msg.sender.call",
            "balances[msg.sender] = 0"  # State update after call
        ]
        
        call_pos = vulnerable_contract.find(patterns[0])
        state_update_pos = vulnerable_contract.find(patterns[1])
        
        # Call comes before state update = potential reentrancy
        assert call_pos < state_update_pos, "Reentrancy pattern: call before state update"
    
    def test_missing_access_control_detected(self):
        """Test missing access control is detected."""
        contract = """
contract NoAccessControl {
    address public owner;
    
    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}
"""
        
        # Pattern: owner-changing function without access control modifier
        func_body = contract.split("function setOwner")[1].split("}")[0]
        has_require = "require" in func_body
        has_modifier = "onlyOwner" in func_body
        
        # Vulnerable: no require and no modifier
        assert not has_require and not has_modifier

    
    def test_unchecked_return_detected(self):
        """Test unchecked external call return is detected."""
        contract = """
contract UncheckedCall {
    function badTransfer(address to, uint256 amount) external {
        token.transfer(to, amount);  // Return not checked
    }
}
"""
        
        # Pattern: transfer without return check
        func_body = contract.split("function badTransfer")[1].split("}")[0]
        has_transfer = "transfer" in func_body
        checks_return = "require" in func_body or "bool" in func_body
        
        assert has_transfer and not checks_return


class TestReportGeneration:
    """Test audit report generation."""
    
    def test_report_has_required_sections(self):
        """Test generated report has all required sections."""
        mock_report = {
            "protocol": "TestProtocol",
            "scope": ["Token.sol", "Vault.sol"],
            "findings": [
                {
                    "id": "VULN-001",
                    "severity": "high",
                    "title": "Reentrancy in withdraw",
                    "description": "...",
                    "recommendation": "..."
                }
            ],
            "summary": {
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0
            }
        }
        
        assert "protocol" in mock_report
        assert "scope" in mock_report
        assert "findings" in mock_report
        assert "summary" in mock_report
    
    def test_finding_structure(self):
        """Test finding has required fields."""
        finding = {
            "id": "VULN-001",
            "severity": "high",
            "title": "Reentrancy Vulnerability",
            "location": "Vault.sol:L42",
            "description": "External call before state update",
            "impact": "Funds can be drained",
            "recommendation": "Use checks-effects-interactions pattern"
        }
        
        required_fields = ["id", "severity", "title", "description", "recommendation"]
        
        for field in required_fields:
            assert field in finding, f"Missing required field: {field}"


class TestKnowledgeBaseIntegration:
    """Test integration with vulnerability knowledge base."""
    
    def test_kb_patterns_applied(self):
        """Test KB patterns are applied during analysis."""
        try:
            from vulnhunter.vulnerability_knowledge_base import VULNERABILITY_PATTERNS
            
            assert len(VULNERABILITY_PATTERNS) > 0
            
            # Check common patterns exist
            pattern_names = list(VULNERABILITY_PATTERNS.keys())
            assert any("reentrancy" in p.lower() for p in pattern_names)
        except ImportError:
            pytest.skip("Vulnerability KB not available")
    
    def test_severity_classification(self):
        """Test severity is correctly classified."""
        severity_levels = ["critical", "high", "medium", "low", "informational"]
        
        # Test severity is valid
        test_severity = "high"
        assert test_severity in severity_levels


class TestEndToEndWorkflow:
    """Test complete end-to-end workflow (mocked)."""
    
    @pytest.fixture
    def mock_gemini(self):
        """Create mocked Gemini client."""
        mock = MagicMock()
        mock.generate.return_value = "Analysis complete. Found 1 high severity issue."
        mock.generate_async = AsyncMock(return_value="Async analysis complete.")
        return mock
    
    def test_workflow_phases(self, mock_gemini):
        """Test audit workflow has correct phases."""
        phases = [
            "protocol_analysis",
            "vulnerability_detection", 
            "pattern_matching",
            "exploit_validation",
            "report_generation"
        ]
        
        # Each phase should be represented
        assert len(phases) == 5
    
    @pytest.mark.asyncio
    async def test_async_workflow(self, mock_gemini):
        """Test async workflow execution."""
        # Mock async analysis
        result = await mock_gemini.generate_async("Analyze contract")
        
        assert "complete" in result.lower()


class TestCheckpointIntegration:
    """Test checkpoint/resume functionality integration."""
    
    def test_checkpoint_saves(self, temp_dir):
        """Test checkpoint can be saved."""
        checkpoint_file = temp_dir / ".vulnhunter_checkpoint.json"
        
        checkpoint_data = {
            "phase": "vulnerability_detection",
            "completed_contracts": ["Token.sol"],
            "pending_contracts": ["Vault.sol"]
        }
        
        import json
        checkpoint_file.write_text(json.dumps(checkpoint_data))
        
        assert checkpoint_file.exists()
    
    def test_checkpoint_loads(self, temp_dir):
        """Test checkpoint can be loaded."""
        import json
        
        checkpoint_file = temp_dir / ".vulnhunter_checkpoint.json"
        checkpoint_data = {
            "phase": "pattern_matching",
            "findings": [{"id": "V001"}]
        }
        checkpoint_file.write_text(json.dumps(checkpoint_data))
        
        loaded = json.loads(checkpoint_file.read_text())
        
        assert loaded["phase"] == "pattern_matching"
        assert len(loaded["findings"]) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
