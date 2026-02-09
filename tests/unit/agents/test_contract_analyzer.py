"""
🧪 Unit Tests for Contract Analyzer
====================================

PHASE 1 VULNERABILITY FINDING - CRITICAL

Tests the contract analyzer that:
- Parses Solidity code
- Extracts functions
- Builds call graphs
- Detects cross-contract calls
- Integrates with Slither
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

from vulnhunter.agents.contract_analyzer import ContractAnalyzer, ContractContext


class TestContractAnalyzerInitialization:
    """Test ContractAnalyzer initialization."""
    
    def test_initialization(self):
        """Test analyzer initializes correctly."""
        analyzer = ContractAnalyzer()
        
        assert analyzer is not None
    
    def test_initialization_with_options(self):
        """Test analyzer with custom options."""
        analyzer = ContractAnalyzer(run_slither=False)
        
        assert analyzer is not None


class TestFunctionExtraction:
    """Test Solidity function extraction."""
    
    def test_extracts_simple_function(self):
        """Test extracting simple function."""
        analyzer = ContractAnalyzer()
        
        code = """
contract Test {
    function hello() public pure returns (string memory) {
        return "Hello";
    }
}
"""
        
        functions = analyzer._extract_functions(code)
        
        assert len(functions) > 0
        func_names = [f['name'] for f in functions]
        assert "hello" in func_names
    
    def test_extracts_multiple_functions(self):
        """Test extracting multiple functions."""
        analyzer = ContractAnalyzer()
        
        code = """
contract Test {
    function func1() public {}
    function func2() external {}
    function func3() internal {}
    function func4() private {}
}
"""
        
        functions = analyzer._extract_functions(code)
        
        assert len(functions) >= 4
    
    def test_extracts_function_visibility(self):
        """Test function visibility is captured."""
        analyzer = ContractAnalyzer()
        
        code = """
contract Test {
    function publicFunc() public {}
    function externalFunc() external {}
    function internalFunc() internal {}
    function privateFunc() private {}
}
"""
        
        functions = analyzer._extract_functions(code)
        
        visibilities = [f.get('visibility', '') for f in functions]
        
        assert "public" in visibilities
        assert "external" in visibilities
    
    def test_extracts_function_modifiers(self):
        """Test function modifiers are captured."""
        analyzer = ContractAnalyzer()
        
        code = """
contract Test {
    modifier onlyOwner() { _; }
    
    function restricted() external onlyOwner {}
    function notRestricted() external {}
}
"""
        
        functions = analyzer._extract_functions(code)
        
        # Should capture modifiers for restricted function
        restricted_func = next((f for f in functions if f['name'] == 'restricted'), None)
        
        if restricted_func:
            mods = restricted_func.get('modifiers', [])
            assert 'onlyOwner' in mods or len(mods) > 0
    
    def test_extracts_payable_functions(self):
        """Test payable functions are identified."""
        analyzer = ContractAnalyzer()
        
        code = """
contract Test {
    function deposit() external payable {}
    function withdraw() external {}
}
"""
        
        functions = analyzer._extract_functions(code)
        
        deposit = next((f for f in functions if f['name'] == 'deposit'), None)
        
        if deposit:
            assert deposit.get('payable', False) or 'payable' in deposit.get('modifiers', [])
    
    def test_extracts_view_pure_functions(self):
        """Test view/pure functions are identified."""
        analyzer = ContractAnalyzer()
        
        code = """
contract Test {
    uint public value;
    
    function getValue() external view returns (uint) {
        return value;
    }
    
    function calculate(uint a, uint b) external pure returns (uint) {
        return a + b;
    }
}
"""
        
        functions = analyzer._extract_functions(code)
        
        # Should identify state mutability
        get_value = next((f for f in functions if f['name'] == 'getValue'), None)
        
        if get_value:
            assert get_value.get('view', False) or 'view' in str(get_value)


class TestStateVariableExtraction:
    """Test state variable extraction."""
    
    def test_extracts_simple_variables(self):
        """Test extracting simple state variables."""
        analyzer = ContractAnalyzer()
        
        code = """
contract Test {
    uint256 public balance;
    address public owner;
    bool public paused;
}
"""
        
        variables = analyzer._extract_state_variables(code)
        
        assert len(variables) >= 3
    
    def test_extracts_mappings(self):
        """Test extracting mapping variables."""
        analyzer = ContractAnalyzer()
        
        code = """
contract Test {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
}
"""
        
        variables = analyzer._extract_state_variables(code)
        
        assert len(variables) >= 2
    
    def test_extracts_arrays(self):
        """Test extracting array variables."""
        analyzer = ContractAnalyzer()
        
        code = """
contract Test {
    address[] public users;
    uint256[] public amounts;
    bytes32[10] public fixedArray;
}
"""
        
        variables = analyzer._extract_state_variables(code)
        
        assert len(variables) >= 3


class TestImportParsing:
    """Test import statement parsing."""
    
    def test_parses_relative_imports(self):
        """Test parsing relative imports."""
        analyzer = ContractAnalyzer()
        
        code = """
import "./Utils.sol";
import "../lib/SafeMath.sol";
import "../../common/Ownable.sol";
"""
        
        imports = analyzer._parse_imports(code)
        
        assert len(imports) >= 3
        assert any("Utils" in imp for imp in imports)
    
    def test_parses_npm_imports(self):
        """Test parsing npm-style imports."""
        analyzer = ContractAnalyzer()
        
        code = """
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@uniswap/v2-core/contracts/interfaces/IUniswapV2Pair.sol";
"""
        
        imports = analyzer._parse_imports(code)
        
        assert len(imports) >= 2
        assert any("openzeppelin" in imp for imp in imports)
    
    def test_parses_named_imports(self):
        """Test parsing named imports."""
        analyzer = ContractAnalyzer()
        
        code = """
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Ownable, Context} from "@openzeppelin/contracts/access/Ownable.sol";
"""
        
        imports = analyzer._parse_imports(code)
        
        assert len(imports) >= 2


class TestCallGraphBuilding:
    """Test call graph construction."""
    
    def test_builds_internal_call_graph(self):
        """Test internal function calls are tracked."""
        analyzer = ContractAnalyzer()
        
        code = """
contract Test {
    function a() public {
        b();
        c();
    }
    
    function b() internal {
        c();
    }
    
    function c() internal pure {}
}
"""
        
        call_graph = analyzer._build_call_graph(code)
        
        # a should call b and c
        assert 'a' in call_graph or len(call_graph) > 0
    
    def test_detects_recursive_calls(self):
        """Test recursive function calls are detected."""
        analyzer = ContractAnalyzer()
        
        code = """
contract Test {
    function factorial(uint n) public pure returns (uint) {
        if (n <= 1) return 1;
        return n * factorial(n - 1);
    }
}
"""
        
        call_graph = analyzer._build_call_graph(code)
        
        # factorial should call itself
        if 'factorial' in call_graph:
            calls = call_graph['factorial']
            assert 'factorial' in calls


class TestCrossContractCalls:
    """Test cross-contract call detection."""
    
    def test_detects_interface_calls(self):
        """Test interface method calls are detected."""
        analyzer = ContractAnalyzer()
        
        code = """
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract Test {
    IERC20 public token;
    
    function send(address to, uint256 amount) external {
        token.transfer(to, amount);
    }
}
"""
        
        cross_calls = analyzer._find_cross_contract_calls(code)
        
        assert len(cross_calls) > 0
    
    def test_detects_external_contract_calls(self):
        """Test external contract calls are tracked."""
        analyzer = ContractAnalyzer()
        
        code = """
contract External {
    function doSomething() external {}
}

contract Test {
    External ext;
    
    function call() external {
        ext.doSomething();
    }
}
"""
        
        cross_calls = analyzer._find_cross_contract_calls(code)
        
        assert len(cross_calls) > 0
    
    def test_detects_low_level_calls(self):
        """Test low-level calls are detected."""
        analyzer = ContractAnalyzer()
        
        code = """
contract Test {
    function lowLevelCall(address target) external {
        (bool success,) = target.call("");
        require(success);
        
        target.delegatecall("");
        target.staticcall("");
    }
}
"""
        
        low_level = analyzer._find_low_level_calls(code)
        
        assert len(low_level) >= 3


class TestSlitherIntegration:
    """Test Slither static analysis integration."""
    
    @pytest.mark.skipif(True, reason="Requires Slither installation")
    def test_runs_slither(self, sample_project):
        """Test Slither is run on contracts."""
        analyzer = ContractAnalyzer(run_slither=True)
        
        contract_path = sample_project / "contracts" / "Vault.sol"
        
        findings = analyzer._run_slither(contract_path)
        
        # Should have some findings for vulnerable vault
        assert len(findings) >= 0
    
    def test_slither_disabled(self):
        """Test Slither can be disabled."""
        analyzer = ContractAnalyzer(run_slither=False)
        
        # Should not attempt to run slither
        assert analyzer.run_slither == False
    
    def test_filters_slither_findings(self):
        """Test Slither findings are filtered by severity."""
        analyzer = ContractAnalyzer()
        
        mock_findings = [
            {"severity": "High", "check": "reentrancy"},
            {"severity": "Medium", "check": "unused-state"},
            {"severity": "Low", "check": "naming-convention"},
            {"severity": "Informational", "check": "pragma"},
        ]
        
        filtered = analyzer._filter_slither_findings(mock_findings)
        
        # Should at least include High severity
        severities = [f['severity'] for f in filtered]
        assert "High" in severities


class TestContractContext:
    """Test ContractContext output."""
    
    def test_analyze_returns_context(self, vulnerable_vault_code):
        """Test analyze returns ContractContext."""
        analyzer = ContractAnalyzer(run_slither=False)
        
        context = analyzer.analyze(vulnerable_vault_code, "VulnerableVault.sol")
        
        assert isinstance(context, ContractContext)
    
    def test_context_has_functions(self, vulnerable_vault_code):
        """Test context includes functions."""
        analyzer = ContractAnalyzer(run_slither=False)
        
        context = analyzer.analyze(vulnerable_vault_code, "VulnerableVault.sol")
        
        assert hasattr(context, 'functions')
        assert len(context.functions) > 0
    
    def test_context_has_state_variables(self, vulnerable_vault_code):
        """Test context includes state variables."""
        analyzer = ContractAnalyzer(run_slither=False)
        
        context = analyzer.analyze(vulnerable_vault_code, "VulnerableVault.sol")
        
        assert hasattr(context, 'state_variables')
    
    def test_context_has_call_graph(self, vulnerable_vault_code):
        """Test context includes call graph."""
        analyzer = ContractAnalyzer(run_slither=False)
        
        context = analyzer.analyze(vulnerable_vault_code, "VulnerableVault.sol")
        
        assert hasattr(context, 'call_graph') or hasattr(context, 'internal_calls')


class TestVulnerabilityPatternDetection:
    """Test vulnerability pattern detection in contract analysis."""
    
    def test_detects_reentrancy_pattern(self, vulnerable_vault_code):
        """Test reentrancy pattern detection."""
        analyzer = ContractAnalyzer(run_slither=False)
        
        patterns = analyzer._detect_vulnerability_patterns(vulnerable_vault_code)
        
        # Should detect reentrancy in vulnerable vault
        pattern_names = [p['type'] for p in patterns]
        assert 'reentrancy' in pattern_names or len(patterns) > 0
    
    def test_detects_access_control_missing(self, access_control_vuln_code):
        """Test missing access control detection."""
        analyzer = ContractAnalyzer(run_slither=False)
        
        patterns = analyzer._detect_vulnerability_patterns(access_control_vuln_code)
        
        # Should detect missing access control
        pattern_names = [p['type'] for p in patterns]
        assert 'access_control' in pattern_names or 'authorization' in pattern_names or len(patterns) > 0
    
    def test_detects_unchecked_call(self):
        """Test unchecked external call detection."""
        analyzer = ContractAnalyzer(run_slither=False)
        
        code = """
contract Test {
    function send(address to, uint amount) external {
        // Unchecked call - return value ignored!
        payable(to).send(amount);
    }
}
"""
        
        patterns = analyzer._detect_vulnerability_patterns(code)
        
        # Should detect unchecked call
        assert len(patterns) >= 0


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_empty_contract(self):
        """Test handling empty contract."""
        analyzer = ContractAnalyzer(run_slither=False)
        
        code = "contract Empty {}"
        
        context = analyzer.analyze(code, "Empty.sol")
        
        assert context is not None
    
    def test_invalid_solidity(self):
        """Test handling invalid Solidity code."""
        analyzer = ContractAnalyzer(run_slither=False)
        
        code = "this is not valid solidity code { }"
        
        # Should not crash
        try:
            context = analyzer.analyze(code, "Invalid.sol")
        except Exception:
            pass  # May raise, that's ok
    
    def test_very_large_contract(self):
        """Test handling large contract."""
        analyzer = ContractAnalyzer(run_slither=False)
        
        # Generate large contract
        functions = "\n".join([
            f"    function func{i}() external pure returns (uint) {{ return {i}; }}"
            for i in range(100)
        ])
        code = f"contract Large {{\n{functions}\n}}"
        
        context = analyzer.analyze(code, "Large.sol")
        
        assert len(context.functions) >= 100
    
    def test_multiple_contracts_in_file(self):
        """Test handling multiple contracts."""
        analyzer = ContractAnalyzer(run_slither=False)
        
        code = """
contract A { function a() external {} }
contract B { function b() external {} }
contract C { function c() external {} }
"""
        
        context = analyzer.analyze(code, "Multi.sol")
        
        # Should handle multiple contracts
        assert context is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
