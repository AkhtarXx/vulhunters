"""
🧪 Shared Test Fixtures for VulHunters Test Suite
==================================================

Provides common fixtures used across all tests:
- Temporary directories and project structures
- Mock Gemini client
- Sample contracts
- Rate limiter with isolated state
- Checkpoint fixtures
"""

import pytest
import asyncio
import sys
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, MagicMock, AsyncMock, patch
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


# =============================================================================
# DIRECTORY & PATH FIXTURES
# =============================================================================

@pytest.fixture
def temp_dir():
    """Create a temporary directory that's cleaned up after the test."""
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def temp_workspace(temp_dir):
    """Create a temporary workspace with project structure."""
    workspace = temp_dir / "workspace"
    workspace.mkdir()
    return workspace


@pytest.fixture
def sample_project(temp_workspace):
    """
    Create a sample Foundry project with scope.txt.
    
    Structure:
        sample_project/
        ├── foundry.toml
        ├── scope.txt
        └── contracts/
            ├── Token.sol
            ├── Vault.sol
            └── lib/
                └── SafeMath.sol
    """
    project = temp_workspace / "sample_project"
    project.mkdir()
    
    # Create foundry.toml
    (project / "foundry.toml").write_text("""[profile.default]
src = "contracts"
out = "out"
libs = ["lib"]
""")
    
    # Create scope.txt
    (project / "scope.txt").write_text("""# In-scope contracts
contracts/Token.sol
contracts/Vault.sol
contracts/lib/SafeMath.sol
""")
    
    # Create contracts directory
    contracts_dir = project / "contracts"
    contracts_dir.mkdir()
    
    # Token.sol
    (contracts_dir / "Token.sol").write_text("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./lib/SafeMath.sol";

contract Token {
    using SafeMath for uint256;
    
    string public name = "TestToken";
    string public symbol = "TT";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    constructor(uint256 _initialSupply) {
        totalSupply = _initialSupply;
        balanceOf[msg.sender] = _initialSupply;
    }
    
    function transfer(address to, uint256 amount) public returns (bool) {
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(amount);
        balanceOf[to] = balanceOf[to].add(amount);
        emit Transfer(msg.sender, to, amount);
        return true;
    }
    
    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }
    
    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        allowance[from][msg.sender] = allowance[from][msg.sender].sub(amount);
        balanceOf[from] = balanceOf[from].sub(amount);
        balanceOf[to] = balanceOf[to].add(amount);
        emit Transfer(from, to, amount);
        return true;
    }
}
""")
    
    # Vault.sol - with reentrancy vulnerability
    (contracts_dir / "Vault.sol").write_text("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Token.sol";

contract Vault {
    Token public token;
    mapping(address => uint256) public balances;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);
    
    constructor(address _token) {
        token = Token(_token);
    }
    
    function deposit(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "Transfer failed");
        balances[msg.sender] += amount;
        emit Deposit(msg.sender, amount);
    }
    
    // VULNERABLE: External call before state update (reentrancy)
    function withdraw() external {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");
        
        // External call BEFORE state update - REENTRANCY VULNERABILITY!
        (bool success,) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] = 0;  // State update AFTER call
        emit Withdraw(msg.sender, balance);
    }
    
    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }
    
    receive() external payable {}
}
""")
    
    # SafeMath.sol
    lib_dir = contracts_dir / "lib"
    lib_dir.mkdir()
    (lib_dir / "SafeMath.sol").write_text("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");
        return c;
    }
    
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "SafeMath: subtraction overflow");
        return a - b;
    }
    
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) return 0;
        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");
        return c;
    }
    
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b > 0, "SafeMath: division by zero");
        return a / b;
    }
}
""")
    
    return project


@pytest.fixture
def multi_project_workspace(temp_workspace):
    """Create workspace with multiple projects."""
    # Project 1 - with scope.txt
    p1 = temp_workspace / "project_alpha"
    p1.mkdir()
    (p1 / "foundry.toml").write_text("[profile.default]\n")
    (p1 / "scope.txt").write_text("contracts/Alpha.sol\n")
    (p1 / "contracts").mkdir()
    (p1 / "contracts" / "Alpha.sol").write_text("// Alpha contract\ncontract Alpha {}")
    
    # Project 2 - without scope.txt
    p2 = temp_workspace / "project_beta"
    p2.mkdir()
    (p2 / "foundry.toml").write_text("[profile.default]\n")
    (p2 / "contracts").mkdir()
    (p2 / "contracts" / "Beta.sol").write_text("// Beta contract\ncontract Beta {}")
    
    # Non-project directory
    other = temp_workspace / "not_a_project"
    other.mkdir()
    (other / "readme.md").write_text("This is not a project")
    
    return temp_workspace


# =============================================================================
# CONTRACT CODE FIXTURES
# =============================================================================

@pytest.fixture
def vulnerable_vault_code():
    """Sample vulnerable vault contract with reentrancy."""
    return """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableVault {
    mapping(address => uint256) public balances;
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    // VULNERABLE: External call before state update
    function withdraw() external {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");
        
        (bool success,) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] = 0;
    }
}
"""


@pytest.fixture
def flashloan_example_code():
    """Sample flashloan attack contract."""
    return """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IFlashLender {
    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract FlashLoanAttack {
    IFlashLender public lender;
    IERC20 public token;
    address public target;
    
    constructor(address _lender, address _token, address _target) {
        lender = IFlashLender(_lender);
        token = IERC20(_token);
        target = _target;
    }
    
    function attack() external {
        // 1. Request flash loan
        lender.flashLoan(address(this), address(token), 1_000_000 ether, "");
    }
    
    function onFlashLoan(
        address initiator,
        address token_,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32) {
        // 2. Do something malicious with borrowed funds
        // 3. Repay
        IERC20(token_).transfer(msg.sender, amount + fee);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}
"""


@pytest.fixture
def access_control_vuln_code():
    """Sample contract with missing access control."""
    return """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MissingAccessControl {
    address public owner;
    uint256 public treasuryBalance;
    
    constructor() {
        owner = msg.sender;
    }
    
    function deposit() external payable {
        treasuryBalance += msg.value;
    }
    
    // VULNERABLE: No access control check!
    function withdrawAll(address to) external {
        payable(to).transfer(treasuryBalance);
        treasuryBalance = 0;
    }
    
    // VULNERABLE: Anyone can change owner!
    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}
"""


@pytest.fixture
def sample_contracts(vulnerable_vault_code, flashloan_example_code, access_control_vuln_code):
    """Dictionary of sample contracts for testing."""
    return {
        "VulnerableVault.sol": vulnerable_vault_code,
        "FlashLoanAttack.sol": flashloan_example_code,
        "MissingAccessControl.sol": access_control_vuln_code,
    }


# =============================================================================
# MOCK FIXTURES
# =============================================================================

@pytest.fixture
def mock_gemini_client():
    """Mock GeminiClient for testing without API calls."""
    mock = MagicMock()
    mock.generate.return_value = '{"result": "mock_analysis"}'
    mock.generate_async = AsyncMock(return_value='{"result": "mock_analysis"}')
    mock.cache_contract.return_value = "mock_cache_name"
    mock.cache_contract_async = AsyncMock(return_value="mock_cache_name")
    return mock


@pytest.fixture
def mock_mcp_orchestrator():
    """Mock MCPOrchestrator for testing without MCP servers."""
    mock = MagicMock()
    mock.get_all_tools = AsyncMock(return_value=[])
    mock.call_tool = AsyncMock(return_value={"result": "mock_tool_result"})
    mock.start_all = AsyncMock()
    mock.stop_all = AsyncMock()
    return mock


# =============================================================================
# RATE LIMITER FIXTURES
# =============================================================================

@pytest.fixture
def isolated_rate_limiter(temp_dir):
    """Create rate limiter with isolated state file."""
    from vulnhunter.rate_limiter import RateLimiter
    
    state_file = temp_dir / "rate_limit_test.json"
    limiter = RateLimiter(
        requests_per_minute=22,
        tokens_per_minute=900_000,
        requests_per_day=245,
        state_file=state_file
    )
    return limiter


# =============================================================================
# CHECKPOINT FIXTURES
# =============================================================================

@pytest.fixture
def sample_checkpoint_data():
    """Sample checkpoint data for testing."""
    return {
        "protocol_name": "TestProtocol",
        "chain": "ethereum",
        "started_at": datetime.now().isoformat(),
        "last_updated": datetime.now().isoformat(),
        "total_contracts": 5,
        "contracts_completed": ["A.sol", "B.sol"],
        "contracts_pending": ["C.sol", "D.sol", "E.sol"],
        "contracts_hash": "abc123def456",
        "vulnerabilities_found": [
            {"id": "V001", "type": "reentrancy", "severity": "CRITICAL"},
            {"id": "V002", "type": "access_control", "severity": "HIGH"},
        ],
    }


# =============================================================================
# ASYNC FIXTURES
# =============================================================================

@pytest.fixture
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# =============================================================================
# DATABASE FIXTURES
# =============================================================================

@pytest.fixture
def defihacklabs_db():
    """Get DeFiHackLabs database (cached)."""
    from vulnhunter.defihacklabs_db import build_exploit_database
    return build_exploit_database()


@pytest.fixture
def vulnerability_patterns():
    """Get vulnerability patterns from knowledge base."""
    from vulnhunter.vulnerability_knowledge_base import VULNERABILITY_PATTERNS
    return VULNERABILITY_PATTERNS


# =============================================================================
# AGENT FIXTURES
# =============================================================================

@pytest.fixture
def mock_base_agent(mock_gemini_client):
    """Create mocked base agent."""
    with patch('vulnhunter.agents.base_agent.GeminiClient', return_value=mock_gemini_client):
        from vulnhunter.agents.base_agent import BaseAgent
        
        # BaseAgent is abstract, create minimal implementation
        class TestAgent(BaseAgent):
            async def analyze(self, **kwargs):
                return {"status": "test"}
        
        return TestAgent()


@pytest.fixture
def mock_exploit_agent_v3(mock_gemini_client):
    """Create mocked ExploitAgentV3."""
    with patch('vulnhunter.agents.exploit_agent_v3.GeminiClient', return_value=mock_gemini_client):
        from vulnhunter.agents.exploit_agent_v3 import ExploitAgentV3
        return ExploitAgentV3()


# =============================================================================
# PYTEST CONFIGURATION
# =============================================================================

def pytest_configure(config):
    """Add custom markers."""
    config.addinivalue_line("markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')")
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "requires_api: marks tests that require real API calls")
