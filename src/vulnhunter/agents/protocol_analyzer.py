"""
🔍 Protocol Analyzer - Cross-Contract Intelligence

Analyzes full protocol structure before exploitation:
- Parses scope.txt to get in-scope contracts
- Builds contract dependency graph
- Identifies trust boundaries
- Maps fund flows
- Prepares comprehensive context for ExploitAgent
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from loguru import logger


@dataclass
class ContractInfo:
    """Information about a single contract."""
    name: str
    path: Path
    source_code: str
    lines: int
    imports: List[str] = field(default_factory=list)
    external_calls: List[Dict] = field(default_factory=list)
    state_variables: List[str] = field(default_factory=list)
    functions: List[Dict] = field(default_factory=list)
    modifiers: List[str] = field(default_factory=list)
    inheritance: List[str] = field(default_factory=list)


@dataclass
class ProtocolContext:
    """Complete protocol context for ExploitAgent."""
    protocol_name: str
    contracts: Dict[str, ContractInfo]
    dependency_graph: Dict[str, Dict]
    trust_boundaries: List[str]
    fund_flows: List[str]
    external_protocols: List[str]
    scope_files: List[str]
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "protocol_name": self.protocol_name,
            "contracts": {name: asdict(info) for name, info in self.contracts.items()},
            "dependency_graph": self.dependency_graph,
            "trust_boundaries": self.trust_boundaries,
            "fund_flows": self.fund_flows,
            "external_protocols": self.external_protocols,
            "scope_files": self.scope_files,
        }


class ProtocolAnalyzer:
    """
    Analyzes smart contract protocols for cross-contract vulnerabilities.
    
    Key responsibilities:
    - Parse scope.txt / README.md for in-scope contracts
    - Build dependency graph (who calls whom)
    - Identify trust boundaries
    - Map fund flows
    - Prepare context for ExploitAgent
    """
    
    def __init__(self, project_root: Path):
        """Initialize with project root directory."""
        self.project_root = Path(project_root)
        self.contracts: Dict[str, ContractInfo] = {}
        self.dependency_graph: Dict[str, Dict] = {}
        
    def analyze_protocol(self) -> ProtocolContext:
        """
        Perform complete protocol analysis.
        
        Returns:
            ProtocolContext with all information needed for ExploitAgent
        """
        logger.info(f"🔍 Analyzing protocol at: {self.project_root}")
        
        # Step 1: Find scope
        scope_files = self._parse_scope()
        logger.info(f"   📋 Scope: {len(scope_files)} contracts")
        
        # Step 2: Load all contracts
        self._load_contracts(scope_files)
        logger.info(f"   📄 Loaded: {len(self.contracts)} contracts")
        
        # Step 3: Analyze each contract
        for name, info in self.contracts.items():
            self._analyze_contract(info)
        
        # Step 4: Build dependency graph
        dependency_graph = self._build_dependency_graph()
        logger.info(f"   🔗 Dependencies mapped")
        
        # Step 5: Identify trust boundaries
        trust_boundaries = self._identify_trust_boundaries()
        logger.info(f"   🛡️  Trust boundaries: {len(trust_boundaries)}")
        
        # Step 6: Map fund flows
        fund_flows = self._map_fund_flows()
        logger.info(f"   💰 Fund flows: {len(fund_flows)}")
        
        # Step 7: Find external protocols
        external_protocols = self._find_external_protocols()
        logger.info(f"   🌐 External protocols: {len(external_protocols)}")
        
        # Build protocol name from directory
        protocol_name = self.project_root.name
        
        return ProtocolContext(
            protocol_name=protocol_name,
            contracts=self.contracts,
            dependency_graph=dependency_graph,
            trust_boundaries=trust_boundaries,
            fund_flows=fund_flows,
            external_protocols=external_protocols,
            scope_files=scope_files,
        )
    
    def _parse_scope(self) -> List[str]:
        """Parse scope.txt or README.md to get in-scope files."""
        scope_files = []
        
        # Try scope.txt first
        scope_txt = self.project_root / "scope.txt"
        if scope_txt.exists():
            content = scope_txt.read_text()
            for line in content.strip().split("\n"):
                line = line.strip()
                if line and line.endswith(".sol"):
                    if line.startswith("./"):
                        line = line[2:]
                    scope_files.append(line)
            return scope_files
        
        # Try README.md
        readme = self.project_root / "README.md"
        if readme.exists():
            content = readme.read_text()
            patterns = [
                r'\[([^\]]+\.sol)\]',
                r'\|\s*([^\|]+\.sol)\s*\|',
                r'`([^`]+\.sol)`',
            ]
            for pattern in patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    path = match.strip()
                    if path.startswith("./"):
                        path = path[2:]
                    if path.startswith("/"):
                        path = path[1:]
                    if path not in scope_files and "test/" not in path.lower():
                        scope_files.append(path)
            
            if scope_files:
                return scope_files
        
        # Fallback: find all .sol files in contracts/ or src/
        for dirname in ["contracts", "src", "protocol"]:
            contracts_dir = self.project_root / dirname
            if contracts_dir.exists():
                for sol_file in contracts_dir.rglob("*.sol"):
                    if "test" not in str(sol_file).lower() and "mock" not in str(sol_file).lower():
                        rel_path = sol_file.relative_to(self.project_root)
                        scope_files.append(str(rel_path))
        
        return scope_files
    
    def _load_contracts(self, scope_files: List[str]) -> None:
        """Load all in-scope contracts."""
        for file_path in scope_files:
            full_path = self.project_root / file_path
            
            if not full_path.exists():
                # Try to find by name
                matches = list(self.project_root.rglob(Path(file_path).name))
                if matches:
                    full_path = matches[0]
                else:
                    logger.warning(f"   ⚠️  Not found: {file_path}")
                    continue
            
            try:
                source_code = full_path.read_text()
                contract_name = full_path.stem
                
                self.contracts[contract_name] = ContractInfo(
                    name=contract_name,
                    path=full_path,
                    source_code=source_code,
                    lines=len(source_code.splitlines()),
                )
            except Exception as e:
                logger.warning(f"   ⚠️  Failed to load {file_path}: {e}")
    
    def _analyze_contract(self, contract: ContractInfo) -> None:
        """Analyze a single contract for structure."""
        source = contract.source_code
        
        # Extract imports
        import_pattern = r'import\s+(?:{[^}]+}\s+from\s+)?["\']([^"\']+)["\']'
        contract.imports = re.findall(import_pattern, source)
        
        # Extract inheritance
        inheritance_pattern = r'contract\s+\w+\s+is\s+([^{]+)'
        inheritance_match = re.search(inheritance_pattern, source)
        if inheritance_match:
            parents = inheritance_match.group(1).split(",")
            contract.inheritance = [p.strip().split("(")[0] for p in parents]
        
        # Extract external calls
        external_call_patterns = [
            r'(\w+)\.(\w+)\s*\(',  # contract.function(
            r'(\w+)\(([^)]*)\)\.(\w+)\s*\(',  # Interface(addr).function(
        ]
        
        calls = []
        for pattern in external_call_patterns:
            for match in re.finditer(pattern, source):
                groups = match.groups()
                if len(groups) >= 2:
                    calls.append({
                        "target": groups[0],
                        "function": groups[1] if len(groups) == 2 else groups[2],
                        "line": source[:match.start()].count("\n") + 1,
                    })
        contract.external_calls = calls
        
        # Extract function signatures
        func_pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s*(external|public|internal|private)?'
        functions = []
        for match in re.finditer(func_pattern, source):
            functions.append({
                "name": match.group(1),
                "params": match.group(2),
                "visibility": match.group(3) or "public",
                "line": source[:match.start()].count("\n") + 1,
            })
        contract.functions = functions
        
        # Extract modifiers
        modifier_pattern = r'modifier\s+(\w+)'
        contract.modifiers = re.findall(modifier_pattern, source)
        
        # Extract state variables (simplified)
        state_pattern = r'(uint\d*|int\d*|address|bool|bytes\d*|string|mapping)\s+(?:public|private|internal)?\s*(\w+)'
        contract.state_variables = [m[1] for m in re.findall(state_pattern, source)]
    
    def _build_dependency_graph(self) -> Dict[str, Dict]:
        """Build graph of contract dependencies."""
        graph = {}
        
        for name, contract in self.contracts.items():
            graph[name] = {
                "imports": contract.imports,
                "inherits": contract.inheritance,
                "calls": [],
                "called_by": [],
            }
            
            # Track external calls to other in-scope contracts
            for call in contract.external_calls:
                target = call["target"]
                # Check if target is another in-scope contract
                if target in self.contracts:
                    graph[name]["calls"].append({
                        "to": target,
                        "function": call["function"],
                    })
        
        # Build reverse mapping (called_by)
        for name, deps in graph.items():
            for call in deps["calls"]:
                target = call["to"]
                if target in graph:
                    graph[target]["called_by"].append({
                        "from": name,
                        "function": call["function"],
                    })
        
        return graph
    
    def _identify_trust_boundaries(self) -> List[str]:
        """Identify trust boundaries between contracts."""
        boundaries = []
        
        for name, deps in self.dependency_graph.items():
            for call in deps.get("calls", []):
                target = call["to"]
                func = call["function"]
                boundaries.append(f"{name} → {target}.{func}()")
        
        # Add external protocol boundaries
        external_patterns = [
            "UniswapV2", "UniswapV3", "SushiSwap", "Balancer",
            "Aave", "Compound", "Chainlink", "Curve",
        ]
        
        for name, contract in self.contracts.items():
            for pattern in external_patterns:
                if pattern.lower() in contract.source_code.lower():
                    boundaries.append(f"{name} → {pattern} (EXTERNAL)")
        
        return list(set(boundaries))
    
    def _map_fund_flows(self) -> List[str]:
        """Map how funds flow through the protocol."""
        flows = []
        
        # Look for common fund movement patterns
        fund_patterns = [
            (r'transfer\s*\(', "transfer"),
            (r'transferFrom\s*\(', "transferFrom"),
            (r'safeTransfer\s*\(', "safeTransfer"),
            (r'safeTransferFrom\s*\(', "safeTransferFrom"),
            (r'deposit\s*\(', "deposit"),
            (r'withdraw\s*\(', "withdraw"),
            (r'mint\s*\(', "mint"),
            (r'burn\s*\(', "burn"),
            (r'swap\s*\(', "swap"),
            (r'flashLoan\s*\(', "flashLoan"),
            (r'borrow\s*\(', "borrow"),
            (r'repay\s*\(', "repay"),
        ]
        
        for name, contract in self.contracts.items():
            source = contract.source_code
            for pattern, fund_type in fund_patterns:
                if re.search(pattern, source):
                    # Find the function containing this
                    for func in contract.functions:
                        func_start = source.find(f"function {func['name']}")
                        if func_start >= 0:
                            # Check if pattern is in this function
                            func_end = source.find("function ", func_start + 1)
                            if func_end < 0:
                                func_end = len(source)
                            func_body = source[func_start:func_end]
                            if re.search(pattern, func_body):
                                flows.append(f"{name}.{func['name']}() → {fund_type}")
        
        return list(set(flows))
    
    def _find_external_protocols(self) -> List[str]:
        """Find external protocols the contract interacts with."""
        external = set()
        
        known_protocols = {
            "uniswap": "Uniswap",
            "sushiswap": "SushiSwap",
            "balancer": "Balancer",
            "curve": "Curve",
            "aave": "Aave",
            "compound": "Compound",
            "chainlink": "Chainlink Oracle",
            "maker": "MakerDAO",
            "yearn": "Yearn",
            "convex": "Convex",
            "lido": "Lido",
            "frax": "Frax",
        }
        
        for name, contract in self.contracts.items():
            source_lower = contract.source_code.lower()
            for pattern, protocol_name in known_protocols.items():
                if pattern in source_lower:
                    external.add(protocol_name)
        
        return list(external)
    
    def get_contract_source(self, contract_name: str) -> Optional[str]:
        """Get source code for a specific contract."""
        if contract_name in self.contracts:
            return self.contracts[contract_name].source_code
        return None
    
    def get_all_sources(self) -> Dict[str, str]:
        """Get all contract source codes."""
        return {name: info.source_code for name, info in self.contracts.items()}
    
    def print_summary(self) -> None:
        """Print protocol analysis summary."""
        print("\n" + "="*60)
        print("📊 PROTOCOL ANALYSIS SUMMARY")
        print("="*60)
        
        print(f"\n📁 Project: {self.project_root.name}")
        print(f"📄 Contracts: {len(self.contracts)}")
        
        total_lines = sum(c.lines for c in self.contracts.values())
        print(f"📝 Total Lines: {total_lines:,}")
        
        print("\n🔗 Dependency Graph:")
        for name, deps in self.dependency_graph.items():
            calls = deps.get("calls", [])
            if calls:
                targets = [f"{c['to']}.{c['function']}()" for c in calls]
                print(f"   {name} → {', '.join(targets)}")
        
        print("\n" + "="*60)
