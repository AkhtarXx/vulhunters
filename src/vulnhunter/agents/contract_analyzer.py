"""
Contract Analyzer - Build function graphs and run Slither per contract.

This module:
1. Builds function call graph for each contract
2. Identifies cross-contract calls (important for exploits)
3. Runs Slither and filters/groups output
4. Provides clean context to ExploitAgent
"""

import re
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from loguru import logger


@dataclass
class FunctionInfo:
    """Information about a function."""
    name: str
    visibility: str  # public, external, internal, private
    modifiers: List[str] = field(default_factory=list)
    params: str = ""
    returns: str = ""
    line_number: int = 0
    calls: List[str] = field(default_factory=list)  # Functions this calls
    called_by: List[str] = field(default_factory=list)  # Functions that call this


@dataclass
class CrossContractCall:
    """A call from one contract to another."""
    from_contract: str
    from_function: str
    to_contract: str
    to_function: str
    line_number: int
    call_type: str  # "external", "interface", "library"


@dataclass
class SlitherFinding:
    """A filtered Slither finding."""
    severity: str  # High, Medium, Low, Informational
    detector: str
    title: str
    description: str
    contract: str
    function: str
    lines: List[int] = field(default_factory=list)


@dataclass
class ContractContext:
    """Complete context for a single contract analysis."""
    name: str
    source_code: str
    path: Path
    lines: int
    functions: Dict[str, FunctionInfo]
    call_graph: Dict[str, List[str]]  # function -> [calls...]
    cross_contract_calls: List[CrossContractCall]
    slither_findings: Dict[str, List[SlitherFinding]]  # severity -> [findings]
    imports: List[str]
    state_variables: List[str]


class ContractAnalyzer:
    """
    Analyzes a single contract to build context for the agent.
    
    Creates:
    - Function call graph
    - Cross-contract call map
    - Filtered Slither findings
    """
    
    def __init__(self, project_root: Path):
        self.project_root = Path(project_root)
        self._known_libraries = {
            "Math", "SafeMath", "SafeTransferLib", "Strings", 
            "Address", "ECDSA", "MerkleProof", "Constants",
            "Errors", "EfficientHash", "FixedPointMathLib"
        }
    
    def analyze_contract(
        self, 
        contract_name: str, 
        source_code: str,
        contract_path: Path,
        run_slither: bool = True
    ) -> ContractContext:
        """
        Build complete context for a single contract.
        
        Args:
            contract_name: Name of the contract
            source_code: Full source code
            contract_path: Path to the .sol file
            run_slither: Whether to run Slither (default True)
            
        Returns:
            ContractContext with all analysis
        """
        logger.info(f"📊 Analyzing contract: {contract_name}")
        
        # Parse basic info
        functions = self._extract_functions(source_code)
        imports = self._extract_imports(source_code)
        state_vars = self._extract_state_variables(source_code)
        
        # Build call graph
        call_graph = self._build_call_graph(source_code, functions)
        
        # Find cross-contract calls
        cross_calls = self._find_cross_contract_calls(
            contract_name, source_code, functions, imports
        )
        
        # Run Slither and filter output
        slither_findings = {}
        if run_slither:
            slither_findings = self._run_and_filter_slither(contract_path)
        
        context = ContractContext(
            name=contract_name,
            source_code=source_code,
            path=contract_path,
            lines=len(source_code.splitlines()),
            functions=functions,
            call_graph=call_graph,
            cross_contract_calls=cross_calls,
            slither_findings=slither_findings,
            imports=imports,
            state_variables=state_vars,
        )
        
        logger.info(f"   ✅ {len(functions)} functions, {len(cross_calls)} cross-contract calls")
        if slither_findings:
            total = sum(len(f) for f in slither_findings.values())
            logger.info(f"   🔍 {total} Slither findings (filtered)")
        
        return context
    
    def _extract_functions(self, source_code: str) -> Dict[str, FunctionInfo]:
        """Extract all functions from source code."""
        functions = {}
        
        # Match function definitions
        func_pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s*(public|external|internal|private)?[^{]*{'
        
        for i, line in enumerate(source_code.splitlines(), 1):
            match = re.search(func_pattern, line)
            if match:
                name = match.group(1)
                params = match.group(2).strip()
                visibility = match.group(3) or "internal"
                
                # Extract modifiers
                modifiers = re.findall(r'(\w+)\s*(?:\([^)]*\))?\s*(?:public|external|internal|private|returns|{)', line)
                modifiers = [m for m in modifiers if m not in ['function', name, 'public', 'external', 'internal', 'private', 'returns', 'view', 'pure', 'payable', 'virtual', 'override']]
                
                functions[name] = FunctionInfo(
                    name=name,
                    visibility=visibility,
                    modifiers=modifiers,
                    params=params,
                    line_number=i,
                )
        
        return functions
    
    def _extract_imports(self, source_code: str) -> List[str]:
        """Extract import statements."""
        imports = []
        for line in source_code.splitlines():
            if line.strip().startswith('import'):
                # Extract path from import
                match = re.search(r'["\']([^"\']+)["\']', line)
                if match:
                    imports.append(match.group(1))
        return imports
    
    def _extract_state_variables(self, source_code: str) -> List[str]:
        """Extract state variable declarations."""
        state_vars = []
        in_contract = False
        brace_depth = 0
        
        for line in source_code.splitlines():
            # Track contract body
            if re.search(r'contract\s+\w+', line):
                in_contract = True
            
            if in_contract:
                brace_depth += line.count('{') - line.count('}')
                
                # State vars are at depth 1 (directly in contract)
                if brace_depth == 1:
                    # Match variable declarations
                    var_match = re.search(
                        r'^\s*(mapping|uint\d*|int\d*|address|bool|bytes\d*|string|[\w\.]+)\s+(?:public|private|internal)?\s*(\w+)',
                        line
                    )
                    if var_match and not line.strip().startswith('//'):
                        state_vars.append(var_match.group(2))
        
        return state_vars
    
    def _build_call_graph(
        self, 
        source_code: str, 
        functions: Dict[str, FunctionInfo]
    ) -> Dict[str, List[str]]:
        """Build internal function call graph."""
        call_graph = {name: [] for name in functions}
        
        # For each function, find what it calls
        func_names = set(functions.keys())
        
        lines = source_code.splitlines()
        current_func = None
        brace_depth = 0
        
        for line in lines:
            # Track which function we're in
            func_match = re.search(r'function\s+(\w+)\s*\(', line)
            if func_match and func_match.group(1) in functions:
                current_func = func_match.group(1)
                brace_depth = 0
            
            if current_func:
                brace_depth += line.count('{') - line.count('}')
                
                # Find function calls within this function
                for other_func in func_names:
                    if other_func != current_func:
                        # Check if this function is called
                        call_pattern = rf'\b{other_func}\s*\('
                        if re.search(call_pattern, line):
                            if other_func not in call_graph[current_func]:
                                call_graph[current_func].append(other_func)
                                functions[other_func].called_by.append(current_func)
                
                # End of function
                if brace_depth <= 0 and '{' in source_code[:source_code.find(line)]:
                    current_func = None
        
        return call_graph
    
    def _find_cross_contract_calls(
        self,
        contract_name: str,
        source_code: str,
        functions: Dict[str, FunctionInfo],
        imports: List[str],
    ) -> List[CrossContractCall]:
        """Find calls to other contracts (not libraries)."""
        cross_calls = []
        
        # Patterns for external calls
        patterns = [
            # contract.function()
            r'(\w+)\.(\w+)\s*\(',
            # IERC20(addr).transfer()
            r'I?(\w+)\s*\([^)]*\)\.(\w+)\s*\(',
        ]
        
        lines = source_code.splitlines()
        current_func = None
        
        for i, line in enumerate(lines, 1):
            # Track current function
            func_match = re.search(r'function\s+(\w+)\s*\(', line)
            if func_match and func_match.group(1) in functions:
                current_func = func_match.group(1)
            
            if not current_func:
                continue
            
            for pattern in patterns:
                matches = re.findall(pattern, line)
                for match in matches:
                    target_contract = match[0]
                    target_func = match[1]
                    
                    # Skip libraries and common helpers
                    if target_contract in self._known_libraries:
                        continue
                    
                    # Skip self calls and local vars
                    if target_contract in ['this', 'super', 'self', 'abi', 'msg', 'block', 'tx']:
                        continue
                    
                    # Skip if it's a local variable (lowercase)
                    if target_contract[0].islower() and len(target_contract) < 10:
                        # Might be a variable, check if it's a type call
                        if not re.search(rf'{target_contract}\s*=.*{target_contract[0].upper()}', source_code):
                            continue
                    
                    cross_calls.append(CrossContractCall(
                        from_contract=contract_name,
                        from_function=current_func,
                        to_contract=target_contract,
                        to_function=target_func,
                        line_number=i,
                        call_type="external"
                    ))
        
        return cross_calls
    
    def _run_and_filter_slither(
        self, 
        contract_path: Path
    ) -> Dict[str, List[SlitherFinding]]:
        """Run Slither and filter/group the output."""
        findings = {"High": [], "Medium": [], "Low": [], "Informational": []}
        
        import os as _os
        
        try:
            # Make contract path relative to project root
            # Handle case where path might include project root folder name
            contract_path_str = str(contract_path)
            project_root_name = self.project_root.name
            
            # If path starts with project root name, strip it
            if contract_path_str.startswith(project_root_name + "/"):
                rel_path = Path(contract_path_str[len(project_root_name) + 1:])
            elif contract_path.is_absolute():
                try:
                    rel_path = contract_path.relative_to(self.project_root)
                except ValueError:
                    # Path not relative to project_root, use as-is
                    rel_path = contract_path
            else:
                rel_path = contract_path
            
            # Run slither with JSON output to STDOUT (--json -)
            # File output doesn't work when slither exits with non-zero code
            cmd = [
                "slither",
                str(rel_path),
                "--json", "-",  # Output to stdout!
                # Only exclude obvious noise, keep security findings!
                "--exclude", "naming-convention,solc-version,pragma,assembly,low-level-calls",
            ]
            
            logger.debug(f"   Running in {self.project_root}: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,
                cwd=str(self.project_root)
            )
            
            # JSON goes to stdout even when slither exits with non-zero code
            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    
                    # Parse detectors results
                    for detector in data.get("results", {}).get("detectors", []):
                        severity = detector.get("impact", "Informational")
                        
                        # Map severity
                        if severity in ["High", "Medium", "Low", "Informational"]:
                            # Get first element info
                            elements = detector.get("elements", [])
                            first_el = elements[0] if elements else {}
                            
                            # Get contract and function name properly
                            contract_name = ""
                            func_name = ""
                            if first_el.get("type") == "function":
                                func_name = first_el.get("name", "")
                                parent = first_el.get("type_specific_fields", {}).get("parent")
                                if parent:
                                    contract_name = parent.get("name", "")
                            elif first_el.get("type") == "contract":
                                contract_name = first_el.get("name", "")
                            
                            finding = SlitherFinding(
                                severity=severity,
                                detector=detector.get("check", "unknown"),
                                title=detector.get("check", "").replace("-", " ").title(),
                                description=detector.get("description", "")[:500],
                                contract=contract_name,
                                function=func_name,
                                lines=self._extract_lines_from_elements(elements),
                            )
                            findings[severity].append(finding)
                            
                except json.JSONDecodeError as e:
                    logger.warning(f"   ⚠️ Slither JSON parse error: {e}")
            
        except subprocess.TimeoutExpired:
            logger.warning(f"   ⚠️ Slither timed out for {contract_path}")
        except FileNotFoundError:
            logger.warning("   ⚠️ Slither not installed")
        except Exception as e:
            logger.warning(f"   ⚠️ Slither error: {e}")
        
        return findings
    
    def _parse_slither_text_output(self, stderr: str) -> Dict[str, List[SlitherFinding]]:
        """Parse Slither text output when JSON fails."""
        findings = {"High": [], "Medium": [], "Low": [], "Informational": []}
        
        # Look for INFO:Detectors: sections
        current_detector = ""
        current_desc = []
        
        for line in stderr.split("\n"):
            if "INFO:Detectors:" in line:
                continue
            elif "Reference:" in line:
                # End of finding, determine severity from detector name
                if current_desc:
                    desc = "\n".join(current_desc)
                    severity = "Medium"  # Default
                    
                    # High severity detectors
                    if any(x in current_detector.lower() for x in 
                           ["reentrancy", "arbitrary-from", "unchecked-transfer", 
                            "unprotected-upgrade", "suicidal"]):
                        severity = "High"
                    
                    findings[severity].append(SlitherFinding(
                        severity=severity,
                        detector=current_detector,
                        title=current_detector.replace("-", " ").title(),
                        description=desc[:500],
                        contract="",
                        function="",
                        lines=[],
                    ))
                current_desc = []
            elif line.strip():
                current_desc.append(line.strip())
                # Extract detector name from first line
                if not current_detector and "(" in line:
                    current_detector = line.split("(")[0].strip()
        
        return findings
    
    def _extract_function_from_elements(self, elements: List[dict]) -> str:
        """Extract function name from Slither elements."""
        for el in elements:
            if el.get("type") == "function":
                return el.get("name", "")
        return ""
    
    def _extract_lines_from_elements(self, elements: List[dict]) -> List[int]:
        """Extract line numbers from Slither elements."""
        lines = []
        for el in elements:
            if "source_mapping" in el:
                start = el["source_mapping"].get("start", 0)
                lines.append(start)
        return lines
    
    def _filter_slither_noise(
        self, 
        findings: Dict[str, List[SlitherFinding]]
    ) -> Dict[str, List[SlitherFinding]]:
        """Remove noisy/false-positive findings."""
        
        # Detectors that are usually noise
        noise_detectors = {
            "similar-names",
            "too-many-digits",
            "constable-states",
            "external-function",
            "dead-code",
            "assembly",
            "low-level-calls",  # Often intentional
        }
        
        filtered = {}
        for severity, items in findings.items():
            filtered[severity] = [
                f for f in items 
                if f.detector not in noise_detectors
            ]
        
        return filtered
    
    def format_context_for_agent(self, context: ContractContext) -> str:
        """
        Format ContractContext into a prompt-friendly string.
        
        This is what gets sent to the ExploitAgent.
        """
        parts = []
        
        # Header
        parts.append(f"# CONTRACT: {context.name}")
        parts.append(f"Path: {context.path}")
        parts.append(f"Lines: {context.lines}")
        parts.append("")
        
        # Slither Findings (most important first)
        if any(context.slither_findings.values()):
            parts.append("## 🔍 SLITHER FINDINGS (Pre-analysis)")
            parts.append("")
            
            for severity in ["High", "Medium", "Low"]:
                findings = context.slither_findings.get(severity, [])
                if findings:
                    parts.append(f"### {severity} Severity ({len(findings)})")
                    for f in findings:
                        parts.append(f"- **{f.title}** ({f.detector})")
                        parts.append(f"  - Function: `{f.function}`")
                        if f.description:
                            # Truncate long descriptions
                            desc = f.description[:200] + "..." if len(f.description) > 200 else f.description
                            parts.append(f"  - {desc}")
                    parts.append("")
        
        # Cross-contract calls (critical for exploits)
        if context.cross_contract_calls:
            parts.append("## 🔗 CROSS-CONTRACT CALLS (Focus here!)")
            parts.append("")
            
            # Group by target contract
            by_target = {}
            for call in context.cross_contract_calls:
                key = call.to_contract
                if key not in by_target:
                    by_target[key] = []
                by_target[key].append(call)
            
            for target, calls in by_target.items():
                parts.append(f"### → {target}")
                for call in calls[:5]:  # Limit to 5 per target
                    parts.append(f"- `{call.from_function}()` calls `{target}.{call.to_function}()` (line {call.line_number})")
                if len(calls) > 5:
                    parts.append(f"- ... and {len(calls) - 5} more")
                parts.append("")
        
        # Function Graph (compact)
        parts.append("## 📊 FUNCTION CALL GRAPH")
        parts.append("")
        
        # Show only public/external functions and what they call
        for name, func in context.functions.items():
            if func.visibility in ["public", "external"]:
                calls = context.call_graph.get(name, [])
                if calls:
                    parts.append(f"- `{name}()` → {', '.join(calls[:5])}")
                else:
                    parts.append(f"- `{name}()`")
        parts.append("")
        
        # State Variables (important for storage manipulation bugs)
        if context.state_variables:
            parts.append("## 💾 STATE VARIABLES")
            parts.append(", ".join(context.state_variables[:20]))
            if len(context.state_variables) > 20:
                parts.append(f"... and {len(context.state_variables) - 20} more")
            parts.append("")
        
        # Full source code
        parts.append("## 📄 SOURCE CODE")
        parts.append("```solidity")
        parts.append(context.source_code)
        parts.append("```")
        
        # Tool reminder
        parts.append("")
        parts.append("## 🔧 USE BASH TO EXPLORE")
        parts.append("When you need to see related code in other contracts:")
        parts.append("```bash")
        parts.append(f"# Find function in another contract")
        parts.append(f"grep -n 'function redeem' {context.path.parent}/*.sol")
        parts.append(f"# Read specific lines")
        parts.append(f"sed -n '100,150p' {context.path.parent}/CollateralTracker.sol")
        parts.append("```")
        
        return "\n".join(parts)


def analyze_protocol_contracts(
    project_root: Path,
    contracts: Dict[str, Tuple[str, Path]],  # name -> (source, path)
    run_slither: bool = True
) -> List[ContractContext]:
    """
    Analyze all contracts in a protocol.
    
    Args:
        project_root: Path to project root
        contracts: Dict mapping contract names to (source_code, path)
        run_slither: Whether to run Slither
        
    Returns:
        List of ContractContext for each contract
    """
    analyzer = ContractAnalyzer(project_root)
    contexts = []
    
    for name, (source, path) in contracts.items():
        context = analyzer.analyze_contract(
            contract_name=name,
            source_code=source,
            contract_path=path,
            run_slither=run_slither
        )
        contexts.append(context)
    
    return contexts
