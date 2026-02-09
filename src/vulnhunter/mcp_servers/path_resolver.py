#!/usr/bin/env python3
"""
Smart Path Resolver for MCP Servers

Automatically finds contracts and project roots by:
1. Scanning for foundry.toml / hardhat.config.js
2. Reading scope.txt files
3. Detecting contest structure from README
4. Smart recursive search

This eliminates the need for hardcoded paths!
"""

import os
import re
from pathlib import Path
from typing import Optional, List, Tuple


# Base workspace - detected dynamically
def get_workspace_root() -> Path:
    """Get the workspace root directory."""
    # Check environment variable first
    if "VULNHUNTER_WORKSPACE" in os.environ:
        return Path(os.environ["VULNHUNTER_WORKSPACE"])
    
    # Default locations to check
    candidates = [
        Path.home() / "Desktop" / "bugbounty",
        Path.cwd(),
        Path.cwd().parent,
    ]
    
    for candidate in candidates:
        if candidate.exists():
            # Check if it looks like a workspace (has projects or pyproject.toml)
            if (candidate / "pyproject.toml").exists() or (candidate / "src").exists():
                return candidate
            # Check for any foundry projects
            if list(candidate.glob("*/foundry.toml")):
                return candidate
    
    return Path.cwd()


def find_project_roots(workspace: Optional[Path] = None) -> List[Path]:
    """Find all project roots (Foundry/Hardhat projects) in workspace."""
    if workspace is None:
        workspace = get_workspace_root()
    
    project_roots = []
    
    # Look for foundry.toml or hardhat.config.js
    for foundry_toml in workspace.glob("*/foundry.toml"):
        project_roots.append(foundry_toml.parent)
    
    for foundry_toml in workspace.glob("**/foundry.toml"):
        if foundry_toml.parent not in project_roots:
            project_roots.append(foundry_toml.parent)
    
    for hardhat_config in workspace.glob("*/hardhat.config.js"):
        if hardhat_config.parent not in project_roots:
            project_roots.append(hardhat_config.parent)
    
    return project_roots


def read_scope_file(project_root: Path) -> List[str]:
    """Read scope.txt and return list of contract paths (relative to project root)."""
    scope_file = project_root / "scope.txt"
    if not scope_file.exists():
        return []
    
    contracts = []
    for line in scope_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and line.endswith(".sol"):
            # Normalize path: remove leading ./ if present
            if line.startswith("./"):
                line = line[2:]
            contracts.append(line)
    
    return contracts


def get_scope_contracts(project_root: Path) -> dict:
    """
    Get all contracts from scope.txt with their full paths.
    
    Returns dict: {filename: full_path, ...}
    Example: {"RiskEngine.sol": "/home/user/project/contracts/RiskEngine.sol"}
    """
    scope_paths = read_scope_file(project_root)
    contracts = {}
    
    for rel_path in scope_paths:
        full_path = project_root / rel_path
        if full_path.exists():
            # Key is just the filename (for easy lookup)
            filename = Path(rel_path).name
            contracts[filename] = full_path
            # Also add relative path as key for more specific matches
            contracts[rel_path] = full_path
    
    return contracts


def get_all_scope_contracts(workspace: Optional[Path] = None) -> dict:
    """
    Get all contracts from all projects' scope.txt files.
    
    Returns dict: {filename: full_path, ...}
    This is the main lookup used by find_contract().
    """
    if workspace is None:
        workspace = get_workspace_root()
    
    all_contracts = {}
    
    for project_root in find_project_roots(workspace):
        project_contracts = get_scope_contracts(project_root)
        all_contracts.update(project_contracts)
    
    return all_contracts


def find_contract(contract_name: str, workspace: Optional[Path] = None) -> Optional[Path]:
    """
    Smart contract finder - finds a contract by name or partial path.
    
    PRIORITY ORDER:
    1. Exact match in scope.txt (fastest, most accurate)
    2. Filename match in scope.txt
    3. Direct path if exists
    4. Recursive search in project directories
    
    Handles:
    - Just filename: "RiskEngine.sol"
    - Relative path: "contracts/RiskEngine.sol"
    - Full path: "/home/user/project/contracts/RiskEngine.sol"
    """
    if workspace is None:
        workspace = get_workspace_root()
    
    # If it's already an absolute path and exists, return it
    path = Path(contract_name)
    if path.is_absolute() and path.exists():
        return path
    
    # STEP 1: Check scope.txt first - this is the source of truth!
    all_scope_contracts = get_all_scope_contracts(workspace)
    
    # Get just the filename for matching
    filename = Path(contract_name).name
    
    # Try exact match (relative path or filename)
    if contract_name in all_scope_contracts:
        return all_scope_contracts[contract_name]
    
    # Try filename match
    if filename in all_scope_contracts:
        return all_scope_contracts[filename]
    
    # Try partial match (for paths like "contracts/RiskEngine.sol")
    for key, full_path in all_scope_contracts.items():
        if key.endswith(contract_name) or contract_name.endswith(key):
            return full_path
        if Path(key).name == filename:
            return full_path
    
    # STEP 2: If not in scope, try direct search (for edge cases)
    # Find all project roots
    project_roots = find_project_roots(workspace)
    
    # Search in each project
    for project_root in project_roots:
        # Check scope file first - if contract is in scope, prioritize it
        scope_contracts = read_scope_file(project_root)
        
        # Common contract directories
        search_dirs = [
            project_root / "contracts",
            project_root / "src",
            project_root,
        ]
        
        for search_dir in search_dirs:
            if not search_dir.exists():
                continue
            
            # Direct match
            candidate = search_dir / filename
            if candidate.exists():
                return candidate
            
            # Recursive search
            matches = list(search_dir.glob(f"**/{filename}"))
            if matches:
                # Prefer matches that are in scope
                for match in matches:
                    rel_path = str(match.relative_to(project_root))
                    if any(rel_path.endswith(s) or s.endswith(filename) for s in scope_contracts):
                        return match
                # Return first match if none in scope
                return matches[0]
    
    # Last resort: search entire workspace
    matches = list(workspace.glob(f"**/{filename}"))
    if matches:
        # Filter out lib/node_modules/test directories
        filtered = [m for m in matches if not any(
            part in str(m) for part in ["/lib/", "/node_modules/", "/test/"]
        )]
        if filtered:
            return filtered[0]
        return matches[0]
    
    return None


def find_project_root(hint: Optional[str] = None, workspace: Optional[Path] = None) -> Optional[Path]:
    """
    Find project root directory.
    
    Args:
        hint: Optional hint (project name, partial path, or contract name)
        workspace: Workspace to search in
    """
    if workspace is None:
        workspace = get_workspace_root()
    
    project_roots = find_project_roots(workspace)
    
    if not project_roots:
        return None
    
    if hint is None:
        # Return the most likely project (prefer ones with scope.txt)
        for root in project_roots:
            if (root / "scope.txt").exists():
                return root
        return project_roots[0]
    
    hint_path = Path(hint)
    
    # If hint is absolute and exists
    if hint_path.is_absolute() and hint_path.exists() and hint_path.is_dir():
        return hint_path
    
    # Search for matching project
    hint_lower = hint.lower()
    for root in project_roots:
        # Check if hint matches project name
        if hint_lower in root.name.lower():
            return root
        
        # Check if hint is a subdirectory
        candidate = root / hint
        if candidate.exists() and candidate.is_dir():
            return candidate
    
    # Try finding by contract name
    if hint.endswith(".sol"):
        contract_path = find_contract(hint, workspace)
        if contract_path:
            # Walk up to find foundry.toml
            current = contract_path.parent
            while current != workspace and current != current.parent:
                if (current / "foundry.toml").exists():
                    return current
                current = current.parent
    
    return project_roots[0] if project_roots else None


def resolve_contract_path(contract_path: str) -> Tuple[Optional[Path], Optional[Path]]:
    """
    Resolve a contract path and return (contract_path, project_root).
    
    This is the main function MCP servers should use.
    """
    workspace = get_workspace_root()
    
    # Try to find the contract
    resolved_contract = find_contract(contract_path, workspace)
    
    if resolved_contract is None:
        return None, None
    
    # Find the project root for this contract
    current = resolved_contract.parent
    while current != workspace and current != current.parent:
        if (current / "foundry.toml").exists() or (current / "hardhat.config.js").exists():
            return resolved_contract, current
        current = current.parent
    
    # If no foundry.toml found, return parent of contracts folder
    if "contracts" in str(resolved_contract):
        idx = str(resolved_contract).find("contracts")
        project_root = Path(str(resolved_contract)[:idx].rstrip("/"))
        return resolved_contract, project_root
    
    return resolved_contract, resolved_contract.parent


def resolve_project_path(project_path: str) -> Optional[Path]:
    """
    Resolve a project path.
    
    This is for MCP servers that need project_root.
    """
    workspace = get_workspace_root()
    return find_project_root(project_path, workspace)


def get_valid_contract_names(workspace: Optional[Path] = None) -> List[str]:
    """
    Get list of all valid contract filenames from scope.txt files.
    
    This is useful for providing to agents so they know which
    contracts they can analyze.
    
    Returns: ["RiskEngine.sol", "PanopticPool.sol", ...]
    """
    all_contracts = get_all_scope_contracts(workspace)
    
    # Return unique filenames only (not the full paths)
    filenames = set()
    for key in all_contracts.keys():
        # Only add actual filenames, not paths
        if key.endswith(".sol") and "/" not in key:
            filenames.add(key)
    
    return sorted(list(filenames))


def get_scope_summary(workspace: Optional[Path] = None) -> dict:
    """
    Get a summary of all scope.txt contracts with their projects.
    
    Returns: {
        "project_name": {
            "root": "/path/to/project",
            "contracts": ["RiskEngine.sol", "PanopticPool.sol", ...]
        }
    }
    """
    if workspace is None:
        workspace = get_workspace_root()
    
    summary = {}
    
    for project_root in find_project_roots(workspace):
        scope_contracts = get_scope_contracts(project_root)
        if scope_contracts:
            project_name = project_root.name
            summary[project_name] = {
                "root": str(project_root),
                "contracts": sorted([Path(k).name for k in scope_contracts.keys() if "/" not in k])
            }
    
    return summary


# Quick test
if __name__ == "__main__":
    print(f"Workspace: {get_workspace_root()}")
    print(f"Project roots: {find_project_roots()}")
    
    print("\n📋 Scope Summary:")
    summary = get_scope_summary()
    for project, info in summary.items():
        print(f"\n  {project}:")
        print(f"    Root: {info['root']}")
        print(f"    Contracts ({len(info['contracts'])}):")
        for c in info['contracts']:
            print(f"      - {c}")
    
    print("\n✅ Valid contract names:")
    for name in get_valid_contract_names():
        print(f"  - {name}")
    
    print("\n🔍 Test contract finding:")
    test_contracts = ["RiskEngine.sol", "PanopticPool.sol", "Target.sol"]
    for contract in test_contracts:
        result = find_contract(contract)
        status = "✅" if result else "❌"
        print(f"  {status} {contract} -> {result}")
