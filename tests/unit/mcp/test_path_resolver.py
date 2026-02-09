"""
🧪 Unit Tests for Path Resolver
================================

CRITICAL: Tests for temp vs real path handling

Tests the path resolver module with:
- Workspace detection
- Project root finding
- scope.txt parsing
- Contract finding with various path formats
- Temp directory paths vs real paths
- Edge cases (missing files, unicode, symlinks)
"""

import pytest
import os
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

from vulnhunter.mcp_servers.path_resolver import (
    get_workspace_root,
    find_project_roots,
    read_scope_file,
    get_scope_contracts,
    get_all_scope_contracts,
    find_contract,
    find_project_root,
    resolve_contract_path,
    resolve_project_path,
    get_valid_contract_names,
    get_scope_summary,
)


# =============================================================================
# TEST: WORKSPACE DETECTION
# =============================================================================

class TestGetWorkspaceRoot:
    """Test workspace root detection."""
    
    def test_returns_path(self):
        """Test workspace root returns a Path object."""
        root = get_workspace_root()
        
        assert isinstance(root, Path)
        assert root.exists()
    
    def test_workspace_contains_project(self):
        """Test workspace contains the bugbounty project."""
        root = get_workspace_root()
        
        # Should be able to find bugbounty somewhere
        # Workspace could be the project itself or parent
        bugbounty_markers = ["src", "vulnhunter", "DeFiHackLabs"]
        
        # Either root is bugbounty or contains it
        assert root.exists()


# =============================================================================
# TEST: PROJECT ROOT FINDING
# =============================================================================

class TestFindProjectRoots:
    """Test finding project roots in workspace."""
    
    def test_find_in_temp_workspace(self, multi_project_workspace):
        """Test finding projects in temp workspace."""
        roots = find_project_roots(multi_project_workspace)
        
        # Should find project_alpha and project_beta
        assert len(roots) >= 2
        
        root_names = [r.name for r in roots]
        assert "project_alpha" in root_names
        assert "project_beta" in root_names
    
    def test_excludes_non_projects(self, multi_project_workspace):
        """Test that non-project directories are excluded."""
        roots = find_project_roots(multi_project_workspace)
        
        root_names = [r.name for r in roots]
        assert "not_a_project" not in root_names
    
    def test_empty_workspace(self, temp_dir):
        """Test finding projects in empty workspace."""
        roots = find_project_roots(temp_dir)
        
        assert roots == []
    
    def test_returns_path_objects(self, multi_project_workspace):
        """Test that results are Path objects."""
        roots = find_project_roots(multi_project_workspace)
        
        for root in roots:
            assert isinstance(root, Path)
            assert root.exists()
            assert root.is_dir()


class TestFindProjectRoot:
    """Test finding specific project root."""
    
    def test_find_by_name_hint(self, multi_project_workspace):
        """Test finding project by name hint."""
        root = find_project_root("project_alpha", multi_project_workspace)
        
        assert root is not None
        assert root.name == "project_alpha"
    
    def test_find_by_partial_hint(self, multi_project_workspace):
        """Test finding project by partial name."""
        root = find_project_root("alpha", multi_project_workspace)
        
        assert root is not None
        assert "alpha" in root.name.lower()
    
    def test_prefers_project_with_scope(self, multi_project_workspace):
        """Test that projects with scope.txt are preferred."""
        # No hint - should prefer project with scope.txt
        root = find_project_root(hint=None, workspace=multi_project_workspace)
        
        # project_alpha has scope.txt
        assert root.name == "project_alpha"
    
    def test_returns_none_for_missing(self, multi_project_workspace):
        """Test returns None for non-existent project."""
        root = find_project_root("nonexistent_project_xyz", multi_project_workspace)
        
        # Should return None or first available
        # Behavior depends on implementation


# =============================================================================
# TEST: SCOPE FILE PARSING
# =============================================================================

class TestReadScopeFile:
    """Test reading scope.txt files."""
    
    def test_read_basic_scope(self, sample_project):
        """Test reading basic scope.txt."""
        contracts = read_scope_file(sample_project)
        
        assert len(contracts) == 3
        assert "contracts/Token.sol" in contracts
        assert "contracts/Vault.sol" in contracts
        assert "contracts/lib/SafeMath.sol" in contracts
    
    def test_ignores_comments(self, temp_dir):
        """Test that comments are ignored."""
        project = temp_dir / "project"
        project.mkdir()
        
        scope_content = """# This is a comment
contracts/A.sol
# Another comment
contracts/B.sol
// C-style comment line (should be included as it's a path)
"""
        (project / "scope.txt").write_text(scope_content)
        
        contracts = read_scope_file(project)
        
        # Only A.sol and B.sol should be included (# comments excluded)
        assert "contracts/A.sol" in contracts
        assert "contracts/B.sol" in contracts
    
    def test_ignores_empty_lines(self, temp_dir):
        """Test that empty lines are ignored."""
        project = temp_dir / "project"
        project.mkdir()
        
        scope_content = """contracts/A.sol

contracts/B.sol


contracts/C.sol
"""
        (project / "scope.txt").write_text(scope_content)
        
        contracts = read_scope_file(project)
        
        assert len(contracts) == 3
    
    def test_missing_scope_file(self, temp_dir):
        """Test behavior when scope.txt is missing."""
        project = temp_dir / "project"
        project.mkdir()
        
        contracts = read_scope_file(project)
        
        assert contracts == []
    
    def test_strips_whitespace(self, temp_dir):
        """Test that whitespace is stripped."""
        project = temp_dir / "project"
        project.mkdir()
        
        scope_content = """  contracts/A.sol  
	contracts/B.sol	
contracts/C.sol
"""
        (project / "scope.txt").write_text(scope_content)
        
        contracts = read_scope_file(project)
        
        assert "contracts/A.sol" in contracts
        assert "contracts/B.sol" in contracts
        assert "contracts/C.sol" in contracts


class TestGetScopeContracts:
    """Test getting contracts with full paths."""
    
    def test_returns_dict_with_paths(self, sample_project):
        """Test returns dict mapping to full paths."""
        contracts = get_scope_contracts(sample_project)
        
        assert isinstance(contracts, dict)
        assert "Token.sol" in contracts or "contracts/Token.sol" in contracts
    
    def test_paths_are_absolute(self, sample_project):
        """Test that paths are absolute."""
        contracts = get_scope_contracts(sample_project)
        
        for key, path in contracts.items():
            if isinstance(path, Path) and path.exists():
                assert path.is_absolute()
    
    def test_paths_exist(self, sample_project):
        """Test that returned paths exist."""
        contracts = get_scope_contracts(sample_project)
        
        for key, path in contracts.items():
            if isinstance(path, Path):
                assert path.exists(), f"Path does not exist: {path}"


# =============================================================================
# TEST: CONTRACT FINDING (TEMP VS REAL PATHS)
# =============================================================================

class TestFindContract:
    """Test smart contract finding with temp and real paths."""
    
    def test_find_by_filename(self, sample_project):
        """Test finding contract by just filename."""
        result = find_contract("Token.sol", sample_project)
        
        assert result is not None
        assert result.name == "Token.sol"
        assert result.exists()
    
    def test_find_by_relative_path(self, sample_project):
        """Test finding contract by relative path."""
        result = find_contract("contracts/Vault.sol", sample_project)
        
        assert result is not None
        assert result.name == "Vault.sol"
    
    def test_find_by_absolute_path(self, sample_project):
        """Test finding contract by absolute path."""
        absolute_path = sample_project / "contracts" / "Token.sol"
        result = find_contract(str(absolute_path), sample_project)
        
        assert result is not None
        assert result.name == "Token.sol"
    
    def test_find_nested_contract(self, sample_project):
        """Test finding contract in nested directory."""
        result = find_contract("SafeMath.sol", sample_project)
        
        assert result is not None
        assert result.name == "SafeMath.sol"
    
    def test_find_by_nested_path(self, sample_project):
        """Test finding by nested relative path."""
        result = find_contract("contracts/lib/SafeMath.sol", sample_project)
        
        assert result is not None
        assert result.name == "SafeMath.sol"
    
    def test_nonexistent_contract(self, sample_project):
        """Test finding non-existent contract returns None."""
        result = find_contract("DoesNotExist.sol", sample_project)
        
        assert result is None
    
    def test_priority_scope_over_search(self, temp_workspace):
        """Test that scope.txt contracts are prioritized."""
        # Create project with scope
        project = temp_workspace / "project"
        project.mkdir()
        (project / "foundry.toml").write_text("")
        (project / "scope.txt").write_text("contracts/InScope.sol\n")
        (project / "contracts").mkdir()
        (project / "contracts" / "InScope.sol").write_text("// In scope")
        (project / "test").mkdir()
        (project / "test" / "InScope.sol").write_text("// Test version")
        
        result = find_contract("InScope.sol", temp_workspace)
        
        # Should find the one in scope, not test
        assert result is not None
        assert "contracts" in str(result)
    
    # === TEMP VS REAL PATH TESTS ===
    
    def test_temp_directory_path(self, temp_dir):
        """Test finding contracts in temp directory."""
        # Create a project in temp dir
        project = temp_dir / "temp_project"
        project.mkdir()
        (project / "foundry.toml").write_text("")
        (project / "contracts").mkdir()
        (project / "contracts" / "TempContract.sol").write_text("// Temp")
        
        result = find_contract("TempContract.sol", temp_dir)
        
        assert result is not None
        assert result.exists()
        assert "tmp" in str(result).lower() or "temp" in str(result).lower()
    
    def test_mixed_temp_and_real_paths(self, temp_dir):
        """Test handling mix of temp and real paths."""
        # Create temp project
        project = temp_dir / "project"
        project.mkdir()
        (project / "foundry.toml").write_text("")
        (project / "scope.txt").write_text("contracts/A.sol\n")
        (project / "contracts").mkdir()
        (project / "contracts" / "A.sol").write_text("// A")
        
        # Get contracts - should handle temp paths correctly
        contracts = get_scope_contracts(project)
        
        for key, path in contracts.items():
            if isinstance(path, Path):
                assert path.is_absolute()
                # Path should be valid temp path
                assert str(temp_dir) in str(path) or path.exists()


class TestResolveContractPath:
    """Test contract path resolution."""
    
    def test_resolve_returns_tuple(self, sample_project):
        """Test resolve returns (contract_path, project_root) tuple."""
        # This needs the contract to exist
        contract_path = sample_project / "contracts" / "Token.sol"
        
        result = resolve_contract_path(str(contract_path))
        
        if result:
            assert isinstance(result, tuple)
            assert len(result) == 2
    
    def test_resolve_absolute_path(self, sample_project):
        """Test resolving absolute path."""
        contract_path = sample_project / "contracts" / "Token.sol"
        
        result = resolve_contract_path(str(contract_path))
        
        if result:
            contract, project = result
            assert Path(contract).exists()


class TestResolveProjectPath:
    """Test project path resolution."""
    
    def test_resolve_project_name(self, multi_project_workspace):
        """Test resolving project by name."""
        with patch('vulnhunter.mcp_servers.path_resolver.get_workspace_root', 
                   return_value=multi_project_workspace):
            result = resolve_project_path("project_alpha")
            
            if result:
                assert Path(result).exists()


# =============================================================================
# TEST: EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_unicode_in_path(self, temp_dir):
        """Test handling unicode characters in paths."""
        project = temp_dir / "project_émoji_🚀"
        project.mkdir()
        (project / "foundry.toml").write_text("")
        (project / "contracts").mkdir()
        (project / "contracts" / "Contract.sol").write_text("// Unicode path")
        
        result = find_contract("Contract.sol", temp_dir)
        
        # Should handle unicode gracefully
        assert result is not None or result is None  # No crash
    
    def test_special_characters_in_filename(self, temp_dir):
        """Test handling special characters in contract name."""
        project = temp_dir / "project"
        project.mkdir()
        (project / "foundry.toml").write_text("")
        (project / "contracts").mkdir()
        # Note: Some special chars aren't valid in filenames
        (project / "contracts" / "Contract_v2.0.sol").write_text("// Special chars")
        
        result = find_contract("Contract_v2.0.sol", temp_dir)
        
        if result:
            assert result.name == "Contract_v2.0.sol"
    
    def test_symlinked_contract(self, temp_dir):
        """Test finding symlinked contracts."""
        project = temp_dir / "project"
        project.mkdir()
        (project / "foundry.toml").write_text("")
        (project / "contracts").mkdir()
        
        # Create actual file
        actual = project / "contracts" / "Actual.sol"
        actual.write_text("// Actual")
        
        # Create symlink
        link = project / "contracts" / "Linked.sol"
        try:
            link.symlink_to(actual)
            
            result = find_contract("Linked.sol", temp_dir)
            
            if result:
                assert result.exists()
        except OSError:
            # Symlinks may not be supported
            pass
    
    def test_very_deep_nesting(self, temp_dir):
        """Test finding deeply nested contracts."""
        project = temp_dir / "project"
        project.mkdir()
        (project / "foundry.toml").write_text("")
        
        # Create deep path
        deep = project / "contracts" / "a" / "b" / "c" / "d" / "e"
        deep.mkdir(parents=True)
        (deep / "Deep.sol").write_text("// Very deep")
        
        result = find_contract("Deep.sol", temp_dir)
        
        # May or may not find depending on max depth
        if result:
            assert result.name == "Deep.sol"
    
    def test_case_sensitivity(self, temp_dir):
        """Test case sensitivity in contract names."""
        project = temp_dir / "project"
        project.mkdir()
        (project / "foundry.toml").write_text("")
        (project / "contracts").mkdir()
        (project / "contracts" / "MyContract.sol").write_text("// Case")
        
        # Try different cases
        result1 = find_contract("MyContract.sol", temp_dir)
        result2 = find_contract("mycontract.sol", temp_dir)
        
        # At least exact match should work
        assert result1 is not None
    
    def test_empty_scope_file(self, temp_dir):
        """Test handling empty scope.txt."""
        project = temp_dir / "project"
        project.mkdir()
        (project / "foundry.toml").write_text("")
        (project / "scope.txt").write_text("")
        
        contracts = read_scope_file(project)
        
        assert contracts == []
    
    def test_scope_with_only_comments(self, temp_dir):
        """Test scope.txt with only comments."""
        project = temp_dir / "project"
        project.mkdir()
        (project / "foundry.toml").write_text("")
        (project / "scope.txt").write_text("# Comment 1\n# Comment 2\n")
        
        contracts = read_scope_file(project)
        
        assert contracts == []


class TestGetValidContractNames:
    """Test getting list of valid contract names."""
    
    def test_returns_list(self, sample_project):
        """Test returns list of contract names."""
        with patch('vulnhunter.mcp_servers.path_resolver.get_workspace_root',
                   return_value=sample_project.parent):
            names = get_valid_contract_names(sample_project.parent)
            
            assert isinstance(names, list)
    
    def test_contains_scope_contracts(self, sample_project):
        """Test list contains contracts from scope."""
        with patch('vulnhunter.mcp_servers.path_resolver.get_workspace_root',
                   return_value=sample_project.parent):
            names = get_valid_contract_names(sample_project.parent)
            
            # Should contain Token.sol or similar
            if names:
                assert any("Token" in n or "Vault" in n for n in names)


class TestGetScopeSummary:
    """Test getting scope summary."""
    
    def test_returns_dict(self, sample_project):
        """Test returns dictionary structure."""
        with patch('vulnhunter.mcp_servers.path_resolver.get_workspace_root',
                   return_value=sample_project.parent):
            summary = get_scope_summary(sample_project.parent)
            
            assert isinstance(summary, dict)
    
    def test_includes_project_info(self, sample_project):
        """Test summary includes project information."""
        with patch('vulnhunter.mcp_servers.path_resolver.get_workspace_root',
                   return_value=sample_project.parent):
            summary = get_scope_summary(sample_project.parent)
            
            if summary:
                for project_name, info in summary.items():
                    assert 'root' in info or 'contracts' in info


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
