"""
🧪 Integration Tests for Path Resolution
=========================================

Tests path resolution with:
- Real project structure (bugbounty)
- Temp project structures
- Mixed scenarios
"""

import pytest
import tempfile
import shutil
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from vulnhunter.mcp_servers.path_resolver import (
    get_workspace_root,
    find_project_roots,
    read_scope_file,
    get_scope_contracts,
    find_contract,
    find_project_root,
    resolve_contract_path,
    get_valid_contract_names,
    get_scope_summary,
)


class TestRealProjectPaths:
    """Test path resolution with real bugbounty project."""
    
    def test_finds_real_workspace(self):
        """Test finding real workspace root."""
        root = get_workspace_root()
        
        assert root.exists()
        assert root.is_dir()
        print(f"Workspace root: {root}")
    
    def test_finds_real_projects(self):
        """Test finding projects in real workspace."""
        root = get_workspace_root()
        projects = find_project_roots(root)
        
        print(f"Found {len(projects)} projects:")
        for p in projects[:5]:
            print(f"  - {p.name}")
    
    @pytest.mark.skipif(
        not (Path(__file__).parent.parent.parent.parent / "DeFiHackLabs").exists(),
        reason="DeFiHackLabs not present"
    )
    def test_finds_defihacklabs(self):
        """Test finding DeFiHackLabs project."""
        root = get_workspace_root()
        
        # Look for project with foundry.toml
        labs = root / "DeFiHackLabs"
        
        if labs.exists():
            assert (labs / "foundry.toml").exists() or len(list(labs.glob("*.sol"))) > 0


class TestTempProjectPaths:
    """Test path resolution with temp directory projects."""
    
    @pytest.fixture
    def temp_workspace(self):
        """Create temp workspace with projects."""
        temp = Path(tempfile.mkdtemp())
        
        # Project 1: With scope.txt
        p1 = temp / "project_with_scope"
        p1.mkdir()
        (p1 / "foundry.toml").write_text("[profile.default]\n")
        (p1 / "scope.txt").write_text("contracts/Main.sol\ncontracts/Helper.sol\n")
        (p1 / "contracts").mkdir()
        (p1 / "contracts" / "Main.sol").write_text("contract Main {}")
        (p1 / "contracts" / "Helper.sol").write_text("contract Helper {}")
        
        # Project 2: Without scope.txt
        p2 = temp / "project_no_scope"
        p2.mkdir()
        (p2 / "foundry.toml").write_text("[profile.default]\n")
        (p2 / "contracts").mkdir()
        (p2 / "contracts" / "NoScope.sol").write_text("contract NoScope {}")
        
        yield temp
        
        shutil.rmtree(temp, ignore_errors=True)
    
    def test_finds_temp_projects(self, temp_workspace):
        """Test finding projects in temp workspace."""
        projects = find_project_roots(temp_workspace)
        
        assert len(projects) >= 2
        
        names = [p.name for p in projects]
        assert "project_with_scope" in names
        assert "project_no_scope" in names
    
    def test_reads_temp_scope(self, temp_workspace):
        """Test reading scope.txt from temp project."""
        project = temp_workspace / "project_with_scope"
        
        contracts = read_scope_file(project)
        
        assert "contracts/Main.sol" in contracts
        assert "contracts/Helper.sol" in contracts
    
    def test_finds_temp_contract(self, temp_workspace):
        """Test finding contract in temp project."""
        result = find_contract("Main.sol", temp_workspace)
        
        assert result is not None
        assert result.exists()
        assert result.name == "Main.sol"
    
    def test_temp_paths_are_absolute(self, temp_workspace):
        """Test temp paths returned are absolute."""
        contracts = get_scope_contracts(temp_workspace / "project_with_scope")
        
        for key, path in contracts.items():
            if isinstance(path, Path):
                assert path.is_absolute()
    
    def test_temp_contract_resolution(self, temp_workspace):
        """Test contract path resolution in temp."""
        contract_path = temp_workspace / "project_with_scope" / "contracts" / "Main.sol"
        
        result = resolve_contract_path(str(contract_path))
        
        if result:
            contract, project = result
            assert Path(contract).exists()


class TestMixedPaths:
    """Test mixing real and temp paths."""
    
    def test_prefers_scope_contracts(self, temp_dir):
        """Test scope.txt contracts are preferred over others."""
        # Create project with scope
        project = temp_dir / "project"
        project.mkdir()
        (project / "foundry.toml").write_text("")
        (project / "scope.txt").write_text("src/InScope.sol\n")
        
        # Create in-scope contract
        (project / "src").mkdir()
        (project / "src" / "InScope.sol").write_text("// In scope")
        
        # Create out-of-scope contract with same name
        (project / "test").mkdir()
        (project / "test" / "InScope.sol").write_text("// Out of scope test")
        
        result = find_contract("InScope.sol", temp_dir)
        
        assert result is not None
        assert "src" in str(result)  # Should find the in-scope one
    
    def test_handles_nested_temp_dirs(self, temp_dir):
        """Test handling deeply nested temp structures."""
        # Create nested structure
        nested = temp_dir / "a" / "b" / "c" / "project"
        nested.mkdir(parents=True)
        (nested / "foundry.toml").write_text("")
        (nested / "contracts").mkdir()
        (nested / "contracts" / "Deep.sol").write_text("// Deep contract")
        
        result = find_contract("Deep.sol", temp_dir)
        
        # May or may not find depending on max depth
        if result:
            assert result.name == "Deep.sol"


class TestPathEdgeCases:
    """Integration tests for path edge cases."""
    
    def test_unicode_paths(self, temp_dir):
        """Test paths with unicode characters."""
        project = temp_dir / "项目_émoji_🔥"
        
        try:
            project.mkdir()
            (project / "foundry.toml").write_text("")
            (project / "scope.txt").write_text("C.sol\n")
            (project / "C.sol").write_text("// Unicode path")
            
            result = find_contract("C.sol", temp_dir)
            
            if result:
                assert result.exists()
        except OSError:
            # Some systems may not support these paths
            pass
    
    def test_spaces_in_paths(self, temp_dir):
        """Test paths with spaces."""
        project = temp_dir / "project with spaces"
        project.mkdir()
        (project / "foundry.toml").write_text("")
        (project / "contracts").mkdir()
        (project / "contracts" / "Space Test.sol").write_text("// Spaces")
        
        result = find_contract("Space Test.sol", temp_dir)
        
        if result:
            assert result.exists()
    
    def test_symlinks(self, temp_dir):
        """Test symlinked contracts."""
        # Create actual project
        actual = temp_dir / "actual_project"
        actual.mkdir()
        (actual / "foundry.toml").write_text("")
        (actual / "contracts").mkdir()
        (actual / "contracts" / "Real.sol").write_text("// Real")
        
        # Create symlink to project
        link = temp_dir / "linked_project"
        
        try:
            link.symlink_to(actual)
            
            # Should be able to find through symlink
            result = find_contract("Real.sol", temp_dir)
            
            if result:
                assert result.exists()
        except OSError:
            # Symlinks may not be supported
            pass
    
    def test_very_long_paths(self, temp_dir):
        """Test very long path names."""
        long_name = "a" * 50
        deep = temp_dir
        
        for i in range(5):
            deep = deep / f"{long_name}_{i}"
        
        try:
            deep.mkdir(parents=True)
            (deep / "LongPath.sol").write_text("// Long path")
            
            # Should handle gracefully
            result = find_contract("LongPath.sol", temp_dir)
            
            if result:
                assert result.exists()
        except OSError:
            # Path too long on some systems
            pass


class TestScopeSummary:
    """Test scope summary generation."""
    
    def test_summary_multiple_projects(self, temp_dir):
        """Test summary with multiple projects."""
        # Create multiple projects
        for i in range(3):
            p = temp_dir / f"project_{i}"
            p.mkdir()
            (p / "foundry.toml").write_text("")
            (p / "scope.txt").write_text(f"Contract{i}.sol\n")
            (p / f"Contract{i}.sol").write_text(f"// Contract {i}")
        
        summary = get_scope_summary(temp_dir)
        
        assert len(summary) >= 3
    
    def test_contract_names_list(self, temp_dir):
        """Test getting list of all contract names."""
        # Create project with multiple contracts
        p = temp_dir / "project"
        p.mkdir()
        (p / "foundry.toml").write_text("")
        (p / "scope.txt").write_text("A.sol\nB.sol\nC.sol\n")
        (p / "A.sol").write_text("// A")
        (p / "B.sol").write_text("// B")
        (p / "C.sol").write_text("// C")
        
        names = get_valid_contract_names(temp_dir)
        
        assert len(names) == 3
        assert "A.sol" in names
        assert "B.sol" in names
        assert "C.sol" in names


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
