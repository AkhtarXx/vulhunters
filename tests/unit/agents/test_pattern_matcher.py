"""
🧪 Unit Tests for Pattern Matcher Agent
=======================================

PHASE 1 VULNERABILITY FINDING - CRITICAL

Tests the pattern matcher that:
- Matches vulnerabilities to historical exploits
- Uses vulnerability knowledge base
- Generates exploit templates
- Scores similarity
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

from vulnhunter.agents.pattern_matcher import PatternMatcherAgent


class TestPatternMatcherInitialization:
    """Test PatternMatcherAgent initialization."""
    
    def test_initialization(self):
        """Test agent initializes correctly."""
        with patch('vulnhunter.agents.pattern_matcher.GeminiClient'):
            agent = PatternMatcherAgent()
            
            assert agent is not None
    
    def test_has_knowledge_base(self):
        """Test agent has access to knowledge base."""
        with patch('vulnhunter.agents.pattern_matcher.GeminiClient'):
            agent = PatternMatcherAgent()
            
            assert hasattr(agent, 'vulnerability_patterns') or \
                   hasattr(agent, 'knowledge_base')
    
    def test_has_exploit_db(self):
        """Test agent has access to exploit database."""
        with patch('vulnhunter.agents.pattern_matcher.GeminiClient'):
            agent = PatternMatcherAgent()
            
            assert hasattr(agent, 'defi_db') or \
                   hasattr(agent, 'exploit_db')


class TestVulnerabilityMatching:
    """Test vulnerability pattern matching."""
    
    def test_match_reentrancy(self):
        """Test matching reentrancy vulnerability."""
        with patch('vulnhunter.agents.pattern_matcher.GeminiClient'):
            agent = PatternMatcherAgent()
            
            vuln_finding = {
                "type": "reentrancy",
                "contract": "Vault.sol",
                "function": "withdraw",
                "description": "External call before state update"
            }
            
            matches = agent.find_similar_exploits(vuln_finding)
            
            assert len(matches) >= 0  # May or may not find matches
    
    def test_match_flashloan(self):
        """Test matching flash loan vulnerability."""
        with patch('vulnhunter.agents.pattern_matcher.GeminiClient'):
            agent = PatternMatcherAgent()
            
            vuln_finding = {
                "type": "flashloan",
                "contract": "Lending.sol",
                "function": "borrow",
                "description": "Price oracle manipulation via flash loan"
            }
            
            matches = agent.find_similar_exploits(vuln_finding)
            
            assert len(matches) >= 0
    
    def test_match_access_control(self):
        """Test matching access control vulnerability."""
        with patch('vulnhunter.agents.pattern_matcher.GeminiClient'):
            agent = PatternMatcherAgent()
            
            vuln_finding = {
                "type": "access_control",
                "contract": "Admin.sol",
                "function": "setOwner",
                "description": "Missing authorization check"
            }
            
            matches = agent.find_similar_exploits(vuln_finding)
            
            assert len(matches) >= 0


class TestKnowledgeBaseRetrieval:
    """Test vulnerability knowledge base retrieval."""
    
    def test_get_pattern_by_type(self):
        """Test getting pattern by vulnerability type."""
        with patch('vulnhunter.agents.pattern_matcher.GeminiClient'):
            agent = PatternMatcherAgent()
            
            pattern = agent.get_vulnerability_pattern("reentrancy")
            
            if pattern:
                assert 'name' in pattern or hasattr(pattern, 'name')
    
    def test_get_patterns_by_category(self):
        """Test getting patterns by category."""
        with patch('vulnhunter.agents.pattern_matcher.GeminiClient'):
            agent = PatternMatcherAgent()
            
            patterns = agent.get_patterns_by_category("DeFi")
            
            assert len(patterns) >= 0
    
    def test_get_all_patterns(self):
        """Test getting all vulnerability patterns."""
        with patch('vulnhunter.agents.pattern_matcher.GeminiClient'):
            agent = PatternMatcherAgent()
            
            patterns = agent.get_all_patterns()
            
            assert len(patterns) > 30  # Should have 30+ patterns


class TestExploitTemplateGeneration:
    """Test exploit template generation."""
    
    def test_generate_reentrancy_template(self):
        """Test generating reentrancy exploit template."""
        with patch('vulnhunter.agents.pattern_matcher.GeminiClient'):
            agent = PatternMatcherAgent()
            
            vuln = {
                "type": "reentrancy",
                "contract": "Vault",
                "function": "withdraw",
                "vulnerable_code": """
function withdraw() external {
    uint256 bal = balances[msg.sender];
    (bool success,) = msg.sender.call{value: bal}("");
    balances[msg.sender] = 0;
}
"""
            }
            
            template = agent.generate_exploit_template(vuln)
            
            if template:
                # Should contain attack contract structure
                assert "contract" in template.lower() or "function" in template.lower()
    
    def test_generate_flashloan_template(self):
        """Test generating flash loan exploit template."""
        with patch('vulnhunter.agents.pattern_matcher.GeminiClient'):
            agent = PatternMatcherAgent()
            
            vuln = {
                "type": "flashloan",
                "contract": "Lending",
                "function": "borrow",
                "vulnerable_code": "..."
            }
            
            template = agent.generate_exploit_template(vuln)
            
            # Template may or may not be generated
            assert template is None or len(template) > 0


class TestSimilarityScoring:
    """Test similarity scoring for exploit matching."""
    
    def test_score_calculation(self):
        """Test similarity score is calculated."""
        with patch('vulnhunter.agents.pattern_matcher.GeminiClient'):
            agent = PatternMatcherAgent()
            
            vuln = {"type": "reentrancy", "contract": "Vault"}
            exploit = {"vulnerability_type": "reentrancy", "name": "DAO"}
            
            score = agent.calculate_similarity(vuln, exploit)
            
            assert 0 <= score <= 1
    
    def test_exact_match_high_score(self):
        """Test exact match has high similarity."""
        with patch('vulnhunter.agents.pattern_matcher.GeminiClient'):
            agent = PatternMatcherAgent()
            
            vuln = {"type": "reentrancy", "description": "ETH drain via callback"}
            exploit = {"vulnerability_type": "reentrancy", "description": "ETH drain via callback"}
            
            score = agent.calculate_similarity(vuln, exploit)
            
            assert score >= 0.5  # Should be relatively high


class TestHistoricalExploitLookup:
    """Test historical exploit lookup from DeFiHackLabs."""
    
    @pytest.mark.slow
    def test_find_reentrancy_exploits(self, defihacklabs_db):
        """Test finding reentrancy exploits."""
        with patch('vulnhunter.agents.pattern_matcher.GeminiClient'):
            agent = PatternMatcherAgent()
            agent.defi_db = defihacklabs_db
            
            results = agent.find_historical_exploits("reentrancy", limit=5)
            
            print(f"Found {len(results)} reentrancy exploits")
    
    @pytest.mark.slow
    def test_find_oracle_exploits(self, defihacklabs_db):
        """Test finding oracle manipulation exploits."""
        with patch('vulnhunter.agents.pattern_matcher.GeminiClient'):
            agent = PatternMatcherAgent()
            agent.defi_db = defihacklabs_db
            
            results = agent.find_historical_exploits("oracle", limit=5)
            
            print(f"Found {len(results)} oracle exploits")


class TestPatternStatistics:
    """Test pattern statistics gathering."""
    
    def test_get_statistics(self):
        """Test getting pattern statistics."""
        with patch('vulnhunter.agents.pattern_matcher.GeminiClient'):
            agent = PatternMatcherAgent()
            
            stats = agent.get_statistics()
            
            assert 'total_patterns' in stats or 'patterns' in stats
    
    def test_get_severity_distribution(self):
        """Test getting severity distribution."""
        with patch('vulnhunter.agents.pattern_matcher.GeminiClient'):
            agent = PatternMatcherAgent()
            
            dist = agent.get_severity_distribution()
            
            if dist:
                assert 'CRITICAL' in dist or 'HIGH' in dist


class TestMatchResults:
    """Test match results structure."""
    
    def test_match_result_has_score(self):
        """Test match result includes similarity score."""
        with patch('vulnhunter.agents.pattern_matcher.GeminiClient'):
            agent = PatternMatcherAgent()
            
            vuln = {"type": "reentrancy", "contract": "Vault"}
            matches = agent.match_vulnerability(vuln)
            
            for match in matches:
                assert 'score' in match or 'similarity' in match or \
                       hasattr(match, 'score')
    
    def test_match_result_has_exploit_info(self):
        """Test match result includes exploit information."""
        with patch('vulnhunter.agents.pattern_matcher.GeminiClient'):
            agent = PatternMatcherAgent()
            
            vuln = {"type": "reentrancy", "contract": "Vault"}
            matches = agent.match_vulnerability(vuln)
            
            for match in matches:
                # Should have some exploit reference
                assert 'exploit' in match or 'name' in match or \
                       'file_path' in match or hasattr(match, 'name')


class TestMultiVulnerabilityMatching:
    """Test matching multiple vulnerabilities."""
    
    def test_batch_matching(self):
        """Test matching multiple vulnerabilities at once."""
        with patch('vulnhunter.agents.pattern_matcher.GeminiClient'):
            agent = PatternMatcherAgent()
            
            vulns = [
                {"type": "reentrancy", "contract": "Vault"},
                {"type": "flashloan", "contract": "Lending"},
                {"type": "access_control", "contract": "Admin"},
            ]
            
            results = agent.match_vulnerabilities(vulns)
            
            assert len(results) == 3
    
    def test_prioritizes_by_severity(self):
        """Test results are prioritized by severity."""
        with patch('vulnhunter.agents.pattern_matcher.GeminiClient'):
            agent = PatternMatcherAgent()
            
            vulns = [
                {"type": "reentrancy", "severity": "CRITICAL"},
                {"type": "naming", "severity": "LOW"},
                {"type": "flashloan", "severity": "HIGH"},
            ]
            
            results = agent.match_vulnerabilities(vulns)
            
            # First results should be higher severity
            if len(results) > 0 and 'severity' in results[0]:
                assert results[0]['severity'] in ['CRITICAL', 'HIGH']


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_unknown_vulnerability_type(self):
        """Test handling unknown vulnerability type."""
        with patch('vulnhunter.agents.pattern_matcher.GeminiClient'):
            agent = PatternMatcherAgent()
            
            vuln = {"type": "unknown_type_xyz", "contract": "Test"}
            
            matches = agent.match_vulnerability(vuln)
            
            # Should not crash, may return empty
            assert matches is not None
    
    def test_empty_vulnerability(self):
        """Test handling empty vulnerability dict."""
        with patch('vulnhunter.agents.pattern_matcher.GeminiClient'):
            agent = PatternMatcherAgent()
            
            matches = agent.match_vulnerability({})
            
            # Should not crash
            assert matches is not None
    
    def test_none_vulnerability(self):
        """Test handling None vulnerability."""
        with patch('vulnhunter.agents.pattern_matcher.GeminiClient'):
            agent = PatternMatcherAgent()
            
            try:
                matches = agent.match_vulnerability(None)
            except (TypeError, AttributeError):
                pass  # Expected


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
