"""
Agents Module - Smart Per-Contract Analysis

- ExploitAgent: Original SCONE-bench style
- ExploitAgentV2: Per-contract analysis with Slither + function graphs
- ExploitAgentV3: NEW! Clean separated phases (Phase 1: Analysis, Phase 2: Pattern Matching)
- ProtocolAnalyzer: Cross-contract analysis and context building
- ContractAnalyzer: Build function graphs and run Slither
- PatternMatcher: Historical exploit database (675+ exploits)
"""

from .base_agent import BaseAgent
from .exploit_agent import ExploitAgent
from .exploit_agent_v2 import ExploitAgentV2
from .exploit_agent_v3 import (
    ExploitAgentV3,
    ProtocolAnalysisReport,
    VulnerabilityFinding,
    HistoricalMatch,
    ExploitDevelopmentResult,
    AnalysisCheckpoint,
)
from .protocol_analyzer import ProtocolAnalyzer, ProtocolContext
from .contract_analyzer import ContractAnalyzer, ContractContext, FunctionInfo
from .pattern_matcher import PatternMatcherAgent

__all__ = [
    # Base
    "BaseAgent",
    
    # Main Agents
    "ExploitAgent",
    "ExploitAgentV2",  # Per-contract analysis
    "ExploitAgentV3",  # NEW: Clean separated phases
    
    # V3 Data Classes
    "ProtocolAnalysisReport",
    "VulnerabilityFinding", 
    "HistoricalMatch",
    "ExploitDevelopmentResult",
    "AnalysisCheckpoint",
    
    # Analysis
    "ProtocolAnalyzer",
    "ProtocolContext",
    "ContractAnalyzer",
    "ContractContext",
    "FunctionInfo",
    
    # Pattern Matching
    "PatternMatcherAgent",
]
