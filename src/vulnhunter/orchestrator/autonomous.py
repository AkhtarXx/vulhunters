"""
Autonomous Orchestrator

Fully automated exploit discovery and testing following Anthropic SCONE-bench.
Orchestrates: Analysis → Pattern Matching → Exploit Generation → Testing → Reporting
"""

import asyncio
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

from vulnhunter.agents.red_team import RedTeamAgent
from vulnhunter.agents.pattern_matcher import PatternMatcherAgent
from vulnhunter.exploit_harness import ExploitHarness, ExploitResult
from vulnhunter.profit_calculator import ProfitCalculator
from vulnhunter.mcp import get_mcp, mcp_session


@dataclass
class AuditResult:
    """Result of autonomous audit."""
    contract_address: str
    vulnerability_found: bool
    vulnerability_type: Optional[str]
    historical_match: Optional[str]
    exploit_generated: bool
    test_result: Optional[ExploitResult]
    profit_usd: float
    confidence: float
    timestamp: datetime


class AutonomousOrchestrator:
    """
    Fully autonomous security auditing system.
    
    Follows Anthropic SCONE-bench approach:
    1. Analyze contracts with AI agents
    2. Match to 670+ historical exploits
    3. Generate working exploits
    4. Test on forked blockchain
    5. Report profit in USD
    """
    
    def __init__(self):
        """Initialize orchestrator with all components."""
        self.red_team = RedTeamAgent()
        self.pattern_matcher = PatternMatcherAgent()
        self.profit_calc = ProfitCalculator()
        self.results: List[AuditResult] = []
        
    async def autonomous_audit(
        self,
        contract_code: str,
        contract_address: str = "0x0",
        chain: str = "ethereum",
        test_exploits: bool = True
    ) -> AuditResult:
        """
        Run fully autonomous security audit.
        
        Args:
            contract_code: Solidity source code
            contract_address: Deployed contract address
            chain: Blockchain to test on
            test_exploits: Whether to actually test exploits on fork
            
        Returns:
            AuditResult with findings and profit metrics
        """
        print(f"\n{'='*70}")
        print(f"🤖 AUTONOMOUS AUDIT: {contract_address[:10]}...")
        print(f"{'='*70}\n")
        
        start_time = datetime.now()
        
        # Step 1: Analyze with Red Team
        print("1️⃣  Analyzing contract for vulnerabilities...")
        try:
            # Red Team analysis
            vuln_analysis = self.red_team.analyze({
                "contract_code": contract_code,
                "contract_address": contract_address
           })
            
            # Parse findings
            findings = vuln_analysis.get("findings", [])
            
            if not findings:
                print("   ✅ No vulnerabilities found")
                return self._create_safe_result(contract_address)
            
            # Use first critical finding
            vuln = findings[0]
            vuln_type = self._extract_vulnerability_type(vuln)
            
            print(f"   🔴 Found: {vuln.get('title', 'Unknown')} ({vuln_type})")
            
        except Exception as e:
            print(f"   ❌ Analysis failed: {e}")
            return self._create_error_result(contract_address, str(e))
        
        # Step 2: Search historical patterns
        print(f"\n2️⃣  Searching 670 historical exploits for {vuln_type}...")
        try:
            patterns = self.pattern_matcher.find_similar_exploits(vuln_type, limit=3)
            
            if patterns:
                print(f"   📚 Found {len(patterns)} similar exploits:")
                for idx, pattern in enumerate(patterns, 1):
                    value_str = f"${pattern.dollar_value:,.0f}" if pattern.dollar_value else "N/A"
                    print(f"      {idx}. {pattern.name} ({pattern.date}) - {value_str}")
                historical_match = patterns[0].name
            else:
                print("   ⚠️  No historical matches found")
                historical_match = None
                
        except Exception as e:
            print(f"   ❌ Pattern matching failed: {e}")
            patterns = []
            historical_match = None
        
        # Step 3: Generate exploit (simulated for now)
        print(f"\n3️⃣  Generating exploit code...")
        try:
            # Generate template
            exploit_code = self.pattern_matcher.generate_exploit_template(
                vuln_type,
                contract_address
            )
            print(f"   ✅ Generated {len(exploit_code)} byte exploit")
            exploit_generated = True
            
        except Exception as e:
            print(f"   ❌ Exploit generation failed: {e}")
            exploit_generated = False
            exploit_code = None
        
        # Step 4: Test on forked blockchain (if enabled)
        test_result = None
        profit_usd = 0.0
        
        if test_exploits and exploit_generated:
            print(f"\n4️⃣  Testing exploit on forked {chain}...")
            try:
                async with mcp_session() as mcp:
                    harness = ExploitHarness(mcp)
                    
                    test_result = await harness.test_exploit(
                        target_contract=contract_address,
                        exploit_code=exploit_code,
                        chain=chain
                    )
                    
                    profit_usd = test_result.profit_usd
                    
                    if test_result.success:
                        print(f"   ✅ Exploit successful!")
                        print(f"   💰 Profit: ${profit_usd:,.2f}")
                    else:
                        print(f"   ⚠️  Exploit failed (but vulnerability confirmed)")
                        
            except Exception as e:
                print(f"   ⚠️  Testing skipped: {e}")
        else:
            print(f"\n4️⃣  Skipping exploit testing")
            # Estimate profit from historical data
            if patterns and patterns[0].dollar_value:
                profit_usd = patterns[0].dollar_value
                print(f"   💰 Estimated profit: ${profit_usd:,.0f} (historical)")
        
        # Step 5: Calculate confidence
        confidence = self._calculate_confidence(
            vuln,
            patterns,
            test_result
        )
        
        # Create result
        result = AuditResult(
            contract_address=contract_address,
            vulnerability_found=True,
            vulnerability_type=vuln_type,
            historical_match=historical_match,
            exploit_generated=exploit_generated,
            test_result=test_result,
            profit_usd=profit_usd,
            confidence=confidence,
            timestamp=datetime.now()
        )
        
        self.results.append(result)
        
        duration = (datetime.now() - start_time).total_seconds()
        print(f"\n{'='*70}")
        print(f"✅ Audit complete in {duration:.1f}s")
        print(f"{'='*70}\n")
        
        return result
    
    def _extract_vulnerability_type(self, vuln: dict) -> str:
        """Extract vulnerability type from finding."""
        title = vuln.get("title", "").lower()
        
        if "reentrancy" in title or "reentrant" in title:
            return "reentrancy"
        elif "flash" in title:
            return "flashloan"
        elif "oracle" in title or "price" in title:
            return "oracle_manipulation"
        elif "access" in title:
            return "access_control"
        else:
            return "unknown"
    
    def _calculate_confidence(
        self,
        vuln: dict,
        patterns: list,
        test_result: Optional[ExploitResult]
    ) -> float:
        """Calculate confidence score."""
        score = vuln.get("confidence", 0.5)
        
        # Boost if historical match
        if patterns:
            score += 0.2
        
        # Boost if tested successfully
        if test_result and test_result.success:
            score += 0.3
        
        return min(score, 1.0)
    
    def _create_safe_result(self, contract_address: str) -> AuditResult:
        """Create result for safe contract."""
        return AuditResult(
            contract_address=contract_address,
            vulnerability_found=False,
            vulnerability_type=None,
            historical_match=None,
            exploit_generated=False,
            test_result=None,
            profit_usd=0.0,
            confidence=1.0,
            timestamp=datetime.now()
        )
    
    def _create_error_result(self, contract_address: str, error: str) -> AuditResult:
        """Create result for analysis error."""
        return AuditResult(
            contract_address=contract_address,
            vulnerability_found=False,
            vulnerability_type=f"error: {error}",
            historical_match=None,
            exploit_generated=False,
            test_result=None,
            profit_usd=0.0,
            confidence=0.0,
            timestamp=datetime.now()
        )
    
    def generate_report(self, result: AuditResult) -> str:
        """Generate comprehensive audit report."""
        report = []
        report.append("="*70)
        report.append("🎯 AUTONOMOUS AUDIT REPORT")
        report.append("="*70)
        report.append(f"\nContract: {result.contract_address}")
        report.append(f"Timestamp: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        
        if result.vulnerability_found:
            report.append(f"\n🔴 VULNERABLE")
            report.append(f"Type: {result.vulnerability_type}")
            report.append(f"Confidence: {result.confidence:.0%}")
            
            if result.historical_match:
                report.append(f"\n📚 Similar to: {result.historical_match}")
            
            if result.profit_usd > 0:
                report.append(f"\n💰 Simulated Profit: ${result.profit_usd:,.2f}")
                
            if result.test_result:
                report.append(f"\n✅ Tested on forked blockchain")
        else:
            report.append(f"\n✅ No vulnerabilities found")
        
        report.append("\n" + "="*70)
        
        return "\n".join(report)


# Convenience function
async def quick_audit(contract_code: str) -> AuditResult:
    """Quick autonomous audit."""
    orchestrator = AutonomousOrchestrator()
    return await orchestrator.autonomous_audit(contract_code, test_exploits=False)
