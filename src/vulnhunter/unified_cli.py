"""
🔥 VulnHunter v2.0 - Smart Per-Contract Analysis

Improved approach:
- Analyze ONE contract at a time
- Build function call graph
- Run Slither and filter output
- Agent uses bash to explore related code
- Combine findings at the end

Usage:
    vulnhunter audit 2025-12-panoptic/
    vulnhunter audit protocol/ --chain bsc
"""

import json
import asyncio
from pathlib import Path
from typing import Optional, Dict
from datetime import datetime

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from loguru import logger

# Import components
from vulnhunter.agents import ProtocolAnalyzer, PatternMatcherAgent
from vulnhunter.agents.exploit_agent_v2 import ExploitAgentV2
from vulnhunter.harness import ExploitValidator
from vulnhunter.gemini import get_client
from vulnhunter.config import settings

app = typer.Typer(
    name="vulnhunter",
    help="🔥 VulnHunter v2.0 - SCONE-bench Inspired Security Auditor",
    add_completion=False,
)
console = Console()


@app.command()
def audit(
    protocol_dir: Path = typer.Argument(
        ...,
        help="Protocol directory (with scope.txt or contracts/)",
        exists=True,
        dir_okay=True,
        file_okay=False,
    ),
    chain: str = typer.Option(
        "ethereum",
        "--chain", "-c",
        help="Blockchain to fork (ethereum, bsc, polygon, base)",
    ),
    timeout: int = typer.Option(
        60,
        "--timeout", "-t",
        help="Timeout per contract in minutes",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Output file path (default: protocol_name_audit_report.json)",
    ),
    test_exploits: bool = typer.Option(
        True,
        "--test-exploits/--no-test-exploits",
        help="Test exploits on forked blockchain",
    ),
):
    """
    🚀 SCONE-bench Style Protocol Security Audit
    
    This tool analyzes smart contract protocols for vulnerabilities
    and attempts to develop working exploits.
    
    Features:
        ✅ Cross-contract vulnerability detection
        ✅ Protocol dependency graph analysis
        ✅ Automatic exploit development
        ✅ Profit validation (≥0.1 ETH threshold)
        ✅ Historical exploit pattern matching (670+)
    
    Example:
        vulnhunter audit 2025-12-panoptic/
        vulnhunter audit protocol/ --chain bsc --timeout 90
    """
    
    # Banner
    console.print(Panel.fit(
        "[bold cyan]VulnHunter v2.0[/bold cyan] 🔥\n"
        "[bold green]SCONE-bench Inspired Auditor[/bold green]\n"
        f"[dim]Chain: {chain} | Timeout: {timeout}min[/dim]",
        border_style="cyan"
    ))
    
    # Run async audit
    asyncio.run(_run_scone_audit(
        protocol_dir=protocol_dir,
        chain=chain,
        timeout=timeout,
        output=output,
        test_exploits=test_exploits,
    ))


async def _run_scone_audit(
    protocol_dir: Path,
    chain: str,
    timeout: int,
    output: Optional[Path],
    test_exploits: bool,
):
    """Run SCONE-bench style protocol audit."""
    
    start_time = datetime.now()
    
    # ========== PHASE 1: PROTOCOL ANALYSIS ==========
    console.print("\n" + "="*60)
    console.print("[bold cyan]📊 PHASE 1: PROTOCOL ANALYSIS[/bold cyan]")
    console.print("="*60)
    
    # Analyze protocol structure
    analyzer = ProtocolAnalyzer(protocol_dir)
    protocol_context = analyzer.analyze_protocol()
    
    console.print(f"\n✅ Protocol: [bold]{protocol_context.protocol_name}[/bold]")
    console.print(f"   📄 Contracts in scope: {len(protocol_context.contracts)}")
    console.print(f"   🔗 Dependencies: {len(protocol_context.dependency_graph)}")
    console.print(f"   🛡️  Trust boundaries: {len(protocol_context.trust_boundaries)}")
    console.print(f"   💰 Fund flows: {len(protocol_context.fund_flows)}")
    console.print(f"   🌐 External protocols: {', '.join(protocol_context.external_protocols) or 'None'}")
    
    # Show contracts
    console.print("\n📋 [bold]In-Scope Contracts:[/bold]")
    for name, info in list(protocol_context.contracts.items())[:10]:
        console.print(f"   • {name}.sol ({info.lines} lines)")
    if len(protocol_context.contracts) > 10:
        console.print(f"   ... and {len(protocol_context.contracts) - 10} more")
    
    # ========== PHASE 2: START BLOCKCHAIN FORK ==========
    if test_exploits:
        console.print("\n" + "="*60)
        console.print("[bold cyan]⛓️  PHASE 2: BLOCKCHAIN FORK[/bold cyan]")
        console.print("="*60)
        
        console.print(f"\n🔄 Starting Anvil fork for {chain}...")
        
        # Start anvil via MCP or direct
        try:
            from vulnhunter.mcp import get_mcp
            mcp = get_mcp()
            mcp_servers_dir = Path(__file__).parent / "mcp_servers"
            mcp.add_client("anvil", str(mcp_servers_dir / "anvil_server.py"))
            mcp.add_client("uniswap", str(mcp_servers_dir / "uniswap_path_server.py"))
            await mcp.start_all()
            
            # Fork blockchain
            tools = await mcp.get_all_tools()
            console.print(f"   ✅ Anvil MCP ready: {len(tools)} tools available")
            
            # Call fork_blockchain tool
            fork_result = await mcp.call_tool("fork_blockchain", {
                "chain": chain,
            })
            console.print(f"   ✅ Forked {chain} at localhost:8545")
            
        except Exception as e:
            logger.warning(f"   ⚠️  Anvil fork failed: {e}")
            console.print(f"   ⚠️  Continuing without blockchain fork")
            mcp = None
    else:
        mcp = None
    
    # ========== PHASE 3: PATTERN MATCHING ==========
    console.print("\n" + "="*60)
    console.print("[bold cyan]📚 PHASE 3: HISTORICAL PATTERN MATCHING[/bold cyan]")
    console.print("="*60)
    
    try:
        pattern_matcher = PatternMatcherAgent()
        stats = pattern_matcher.get_statistics()
        console.print(f"\n✅ Loaded {stats['total_exploits']} historical exploits")
        console.print(f"   📊 Categories: {', '.join(list(stats.get('by_type', {}).keys())[:5])}")
    except Exception as e:
        logger.warning(f"Pattern matcher failed: {e}")
        pattern_matcher = None
        console.print("   ⚠️  Pattern matching unavailable")
    
    # ========== PHASE 4: EXPLOIT AGENT ==========
    console.print("\n" + "="*60)
    console.print("[bold cyan]🔥 PHASE 4: PER-CONTRACT ANALYSIS[/bold cyan]")
    console.print("="*60)
    
    # Initialize ExploitAgentV2 (analyzes one contract at a time)
    exploit_agent = ExploitAgentV2(timeout_minutes=timeout)
    
    # Get all contract sources with paths
    contracts_with_paths = {}
    for name, info in protocol_context.contracts.items():
        contracts_with_paths[name] = (info.source_code, info.path)
    
    console.print(f"\n🤖 ExploitAgentV2 analyzing {len(contracts_with_paths)} contracts...")
    console.print(f"   ⏱️  Timeout: {timeout} minutes per contract")
    console.print(f"   ⛓️  Chain: {chain}")
    console.print(f"   🔍 Slither: enabled")
    console.print(f"\n   📊 Per-contract approach:")
    console.print(f"      1. Build function call graph")
    console.print(f"      2. Run Slither (filtered output)")
    console.print(f"      3. Identify cross-contract calls")
    console.print(f"      4. Agent analyzes with bash exploration")
    
    # Run analysis
    result = {}
    try:
        result = await exploit_agent.analyze_protocol(
            project_root=protocol_dir.absolute(),
            contracts=contracts_with_paths,
            chain=chain,
            run_slither=True,
        )
        
        # ========== PHASE 5: VALIDATE EXPLOITS ==========
        if test_exploits and result.get("exploits_developed"):
            console.print("\n" + "="*60)
            console.print("[bold cyan]🎯 PHASE 5: EXPLOIT VALIDATION[/bold cyan]")
            console.print("="*60)
            
            validator = ExploitValidator()
            
            for exploit in result.get("exploits_developed", []):
                if exploit.get("exploit_command"):
                    console.print(f"\n🧪 Testing exploit for: {exploit.get('vulnerability_id')}")
                    
                    validation = await validator.run_exploit_and_validate(
                        exploit_command=exploit["exploit_command"],
                        chain=chain,
                    )
                    
                    exploit["validation"] = validation
                    console.print(ExploitValidator.format_result(validation))

    except KeyboardInterrupt:
        console.print("\n\n[bold yellow]⚠️  AUDIT INTERRUPTED BY USER (Ctrl+C)[/bold yellow]")
        console.print("[dim]Saving partial results and generating report...[/dim]")
        
        # Compile partial report
        elapsed = (datetime.now() - start_time).total_seconds() / 60
        result = exploit_agent._compile_report(elapsed)
        
    except Exception as e:
        console.print(f"\n\n[bold red]❌ Unexpected error during audit: {e}[/bold red]")
        console.print("[dim]Attempting to save partial results...[/dim]")
        logger.exception("Audit failed")
        
        # Compile partial report
        elapsed = (datetime.now() - start_time).total_seconds() / 60
        result = exploit_agent._compile_report(elapsed)
    
    # ========== PHASE 5: VALIDATE EXPLOITS ==========
    if test_exploits and result.get("exploits_developed"):
        console.print("\n" + "="*60)
        console.print("[bold cyan]🎯 PHASE 5: EXPLOIT VALIDATION[/bold cyan]")
        console.print("="*60)
        
        validator = ExploitValidator()
        
        for exploit in result.get("exploits_developed", []):
            if exploit.get("exploit_command"):
                console.print(f"\n🧪 Testing exploit for: {exploit.get('vulnerability_id')}")
                
                validation = await validator.run_exploit_and_validate(
                    exploit_command=exploit["exploit_command"],
                    chain=chain,
                )
                
                exploit["validation"] = validation
                console.print(ExploitValidator.format_result(validation))
    
    # ========== PHASE 6: GENERATE REPORT ==========
    console.print("\n" + "="*60)
    console.print("[bold cyan]📝 PHASE 6: REPORT GENERATION[/bold cyan]")
    console.print("="*60)
    
    # Build final report
    elapsed = (datetime.now() - start_time).total_seconds() / 60
    
    report = {
        "protocol": protocol_context.protocol_name,
        "chain": chain,
        "analyzed_at": datetime.now().isoformat(),
        "elapsed_minutes": round(elapsed, 2),
        "contracts_analyzed": len(contracts_with_paths),
        "vulnerabilities": result.get("vulnerabilities", []),
        "exploits_developed": result.get("exploits_developed", []),
        "summary": result.get("summary", {}),
        "protocol_context": {
            "scope_files": protocol_context.scope_files,
            "trust_boundaries": protocol_context.trust_boundaries,
            "fund_flows": protocol_context.fund_flows,
            "external_protocols": protocol_context.external_protocols,
        },
    }
    
    # Save JSON report
    output_file = output or Path(f"{protocol_context.protocol_name}_audit_report.json")
    output_file.write_text(json.dumps(report, indent=2, default=str))
    console.print(f"\n✅ JSON report: {output_file}")
    
    # Save Markdown report
    md_file = output_file.with_suffix(".md")
    _generate_markdown_report(report, md_file)
    console.print(f"✅ Markdown report: {md_file}")
    
    # ========== SUMMARY ==========
    _display_summary(report)
    
    # Cleanup
    if mcp:
        try:
            await mcp.stop_all()
        except:
            pass


def _generate_markdown_report(report: Dict, output_file: Path):
    """Generate comprehensive Markdown report."""
    
    lines = []
    lines.append(f"# {report['protocol']} Security Audit Report\n")
    lines.append(f"**Generated by VulnHunter v2.0** (SCONE-bench Inspired)\n")
    lines.append(f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    lines.append(f"**Chain**: {report['chain']}\n")
    lines.append(f"**Contracts Analyzed**: {report['contracts_analyzed']}\n")
    lines.append(f"**Time Elapsed**: {report['elapsed_minutes']:.1f} minutes\n")
    lines.append("\n---\n")
    
    # Summary
    summary = report.get("summary", {})
    lines.append("## Executive Summary\n")
    lines.append(f"- **Total Vulnerabilities**: {summary.get('total_vulnerabilities', 0)}\n")
    lines.append(f"- **Critical**: {summary.get('critical', 0)}\n")
    lines.append(f"- **High**: {summary.get('high', 0)}\n")
    lines.append(f"- **Medium**: {summary.get('medium', 0)}\n")
    lines.append(f"- **Exploits Developed**: {summary.get('exploits_successful', 0)}\n")
    lines.append(f"- **Total Profit (ETH)**: {summary.get('total_profit_eth', 0):.4f}\n")
    lines.append("\n---\n")
    
    # Protocol Context
    ctx = report.get("protocol_context", {})
    lines.append("## Protocol Analysis\n")
    
    lines.append("### Trust Boundaries\n")
    for boundary in ctx.get("trust_boundaries", [])[:10]:
        lines.append(f"- {boundary}\n")
    
    lines.append("\n### Fund Flows\n")
    for flow in ctx.get("fund_flows", [])[:10]:
        lines.append(f"- {flow}\n")
    
    lines.append("\n### External Protocols\n")
    for ext in ctx.get("external_protocols", []):
        lines.append(f"- {ext}\n")
    
    lines.append("\n---\n")
    
    # Vulnerabilities
    lines.append("## Vulnerabilities Found\n")
    
    vulns = report.get("vulnerabilities", [])
    if vulns:
        for idx, vuln in enumerate(vulns, 1):
            severity = vuln.get("severity", "UNKNOWN")
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
            
            lines.append(f"### {idx}. {vuln.get('title', 'Untitled')} {emoji}\n")
            lines.append(f"**Severity**: {severity}\n")
            lines.append(f"**Type**: {vuln.get('type', 'Unknown')}\n")
            lines.append(f"**Contracts**: {', '.join(vuln.get('contracts_involved', []))}\n")
            lines.append(f"\n**Description**:\n{vuln.get('description', 'No description')}\n")
            lines.append(f"\n**Root Cause**:\n{vuln.get('root_cause', 'Unknown')}\n")
            lines.append(f"\n**Attack Vector**:\n{vuln.get('attack_vector', 'Unknown')}\n")
            lines.append("\n---\n")
    else:
        lines.append("No vulnerabilities found.\n")
    
    # Exploits
    lines.append("## Exploits Developed\n")
    
    exploits = report.get("exploits_developed", [])
    if exploits:
        for idx, exploit in enumerate(exploits, 1):
            lines.append(f"### Exploit {idx}: {exploit.get('vulnerability_id', 'Unknown')}\n")
            lines.append(f"**Success**: {'✅' if exploit.get('success') else '❌'}\n")
            
            if exploit.get("validation"):
                val = exploit["validation"]
                lines.append(f"**Profit**: {val.get('profit_eth', 0):.4f} ETH (${val.get('profit_usd', 0):,.2f})\n")
            
            if exploit.get("explanation"):
                lines.append(f"\n**How it works**:\n{exploit['explanation']}\n")
            
            lines.append("\n---\n")
    else:
        lines.append("No exploits developed.\n")
    
    output_file.write_text("".join(lines))


def _display_summary(report: Dict):
    """Display final summary table."""
    console.print("\n" + "="*60)
    console.print("[bold cyan]📊 AUDIT SUMMARY[/bold cyan]")
    console.print("="*60)
    
    summary = report.get("summary", {})
    
    table = Table()
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")
    
    table.add_row("Contracts Analyzed", str(report.get("contracts_analyzed", 0)))
    table.add_row("Total Vulnerabilities", str(summary.get("total_vulnerabilities", 0)))
    table.add_row("Critical", f"🔴 {summary.get('critical', 0)}")
    table.add_row("High", f"🟠 {summary.get('high', 0)}")
    table.add_row("Medium", f"🟡 {summary.get('medium', 0)}")
    table.add_row("Exploits Successful", str(summary.get("exploits_successful", 0)))
    table.add_row("Total Profit (ETH)", f"{summary.get('total_profit_eth', 0):.4f}")
    table.add_row("Time Elapsed", f"{report.get('elapsed_minutes', 0):.1f} min")
    
    console.print(table)
    
    # Final verdict
    vulns = summary.get("total_vulnerabilities", 0)
    critical = summary.get("critical", 0)
    
    if critical > 0:
        console.print("\n[bold red]🚨 CRITICAL VULNERABILITIES FOUND![/bold red]")
    elif vulns > 0:
        console.print("\n[bold yellow]⚠️  Vulnerabilities found - review recommended[/bold yellow]")
    else:
        console.print("\n[bold green]✅ No vulnerabilities detected[/bold green]")


@app.command()
def version():
    """Show VulnHunter version."""
    console.print("[cyan]VulnHunter v2.0[/cyan] - SCONE-bench Inspired Security Auditor")
    console.print("[dim]Based on Anthropic's smart contract exploitation research[/dim]")


@app.command()
def quick(
    contract_file: Path = typer.Argument(
        ...,
        help="Single Solidity contract file",
        exists=True,
    ),
):
    """
    Quick single-contract scan.
    
    Fast vulnerability detection for a single contract without full protocol analysis.
    
    Example:
        vulnhunter quick contracts/Token.sol
    """
    console.print(Panel.fit(
        "[bold cyan]VulnHunter Quick Scan[/bold cyan] ⚡",
        border_style="cyan"
    ))
    
    asyncio.run(_quick_scan(contract_file))


async def _quick_scan(contract_file: Path):
    """Quick single-contract scan."""
    
    contract_code = contract_file.read_text()
    contract_name = contract_file.stem
    
    console.print(f"\n📄 Contract: {contract_name}")
    console.print(f"   Lines: {len(contract_code.splitlines())}")
    
    # Quick scan with ExploitAgent
    agent = ExploitAgent()
    result = await agent.quick_scan(contract_code, contract_name)
    
    # Display results
    console.print("\n" + "="*60)
    console.print("[bold cyan]🔍 QUICK SCAN RESULTS[/bold cyan]")
    console.print("="*60)
    
    vulns = result.get("vulnerabilities", [])
    if vulns:
        for vuln in vulns:
            severity = vuln.get("severity", "UNKNOWN")
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠"}.get(severity, "⚪")
            
            console.print(f"\n{emoji} [bold]{vuln.get('title', 'Unknown')}[/bold]")
            console.print(f"   Type: {vuln.get('type', 'Unknown')}")
            console.print(f"   Location: {vuln.get('location', 'Unknown')}")
            console.print(f"   Quick Exploit: {vuln.get('quick_exploit', 'N/A')}")
    else:
        console.print("\n✅ No critical/high vulnerabilities detected in quick scan")
        console.print("[dim]For deep analysis, use: vulnhunter audit <protocol_dir>[/dim]")


if __name__ == "__main__":
    app()
