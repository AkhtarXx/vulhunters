"""
MCP (Model Context Protocol) integration for VulnHunter.

Connects AI agents to external security tools via MCP servers.
"""

from .client import MCPClient, MCPOrchestrator, get_mcp, mcp_session

__all__ = ["MCPClient", "MCPOrchestrator", "get_mcp", "mcp_session"]
