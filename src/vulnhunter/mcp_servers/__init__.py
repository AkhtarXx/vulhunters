"""
MCP Servers - SCONE-bench Style

Minimal tool set following Anthropic's SCONE-bench approach:
- Anvil: Blockchain forking with bash + file_editor tools

The agent uses bash to run forge, cast, slither, python, etc.
No need for separate MCP servers for each tool.
"""

__all__ = [
    "anvil_server",
]
