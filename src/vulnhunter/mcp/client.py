"""
Model Context Protocol (MCP) Client - REFACTORED v2

Enables agents to connect to external tools (Slither, Foundry, Anvil) via MCP.
Uses stdio transport to communicate with MCP servers.

FIXED: Proper async context manager lifecycle management per 2025-2026 MCP SDK docs.
"""

import asyncio
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from google.genai import types
from loguru import logger

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    MCP_AVAILABLE = True
except ImportError:
    logger.warning("MCP SDK not installed. Run: pip install mcp")
    MCP_AVAILABLE = False


class MCPClient:
    """Client for a single MCP server using stdio transport."""
    
    def __init__(self, name: str, server_script: Path):
        """
        Initialize MCP client for a stdio server.
        
        Args:
            name: Server name (e.g. "slither")
            server_script: Path to Python server script
        """
        self.name = name
        self.server_script = server_script
        self.session: Optional[ClientSession] = None
        self._stdio_context = None
        self._session_context = None
        self._tools_cache: List[types.Tool] = []
        
    async def connect(self):
        """Start the MCP server process and establish connection."""
        if not MCP_AVAILABLE:
            raise ImportError("MCP SDK not available")
            
        if not self.server_script.exists():
            raise FileNotFoundError(f"MCP server script not found: {self.server_script}")
        
        logger.info(f"🔌 Starting MCP server: {self.name}")
        
        try:
            # Create stdio server parameters
            server_params = StdioServerParameters(
                command=sys.executable,
                args=[str(self.server_script)],
                env=None,
            )
            
            # stdio_client is an async context manager - enter it
            self._stdio_context = stdio_client(server_params)
            read_stream, write_stream = await self._stdio_context.__aenter__()
            
            # Create and enter session context manager
            self._session_context = ClientSession(read_stream, write_stream)
            self.session = await self._session_context.__aenter__()
            
            # Initialize the session
            await self.session.initialize()
            
            logger.info(f"✅ MCP server {self.name} connected")
            
        except Exception as e:
            logger.error(f"❌ Failed to start MCP server {self.name}: {e}")
            # Clean up if connection failed
            await self._cleanup()
            raise

    async def _cleanup(self):
        """Clean up context managers."""
        if self._session_context:
            try:
                await self._session_context.__aexit__(None, None, None)
            except:
                pass
        if self._stdio_context:
            try:
                await self._stdio_context.__aexit__(None, None, None)
            except:
                pass

    async def get_tools(self) -> List[types.Tool]:
        """Get tools from the MCP server and convert to Gemini format."""
        if not self.session:
            raise RuntimeError(f"MCP client {self.name} not connected")
        
        if self._tools_cache:
            return self._tools_cache
        
        try:
            response = await self.session.list_tools()
            
            gemini_tools = []
            for mcp_tool in response.tools:
                func_decl = types.FunctionDeclaration(
                    name=mcp_tool.name,
                    description=mcp_tool.description or f"Tool: {mcp_tool.name}",
                    parameters=self._convert_schema(mcp_tool.inputSchema),
                )
                
                tool = types.Tool(function_declarations=[func_decl])
                gemini_tools.append(tool)
            
            self._tools_cache = gemini_tools
            logger.info(f"📋 Loaded {len(gemini_tools)} tools from {self.name}")
            
            return gemini_tools
            
        except Exception as e:
            logger.error(f"Failed to get tools from {self.name}: {e}")
            return []
    
    def _convert_schema(self, mcp_schema: dict) -> types.Schema:
        """Convert MCP JSON schema to Gemini Schema."""
        if not mcp_schema:
            return types.Schema(type="OBJECT", properties={})
        
        properties = {}
        for prop_name, prop_schema in mcp_schema.get("properties", {}).items():
            prop_type = prop_schema.get("type", "string").upper()
            
            type_mapping = {
                "STRING": "STRING",
                "INTEGER": "INTEGER",
                "NUMBER": "NUMBER",
                "BOOLEAN": "BOOLEAN",
                "ARRAY": "ARRAY",
                "OBJECT": "OBJECT",
            }
            
            gemini_type = type_mapping.get(prop_type, "STRING")
            
            schema_args = {
                "type": gemini_type,
                "description": prop_schema.get("description", ""),
            }
            
            if "enum" in prop_schema:
                schema_args["enum"] = prop_schema["enum"]
            
            if gemini_type == "ARRAY" and "items" in prop_schema:
                schema_args["items"] = self._convert_schema(prop_schema["items"])
            
            properties[prop_name] = types.Schema(**schema_args)
        
        return types.Schema(
            type="OBJECT",
            properties=properties,
            required=mcp_schema.get("required", []),
        )

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any], timeout: float = 120.0) -> Any:
        """Call a tool on the MCP server with timeout.
        
        Args:
            tool_name: Name of the tool to call
            arguments: Tool arguments
            timeout: Max seconds to wait (default: 120s for slither/analysis tools)
        """
        if not self.session:
            raise RuntimeError(f"MCP client {self.name} not connected")
        
        try:
            logger.info(f"🛠️ Calling {self.name}.{tool_name}() (timeout: {timeout}s)")
            
            # Wrap in timeout to prevent hanging
            response = await asyncio.wait_for(
                self.session.call_tool(tool_name, arguments),
                timeout=timeout
            )
            
            if hasattr(response, 'content') and response.content:
                result_text = ""
                for content in response.content:
                    if hasattr(content, 'text'):
                        result_text += content.text
                
                try:
                    import json
                    return json.loads(result_text)
                except json.JSONDecodeError:
                    return {"result": result_text}
            else:
                return {"result": "No output"}
                
        except asyncio.TimeoutError:
            logger.warning(f"⏰ Tool {tool_name} timed out after {timeout}s")
            return {"error": f"Tool timed out after {timeout}s", "timeout": True}
        except Exception as e:
            logger.error(f"Tool execution failed: {e}")
            return {"error": str(e)}

    async def disconnect(self):
        """Disconnect from MCP server."""
        try:
            await self._cleanup()
            logger.info(f"🛑 MCP server {self.name} disconnected")
        except Exception as e:
            logger.error(f"Error disconnecting {self.name}: {e}")


class MCPOrchestrator:
    """Manages multiple MCP clients."""
    
    def __init__(self):
        self.clients: Dict[str, MCPClient] = {}
        self._servers_dir = Path(__file__).parent.parent / "mcp_servers"
        
    def add_client(self, name: str, server_script: str):
        """Add an MCP client."""
        script_path = Path(server_script)
        if not script_path.is_absolute():
            script_path = self._servers_dir / server_script
        
        client = MCPClient(name, script_path)
        self.clients[name] = client
        logger.info(f"Registered MCP client: {name} -> {script_path}")
        
    async def start_all(self):
        """Connect to all registered MCP servers."""
        if not MCP_AVAILABLE:
            logger.warning("MCP SDK not available, skipping server connections")
            return
        
        for name, client in self.clients.items():
            try:
                await client.connect()
            except Exception as e:
                logger.error(f"Failed to start {name}: {e}")
                
    async def get_all_tools(self) -> List[types.Tool]:
        """Get tools from all connected servers."""
        all_tools = []
        for client in self.clients.values():
            if client.session:
                tools = await client.get_tools()
                all_tools.extend(tools)
        return all_tools
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Find capable client and call the tool."""
        for client in self.clients.values():
            if not client.session:
                continue
            
            tools = await client.get_tools()
            tool_names = [
                decl.name
                for tool in tools
                for decl in tool.function_declarations
            ]
            
            if tool_name in tool_names:
                return await client.call_tool(tool_name, arguments)
        
        raise ValueError(f"No MCP client found for tool: {tool_name}")
        
    async def stop_all(self):
        """Disconnect from all MCP servers."""
        for client in self.clients.values():
            await client.disconnect()
        # Reset clients so they can be reconnected
        for client in self.clients.values():
            client.session = None
            client._stdio_context = None
            client._session_context = None
            client._tools_cache = []


# Singleton instance
_mcp_orchestrator: Optional[MCPOrchestrator] = None


def get_mcp() -> MCPOrchestrator:
    """Get or create MCP orchestrator singleton."""
    global _mcp_orchestrator
    if _mcp_orchestrator is None:
        _mcp_orchestrator = MCPOrchestrator()
        
        # Auto-register anvil MCP server (SCONE-bench style - only anvil with bash+file_editor)
        servers_dir = Path(__file__).parent.parent / "mcp_servers"
        if servers_dir.exists():
            server_files = {
                "anvil": "anvil_server.py",  # Blockchain forking with bash + file_editor
            }
            
            for name, filename in server_files.items():
                server_path = servers_dir / filename
                if server_path.exists():
                    _mcp_orchestrator.add_client(name, str(server_path))
    
    return _mcp_orchestrator


@asynccontextmanager
async def mcp_session():
    """Context manager for MCP session lifecycle."""
    mcp = get_mcp()
    try:
        await mcp.start_all()
        yield mcp
    finally:
        await mcp.stop_all()
