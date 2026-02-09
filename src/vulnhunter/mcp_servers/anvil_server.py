#!/usr/bin/env python3
"""
Anvil MCP Server

Exposes blockchain forking capabilities via Model Context Protocol.
Allows AI agents to fork Ethereum/BSC/Polygon for safe exploit testing.

Based on Anthropic's SCONE-bench approach for smart contract exploitation.
"""

import asyncio
import json
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent


app = Server("anvil-blockchain-forker")

# Global state for anvil process management
_anvil_process: Optional[subprocess.Popen] = None
_current_chain: Optional[str] = None
_current_block: Optional[int] = None
_rpc_url = "http://localhost:8545"


# RPC endpoints
# Using Alchemy for Ethereum (premium, faster, more reliable)
RPC_ENDPOINTS = {
    "ethereum": "https://eth-mainnet.g.alchemy.com/v2/9FC_MfmgPpgfbXb1SIVxs",  # Alchemy API
    "bsc": "https://bsc-dataseed.binance.org",  # Free BSC node
    "polygon": "https://polygon-rpc.com",  # Free Polygon node
    "base": "https://mainnet.base.org",  # Free Base node
}


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available Anvil blockchain forking tools."""
    return [
        # ========== ANTHROPIC-STYLE CORE TOOLS ==========
        Tool(
            name="bash",
            description=(
                "Execute bash commands in a persistent shell session. "
                "Use this to run Foundry commands (forge, cast, anvil), Python scripts, "
                "grep/cat for file inspection, or any other bash operation. "
                "This is the main tool for flexible blockchain interaction."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Bash command to execute (e.g., 'forge test', 'cast balance 0x...')",
                    },
                },
                "required": ["command"],
            },
        ),
        Tool(
            name="file_editor",
            description=(
                "Perform CRUD operations on files. Create exploit contracts, "
                "edit Solidity files, write test scripts, or save results. "
                "Essential for writing and modifying smart contract code."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "operation": {
                        "type": "string",
                        "enum": ["read", "write", "append", "delete"],
                        "description": "File operation to perform",
                    },
                    "path": {
                        "type": "string",
                        "description": "File path (relative or absolute)",
                    },
                    "content": {
                        "type": "string",
                        "description": "Content to write/append (required for write/append operations)",
                    },
                },
                "required": ["operation", "path"],
            },
        ),
        # ========== SPECIFIC HELPER TOOLS ==========
        Tool(
            name="fork_blockchain",
            description=(
                "Fork a live blockchain (Ethereum, BSC, Polygon, Base) at a specific block number. "
                "Creates a local blockchain fork at localhost:8545 with exact on-chain state. "
                "Perfect for testing exploits safely without affecting the real chain. "
                "Returns RPC URL and fork details."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "chain": {
                        "type": "string",
                        "enum": ["ethereum", "bsc", "polygon", "base"],
                        "description": "Blockchain to fork (ethereum, bsc, polygon, or base)",
                    },
                    "block_number": {
                        "type": "integer",
                        "description": "Specific block number to fork at (optional, uses latest if not specified)",
                    },
                    "port": {
                        "type": "integer",
                        "description": "Port to run forked node on (default: 8545)",
                        "default": 8545,
                    },
                },
                "required": ["chain"],
            },
        ),
        Tool(
            name="get_balance",
            description=(
                "Get native token balance (ETH/BNB/MATIC) for an address on the forked blockchain. "
                "Can also query ERC20 token balances by providing token contract address."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Ethereum address to query (0x...)",
                    },
                    "token_address": {
                        "type": "string",
                        "description": "ERC20 token contract address (optional, queries native token if not provided)",
                    },
                },
                "required": ["address"],
            },
        ),
        Tool(
            name="call_contract",
            description=(
                "Make a read-only call to a contract function on the forked blockchain. "
                "Use this to query contract state without modifying it."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "contract_address": {
                        "type": "string",
                        "description": "Contract address to call",
                    },
                    "function_signature": {
                        "type": "string",
                        "description": "Function signature (e.g., 'balanceOf(address)(uint256)')",
                    },
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Function arguments as array of strings",
                        "default": [],
                    },
                },
                "required": ["contract_address", "function_signature"],
            },
        ),
        Tool(
            name="send_transaction",
            description=(
                "Send a transaction on the forked blockchain. "
                "Use this to execute exploit contracts, transfer funds, or call state-changing functions."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "from_address": {
                        "type": "string",
                        "description": "Sender address",
                    },
                    "to_address": {
                        "type": "string",
                        "description": "Recipient address or contract",
                    },
                    "value": {
                        "type": "string",
                        "description": "Value to send in wei (optional)",
                        "default": "0",
                    },
                    "data": {
                        "type": "string",
                        "description": "Transaction data (e.g., encoded function call)",
                        "default": "0x",
                    },
                },
                "required": ["from_address", "to_address"],
            },
        ),
        Tool(
            name="reset_fork",
            description="Reset the forked blockchain to its original state at the fork block",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="stop_fork",
            description="Stop the currently running forked blockchain and clean up resources",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool calls."""
    if name == "bash":
        return await execute_bash(arguments)
    elif name == "file_editor":
        return await file_editor(arguments)
    elif name == "fork_blockchain":
        return await fork_blockchain(arguments)
    elif name == "get_balance":
        return await get_balance(arguments)
    elif name == "call_contract":
        return await call_contract_func(arguments)
    elif name == "send_transaction":
        return await send_transaction(arguments)
    elif name == "reset_fork":
        return await reset_fork()
    elif name == "stop_fork":
        return await stop_fork()
    else:
        raise ValueError(f"Unknown tool: {name}")

# Anthropic SCONE-bench style tools
async def execute_bash(arguments: dict) -> list[TextContent]:
    """Execute bash command."""
    command = arguments.get("command")
    if not command:
        return [TextContent(type="text", text="Error: command required")]
    try:
        import os
        env = os.environ.copy()
        env["PATH"] = f"{Path.home()}/.foundry/bin:{env.get('PATH', '')}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30, env=env, cwd="/tmp")
        return [TextContent(type="text", text=json.dumps({"success": result.returncode == 0, "exit_code": result.returncode, "output": (result.stdout + result.stderr).strip(), "command": command}, indent=2))]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]

async def file_editor(arguments: dict) -> list[TextContent]:
    """File CRUD operations."""
    operation, path, content = arguments.get("operation"), arguments.get("path"), arguments.get("content", "")
    if not operation or not path:
        return [TextContent(type="text", text="Error: operation and path required")]
    try:
        file_path = Path(path) if path.startswith("/tmp") or path.startswith(str(Path.cwd())) else Path("/tmp") / Path(path).name
        if operation == "read":
            return [TextContent(type="text", text=json.dumps({"success": True, "content": file_path.read_text(), "path": str(file_path)}, indent=2))] if file_path.exists() else [TextContent(type="text", text=f"Error: File not found")]
        elif operation == "write":
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content)
            return [TextContent(type="text", text=json.dumps({"success": True, "path": str(file_path), "bytes": len(content)}, indent=2))]
        elif operation == "append":
            file_path.parent.mkdir(parents=True, exist_ok=True)
            with file_path.open("a") as f: f.write(content)
            return [TextContent(type="text", text=json.dumps({"success": True, "path": str(file_path)}, indent=2))]
        elif operation == "delete":
            file_path.unlink() if file_path.exists() else None
            return [TextContent(type="text", text=json.dumps({"success": True}, indent=2))]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]



async def fork_blockchain(arguments: dict) -> list[TextContent]:
    """Fork a blockchain using Anvil."""
    global _anvil_process, _current_chain, _current_block
    
    chain = arguments.get("chain")
    block_number = arguments.get("block_number")
    port = arguments.get("port", 8545)
    
    if not chain or chain not in RPC_ENDPOINTS:
        return [TextContent(
            type="text",
            text=f"Error: Invalid chain '{chain}'. Must be one of: {list(RPC_ENDPOINTS.keys())}"
        )]
    
    # Stop existing fork if running
    if _anvil_process:
        await stop_fork()
    
    # Build anvil command
    rpc_url = RPC_ENDPOINTS[chain]
    cmd = ["anvil", "--fork-url", rpc_url, "--port", str(port), "--host", "0.0.0.0"]
    
    if block_number:
        cmd.extend(["--fork-block-number", str(block_number)])
    
    try:
        # Start anvil process
        _anvil_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Wait for startup
        await asyncio.sleep(3)
        
        # Check if process is running
        if _anvil_process.poll() is not None:
            stderr_output = _anvil_process.stderr.read() if _anvil_process.stderr else "Unknown error"
            return [TextContent(
                type="text",
                text=f"Error: Anvil failed to start. Error: {stderr_output}"
            )]
        
        _current_chain = chain
        _current_block = block_number
        
        result = {
            "success": True,
            "rpc_url": f"http://localhost:{port}",
            "chain": chain,
            "block_number": block_number or "latest",
            "status": "running",
            "message": f"Successfully forked {chain} blockchain at block {block_number or 'latest'}"
        }
        
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
        
    except FileNotFoundError:
        return [TextContent(
            type="text",
            text=(
                "Error: Anvil not found. Please install Foundry:\n"
                "curl -L https://foundry.paradigm.xyz | bash\n"
                "foundryup"
            )
        )]
    except Exception as e:
        return [TextContent(type="text", text=f"Error forking blockchain: {str(e)}")]


async def get_balance(arguments: dict) -> list[TextContent]:
    """Get balance of an address."""
    if not _anvil_process:
        return [TextContent(type="text", text="Error: No forked blockchain running. Call fork_blockchain first.")]
    
    address = arguments.get("address")
    token_address = arguments.get("token_address")
    
    if not address:
        return [TextContent(type="text", text="Error: address is required")]
    
    try:
        if token_address:
            # Query ERC20 balance
            cmd = [
                "cast", "call", token_address,
                f"balanceOf(address)(uint256)",
                address,
                "--rpc-url", _rpc_url
            ]
        else:
            # Query native balance
            cmd = ["cast", "balance", address, "--rpc-url", _rpc_url]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            return [TextContent(type="text", text=f"Error querying balance: {result.stderr}")]
        
        balance_wei = result.stdout.strip()
        balance_eth = int(balance_wei) / 1e18 if balance_wei.isdigit() else balance_wei
        
        response = {
            "success": True,
            "address": address,
            "token_address": token_address or "native",
            "balance_wei": balance_wei,
            "balance_human": f"{balance_eth:.6f}" if isinstance(balance_eth, float) else balance_wei
        }
        
        return [TextContent(type="text", text=json.dumps(response, indent=2))]
        
    except Exception as e:
        return [TextContent(type="text", text=f"Error getting balance: {str(e)}")]


async def call_contract_func(arguments: dict) -> list[TextContent]:
    """Call a contract function (read-only)."""
    if not _anvil_process:
        return [TextContent(type="text", text="Error: No forked blockchain running")]
    
    contract_address = arguments.get("contract_address")
    function_signature = arguments.get("function_signature")
    args = arguments.get("args", [])
    
    try:
        cmd = ["cast", "call", contract_address, function_signature] + args + ["--rpc-url", _rpc_url]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            return [TextContent(type="text", text=f"Error calling contract: {result.stderr}")]
        
        return [TextContent(type="text", text=json.dumps({
            "success": True,
            "contract": contract_address,
            "function": function_signature,
            "result": result.stdout.strip()
        }, indent=2))]
        
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]


async def send_transaction(arguments: dict) -> list[TextContent]:
    """Send a transaction."""
    if not _anvil_process:
        return [TextContent(type="text", text="Error: No forked blockchain running")]
    
    from_address = arguments.get("from_address")
    to_address = arguments.get("to_address")
    value = arguments.get("value", "0")
    data = arguments.get("data", "0x")
    
    try:
        cmd = [
            "cast", "send", to_address,
            "--from", from_address,
            "--value", value,
            "--rpc-url", _rpc_url,
            "--unlocked"
        ]
        
        if data != "0x":
            cmd.extend(["--data", data])
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            return [TextContent(type="text", text=f"Error sending transaction: {result.stderr}")]
        
        return [TextContent(type="text", text=json.dumps({
            "success": True,
            "from": from_address,
            "to": to_address,
            "value": value,
            "output": result.stdout.strip()
        }, indent=2))]
        
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]


async def reset_fork() -> list[TextContent]:
    """Reset fork to original state."""
    if not _anvil_process or not _current_chain:
        return [TextContent(type="text", text="Error: No fork running")]
    
    try:
        # Stop and restart with same parameters
        await stop_fork()
        await asyncio.sleep(1)
        return await fork_blockchain({"chain": _current_chain, "block_number": _current_block})
    except Exception as e:
        return [TextContent(type="text", text=f"Error resetting fork: {str(e)}")]


async def stop_fork() -> list[TextContent]:
    """Stop the forked blockchain."""
    global _anvil_process, _current_chain, _current_block
    
    if not _anvil_process:
        return [TextContent(type="text", text="No fork running")]
    
    try:
        _anvil_process.terminate()
        _anvil_process.wait(timeout=5)
        _anvil_process = None
        _current_chain = None
        _current_block = None
        
        return [TextContent(type="text", text=json.dumps({
            "success": True,
            "message": "Fork stopped successfully"
        }, indent=2))]
    except Exception as e:
        if _anvil_process:
            _anvil_process.kill()
            _anvil_process = None
        return [TextContent(type="text", text=f"Error stopping fork: {str(e)}")]


async def main():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
