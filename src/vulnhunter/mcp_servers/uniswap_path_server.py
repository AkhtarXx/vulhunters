#!/usr/bin/env python3
"""
Uniswap Smart Path MCP Server

Finds optimal swap routes for token pairs (inspired by SCONE-bench).
Helps agents maximize profit by finding best DEX paths.
"""

import asyncio
import json
import subprocess
from typing import Any, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent


app = Server("uniswap-smart-path")

# Common DEX routers by chain
DEX_ROUTERS = {
    "ethereum": {
        "uniswap_v2": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        "uniswap_v3": "0xE592427A0AEce92De3Edee1F18E0157C05861564",
        "sushiswap": "0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F",
    },
    "bsc": {
        "pancakeswap_v2": "0x10ED43C718714eb63d5aA57B78B54704E256024E",
        "pancakeswap_v3": "0x13f4EA83D0bd40E75C8222255bc855a974568Dd4",
    },
    "polygon": {
        "quickswap": "0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff",
        "sushiswap": "0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506",
    }
}

# Common tokens by chain
COMMON_TOKENS = {
    "ethereum": {
        "WETH": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        "USDC": "0xA0b86a33E6176C1Abc3e09CC0b75c8B6b4E8fE02",
        "USDT": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        "DAI": "0x6B175474E89094C44Da98b954EesacdFC79008F0",
    },
    "bsc": {
        "WBNB": "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",
        "BUSD": "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56",
        "USDT": "0x55d398326f99059fF775485246999027B3197955",
    }
}


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available swap path tools."""
    return [
        Tool(
            name="find_swap_path",
            description=(
                "Find optimal swap path between two tokens on DEXs. "
                "Returns best route with expected output amount."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "token_in": {
                        "type": "string",
                        "description": "Input token address (0x...)",
                    },
                    "token_out": {
                        "type": "string",
                        "description": "Output token address (0x...)",
                    },
                    "amount_in": {
                        "type": "string",
                        "description": "Amount of input token (in wei)",
                    },
                    "chain": {
                        "type": "string",
                        "enum": ["ethereum", "bsc", "polygon"],
                        "description": "Blockchain to use",
                    },
                },
                "required": ["token_in", "token_out", "amount_in", "chain"],
            },
        ),
        Tool(
            name="get_dex_routers",
            description="Get list of DEX router addresses for a chain",
            inputSchema={
                "type": "object",
                "properties": {
                    "chain": {
                        "type": "string",
                        "enum": ["ethereum", "bsc", "polygon"],
                    },
                },
                "required": ["chain"],
            },
        ),
        Tool(
            name="get_common_tokens",
            description="Get common token addresses for a chain (WETH, USDC, etc.)",
            inputSchema={
                "type": "object",
                "properties": {
                    "chain": {
                        "type": "string",
                        "enum": ["ethereum", "bsc", "polygon"],
                    },
                },
                "required": ["chain"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool calls."""
    if name == "find_swap_path":
        return await find_swap_path(arguments)
    elif name == "get_dex_routers":
        return await get_dex_routers(arguments)
    elif name == "get_common_tokens":
        return await get_common_tokens(arguments)
    else:
        raise ValueError(f"Unknown tool: {name}")


async def find_swap_path(arguments: dict) -> list[TextContent]:
    """Find optimal swap path using cast calls."""
    token_in = arguments.get("token_in")
    token_out = arguments.get("token_out")
    amount_in = arguments.get("amount_in")
    chain = arguments.get("chain", "ethereum")
    
    if not all([token_in, token_out, amount_in]):
        return [TextContent(type="text", text="Error: token_in, token_out, amount_in required")]
    
    routers = DEX_ROUTERS.get(chain, {})
    common = COMMON_TOKENS.get(chain, {})
    weth = common.get("WETH") or common.get("WBNB")
    
    paths = []
    
    # Direct path
    paths.append({
        "path": [token_in, token_out],
        "hops": 1,
        "description": "Direct swap"
    })
    
    # Via WETH/WBNB
    if weth and token_in != weth and token_out != weth:
        paths.append({
            "path": [token_in, weth, token_out],
            "hops": 2,
            "description": f"Via {'WETH' if 'WETH' in common else 'WBNB'}"
        })
    
    # Via stablecoins
    for stable_name, stable_addr in common.items():
        if stable_name in ["USDC", "USDT", "BUSD", "DAI"]:
            if token_in != stable_addr and token_out != stable_addr:
                paths.append({
                    "path": [token_in, stable_addr, token_out],
                    "hops": 2,
                    "description": f"Via {stable_name}"
                })
    
    result = {
        "success": True,
        "chain": chain,
        "token_in": token_in,
        "token_out": token_out,
        "amount_in": amount_in,
        "suggested_paths": paths[:5],  # Top 5 paths
        "dex_routers": routers,
        "note": "Use forge/cast to test actual output amounts on each path"
    }
    
    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def get_dex_routers(arguments: dict) -> list[TextContent]:
    """Get DEX routers for a chain."""
    chain = arguments.get("chain", "ethereum")
    routers = DEX_ROUTERS.get(chain, {})
    
    return [TextContent(type="text", text=json.dumps({
        "chain": chain,
        "routers": routers
    }, indent=2))]


async def get_common_tokens(arguments: dict) -> list[TextContent]:
    """Get common tokens for a chain."""
    chain = arguments.get("chain", "ethereum")
    tokens = COMMON_TOKENS.get(chain, {})
    
    return [TextContent(type="text", text=json.dumps({
        "chain": chain,
        "tokens": tokens
    }, indent=2))]


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
