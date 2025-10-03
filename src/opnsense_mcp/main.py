#!/usr/bin/env python3
"""
OPNsense MCP Server - Main Entry Point

This module initializes the FastMCP server and registers all domain-specific tools.
It serves as the central coordination point for the modular MCP server architecture.
"""

import logging
from mcp.server.fastmcp import FastMCP

from .core.state import ServerState

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("opnsense-mcp")

# Initialize FastMCP server
mcp = FastMCP("OPNsense MCP Server", description="Manage OPNsense firewalls via MCP")

# Initialize global server state
server_state = ServerState()


# Domain modules will be imported and registered here as they are created
# Example:
# from .domains import configuration
# from .domains import system
# from .domains import firewall
# etc.
#
# Each domain module will use the global `mcp` instance to register its tools
# using decorators like: @mcp.tool(name="tool_name", description="...")


# Entry point for running the server
if __name__ == "__main__":
    mcp.run()
