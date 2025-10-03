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


# Import domain modules to register their MCP tools
# Each domain module uses the global `mcp` instance to register its tools
# using decorators like: @mcp.tool(name="tool_name", description="...")
from .domains import configuration
from .domains import system      # Phase 3: System management tools
from .domains import firewall    # Phase 4: Firewall rule and alias management
from .domains import nat         # Phase 5: NAT management (outbound, one-to-one, port forwarding info)

# Additional domain modules will be imported as they are created
# from .domains import network
# etc.


# Entry point for running the server
if __name__ == "__main__":
    mcp.run()
