#!/usr/bin/env python3
"""
OPNsense MCP Server - Backward Compatibility Wrapper

This file maintains backward compatibility with the original monolithic implementation.
All functionality has been migrated to the modular structure in src/opnsense_mcp/.

For new deployments, consider importing directly from src/opnsense_mcp.main instead.

Original file (9,529 lines) has been refactored into:
- Core infrastructure (exceptions, models, client, connection, retry, state)
- Shared utilities (constants, error handlers)
- 12 domain modules (166 tools total):
  * configuration (2 tools)
  * system (8 tools)
  * firewall (8 tools)
  * nat (8 tools)
  * network (26 tools)
  * dns_dhcp (27 tools)
  * certificates (27 tools)
  * users (24 tools)
  * logging (9 tools)
  * traffic_shaping (25 tools)
  * vpn (1 tool)
  * utilities (1 tool)

This wrapper simply imports and runs the modular server, providing seamless
backward compatibility for existing configurations and deployments.
"""

# Import the modular server
from src.opnsense_mcp.main import mcp

# Entry point - runs the modular MCP server
if __name__ == "__main__":
    mcp.run()
