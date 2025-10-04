#!/usr/bin/env python3
"""
OPNsense MCP Server - Backward Compatibility Wrapper

This file maintains backward compatibility with the original monolithic implementation.
All functionality has been migrated to the modular structure in src/opnsense_mcp/.

For new deployments, consider importing directly from src/opnsense_mcp.main instead.

Original file (9,529 lines) has been refactored into:
- Core infrastructure (exceptions, models, client, connection, retry, state)
- Shared utilities (constants, error handlers, validators)
- 12 domain modules (166 tools total):
  * configuration (2 tools) - Connection setup
  * system (8 tools) - System status, health, services
  * firewall (8 tools) - Rules, aliases, audit
  * nat (8 tools) - Outbound, one-to-one NAT
  * network (26 tools) - Interfaces, VLANs, bridges, LAGG, VIPs
  * dns_dhcp (27 tools) - DHCP server, DNS resolver/forwarder
  * certificates (27 tools) - CA, certificates, CSR, ACME
  * users (24 tools) - Users, groups, privileges, auth
  * logging (9 tools) - Logs, search, export, analysis
  * traffic_shaping (25 tools) - Pipes, queues, rules, QoS
  * vpn (1 tool) - VPN connection monitoring
  * utilities (1 tool) - Custom API calls

This wrapper simply imports and runs the modular server, providing seamless
backward compatibility for existing configurations and deployments.
"""

# Import the modular server
from src.opnsense_mcp.main import mcp

# Entry point - runs the modular MCP server
if __name__ == "__main__":
    mcp.run()
