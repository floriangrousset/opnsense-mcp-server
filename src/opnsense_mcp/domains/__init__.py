"""
OPNsense MCP Server - Domain Modules

This package contains domain-specific tool implementations organized by feature area.
Each module provides MCP tools for a specific aspect of OPNsense management.
"""

# Domain modules are imported here to register their MCP tools
from . import (
    certificates,
    configuration,
    dns_dhcp,
    firewall,
    logging,
    nat,
    network,
    system,
    traffic_shaping,
    users,
    utilities,
    vpn,
)

# Additional domain modules will be imported as they are created
# etc.

__all__ = [
    "certificates",
    "configuration",
    "dns_dhcp",
    "firewall",
    "logging",
    "nat",
    "network",
    "system",
    "traffic_shaping",
    "users",
    "utilities",
    "vpn",
]
