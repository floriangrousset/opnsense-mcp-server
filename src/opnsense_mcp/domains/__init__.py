"""
OPNsense MCP Server - Domain Modules

This package contains domain-specific tool implementations organized by feature area.
Each module provides MCP tools for a specific aspect of OPNsense management.
"""

# Domain modules are imported here to register their MCP tools
from . import configuration
from . import system
from . import firewall
from . import nat
from . import network
from . import dns_dhcp

# Additional domain modules will be imported as they are created
# etc.

__all__ = ["configuration", "system", "firewall", "nat", "network", "dns_dhcp"]
