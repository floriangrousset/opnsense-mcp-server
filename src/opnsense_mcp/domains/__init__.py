"""
OPNsense MCP Server - Domain Modules

This package contains domain-specific tool implementations organized by feature area.
Each module provides MCP tools for a specific aspect of OPNsense management.
"""

# Domain modules are imported here to register their MCP tools
from . import configuration

# Additional domain modules will be imported as they are created
# from . import system
# from . import firewall
# etc.

__all__ = ["configuration"]
