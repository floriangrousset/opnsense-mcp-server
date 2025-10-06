"""
OPNsense MCP Server - Shared Utilities

This package contains shared utilities and constants used across the MCP server.
"""

from . import constants
from .error_handlers import (
    ErrorResponse,
    ErrorSeverity,
    handle_tool_error,
    validate_firewall_parameters,
    validate_uuid,
)

__all__ = [
    "ErrorResponse",
    "ErrorSeverity",
    "constants",
    "handle_tool_error",
    "validate_firewall_parameters",
    "validate_uuid",
]
