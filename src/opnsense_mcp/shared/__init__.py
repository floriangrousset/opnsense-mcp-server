"""
OPNsense MCP Server - Shared Utilities

This package contains shared utilities and constants used across the MCP server.
"""

from . import constants
from .error_handlers import (
    ErrorSeverity,
    ErrorResponse,
    handle_tool_error,
    validate_uuid,
    validate_firewall_parameters,
)

__all__ = [
    "constants",
    "ErrorSeverity",
    "ErrorResponse",
    "handle_tool_error",
    "validate_uuid",
    "validate_firewall_parameters",
]
