"""
OPNsense MCP Server - Error Handling Helpers

This module provides error handling utilities and user-friendly error response generation.
"""

import json
import logging
import re
from datetime import datetime
from enum import Enum
from typing import Dict, Any, TYPE_CHECKING

from ..core.exceptions import (
    OPNsenseError,
    AuthenticationError,
    AuthorizationError,
    NetworkError,
    ConfigurationError,
    ValidationError,
    APIError,
    TimeoutError,
    ResourceNotFoundError,
    RateLimitError
)

if TYPE_CHECKING:
    from mcp.server.fastmcp import Context

logger = logging.getLogger("opnsense-mcp")


class ErrorSeverity(str, Enum):
    """Enumeration for error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorResponse:
    """Structured error response system with user-friendly messaging."""

    def __init__(self, error: Exception, operation: str, severity: ErrorSeverity = ErrorSeverity.MEDIUM):
        """Initialize error response.

        Args:
            error: The exception that occurred
            operation: Name of the operation that failed
            severity: Severity level of the error
        """
        self.error = error
        self.operation = operation
        self.severity = severity
        self.timestamp = datetime.utcnow()
        self.error_id = f"{operation}_{int(self.timestamp.timestamp())}"

    def get_user_message(self) -> str:
        """Get user-friendly error message.

        Returns:
            Human-readable error message
        """
        if isinstance(self.error, AuthenticationError):
            return "Authentication failed. Please check your API credentials."
        elif isinstance(self.error, AuthorizationError):
            return "Access denied. You don't have permission for this operation."
        elif isinstance(self.error, NetworkError):
            return "Cannot connect to OPNsense. Please check the URL and network connectivity."
        elif isinstance(self.error, ConfigurationError):
            return "OPNsense connection not configured. Please configure the connection first."
        elif isinstance(self.error, ValidationError):
            return f"Invalid input: {self.error.message}"
        elif isinstance(self.error, APIError):
            if self.error.status_code == 404:
                return "The requested resource was not found."
            elif self.error.status_code == 429:
                return "API rate limit exceeded. Please wait before trying again."
            else:
                return f"API error: {self.error.message}"
        elif isinstance(self.error, TimeoutError):
            return "Request timed out. The OPNsense server may be overloaded."
        elif isinstance(self.error, ResourceNotFoundError):
            return f"Resource not found: {self.error.message}"
        elif isinstance(self.error, RateLimitError):
            return "Rate limit exceeded. Please slow down your requests."
        else:
            return f"An unexpected error occurred during {self.operation}."

    def get_technical_details(self) -> Dict[str, Any]:
        """Get technical error details for logging.

        Returns:
            Dictionary containing technical error information
        """
        details = {
            "error_id": self.error_id,
            "operation": self.operation,
            "severity": self.severity.value,
            "timestamp": self.timestamp.isoformat(),
            "error_type": type(self.error).__name__,
            "message": str(self.error)
        }

        if isinstance(self.error, OPNsenseError):
            details.update(self.error.to_dict())

        if isinstance(self.error, APIError):
            details["status_code"] = self.error.status_code
            details["response_text"] = self.error.response_text

        return details


async def handle_tool_error(
    ctx: 'Context',
    operation: str,
    error: Exception,
    severity: ErrorSeverity = ErrorSeverity.MEDIUM
) -> str:
    """Centralized error handling for MCP tools.

    Args:
        ctx: MCP context for error reporting
        operation: Name of the operation that failed
        error: The exception that occurred
        severity: Severity level of the error

    Returns:
        User-friendly error message
    """
    error_response = ErrorResponse(error, operation, severity)

    # Log technical details
    technical_details = error_response.get_technical_details()
    logger.error(f"Tool error in {operation}: {json.dumps(technical_details, indent=2)}")

    # Report error to MCP context
    user_message = error_response.get_user_message()
    await ctx.error(user_message)

    return f"Error: {user_message}"


def validate_uuid(uuid: str, operation: str) -> None:
    """Validate UUID format.

    Args:
        uuid: UUID string to validate
        operation: Operation name for error context

    Raises:
        ValidationError: If UUID format is invalid
    """
    uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
    if not uuid_pattern.match(uuid):
        raise ValidationError(
            f"Invalid UUID format: {uuid}",
            context={"uuid": uuid, "operation": operation, "expected_format": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"}
        )


def validate_firewall_parameters(
    action: str,
    direction: str,
    ipprotocol: str,
    protocol: str,
    operation: str
) -> None:
    """Validate common firewall rule parameters.

    Args:
        action: Rule action (pass, block, reject)
        direction: Traffic direction (in, out)
        ipprotocol: IP protocol (inet, inet6)
        protocol: Transport protocol (tcp, udp, icmp, any)
        operation: Operation name for error context

    Raises:
        ValidationError: If any parameter is invalid
    """
    valid_actions = ["pass", "block", "reject"]
    valid_directions = ["in", "out"]
    valid_ipprotocols = ["inet", "inet6"]
    valid_protocols = ["tcp", "udp", "icmp", "any"]

    if action not in valid_actions:
        raise ValidationError(f"Invalid action '{action}'. Must be one of: {valid_actions}",
                            context={"operation": operation, "parameter": "action", "value": action})
    if direction not in valid_directions:
        raise ValidationError(f"Invalid direction '{direction}'. Must be one of: {valid_directions}",
                            context={"operation": operation, "parameter": "direction", "value": direction})
    if ipprotocol not in valid_ipprotocols:
        raise ValidationError(f"Invalid IP protocol '{ipprotocol}'. Must be one of: {valid_ipprotocols}",
                            context={"operation": operation, "parameter": "ipprotocol", "value": ipprotocol})
    if protocol not in valid_protocols:
        raise ValidationError(f"Invalid protocol '{protocol}'. Must be one of: {valid_protocols}",
                            context={"operation": operation, "parameter": "protocol", "value": protocol})
