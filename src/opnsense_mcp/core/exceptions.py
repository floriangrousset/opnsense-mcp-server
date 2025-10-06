"""
OPNsense MCP Server - Exception Hierarchy

This module contains all custom exceptions used throughout the OPNsense MCP server.
"""

from datetime import datetime
from typing import Any


class OPNsenseError(Exception):
    """Base exception for all OPNsense-related errors with enhanced context."""

    def __init__(
        self,
        message: str,
        error_code: str | None = None,
        context: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.context = context or {}
        self.timestamp = datetime.utcnow()
        # Keep backward compatibility
        self.details = context or {}

    def to_dict(self) -> dict[str, Any]:
        """Convert exception to dictionary for structured logging."""
        return {
            "error_type": self.__class__.__name__,
            "error_code": self.error_code,
            "message": self.message,
            "context": self.context,
            "timestamp": self.timestamp.isoformat(),
        }


class ConfigurationError(OPNsenseError):
    """Client not configured or invalid configuration."""


class AuthenticationError(OPNsenseError):
    """Authentication failed."""


class APIError(OPNsenseError):
    """API call failed."""

    def __init__(
        self, message: str, status_code: int | None = None, response_text: str | None = None
    ):
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text


class NetworkError(OPNsenseError):
    """Network communication error."""


class RateLimitError(OPNsenseError):
    """Rate limit exceeded."""


class ValidationError(OPNsenseError):
    """Input parameter validation failed."""


class TimeoutError(OPNsenseError):
    """Request timed out."""


class ResourceNotFoundError(OPNsenseError):
    """Requested resource not found."""


class AuthorizationError(OPNsenseError):
    """User doesn't have permission for the requested operation."""
