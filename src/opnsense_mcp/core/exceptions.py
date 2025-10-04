"""
OPNsense MCP Server - Exception Hierarchy

This module contains all custom exceptions used throughout the OPNsense MCP server.
"""

from typing import Dict, Any, Optional
from datetime import datetime


class OPNsenseError(Exception):
    """Base exception for all OPNsense-related errors with enhanced context."""

    def __init__(self, message: str, error_code: Optional[str] = None, context: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.context = context or {}
        self.timestamp = datetime.utcnow()
        # Keep backward compatibility
        self.details = context or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for structured logging."""
        return {
            "error_type": self.__class__.__name__,
            "error_code": self.error_code,
            "message": self.message,
            "context": self.context,
            "timestamp": self.timestamp.isoformat()
        }


class ConfigurationError(OPNsenseError):
    """Client not configured or invalid configuration."""
    pass


class AuthenticationError(OPNsenseError):
    """Authentication failed."""
    pass


class APIError(OPNsenseError):
    """API call failed."""
    def __init__(self, message: str, status_code: Optional[int] = None, response_text: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text


class NetworkError(OPNsenseError):
    """Network communication error."""
    pass


class RateLimitError(OPNsenseError):
    """Rate limit exceeded."""
    pass


class ValidationError(OPNsenseError):
    """Input parameter validation failed."""
    pass


class TimeoutError(OPNsenseError):
    """Request timed out."""
    pass


class ResourceNotFoundError(OPNsenseError):
    """Requested resource not found."""
    pass


class AuthorizationError(OPNsenseError):
    """User doesn't have permission for the requested operation."""
    pass
