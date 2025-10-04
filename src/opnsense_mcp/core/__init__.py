"""
OPNsense MCP Server - Core Infrastructure

This package contains the core infrastructure components for the OPNsense MCP server.
"""

from .exceptions import (
    OPNsenseError,
    ConfigurationError,
    AuthenticationError,
    APIError,
    NetworkError,
    RateLimitError,
    ValidationError,
    TimeoutError,
    ResourceNotFoundError,
    AuthorizationError,
)
from .models import OPNsenseConfig
from .client import OPNsenseClient, RequestResponseLogger
from .connection import ConnectionPool
from .state import ServerState
from .retry import RetryConfig, retry_with_backoff

__all__ = [
    # Exceptions
    "OPNsenseError",
    "ConfigurationError",
    "AuthenticationError",
    "APIError",
    "NetworkError",
    "RateLimitError",
    "ValidationError",
    "TimeoutError",
    "ResourceNotFoundError",
    "AuthorizationError",
    # Models
    "OPNsenseConfig",
    # Client
    "OPNsenseClient",
    "RequestResponseLogger",
    # Connection
    "ConnectionPool",
    # State
    "ServerState",
    # Retry
    "RetryConfig",
    "retry_with_backoff",
]
