"""
OPNsense MCP Server - Core Infrastructure

This package contains the core infrastructure components for the OPNsense MCP server.
"""

from .client import OPNsenseClient, RequestResponseLogger
from .connection import ConnectionPool
from .exceptions import (
    APIError,
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    NetworkError,
    OPNsenseError,
    RateLimitError,
    ResourceNotFoundError,
    TimeoutError,
    ValidationError,
)
from .models import OPNsenseConfig
from .retry import RetryConfig, retry_with_backoff
from .state import ServerState

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
