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
    "APIError",
    "AuthenticationError",
    "AuthorizationError",
    "ConfigurationError",
    "ConnectionPool",
    "NetworkError",
    "OPNsenseClient",
    "OPNsenseConfig",
    "OPNsenseError",
    "RateLimitError",
    "RequestResponseLogger",
    "ResourceNotFoundError",
    "RetryConfig",
    "ServerState",
    "TimeoutError",
    "ValidationError",
    "retry_with_backoff",
]
