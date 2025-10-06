"""
OPNsense MCP Server

A Model Context Protocol (MCP) server implementation for managing OPNsense firewalls.
This server allows Claude and other MCP-compatible clients to interact with all features
exposed by the OPNsense API.
"""

__version__ = "1.0.0"
__author__ = "Florian Grousset"
__license__ = "AGPL-3.0"

from .core.client import OPNsenseClient
from .core.connection import ConnectionPool
from .core.exceptions import (
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
from .core.models import OPNsenseConfig
from .core.state import ServerState

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
    # Core classes
    "OPNsenseConfig",
    "OPNsenseClient",
    "ConnectionPool",
    "ServerState",
]
