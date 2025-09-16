#!/usr/bin/env python3
"""
OPNsense MCP Server

A Model Context Protocol (MCP) server implementation for managing OPNsense firewalls.
This server allows Claude and other MCP-compatible clients to interact with all features
exposed by the OPNsense API. This server is designed to be run on a local machine and
not exposed to the public internet. Please see the README.md file for more information.
"""

import os
import json
import logging
import asyncio
import base64
import hashlib
from typing import Dict, List, Any, Optional, Union, Tuple, TypedDict
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from dataclasses import dataclass
import urllib.parse
import httpx
from mcp.server.fastmcp import FastMCP, Context
from mcp import types
from pydantic import BaseModel, Field, field_validator, ValidationError
import keyring
from aiolimiter import AsyncLimiter


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("opnsense-mcp")


# ========== ENHANCED EXCEPTION HIERARCHY ==========

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


# Pydantic Models for Configuration and Validation
class OPNsenseConfig(BaseModel):
    """Configuration for OPNsense connection."""
    url: str = Field(..., description="OPNsense base URL")
    api_key: str = Field(..., description="API key")
    api_secret: str = Field(..., description="API secret", repr=False)  # Hide in logs
    verify_ssl: bool = Field(default=True, description="Whether to verify SSL certificates")

    @field_validator('url')
    @classmethod
    def validate_url(cls, v):
        """Validate URL format."""
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return v.rstrip('/')

    class Config:
        """Pydantic configuration."""
        validate_assignment = True


# Connection Pool and Rate Limiting
class ConnectionPool:
    """Manages OPNsense client connections with pooling and rate limiting."""

    def __init__(self, max_connections: int = 5, ttl_seconds: int = 300):
        self.max_connections = max_connections
        self.ttl = timedelta(seconds=ttl_seconds)
        self.connections: Dict[str, Tuple[OPNsenseClient, datetime]] = {}
        self.lock = asyncio.Lock()
        # Rate limiting: 10 requests per second with burst of 20
        self.rate_limiter = AsyncLimiter(max_rate=10, time_period=1.0)
        self.burst_limiter = AsyncLimiter(max_rate=20, time_period=1.0)

    def _get_config_hash(self, config: OPNsenseConfig) -> str:
        """Generate hash for config to use as pool key."""
        config_str = f"{config.url}:{config.api_key}"
        return hashlib.sha256(config_str.encode()).hexdigest()[:16]

    async def get_client(self, config: OPNsenseConfig) -> 'OPNsenseClient':
        """Get or create client from pool."""
        config_hash = self._get_config_hash(config)

        async with self.lock:
            # Check if we have a valid existing client
            if config_hash in self.connections:
                client, created_at = self.connections[config_hash]
                if datetime.now() - created_at < self.ttl:
                    return client
                else:
                    # Client expired, close and remove
                    await client.close()
                    del self.connections[config_hash]

            # Create new client
            client = OPNsenseClient(config, self)
            self.connections[config_hash] = (client, datetime.now())

            # Cleanup old connections if pool is full
            if len(self.connections) > self.max_connections:
                await self._cleanup_oldest()

            return client

    async def _cleanup_oldest(self):
        """Remove oldest connection from pool."""
        if not self.connections:
            return

        oldest_key = min(
            self.connections.keys(),
            key=lambda k: self.connections[k][1]
        )
        client, _ = self.connections[oldest_key]
        await client.close()
        del self.connections[oldest_key]

    async def check_rate_limit(self):
        """Check and enforce rate limits."""
        # Try burst limit first
        if not self.burst_limiter.has_capacity():
            raise RateLimitError("Burst rate limit exceeded. Please slow down requests.")

        # Apply rate limit
        await self.rate_limiter.acquire()
        await self.burst_limiter.acquire()

    async def close_all(self):
        """Close all connections in pool."""
        async with self.lock:
            for client, _ in self.connections.values():
                await client.close()
            self.connections.clear()


# Server State Management
@dataclass
class ServerState:
    """Managed server state with proper lifecycle."""
    config: Optional[OPNsenseConfig] = None
    pool: Optional[ConnectionPool] = None
    session_created: Optional[datetime] = None
    session_ttl: timedelta = timedelta(hours=1)  # 1 hour session timeout

    async def initialize(self, config: OPNsenseConfig):
        """Initialize server state with validation."""
        await self.cleanup()

        # Store encrypted credentials
        try:
            await self._store_credentials(config)
        except Exception as e:
            logger.warning(f"Could not store credentials securely: {e}. Using in-memory storage.")

        self.config = config
        self.pool = ConnectionPool()
        self.session_created = datetime.now()

        # Validate connection
        client = await self.pool.get_client(config)
        await client.request("GET", API_CORE_FIRMWARE_STATUS)

        logger.info("OPNsense connection initialized successfully")

    async def _store_credentials(self, config: OPNsenseConfig):
        """Store credentials securely using keyring."""
        service_name = "opnsense-mcp-server"
        username = f"{config.url}-{config.api_key[:8]}"  # Partial key for identification

        # Store as JSON for easy retrieval
        credentials = {
            "url": config.url,
            "api_key": config.api_key,
            "api_secret": config.api_secret,
            "verify_ssl": config.verify_ssl
        }

        keyring.set_password(service_name, username, json.dumps(credentials))
        logger.debug("Credentials stored securely")

    async def get_client(self) -> 'OPNsenseClient':
        """Get OPNsense client with session validation."""
        if not self.config or not self.pool:
            raise ConfigurationError("OPNsense client not configured. Use configure_opnsense_connection first.")

        # Check session expiry
        if self.session_created and datetime.now() - self.session_created > self.session_ttl:
            logger.info("Session expired, reinitializing...")
            await self.initialize(self.config)

        return await self.pool.get_client(self.config)

    async def cleanup(self):
        """Cleanup resources."""
        if self.pool:
            await self.pool.close_all()
            self.pool = None
        self.config = None
        self.session_created = None


# ========== ERROR RESPONSE SYSTEM ==========

from enum import Enum

class ErrorSeverity(str, Enum):
    """Enumeration for error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorResponse:
    """Structured error response system with user-friendly messaging."""

    def __init__(self, error: Exception, operation: str, severity: ErrorSeverity = ErrorSeverity.MEDIUM):
        self.error = error
        self.operation = operation
        self.severity = severity
        self.timestamp = datetime.utcnow()
        self.error_id = f"{operation}_{int(self.timestamp.timestamp())}"

    def get_user_message(self) -> str:
        """Get user-friendly error message."""
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
        """Get technical error details for logging."""
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


# ========== RETRY MECHANISM ==========

class RetryConfig:
    """Configuration for retry mechanism with exponential backoff."""

    def __init__(self, max_attempts: int = 3, base_delay: float = 1.0, max_delay: float = 60.0,
                 exponential_backoff: bool = True, retryable_errors: Optional[List[type]] = None):
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_backoff = exponential_backoff
        self.retryable_errors = retryable_errors or [NetworkError, TimeoutError, APIError, RateLimitError]


async def retry_with_backoff(func, *args, retry_config: RetryConfig = None, **kwargs):
    """Retry function with exponential backoff for transient failures."""
    if retry_config is None:
        retry_config = RetryConfig()

    last_exception = None

    for attempt in range(retry_config.max_attempts):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            last_exception = e

            # Check if error is retryable
            if not any(isinstance(e, err_type) for err_type in retry_config.retryable_errors):
                raise e

            # Don't retry on last attempt
            if attempt == retry_config.max_attempts - 1:
                break

            # Calculate delay with exponential backoff
            if retry_config.exponential_backoff:
                delay = min(retry_config.base_delay * (2 ** attempt), retry_config.max_delay)
            else:
                delay = retry_config.base_delay

            logger.info(f"Attempt {attempt + 1} failed, retrying in {delay}s: {str(e)}")
            await asyncio.sleep(delay)

    # All attempts failed
    raise last_exception


# ========== REQUEST/RESPONSE LOGGING ==========

class RequestResponseLogger:
    """Framework for logging API requests and responses with sensitive data protection."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def log_request(self, method: str, url: str, headers: Optional[Dict] = None,
                   data: Optional[Dict] = None, operation: str = "unknown"):
        """Log API request details with sensitive data sanitization."""
        # Sanitize sensitive headers
        safe_headers = {}
        if headers:
            for key, value in headers.items():
                if key.lower() in ['authorization', 'x-api-key']:
                    safe_headers[key] = '[REDACTED]'
                else:
                    safe_headers[key] = value

        log_data = {
            "operation": operation,
            "request": {
                "method": method,
                "url": url,
                "headers": safe_headers,
                "has_data": bool(data)
            }
        }

        self.logger.info(f"API Request: {json.dumps(log_data)}")

    def log_response(self, status_code: int, response_size: Optional[int] = None,
                    duration_ms: Optional[float] = None, operation: str = "unknown",
                    error: Optional[Exception] = None):
        """Log API response details with performance metrics."""
        log_data = {
            "operation": operation,
            "response": {
                "status_code": status_code,
                "response_size": response_size,
                "duration_ms": duration_ms,
                "success": 200 <= status_code < 300,
                "has_error": bool(error)
            }
        }

        if error:
            log_data["error"] = str(error)

        level = logging.INFO if log_data["response"]["success"] else logging.WARNING
        self.logger.log(level, f"API Response: {json.dumps(log_data)}")


# Initialize request/response logger
request_logger = RequestResponseLogger(logger)


# API Endpoint Constants
# Core
API_CORE_MENU_GET_ITEMS = "/core/menu/getItems"
API_CORE_FIRMWARE_STATUS = "/core/firmware/status"
API_CORE_SYSTEM_INFO = "/core/system/info"
API_CORE_SERVICE_SEARCH = "/core/service/search"
API_CORE_SERVICE_RESTART = "/core/service/restart"  # Needs /{service_name}
API_CORE_BACKUP_DOWNLOAD = "/core/backup/download"
API_CORE_FIRMWARE_PLUGINS = "/core/firmware/plugins"
API_CORE_FIRMWARE_INSTALL = "/core/firmware/install"  # Needs /{plugin_name}

# Firewall
API_FIREWALL_FILTER_SEARCH_RULE = "/firewall/filter/searchRule"
API_FIREWALL_FILTER_ADD_RULE = "/firewall/filter/addRule"
API_FIREWALL_FILTER_DEL_RULE = "/firewall/filter/delRule"    # Needs /{uuid}
API_FIREWALL_FILTER_TOGGLE_RULE = "/firewall/filter/toggleRule" # Needs /{uuid}/{enabled_int}
API_FIREWALL_FILTER_APPLY = "/firewall/filter/apply"
API_FIREWALL_ALIAS_SEARCH_ITEM = "/firewall/alias/searchItem"
API_FIREWALL_ALIAS_UTIL_ADD = "/firewall/alias_util/add"      # Needs /{alias_name}/{address}
API_FIREWALL_ALIAS_UTIL_DELETE = "/firewall/alias_util/delete"  # Needs /{alias_name}/{address}
API_FIREWALL_ALIAS_RECONFIGURE = "/firewall/alias/reconfigure"

# Interfaces
API_INTERFACES_OVERVIEW_INFO = "/interfaces/overview/interfacesInfo"

# DHCP
API_DHCP_LEASES_SEARCH = "/dhcp/leases/searchLease"

# ========== INTERFACE & VLAN MANAGEMENT API ENDPOINTS ==========

# Interface Overview & Control
API_INTERFACES_OVERVIEW_GET_INTERFACE = "/interfaces/overview/getInterface"  # /{interface}
API_INTERFACES_OVERVIEW_RELOAD_INTERFACE = "/interfaces/overview/reloadInterface"  # /{identifier}
API_INTERFACES_OVERVIEW_EXPORT = "/interfaces/overview/export"

# Bridge Management
API_INTERFACES_BRIDGE_SEARCH = "/interfaces/bridge_settings/search_item"
API_INTERFACES_BRIDGE_GET = "/interfaces/bridge_settings/get_item"  # /{uuid}
API_INTERFACES_BRIDGE_ADD = "/interfaces/bridge_settings/add_item"
API_INTERFACES_BRIDGE_SET = "/interfaces/bridge_settings/set_item"  # /{uuid}
API_INTERFACES_BRIDGE_DEL = "/interfaces/bridge_settings/del_item"  # /{uuid}
API_INTERFACES_BRIDGE_RECONFIGURE = "/interfaces/bridge_settings/reconfigure"

# LAGG (Link Aggregation) Management
API_INTERFACES_LAGG_SEARCH = "/interfaces/lagg_settings/search_item"
API_INTERFACES_LAGG_GET = "/interfaces/lagg_settings/get_item"  # /{uuid}
API_INTERFACES_LAGG_ADD = "/interfaces/lagg_settings/add_item"
API_INTERFACES_LAGG_SET = "/interfaces/lagg_settings/set_item"  # /{uuid}
API_INTERFACES_LAGG_DEL = "/interfaces/lagg_settings/del_item"  # /{uuid}
API_INTERFACES_LAGG_RECONFIGURE = "/interfaces/lagg_settings/reconfigure"

# VLAN Management
API_INTERFACES_VLAN_SEARCH = "/interfaces/vlan_settings/search_item"
API_INTERFACES_VLAN_GET = "/interfaces/vlan_settings/get_item"  # /{uuid}
API_INTERFACES_VLAN_ADD = "/interfaces/vlan_settings/add_item"
API_INTERFACES_VLAN_SET = "/interfaces/vlan_settings/set_item"  # /{uuid}
API_INTERFACES_VLAN_DEL = "/interfaces/vlan_settings/del_item"  # /{uuid}
API_INTERFACES_VLAN_RECONFIGURE = "/interfaces/vlan_settings/reconfigure"

# VXLAN Management
API_INTERFACES_VXLAN_SEARCH = "/interfaces/vxlan_settings/search_item"
API_INTERFACES_VXLAN_GET = "/interfaces/vxlan_settings/get_item"  # /{uuid}
API_INTERFACES_VXLAN_ADD = "/interfaces/vxlan_settings/add_item"
API_INTERFACES_VXLAN_SET = "/interfaces/vxlan_settings/set_item"  # /{uuid}
API_INTERFACES_VXLAN_DEL = "/interfaces/vxlan_settings/del_item"  # /{uuid}
API_INTERFACES_VXLAN_RECONFIGURE = "/interfaces/vxlan_settings/reconfigure"

# Virtual IP Management
API_INTERFACES_VIP_SEARCH = "/interfaces/vip_settings/search_item"
API_INTERFACES_VIP_GET = "/interfaces/vip_settings/get_item"  # /{uuid}
API_INTERFACES_VIP_ADD = "/interfaces/vip_settings/add_item"
API_INTERFACES_VIP_SET = "/interfaces/vip_settings/set_item"  # /{uuid}
API_INTERFACES_VIP_DEL = "/interfaces/vip_settings/del_item"  # /{uuid}
API_INTERFACES_VIP_GET_UNUSED_VHID = "/interfaces/vip_settings/get_unused_vhid"
API_INTERFACES_VIP_RECONFIGURE = "/interfaces/vip_settings/reconfigure"

# Loopback Interface Management
API_INTERFACES_LOOPBACK_SEARCH = "/interfaces/loopback_settings/search_item"
API_INTERFACES_LOOPBACK_GET = "/interfaces/loopback_settings/get_item"  # /{uuid}
API_INTERFACES_LOOPBACK_ADD = "/interfaces/loopback_settings/add_item"
API_INTERFACES_LOOPBACK_SET = "/interfaces/loopback_settings/set_item"  # /{uuid}
API_INTERFACES_LOOPBACK_DEL = "/interfaces/loopback_settings/del_item"  # /{uuid}
API_INTERFACES_LOOPBACK_RECONFIGURE = "/interfaces/loopback_settings/reconfigure"

# GIF Tunnel Interface Management
API_INTERFACES_GIF_SEARCH = "/interfaces/gif_settings/search_item"
API_INTERFACES_GIF_GET = "/interfaces/gif_settings/get_item"  # /{uuid}
API_INTERFACES_GIF_ADD = "/interfaces/gif_settings/add_item"
API_INTERFACES_GIF_SET = "/interfaces/gif_settings/set_item"  # /{uuid}
API_INTERFACES_GIF_DEL = "/interfaces/gif_settings/del_item"  # /{uuid}
API_INTERFACES_GIF_RECONFIGURE = "/interfaces/gif_settings/reconfigure"

# GRE Tunnel Interface Management
API_INTERFACES_GRE_SEARCH = "/interfaces/gre_settings/search_item"
API_INTERFACES_GRE_GET = "/interfaces/gre_settings/get_item"  # /{uuid}
API_INTERFACES_GRE_ADD = "/interfaces/gre_settings/add_item"
API_INTERFACES_GRE_SET = "/interfaces/gre_settings/set_item"  # /{uuid}
API_INTERFACES_GRE_DEL = "/interfaces/gre_settings/del_item"  # /{uuid}
API_INTERFACES_GRE_RECONFIGURE = "/interfaces/gre_settings/reconfigure"

# ========== DNS & DHCP MANAGEMENT API ENDPOINTS ==========

# DHCP Server Management
API_DHCP_SERVER_SEARCH = "/dhcp/server/search"
API_DHCP_SERVER_GET = "/dhcp/server/get"  # Optional /{uuid}
API_DHCP_SERVER_ADD = "/dhcp/server/add"
API_DHCP_SERVER_SET = "/dhcp/server/set"  # Needs /{uuid}
API_DHCP_SERVER_DEL = "/dhcp/server/del"  # Needs /{uuid}
API_DHCP_SERVER_TOGGLE = "/dhcp/server/toggle"  # Needs /{uuid}/{enabled}

# DHCP Static Mappings (Reservations)
API_DHCP_STATIC_SEARCH = "/dhcp/static/search"
API_DHCP_STATIC_GET = "/dhcp/static/get"  # Optional /{uuid}
API_DHCP_STATIC_ADD = "/dhcp/static/add"
API_DHCP_STATIC_SET = "/dhcp/static/set"  # Needs /{uuid}
API_DHCP_STATIC_DEL = "/dhcp/static/del"  # Needs /{uuid}

# DHCP Service Control
API_DHCP_SERVICE_STATUS = "/dhcp/service/status"
API_DHCP_SERVICE_START = "/dhcp/service/start"
API_DHCP_SERVICE_STOP = "/dhcp/service/stop"
API_DHCP_SERVICE_RESTART = "/dhcp/service/restart"
API_DHCP_SERVICE_RECONFIGURE = "/dhcp/service/reconfigure"

# DNS Resolver (Unbound)
API_DNS_RESOLVER_SETTINGS = "/dns/resolver/settings"
API_DNS_RESOLVER_SET_SETTINGS = "/dns/resolver/setSettings"
API_DNS_RESOLVER_HOST_SEARCH = "/dns/resolver/searchHost"
API_DNS_RESOLVER_HOST_GET = "/dns/resolver/getHost"  # Optional /{uuid}
API_DNS_RESOLVER_HOST_ADD = "/dns/resolver/addHost"
API_DNS_RESOLVER_HOST_SET = "/dns/resolver/setHost"  # Needs /{uuid}
API_DNS_RESOLVER_HOST_DEL = "/dns/resolver/delHost"  # Needs /{uuid}

# DNS Resolver Domain Overrides
API_DNS_RESOLVER_DOMAIN_SEARCH = "/dns/resolver/searchDomain"
API_DNS_RESOLVER_DOMAIN_GET = "/dns/resolver/getDomain"  # Optional /{uuid}
API_DNS_RESOLVER_DOMAIN_ADD = "/dns/resolver/addDomain"
API_DNS_RESOLVER_DOMAIN_SET = "/dns/resolver/setDomain"  # Needs /{uuid}
API_DNS_RESOLVER_DOMAIN_DEL = "/dns/resolver/delDomain"  # Needs /{uuid}

# DNS Forwarder (dnsmasq)
API_DNS_FORWARDER_SETTINGS = "/dns/forwarder/settings"
API_DNS_FORWARDER_SET_SETTINGS = "/dns/forwarder/setSettings"
API_DNS_FORWARDER_HOST_SEARCH = "/dns/forwarder/searchHost"
API_DNS_FORWARDER_HOST_GET = "/dns/forwarder/getHost"  # Optional /{uuid}
API_DNS_FORWARDER_HOST_ADD = "/dns/forwarder/addHost"
API_DNS_FORWARDER_HOST_SET = "/dns/forwarder/setHost"  # Needs /{uuid}
API_DNS_FORWARDER_HOST_DEL = "/dns/forwarder/delHost"  # Needs /{uuid}

# DNS Service Control
API_DNS_RESOLVER_SERVICE_STATUS = "/dns/resolver/status"
API_DNS_RESOLVER_SERVICE_START = "/dns/resolver/start"
API_DNS_RESOLVER_SERVICE_STOP = "/dns/resolver/stop"
API_DNS_RESOLVER_SERVICE_RESTART = "/dns/resolver/restart"
API_DNS_RESOLVER_SERVICE_RECONFIGURE = "/dns/resolver/reconfigure"

API_DNS_FORWARDER_SERVICE_STATUS = "/dns/forwarder/status"
API_DNS_FORWARDER_SERVICE_START = "/dns/forwarder/start"
API_DNS_FORWARDER_SERVICE_STOP = "/dns/forwarder/stop"
API_DNS_FORWARDER_SERVICE_RESTART = "/dns/forwarder/restart"
API_DNS_FORWARDER_SERVICE_RECONFIGURE = "/dns/forwarder/reconfigure"

# Diagnostics
API_DIAGNOSTICS_LOG_FIREWALL = "/diagnostics/log/firewall"
API_DIAGNOSTICS_SYSTEM_PROCESSOR = "/diagnostics/system/processor"
API_DIAGNOSTICS_SYSTEM_MEMORY = "/diagnostics/system/memory"
API_DIAGNOSTICS_SYSTEM_STORAGE = "/diagnostics/system/storage"
API_DIAGNOSTICS_SYSTEM_TEMPERATURE = "/diagnostics/system/temperature"

# ========== LOGGING & LOG MANAGEMENT API ENDPOINTS ==========

# Core Logging
API_DIAGNOSTICS_LOG_SYSTEM = "/diagnostics/log/system"
API_DIAGNOSTICS_LOG_SYSTEM_SEARCH = "/diagnostics/log/system/search"
API_DIAGNOSTICS_LOG_ACCESS = "/diagnostics/log/access"
API_DIAGNOSTICS_LOG_AUTHENTICATION = "/diagnostics/log/authentication"
API_DIAGNOSTICS_LOG_DHCP = "/diagnostics/log/dhcp"
API_DIAGNOSTICS_LOG_DNS = "/diagnostics/log/dns"
API_DIAGNOSTICS_LOG_OPENVPN = "/diagnostics/log/openvpn"
API_DIAGNOSTICS_LOG_IPSEC = "/diagnostics/log/ipsec"
API_DIAGNOSTICS_LOG_SQUID = "/diagnostics/log/squid"
API_DIAGNOSTICS_LOG_HAPROXY = "/diagnostics/log/haproxy"

# Log Management
API_DIAGNOSTICS_LOG_CLEAR = "/diagnostics/log/clear"  # Needs /{log_type}
API_DIAGNOSTICS_LOG_EXPORT = "/diagnostics/log/export"  # Needs /{log_type}
API_DIAGNOSTICS_LOG_STATS = "/diagnostics/log/stats"  # Needs /{log_type}
API_DIAGNOSTICS_LOG_TAIL = "/diagnostics/log/tail"  # Needs /{log_type}
API_DIAGNOSTICS_LOG_SETTINGS = "/diagnostics/log/settings"
API_DIAGNOSTICS_LOG_SET_SETTINGS = "/diagnostics/log/setSettings"

# Log Streaming and Real-time
API_DIAGNOSTICS_LOG_STREAM = "/diagnostics/log/stream"  # Needs /{log_type}
API_DIAGNOSTICS_LOG_FIREWALL_STREAM = "/diagnostics/log/firewall/stream"

# Advanced Log Analysis
API_DIAGNOSTICS_LOG_PATTERNS = "/diagnostics/log/patterns"  # Needs /{log_type}
API_DIAGNOSTICS_LOG_SUMMARY = "/diagnostics/log/summary"  # Needs /{log_type}
API_DIAGNOSTICS_LOG_SEARCH_ALL = "/diagnostics/log/search"

# Routes
API_ROUTES_GET = "/routes/routes/get"

# VPN
API_OPENVPN_SERVICE_STATUS = "/openvpn/service/getStatus"
API_IPSEC_SERVICE_STATUS = "/ipsec/service/status"
API_WIREGUARD_SERVICE_SHOW = "/wireguard/service/show"

# NAT (Network Address Translation)
# Source NAT (Outbound NAT)
API_FIREWALL_SOURCE_NAT_SEARCH_RULE = "/firewall/source_nat/search_rule"
API_FIREWALL_SOURCE_NAT_GET_RULE = "/firewall/source_nat/get_rule"  # Needs /{uuid}
API_FIREWALL_SOURCE_NAT_ADD_RULE = "/firewall/source_nat/add_rule"
API_FIREWALL_SOURCE_NAT_SET_RULE = "/firewall/source_nat/set_rule"  # Needs /{uuid}
API_FIREWALL_SOURCE_NAT_DEL_RULE = "/firewall/source_nat/del_rule"  # Needs /{uuid}
API_FIREWALL_SOURCE_NAT_TOGGLE_RULE = "/firewall/source_nat/toggle_rule"  # Needs /{uuid}/{enabled}

# One-to-One NAT
API_FIREWALL_ONE_TO_ONE_SEARCH_RULE = "/firewall/one_to_one/search_rule"
API_FIREWALL_ONE_TO_ONE_GET_RULE = "/firewall/one_to_one/get_rule"  # Needs /{uuid}
API_FIREWALL_ONE_TO_ONE_ADD_RULE = "/firewall/one_to_one/add_rule"
API_FIREWALL_ONE_TO_ONE_SET_RULE = "/firewall/one_to_one/set_rule"  # Needs /{uuid}
API_FIREWALL_ONE_TO_ONE_DEL_RULE = "/firewall/one_to_one/del_rule"  # Needs /{uuid}
API_FIREWALL_ONE_TO_ONE_TOGGLE_RULE = "/firewall/one_to_one/toggle_rule"  # Needs /{uuid}/{enabled}

# Firewall Configuration Management
API_FIREWALL_FILTER_BASE_APPLY = "/firewall/filter_base/apply"
API_FIREWALL_FILTER_BASE_SAVEPOINT = "/firewall/filter_base/savepoint"
API_FIREWALL_FILTER_BASE_REVERT = "/firewall/filter_base/revert"

# ========== USER & GROUP MANAGEMENT API ENDPOINTS ==========

# Core User Management
API_CORE_USER_SEARCH = "/core/user/searchUser"
API_CORE_USER_GET = "/core/user/getUser"  # Optional /{uuid}
API_CORE_USER_ADD = "/core/user/addUser"
API_CORE_USER_SET = "/core/user/setUser"  # Needs /{uuid}
API_CORE_USER_DEL = "/core/user/delUser"  # Needs /{uuid}
API_CORE_USER_TOGGLE = "/core/user/toggleUser"  # Needs /{uuid}/{enabled}

# Core Group Management
API_CORE_GROUP_SEARCH = "/core/group/searchGroup"
API_CORE_GROUP_GET = "/core/group/getGroup"  # Optional /{uuid}
API_CORE_GROUP_ADD = "/core/group/addGroup"
API_CORE_GROUP_SET = "/core/group/setGroup"  # Needs /{uuid}
API_CORE_GROUP_DEL = "/core/group/delGroup"  # Needs /{uuid}

# Authentication & Privileges
API_CORE_AUTH_PRIVILEGES = "/core/auth/privileges"
API_CORE_AUTH_SERVERS = "/core/auth/authServers"
API_CORE_AUTH_TEST = "/core/auth/testAuthentication"

# Configuration Management
API_CORE_CONFIG_RELOAD = "/core/config/reload"


class OPNsenseClient:
    """Client for interacting with OPNsense API."""

    def __init__(self, config: OPNsenseConfig, pool: Optional['ConnectionPool'] = None):
        """Initialize OPNsense API client.

        Args:
            config: Configuration for OPNsense connection
            pool: Connection pool for rate limiting
        """
        self.base_url = config.url.rstrip("/")
        self.api_key = config.api_key
        self.api_secret = config.api_secret
        self.verify_ssl = config.verify_ssl
        self.pool = pool

        # Enhanced client configuration
        self.client = httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=httpx.Timeout(30.0, pool=5.0),
            limits=httpx.Limits(
                max_keepalive_connections=5,
                max_connections=10,
                keepalive_expiry=30.0
            )
        )

        # Set up Basic Auth
        auth_str = f"{self.api_key}:{self.api_secret}"
        self.auth_header = base64.b64encode(auth_str.encode()).decode()
        
        logger.info(f"Initialized OPNsense client for {self.base_url}")
    
    async def close(self):
        """Close the httpx client."""
        await self.client.aclose()
    
    async def request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        operation: str = "api_request",
        timeout: float = 30.0,
        retry_config: Optional[RetryConfig] = None
    ) -> Dict[str, Any]:
        """Make a request to the OPNsense API with comprehensive error handling and logging.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (e.g., "/core/firmware/status")
            data: Request payload for POST requests
            params: Query parameters for GET requests
            operation: Name of operation for logging/error context
            timeout: Request timeout in seconds
            retry_config: Configuration for retry mechanism

        Returns:
            Response from the API as a dictionary

        Raises:
            ValidationError: For invalid input parameters
            AuthenticationError: If authentication fails (401)
            AuthorizationError: If authorization fails (403)
            ResourceNotFoundError: For not found errors (404)
            RateLimitError: If rate limit is exceeded (429)
            APIError: For other HTTP errors
            NetworkError: For network connection issues
            TimeoutError: For request timeouts
        """
        # Validate inputs
        if not method or not endpoint:
            raise ValidationError("Method and endpoint are required",
                                context={"method": method, "endpoint": endpoint})

        if method.upper() not in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
            raise ValidationError(f"Unsupported HTTP method: {method}",
                                context={"method": method})

        # Apply rate limiting if pool is available
        if self.pool:
            await self.pool.check_rate_limit()

        url = f"{self.base_url}/api{endpoint}"
        headers = {
            "Authorization": f"Basic {self.auth_header}",
            "Accept": "application/json",
            "User-Agent": "OPNsense-MCP-Server/1.0"
        }

        # Log the request
        request_logger.log_request(method, url, headers, data, operation)
        start_time = datetime.utcnow()

        async def _make_request():
            """Internal request function for retry mechanism."""
            try:
                if method.upper() == "GET":
                    response = await self.client.get(url, headers=headers, params=params, timeout=timeout)
                elif method.upper() == "POST":
                    response = await self.client.post(url, headers=headers, json=data, timeout=timeout)
                elif method.upper() == "PUT":
                    response = await self.client.put(url, headers=headers, json=data, timeout=timeout)
                elif method.upper() == "DELETE":
                    response = await self.client.delete(url, headers=headers, params=params, timeout=timeout)
                elif method.upper() == "PATCH":
                    response = await self.client.patch(url, headers=headers, json=data, timeout=timeout)

                # Calculate response time
                duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
                response_size = len(response.content) if response.content else 0

                # Handle HTTP errors with proper exception mapping
                if response.status_code == 401:
                    request_logger.log_response(response.status_code, response_size, duration_ms, operation)
                    raise AuthenticationError("Authentication failed - invalid API credentials",
                                            context={"status_code": 401, "endpoint": endpoint})
                elif response.status_code == 403:
                    request_logger.log_response(response.status_code, response_size, duration_ms, operation)
                    raise AuthorizationError("Access denied - insufficient permissions",
                                           context={"status_code": 403, "endpoint": endpoint})
                elif response.status_code == 404:
                    request_logger.log_response(response.status_code, response_size, duration_ms, operation)
                    raise ResourceNotFoundError(f"Resource not found: {endpoint}",
                                              context={"status_code": 404, "endpoint": endpoint})
                elif response.status_code == 429:
                    request_logger.log_response(response.status_code, response_size, duration_ms, operation)
                    raise RateLimitError("API rate limit exceeded",
                                       context={"status_code": 429, "endpoint": endpoint, "retry_after": response.headers.get("Retry-After")})
                elif not (200 <= response.status_code < 300):
                    request_logger.log_response(response.status_code, response_size, duration_ms, operation)
                    try:
                        error_data = response.json()
                    except:
                        error_data = {"error": response.text}

                    raise APIError(f"API error: {response.status_code}",
                                 status_code=response.status_code,
                                 response_text=response.text)

                # Parse JSON response
                try:
                    result = response.json()
                    request_logger.log_response(response.status_code, response_size, duration_ms, operation)
                    return result
                except json.JSONDecodeError as e:
                    request_logger.log_response(response.status_code, response_size, duration_ms, operation, e)
                    raise APIError(f"Invalid JSON response from OPNsense API: {str(e)}",
                                 status_code=response.status_code,
                                 response_text=response.text)

            except httpx.TimeoutException as e:
                duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
                request_logger.log_response(0, 0, duration_ms, operation, e)
                raise TimeoutError(f"Request timed out after {timeout}s",
                                 context={"timeout": timeout, "endpoint": endpoint})

            except httpx.ConnectError as e:
                duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
                request_logger.log_response(0, 0, duration_ms, operation, e)
                raise NetworkError(f"Cannot connect to OPNsense at {self.base_url}",
                                    context={"base_url": self.base_url, "endpoint": endpoint, "error": str(e)})

            except httpx.RequestError as e:
                duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
                request_logger.log_response(0, 0, duration_ms, operation, e)
                raise NetworkError(f"Network error: {str(e)}",
                                    context={"endpoint": endpoint, "error": str(e)})

        # Use retry mechanism if configured
        if retry_config:
            return await retry_with_backoff(_make_request, retry_config=retry_config)
        else:
            return await _make_request()


# Initialize MCP server
mcp = FastMCP("OPNsense MCP Server", description="Manage OPNsense firewalls via MCP")


# Initialize server state management
server_state = ServerState()


# ========== ERROR HANDLING HELPERS ==========

async def handle_tool_error(ctx: Context, operation: str, error: Exception, severity: ErrorSeverity = ErrorSeverity.MEDIUM) -> str:
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
    import re
    uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
    if not uuid_pattern.match(uuid):
        raise ValidationError(
            f"Invalid UUID format: {uuid}",
            context={"uuid": uuid, "operation": operation, "expected_format": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"}
        )


def validate_firewall_parameters(action: str, direction: str, ipprotocol: str, protocol: str, operation: str) -> None:
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


async def get_opnsense_client() -> OPNsenseClient:
    """Get OPNsense client from server state with validation."""
    return await server_state.get_client()


@mcp.tool(name="get_api_endpoints", description="List available API endpoints from OPNsense")
async def get_api_endpoints(
    ctx: Context,
    module: Optional[str] = None
) -> str:
    """List available API endpoints from OPNsense.

    Args:
        ctx: MCP context
        module: Optional module name to filter endpoints

    Returns:
        JSON string of available endpoints
    """
    try:
        client = await get_opnsense_client()

        # Get all available modules first
        response = await client.request("GET", API_CORE_MENU_GET_ITEMS)

        if module:
            # Filter endpoints by module if specified
            if module in response:
                return json.dumps(response[module], indent=2)
            else:
                available_modules = list(response.keys())
                return f"Module '{module}' not found. Available modules: {available_modules}"
        else:
            # Return all modules and endpoints
            return json.dumps(response, indent=2)

    except ConfigurationError as e:
        await ctx.error(str(e))
        return f"Configuration Error: {str(e)}"
    except (AuthenticationError, NetworkError, APIError) as e:
        logger.error(f"Error in get_api_endpoints: {str(e)}", exc_info=True)
        await ctx.error(f"Error fetching API endpoints: {str(e)}")
        return f"Error: {str(e)}"
    except Exception as e:
        logger.error(f"Unexpected error in get_api_endpoints: {str(e)}", exc_info=True)
        await ctx.error(f"Unexpected error: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="get_system_status", description="Get OPNsense system status")
async def get_system_status(ctx: Context) -> str:
    """Get OPNsense system status.
    
    Args:
        ctx: MCP context
        
    Returns:
        Formatted system status information
    """
    try:
        client = await get_opnsense_client()

        # Get firmware status
        firmware = await client.request("GET", API_CORE_FIRMWARE_STATUS)

        # Get system information
        system_info = await client.request("GET", API_CORE_SYSTEM_INFO)

        # Get service status
        services = await client.request(
            "POST",
            API_CORE_SERVICE_SEARCH,
            data={"current": 1, "rowCount": -1, "searchPhrase": ""}
        )

        # Format and return the combined status
        status = {
            "firmware": firmware,
            "system": system_info,
            "services": services.get("rows", [])
        }

        return json.dumps(status, indent=2)

    except ConfigurationError as e:
        await ctx.error(str(e))
        return f"Configuration Error: {str(e)}"
    except (AuthenticationError, NetworkError, APIError) as e:
        logger.error(f"Error in get_system_status: {str(e)}", exc_info=True)
        await ctx.error(f"Error fetching system status: {str(e)}")
        return f"Error: {str(e)}"
    except Exception as e:
        logger.error(f"Unexpected error in get_system_status: {str(e)}", exc_info=True)
        await ctx.error(f"Unexpected error: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="firewall_get_rules", description="Get OPNsense firewall rules")
async def firewall_get_rules(
    ctx: Context,
    search_phrase: str = "",
    page: int = 1,
    rows_per_page: int = 20
) -> str:
    """Get OPNsense firewall rules.
    
    Args:
        ctx: MCP context
        search_phrase: Optional search phrase to filter rules
        page: Page number for pagination
        rows_per_page: Number of rows per page
        
    Returns:
        JSON string of firewall rules
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        response = await opnsense_client.request(
            "POST",
            API_FIREWALL_FILTER_SEARCH_RULE,
            data={
                "current": page,
                "rowCount": rows_per_page,
                "searchPhrase": search_phrase
            }
        )
        
        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in firewall_get_rules: {str(e)}", exc_info=True)
        await ctx.error(f"Error fetching firewall rules: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="firewall_add_rule", description="Add a new firewall rule")
async def firewall_add_rule(
    ctx: Context,
    description: str,
    action: str = "pass",
    interface: str = "lan",
    direction: str = "in",
    ipprotocol: str = "inet",
    protocol: str = "any",
    source_net: str = "any",
    destination_net: str = "any",
    destination_port: str = "",
    enabled: bool = True
) -> str:
    """Add a new firewall rule with comprehensive validation and error handling.

    Args:
        ctx: MCP context
        description: Rule description
        action: Rule action (pass, block, reject)
        interface: Network interface
        direction: Traffic direction (in, out)
        ipprotocol: IP protocol (inet for IPv4, inet6 for IPv6)
        protocol: Transport protocol (tcp, udp, icmp, any)
        source_net: Source network/host
        destination_net: Destination network/host
        destination_port: Destination port(s)
        enabled: Whether the rule is enabled

    Returns:
        JSON string with the result
    """
    try:
        client = await get_opnsense_client()

        # Validate firewall rule parameters
        validate_firewall_parameters(action, direction, ipprotocol, protocol, "firewall_add_rule")

        # Validate description
        if not description or len(description.strip()) == 0:
            raise ValidationError("Rule description is required",
                                context={"operation": "firewall_add_rule", "parameter": "description"})

        # Additional validation for specific protocols and ports
        if protocol in ["tcp", "udp"] and destination_port and not destination_port.replace("-", "").replace(",", "").replace(" ", "").isdigit():
            # Simple port validation - could be enhanced
            if not all(part.strip().isdigit() or "-" in part for part in destination_port.split(",")):
                raise ValidationError(f"Invalid port format: {destination_port}",
                                    context={"operation": "firewall_add_rule", "parameter": "destination_port", "value": destination_port})
        # Prepare rule data
        rule_data = {
            "rule": {
                "description": description,
                "action": action,
                "interface": interface,
                "direction": direction,
                "ipprotocol": ipprotocol,
                "protocol": protocol,
                "source_net": source_net,
                "destination_net": destination_net,
                "destination_port": destination_port,
                "enabled": "1" if enabled else "0"
            }
        }
        
        # Add the rule
        add_result = await opnsense_client.request(
            "POST",
            API_FIREWALL_FILTER_ADD_RULE,
            data=rule_data
        )
        
        # Apply changes
        await ctx.info("Rule added, applying changes...")
        apply_result = await opnsense_client.request(
            "POST",
            API_FIREWALL_FILTER_APPLY
        )
        
        return json.dumps({
            "add_result": add_result,
            "apply_result": apply_result
        }, indent=2)
    except Exception as e:
        return await handle_tool_error(ctx, "firewall_add_rule", e, ErrorSeverity.HIGH)


@mcp.tool(name="firewall_delete_rule", description="Delete a firewall rule by UUID")
async def firewall_delete_rule(ctx: Context, uuid: str) -> str:
    """Delete a firewall rule by UUID with enhanced validation and error handling.

    Args:
        ctx: MCP context
        uuid: UUID of the rule to delete

    Returns:
        JSON string with the result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID format
        validate_uuid(uuid, "firewall_delete_rule")
        # Delete the rule
        delete_result = await client.request(
            "POST",
            f"{API_FIREWALL_FILTER_DEL_RULE}/{uuid}",
            operation="delete_firewall_rule"
        )

        # Apply changes with retry for reliability
        await ctx.info("Rule deleted, applying changes...")
        retry_config = RetryConfig(max_attempts=2, base_delay=1.0)
        apply_result = await client.request(
            "POST",
            API_FIREWALL_FILTER_APPLY,
            operation="apply_firewall_changes",
            retry_config=retry_config
        )

        return json.dumps({
            "delete_result": delete_result,
            "apply_result": apply_result
        }, indent=2)
    except Exception as e:
        return await handle_tool_error(ctx, "firewall_delete_rule", e, ErrorSeverity.HIGH)


@mcp.tool(name="firewall_toggle_rule", description="Enable or disable a firewall rule")
async def firewall_toggle_rule(ctx: Context, uuid: str, enabled: bool) -> str:
    """Enable or disable a firewall rule.
    
    Args:
        ctx: MCP context
        uuid: UUID of the rule to toggle
        enabled: Whether to enable or disable the rule
        
    Returns:
        JSON string with the result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        # Toggle the rule
        toggle_result = await opnsense_client.request(
            "POST",
            f"{API_FIREWALL_FILTER_TOGGLE_RULE}/{uuid}/{1 if enabled else 0}"
        )
        
        # Apply changes
        await ctx.info(f"Rule {'enabled' if enabled else 'disabled'}, applying changes...")
        apply_result = await opnsense_client.request(
            "POST",
            API_FIREWALL_FILTER_APPLY
        )
        
        return json.dumps({
            "toggle_result": toggle_result,
            "apply_result": apply_result
        }, indent=2)
    except Exception as e:
        logger.error(f"Error in firewall_toggle_rule (uuid: {uuid}, enabled: {enabled}): {str(e)}", exc_info=True)
        await ctx.error(f"Error toggling firewall rule: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="get_interfaces", description="Get network interfaces")
async def get_interfaces(ctx: Context) -> str:
    """Get network interfaces.
    
    Args:
        ctx: MCP context
        
    Returns:
        JSON string of network interfaces
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        response = await opnsense_client.request("GET", API_INTERFACES_OVERVIEW_INFO)
        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in get_interfaces: {str(e)}", exc_info=True)
        await ctx.error(f"Error fetching interfaces: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="get_dhcp_leases", description="Get DHCP leases")
async def get_dhcp_leases(ctx: Context) -> str:
    """Get DHCP leases.
    
    Args:
        ctx: MCP context
        
    Returns:
        JSON string of DHCP leases
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        response = await opnsense_client.request("GET", API_DHCP_LEASES_SEARCH)
        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in get_dhcp_leases: {str(e)}", exc_info=True)
        await ctx.error(f"Error fetching DHCP leases: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="get_firewall_aliases", description="Get firewall aliases")
async def get_firewall_aliases(
    ctx: Context,
    search_phrase: str = "",
    page: int = 1,
    rows_per_page: int = 20
) -> str:
    """Get firewall aliases.
    
    Args:
        ctx: MCP context
        search_phrase: Optional search phrase to filter aliases
        page: Page number for pagination
        rows_per_page: Number of rows per page
        
    Returns:
        JSON string of firewall aliases
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        response = await opnsense_client.request(
            "POST",
            API_FIREWALL_ALIAS_SEARCH_ITEM,
            data={
                "current": page,
                "rowCount": rows_per_page,
                "searchPhrase": search_phrase
            }
        )
        
        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in get_firewall_aliases: {str(e)}", exc_info=True)
        await ctx.error(f"Error fetching firewall aliases: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="add_to_alias", description="Add an entry to a firewall alias")
async def add_to_alias(ctx: Context, alias_name: str, address: str) -> str:
    """Add an entry to a firewall alias.
    
    Args:
        ctx: MCP context
        alias_name: Name of the alias
        address: IP address, network, or hostname to add
        
    Returns:
        JSON string with the result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        # Add to alias
        add_result = await opnsense_client.request(
            "POST",
            f"{API_FIREWALL_ALIAS_UTIL_ADD}/{alias_name}/{urllib.parse.quote_plus(address)}"
        )
        
        # Reconfigure aliases
        await ctx.info("Entry added, applying changes...")
        reconfigure_result = await opnsense_client.request(
            "POST",
            API_FIREWALL_ALIAS_RECONFIGURE
        )
        
        return json.dumps({
            "add_result": add_result,
            "reconfigure_result": reconfigure_result
        }, indent=2)
    except Exception as e:
        logger.error(f"Error in add_to_alias (alias: {alias_name}, address: {address}): {str(e)}", exc_info=True)
        await ctx.error(f"Error adding to alias: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="delete_from_alias", description="Delete an entry from a firewall alias")
async def delete_from_alias(ctx: Context, alias_name: str, address: str) -> str:
    """Delete an entry from a firewall alias.
    
    Args:
        ctx: MCP context
        alias_name: Name of the alias
        address: IP address, network, or hostname to delete
        
    Returns:
        JSON string with the result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        # Delete from alias
        delete_result = await opnsense_client.request(
            "POST",
            f"{API_FIREWALL_ALIAS_UTIL_DELETE}/{alias_name}/{urllib.parse.quote_plus(address)}"
        )
        
        # Reconfigure aliases
        await ctx.info("Entry deleted, applying changes...")
        reconfigure_result = await opnsense_client.request(
            "POST",
            API_FIREWALL_ALIAS_RECONFIGURE
        )
        
        return json.dumps({
            "delete_result": delete_result,
            "reconfigure_result": reconfigure_result
        }, indent=2)
    except Exception as e:
        logger.error(f"Error in delete_from_alias (alias: {alias_name}, address: {address}): {str(e)}", exc_info=True)
        await ctx.error(f"Error deleting from alias: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="exec_api_call", description="Execute a custom API call to OPNsense")
async def exec_api_call(
    ctx: Context,
    method: str,
    endpoint: str,
    data: Optional[str] = None,
    params: Optional[str] = None
) -> str:
    """Execute a custom API call to OPNsense.
    
    Args:
        ctx: MCP context
        method: HTTP method (GET, POST)
        endpoint: API endpoint (e.g., "/core/firmware/status")
        data: JSON string of POST data (optional)
        params: JSON string of query parameters for GET (optional)
        
    Returns:
        JSON string with the API response
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        data_dict = json.loads(data) if data else None
        params_dict = json.loads(params) if params else None
        
        response = await opnsense_client.request(
            method,
            endpoint,
            data=data_dict,
            params=params_dict
        )
        
        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in exec_api_call (method: {method}, endpoint: {endpoint}): {str(e)}", exc_info=True)
        await ctx.error(f"Error executing API call: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="configure_opnsense_connection", description="Configure the OPNsense connection with enhanced security")
async def configure_opnsense_connection(
    ctx: Context,
    url: str,
    api_key: str,
    api_secret: str,
    verify_ssl: bool = True
) -> str:
    """Configure the OPNsense connection with enhanced security and validation.

    Args:
        ctx: MCP context
        url: OPNsense base URL (e.g., "https://192.168.1.1")
        api_key: API key
        api_secret: API secret
        verify_ssl: Whether to verify SSL certificates

    Returns:
        Success message
    """
    try:
        # Validate configuration using Pydantic
        config = OPNsenseConfig(
            url=url,
            api_key=api_key,
            api_secret=api_secret,
            verify_ssl=verify_ssl
        )

        # Initialize server state with new configuration
        await server_state.initialize(config)

        await ctx.info("OPNsense connection configured and validated successfully")
        return "OPNsense connection configured successfully with enhanced security"

    except AuthenticationError as e:
        error_msg = f"Authentication failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        await ctx.error(error_msg)
        return f"Authentication Error: {str(e)}"

    except NetworkError as e:
        error_msg = f"Network error: {str(e)}"
        logger.error(error_msg, exc_info=True)
        await ctx.error(error_msg)
        return f"Network Error: {str(e)}"

    except ValidationError as e:
        error_msg = f"Configuration validation failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        await ctx.error(error_msg)
        return f"Configuration Error: {str(e)}"

    except Exception as e:
        error_msg = f"Error configuring OPNsense connection: {str(e)}"
        logger.error(f"Unexpected error in configure_opnsense_connection (url: {url}): {str(e)}", exc_info=True)
        await ctx.error(error_msg)
        return f"Error: {str(e)}"


# More tools for other OPNsense modules can be added here


@mcp.tool(name="get_firewall_logs", description="Get firewall log entries")
async def get_firewall_logs(
    ctx: Context,
    count: int = 100,
    filter_text: str = ""
) -> str:
    """Get firewall log entries.
    
    Args:
        ctx: MCP context
        count: Number of log entries to retrieve
        filter_text: Optional text to filter log entries
        
    Returns:
        JSON string of log entries
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        response = await opnsense_client.request(
            "GET",
            API_DIAGNOSTICS_LOG_FIREWALL,
            params={"limit": count, "filter": filter_text}
        )
        
        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in get_firewall_logs: {str(e)}", exc_info=True)
        await ctx.error(f"Error fetching firewall logs: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="restart_service", description="Restart an OPNsense service")
async def restart_service(ctx: Context, service_name: str) -> str:
    """Restart an OPNsense service.
    
    Args:
        ctx: MCP context
        service_name: Name of the service to restart
        
    Returns:
        JSON string with the result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        response = await opnsense_client.request(
            "POST",
            f"{API_CORE_SERVICE_RESTART}/{service_name}"
        )
        
        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in restart_service (service: {service_name}): {str(e)}", exc_info=True)
        await ctx.error(f"Error restarting service: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="backup_config", description="Create a backup of the OPNsense configuration")
async def backup_config(ctx: Context) -> str:
    """Create a backup of the OPNsense configuration.
    
    Args:
        ctx: MCP context
        
    Returns:
        JSON string with the result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        response = await opnsense_client.request("POST", API_CORE_BACKUP_DOWNLOAD)
        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in backup_config: {str(e)}", exc_info=True)
        await ctx.error(f"Error creating backup: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="get_system_routes", description="Get system routing table")
async def get_system_routes(ctx: Context) -> str:
    """Get system routing table.
    
    Args:
        ctx: MCP context
        
    Returns:
        JSON string of system routes
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        response = await opnsense_client.request("GET", API_ROUTES_GET)
        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in get_system_routes: {str(e)}", exc_info=True)
        await ctx.error(f"Error fetching system routes: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="get_system_health", description="Get system health metrics")
async def get_system_health(ctx: Context) -> str:
    """Get system health metrics.
    
    Args:
        ctx: MCP context
        
    Returns:
        JSON string of system health metrics
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        # Get multiple health metrics
        cpu = await opnsense_client.request("GET", API_DIAGNOSTICS_SYSTEM_PROCESSOR)
        memory = await opnsense_client.request("GET", API_DIAGNOSTICS_SYSTEM_MEMORY)
        disk = await opnsense_client.request("GET", API_DIAGNOSTICS_SYSTEM_STORAGE)
        temperature = await opnsense_client.request("GET", API_DIAGNOSTICS_SYSTEM_TEMPERATURE)
        
        # Combine results
        return json.dumps({
            "cpu": cpu,
            "memory": memory,
            "disk": disk,
            "temperature": temperature
        }, indent=2)
    except Exception as e:
        logger.error(f"Error in get_system_health: {str(e)}", exc_info=True)
        await ctx.error(f"Error fetching system health: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="list_plugins", description="List installed plugins")
async def list_plugins(ctx: Context) -> str:
    """List installed plugins.
    
    Args:
        ctx: MCP context
        
    Returns:
        JSON string of installed plugins
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        response = await opnsense_client.request("GET", API_CORE_FIRMWARE_PLUGINS)
        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in list_plugins: {str(e)}", exc_info=True)
        await ctx.error(f"Error listing plugins: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="install_plugin", description="Install a plugin")
async def install_plugin(ctx: Context, plugin_name: str) -> str:
    """Install a plugin.
    
    Args:
        ctx: MCP context
        plugin_name: Name of the plugin to install
        
    Returns:
        JSON string with the result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        response = await opnsense_client.request(
            "POST",
            f"{API_CORE_FIRMWARE_INSTALL}/{plugin_name}"
        )
        
        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in install_plugin (plugin: {plugin_name}): {str(e)}", exc_info=True)
        await ctx.error(f"Error installing plugin: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="get_vpn_connections", description="Get VPN connection status")
async def get_vpn_connections(ctx: Context, vpn_type: str = "OpenVPN") -> str:
    """Get VPN connection status.
    
    Args:
        ctx: MCP context
        vpn_type: Type of VPN (OpenVPN, IPsec, WireGuard)
        
    Returns:
        JSON string of VPN connections
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        if vpn_type.lower() == "openvpn":
            response = await opnsense_client.request("GET", API_OPENVPN_SERVICE_STATUS)
        elif vpn_type.lower() == "ipsec":
            response = await opnsense_client.request("GET", API_IPSEC_SERVICE_STATUS)
        elif vpn_type.lower() == "wireguard":
            response = await opnsense_client.request("GET", API_WIREGUARD_SERVICE_SHOW)
        else:
            return f"Unsupported VPN type: {vpn_type}"
        
        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in get_vpn_connections (type: {vpn_type}): {str(e)}", exc_info=True)
        await ctx.error(f"Error fetching VPN connections: {str(e)}")
        return f"Error: {str(e)}"


# --- Firewall Audit Feature ---

async def _get_all_rules(client: OPNsenseClient) -> List[Dict[str, Any]]:
    """Helper to fetch all firewall rules using pagination."""
    all_rules = []
    current_page = 1
    rows_per_page = 500  # Fetch in larger batches
    while True:
        try:
            response = await client.request(
                "POST",
                API_FIREWALL_FILTER_SEARCH_RULE,
                data={
                    "current": current_page,
                    "rowCount": rows_per_page,
                    "searchPhrase": ""
                }
            )
            rules = response.get("rows", [])
            if not rules:
                break
            all_rules.extend(rules)
            if len(rules) < rows_per_page:
                break # Last page
            current_page += 1
        except Exception as e:
            logger.error(f"Error fetching page {current_page} of firewall rules: {e}", exc_info=True)
            # Return what we have so far, audit can proceed with partial data
            break 
    return all_rules

async def _get_wan_interfaces(client: OPNsenseClient) -> List[str]:
    """Helper to identify WAN interfaces."""
    wan_interfaces = []
    try:
        interfaces_info = await client.request("GET", API_INTERFACES_OVERVIEW_INFO)
        for if_name, if_data in interfaces_info.items():
            # Heuristic: Interface is likely WAN if it has a gateway and isn't loopback/internal
            # OPNsense often names the default WAN 'wan' but users can rename it.
            # Checking for a non-empty gateway field is a common indicator.
            if if_data.get("gateway") and if_data.get("gateway") != "none":
                 wan_interfaces.append(if_name)
            # Fallback: Explicitly check for common WAN names if gateway check fails 
            elif if_name.lower() == 'wan' and not wan_interfaces: 
                 wan_interfaces.append(if_name)
    except Exception as e:
        logger.error(f"Error fetching interfaces info for audit: {e}", exc_info=True)
    
    # If still no WAN identified, maybe return a default guess? For now, return empty. 
    if not wan_interfaces:
        logger.warning("Could not reliably identify WAN interfaces for audit.")
        
    return wan_interfaces

@mcp.tool(name="perform_firewall_audit", description="Performs a basic security audit of the OPNsense configuration.")
async def perform_firewall_audit(ctx: Context) -> str:
    """Performs a basic security audit of the OPNsense configuration.

    Checks for common potential security issues like outdated firmware/plugins, 
    management access from WAN, overly permissive rules, etc.

    Args:
        ctx: MCP context

    Returns:
        JSON string containing a list of audit findings.
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    findings = []
    await ctx.info("Starting OPNsense firewall audit...")

    try:
        # --- Fetch Data --- 
        await ctx.info("Fetching required data (firmware, rules, interfaces, services)...")
        firmware_status = await opnsense_client.request("GET", API_CORE_FIRMWARE_STATUS)
        all_rules = await _get_all_rules(opnsense_client)
        wan_interfaces = await _get_wan_interfaces(opnsense_client)
        services_response = await opnsense_client.request(
            "POST", 
            API_CORE_SERVICE_SEARCH,
            data={"current": 1, "rowCount": -1, "searchPhrase": ""} # Fetch all services
        )
        running_services = {svc['name']: svc for svc in services_response.get("rows", []) if svc.get('running') == 1}

        await ctx.info(f"Identified WAN interfaces: {wan_interfaces or 'None'}")
        await ctx.info(f"Fetched {len(all_rules)} firewall rules.")

        # --- Perform Checks --- 

        # 1. Firmware Update Check
        if firmware_status.get("status") == "update_available":
            findings.append({
                "check": "Firmware Update",
                "severity": "Medium",
                "description": f"Firmware update available. Current: {firmware_status.get('product_version', 'N/A')}, New: {firmware_status.get('product_new_version', 'N/A')}",
                "recommendation": "Consider updating OPNsense firmware via the GUI (System -> Firmware -> Updates)."
            })
        else:
            findings.append({
                "check": "Firmware Update",
                "severity": "Info",
                "description": "Firmware appears to be up-to-date.",
                "recommendation": None
            })

        # 2. Plugin Update Check
        plugin_updates = firmware_status.get("upgrade_packages", [])
        if plugin_updates:
            plugin_names = [p.get('name', 'N/A') for p in plugin_updates]
            findings.append({
                "check": "Plugin Updates",
                "severity": "Medium",
                "description": f"Updates available for {len(plugin_updates)} plugins: {', '.join(plugin_names)}",
                "recommendation": "Consider updating plugins via the GUI (System -> Firmware -> Updates)."
            })
        else:
             findings.append({
                "check": "Plugin Updates",
                "severity": "Info",
                "description": "Installed plugins appear to be up-to-date.",
                "recommendation": None
            })

        # 3. WAN Management Access Check
        management_ports = {'80', '443', '22'} # HTTP, HTTPS, SSH
        insecure_protocols = {'21', '23'} # FTP, Telnet
        wan_mgmt_rules = []
        wan_insecure_proto_rules = []
        wan_any_any_rules = []
        block_rules_no_log = []

        for rule in all_rules:
            # Skip disabled rules
            if not rule.get('enabled', '0') == '1': 
                continue

            interface = rule.get('interface')
            is_wan_rule = interface in wan_interfaces

            # Check logging on block/reject rules
            if rule.get('action') in ['block', 'reject'] and not rule.get('log', '0') == '1':
                 block_rules_no_log.append(rule.get("descr", rule.get("uuid", "N/A")))

            if not is_wan_rule:
                continue # Only check WAN rules for the following
                
            # Basic parsing - assumes 'any' if specific fields are missing/empty
            src_net = rule.get("source_net", "any")
            dst_net = rule.get("destination_net", "any")
            dst_port = rule.get("destination_port", "any")
            protocol = rule.get("protocol", "any").lower()
            action = rule.get('action')

            # Check Any-Any rule
            if action == 'pass' and src_net == 'any' and dst_net == 'any' and dst_port == 'any':
                wan_any_any_rules.append(rule.get("descr", rule.get("uuid", "N/A")))

            # Check Management Access
            # Simplified: Checks if dest port is one of the management ports
            # Doesn't check destination address (assumes firewall itself)
            if action == 'pass' and dst_port in management_ports:
                wan_mgmt_rules.append(rule.get("descr", rule.get("uuid", "N/A")))

            # Check Insecure Protocols
            if action == 'pass' and dst_port in insecure_protocols:
                 wan_insecure_proto_rules.append(rule.get("descr", rule.get("uuid", "N/A")))

        if wan_mgmt_rules:
            findings.append({
                "check": "WAN Management Access",
                "severity": "High",
                "description": f"Potential firewall rules allowing management access (HTTP/HTTPS/SSH) from WAN found: {', '.join(wan_mgmt_rules)}",
                "recommendation": "Review these rules. Exposing management interfaces to the WAN is highly discouraged. Use VPNs for remote access."
            })
        
        if wan_any_any_rules:
            findings.append({
                "check": "WAN Allow Any-Any",
                "severity": "High",
                "description": f"Potential 'allow any source to any destination' rules found on WAN interface(s): {', '.join(wan_any_any_rules)}",
                "recommendation": "Review these rules. 'Allow any-any' rules on WAN are extremely dangerous and likely misconfigured."
            })
            
        if wan_insecure_proto_rules:
            findings.append({
                "check": "WAN Insecure Protocols",
                "severity": "High",
                "description": f"Potential rules allowing insecure protocols (e.g., Telnet, FTP) from WAN found: {', '.join(wan_insecure_proto_rules)}",
                "recommendation": "Review these rules. Avoid using insecure protocols, especially over the WAN."
            })
        
        if block_rules_no_log:
            findings.append({
                "check": "Firewall Log Settings",
                "severity": "Low",
                "description": f"{len(block_rules_no_log)} firewall rule(s) that block or reject traffic do not have logging enabled (Examples: {', '.join(block_rules_no_log[:3])}{'...' if len(block_rules_no_log) > 3 else ''}).",
                "recommendation": "Consider enabling logging on block/reject rules (especially the default deny, if applicable) to monitor potential malicious activity."
            })
        else:
             findings.append({
                "check": "Firewall Log Settings",
                "severity": "Info",
                "description": "Block/reject rules checked appear to have logging enabled.",
                "recommendation": None
            })

        # 4. Check for enabled UPnP service
        if "miniupnpd" in running_services:
             findings.append({
                "check": "UPnP Service",
                "severity": "Low",
                "description": "The UPnP (Universal Plug and Play) service is enabled and running.",
                "recommendation": "Ensure UPnP is intentionally enabled and configured securely if needed. Disable it if unused, as it can potentially open ports automatically."
            })

        await ctx.info("Firewall audit checks complete.")

    except Exception as e:
        logger.error(f"Error during firewall audit: {str(e)}", exc_info=True)
        await ctx.error(f"Error performing firewall audit: {str(e)}")
        # Return partial findings if any were collected before the error
        if findings:
             findings.append({
                "check": "Audit Error",
                "severity": "Critical",
                "description": f"An error occurred during the audit: {str(e)}. Results may be incomplete.",
                "recommendation": "Check server logs for details."
            })
             return json.dumps({"audit_findings": findings}, indent=2)
        else:
             return json.dumps({"error": f"Failed to perform audit: {str(e)}"}, indent=2)

    return json.dumps({"audit_findings": findings}, indent=2)


# --- End Firewall Audit Feature ---


# ========== LOGGING & LOG MANAGEMENT ==========

@mcp.tool()
async def get_system_logs(ctx: RequestContext, log_type: str = "system",
                         count: int = 100, filter_text: str = "",
                         severity: str = "all") -> str:
    """
    Retrieve system logs from OPNsense with filtering capabilities.

    Args:
        log_type: Type of log to retrieve (system, access, authentication, dhcp, dns)
        count: Number of log entries to retrieve (default: 100, max: 1000)
        filter_text: Optional text to filter log entries
        severity: Log severity filter (all, emergency, alert, critical, error, warning, notice, info, debug)

    Returns:
        JSON response with log entries
    """
    try:
        client = get_opnsense_client()
        if not client:
            return "Error: OPNsense connection not configured. Use configure_opnsense_connection first."

        # Validate parameters
        valid_log_types = ["system", "access", "authentication", "dhcp", "dns", "openvpn", "ipsec"]
        if log_type not in valid_log_types:
            return json.dumps({
                "error": f"Invalid log type '{log_type}'. Valid types: {valid_log_types}"
            }, indent=2)

        valid_severities = ["all", "emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"]
        if severity not in valid_severities:
            return json.dumps({
                "error": f"Invalid severity '{severity}'. Valid severities: {valid_severities}"
            }, indent=2)

        # Limit count to reasonable maximum
        if count > 1000:
            count = 1000

        # Map log type to API endpoint
        endpoint_map = {
            "system": API_DIAGNOSTICS_LOG_SYSTEM,
            "access": API_DIAGNOSTICS_LOG_ACCESS,
            "authentication": API_DIAGNOSTICS_LOG_AUTHENTICATION,
            "dhcp": API_DIAGNOSTICS_LOG_DHCP,
            "dns": API_DIAGNOSTICS_LOG_DNS,
            "openvpn": API_DIAGNOSTICS_LOG_OPENVPN,
            "ipsec": API_DIAGNOSTICS_LOG_IPSEC
        }

        endpoint = endpoint_map.get(log_type, API_DIAGNOSTICS_LOG_SYSTEM)

        # Build parameters
        params = {"limit": count}
        if filter_text:
            params["filter"] = filter_text
        if severity != "all":
            params["severity"] = severity

        response = await client.request("GET", endpoint, params=params, operation="get_system_logs")

        return json.dumps({
            "log_type": log_type,
            "count": count,
            "filter_applied": filter_text,
            "severity_filter": severity,
            "entries": response
        }, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_system_logs", e)


@mcp.tool()
async def get_service_logs(ctx: RequestContext, service_name: str,
                          count: int = 100, filter_text: str = "") -> str:
    """
    Retrieve logs for specific OPNsense services.

    Args:
        service_name: Name of the service (squid, haproxy, openvpn, ipsec, dhcp, dns)
        count: Number of log entries to retrieve (default: 100)
        filter_text: Optional text to filter log entries

    Returns:
        JSON response with service log entries
    """
    try:
        client = get_opnsense_client()
        if not client:
            return "Error: OPNsense connection not configured. Use configure_opnsense_connection first."

        # Map service names to endpoints
        service_endpoints = {
            "squid": API_DIAGNOSTICS_LOG_SQUID,
            "haproxy": API_DIAGNOSTICS_LOG_HAPROXY,
            "openvpn": API_DIAGNOSTICS_LOG_OPENVPN,
            "ipsec": API_DIAGNOSTICS_LOG_IPSEC,
            "dhcp": API_DIAGNOSTICS_LOG_DHCP,
            "dns": API_DIAGNOSTICS_LOG_DNS
        }

        if service_name not in service_endpoints:
            return json.dumps({
                "error": f"Service '{service_name}' not supported. Available services: {list(service_endpoints.keys())}"
            }, indent=2)

        endpoint = service_endpoints[service_name]
        params = {"limit": count}
        if filter_text:
            params["filter"] = filter_text

        response = await client.request("GET", endpoint, params=params, operation="get_service_logs")

        return json.dumps({
            "service": service_name,
            "count": count,
            "filter_applied": filter_text,
            "entries": response
        }, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_service_logs", e)


@mcp.tool()
async def search_logs(ctx: RequestContext, search_query: str,
                     log_types: str = "system,firewall",
                     max_results: int = 200,
                     case_sensitive: bool = False) -> str:
    """
    Search across multiple log types for specific patterns or text.

    Args:
        search_query: Text or pattern to search for
        log_types: Comma-separated list of log types to search (system,firewall,access,authentication,dhcp,dns)
        max_results: Maximum number of results to return per log type
        case_sensitive: Whether to perform case-sensitive search

    Returns:
        JSON response with search results from all specified log types
    """
    try:
        client = get_opnsense_client()
        if not client:
            return "Error: OPNsense connection not configured. Use configure_opnsense_connection first."

        if not search_query or len(search_query.strip()) < 2:
            return json.dumps({
                "error": "Search query must be at least 2 characters long"
            }, indent=2)

        # Parse log types
        requested_types = [t.strip().lower() for t in log_types.split(",")]
        available_types = ["system", "firewall", "access", "authentication", "dhcp", "dns", "openvpn", "ipsec"]

        invalid_types = [t for t in requested_types if t not in available_types]
        if invalid_types:
            return json.dumps({
                "error": f"Invalid log types: {invalid_types}. Available: {available_types}"
            }, indent=2)

        search_results = {}

        for log_type in requested_types:
            try:
                # Use the appropriate endpoint for each log type
                if log_type == "firewall":
                    endpoint = API_DIAGNOSTICS_LOG_FIREWALL
                else:
                    endpoint_map = {
                        "system": API_DIAGNOSTICS_LOG_SYSTEM,
                        "access": API_DIAGNOSTICS_LOG_ACCESS,
                        "authentication": API_DIAGNOSTICS_LOG_AUTHENTICATION,
                        "dhcp": API_DIAGNOSTICS_LOG_DHCP,
                        "dns": API_DIAGNOSTICS_LOG_DNS,
                        "openvpn": API_DIAGNOSTICS_LOG_OPENVPN,
                        "ipsec": API_DIAGNOSTICS_LOG_IPSEC
                    }
                    endpoint = endpoint_map.get(log_type)

                if not endpoint:
                    continue

                params = {
                    "limit": max_results,
                    "filter": search_query
                }
                if not case_sensitive:
                    params["case_insensitive"] = "true"

                response = await client.request("GET", endpoint, params=params,
                                              operation=f"search_{log_type}_logs")

                # Extract relevant data and count matches
                if isinstance(response, dict) and "rows" in response:
                    entries = response["rows"]
                elif isinstance(response, list):
                    entries = response
                else:
                    entries = [response] if response else []

                search_results[log_type] = {
                    "matches_found": len(entries),
                    "entries": entries[:max_results]  # Ensure we don't exceed limit
                }

            except Exception as log_error:
                search_results[log_type] = {
                    "error": f"Failed to search {log_type} logs: {str(log_error)}",
                    "matches_found": 0,
                    "entries": []
                }

        # Calculate total matches
        total_matches = sum(result.get("matches_found", 0) for result in search_results.values())

        return json.dumps({
            "search_query": search_query,
            "log_types_searched": requested_types,
            "case_sensitive": case_sensitive,
            "total_matches": total_matches,
            "results_by_log_type": search_results
        }, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "search_logs", e)


@mcp.tool()
async def export_logs(ctx: RequestContext, log_type: str,
                     export_format: str = "json",
                     date_range: str = "today",
                     include_filters: str = "") -> str:
    """
    Export logs in various formats for analysis or archival.

    Args:
        log_type: Type of log to export (system, firewall, access, authentication, dhcp, dns)
        export_format: Export format (json, csv, text)
        date_range: Date range for export (today, yesterday, week, month, custom)
        include_filters: Optional filters to apply during export

    Returns:
        JSON response with export information and download details
    """
    try:
        client = get_opnsense_client()
        if not client:
            return "Error: OPNsense connection not configured. Use configure_opnsense_connection first."

        # Validate parameters
        valid_formats = ["json", "csv", "text"]
        if export_format not in valid_formats:
            return json.dumps({
                "error": f"Invalid export format '{export_format}'. Valid formats: {valid_formats}"
            }, indent=2)

        valid_ranges = ["today", "yesterday", "week", "month", "custom"]
        if date_range not in valid_ranges:
            return json.dumps({
                "error": f"Invalid date range '{date_range}'. Valid ranges: {valid_ranges}"
            }, indent=2)

        # Try using export API endpoint first
        params = {
            "format": export_format,
            "range": date_range
        }
        if include_filters:
            params["filters"] = include_filters

        try:
            export_response = await client.request("GET", f"{API_DIAGNOSTICS_LOG_EXPORT}/{log_type}",
                                                 params=params, operation="export_logs")

            return json.dumps({
                "export_status": "completed",
                "log_type": log_type,
                "format": export_format,
                "date_range": date_range,
                "filters_applied": include_filters,
                "export_data": export_response
            }, indent=2)

        except (APIError, ResourceNotFoundError):
            # If export endpoint doesn't exist, fall back to retrieving logs and formatting
            endpoint_map = {
                "system": API_DIAGNOSTICS_LOG_SYSTEM,
                "firewall": API_DIAGNOSTICS_LOG_FIREWALL,
                "access": API_DIAGNOSTICS_LOG_ACCESS,
                "authentication": API_DIAGNOSTICS_LOG_AUTHENTICATION,
                "dhcp": API_DIAGNOSTICS_LOG_DHCP,
                "dns": API_DIAGNOSTICS_LOG_DNS,
                "openvpn": API_DIAGNOSTICS_LOG_OPENVPN,
                "ipsec": API_DIAGNOSTICS_LOG_IPSEC
            }

            endpoint = endpoint_map.get(log_type)
            if not endpoint:
                return json.dumps({
                    "error": f"Unsupported log type for export: {log_type}"
                }, indent=2)

            # Retrieve logs with larger limit for export
            retrieve_params = {"limit": 10000}
            if include_filters:
                retrieve_params["filter"] = include_filters

            logs_response = await client.request("GET", endpoint, params=retrieve_params,
                                               operation=f"retrieve_logs_for_export")

            return json.dumps({
                "export_status": "completed_via_retrieval",
                "log_type": log_type,
                "format": export_format,
                "date_range": date_range,
                "filters_applied": include_filters,
                "note": "Export completed by retrieving logs (export API not available)",
                "entry_count": len(logs_response) if isinstance(logs_response, list) else 1,
                "export_data": logs_response
            }, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "export_logs", e)


@mcp.tool()
async def get_log_statistics(ctx: RequestContext, log_type: str = "all",
                           time_period: str = "24h") -> str:
    """
    Get statistical analysis of log entries including counts, patterns, and trends.

    Args:
        log_type: Type of log to analyze (all, system, firewall, access, authentication)
        time_period: Time period for analysis (1h, 6h, 24h, 7d, 30d)

    Returns:
        JSON response with log statistics and analysis
    """
    try:
        client = get_opnsense_client()
        if not client:
            return "Error: OPNsense connection not configured. Use configure_opnsense_connection first."

        # Try using statistics API endpoint
        try:
            params = {"period": time_period}
            stats_response = await client.request("GET", f"{API_DIAGNOSTICS_LOG_STATS}/{log_type}",
                                                params=params, operation="get_log_statistics")

            return json.dumps({
                "statistics_source": "api_endpoint",
                "log_type": log_type,
                "time_period": time_period,
                "statistics": stats_response
            }, indent=2)

        except (APIError, ResourceNotFoundError):
            # If stats endpoint doesn't exist, generate basic statistics
            if log_type == "all":
                log_types_to_check = ["system", "firewall", "access", "authentication"]
            else:
                log_types_to_check = [log_type]

            statistics = {}

            for check_type in log_types_to_check:
                try:
                    # Get recent logs for analysis
                    endpoint_map = {
                        "system": API_DIAGNOSTICS_LOG_SYSTEM,
                        "firewall": API_DIAGNOSTICS_LOG_FIREWALL,
                        "access": API_DIAGNOSTICS_LOG_ACCESS,
                        "authentication": API_DIAGNOSTICS_LOG_AUTHENTICATION
                    }

                    endpoint = endpoint_map.get(check_type)
                    if not endpoint:
                        continue

                    response = await client.request("GET", endpoint,
                                                  params={"limit": 1000},
                                                  operation=f"get_{check_type}_stats")

                    # Generate basic statistics
                    if isinstance(response, list):
                        entries = response
                    elif isinstance(response, dict) and "rows" in response:
                        entries = response["rows"]
                    else:
                        entries = []

                    statistics[check_type] = {
                        "total_entries": len(entries),
                        "sample_period": time_period,
                        "entries_per_hour": round(len(entries) / 24, 2) if time_period == "24h" else "N/A"
                    }

                except Exception as type_error:
                    statistics[check_type] = {
                        "error": f"Failed to get statistics: {str(type_error)}",
                        "total_entries": 0
                    }

            return json.dumps({
                "statistics_source": "calculated_from_logs",
                "log_type": log_type,
                "time_period": time_period,
                "statistics": statistics,
                "note": "Statistics calculated from log retrieval (stats API not available)"
            }, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_log_statistics", e)


@mcp.tool()
async def clear_logs(ctx: RequestContext, log_type: str,
                    confirmation: str = "") -> str:
    """
    Clear specific log files with confirmation requirement.

    Args:
        log_type: Type of log to clear (system, firewall, access, authentication, dhcp, dns)
        confirmation: Must be "CONFIRM_CLEAR" to proceed with clearing

    Returns:
        JSON response with clear operation status
    """
    try:
        client = get_opnsense_client()
        if not client:
            return "Error: OPNsense connection not configured. Use configure_opnsense_connection first."

        # Require explicit confirmation
        if confirmation != "CONFIRM_CLEAR":
            return json.dumps({
                "error": "Log clearing requires explicit confirmation",
                "instruction": "Set confirmation parameter to 'CONFIRM_CLEAR' to proceed",
                "warning": "This action will permanently delete log entries and cannot be undone"
            }, indent=2)

        # Validate log type
        valid_log_types = ["system", "firewall", "access", "authentication", "dhcp", "dns", "openvpn", "ipsec"]
        if log_type not in valid_log_types:
            return json.dumps({
                "error": f"Invalid log type '{log_type}'. Valid types: {valid_log_types}"
            }, indent=2)

        try:
            # Try using dedicated clear API
            clear_response = await client.request("POST", f"{API_DIAGNOSTICS_LOG_CLEAR}/{log_type}",
                                                operation="clear_logs")

            return json.dumps({
                "clear_status": "completed",
                "log_type": log_type,
                "message": f"Successfully cleared {log_type} logs",
                "response": clear_response
            }, indent=2)

        except (APIError, ResourceNotFoundError):
            return json.dumps({
                "clear_status": "api_unavailable",
                "log_type": log_type,
                "message": f"Clear API not available for {log_type} logs",
                "recommendation": "Use OPNsense web interface: Firewall > Log Files > Clear Logs"
            }, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "clear_logs", e)


@mcp.tool()
async def configure_logging(ctx: RequestContext,
                          log_level: str = "info",
                          remote_logging: bool = False,
                          remote_server: str = "",
                          log_rotation: str = "daily") -> str:
    """
    Configure logging settings for OPNsense system.

    Args:
        log_level: Logging level (emergency, alert, critical, error, warning, notice, info, debug)
        remote_logging: Whether to enable remote logging
        remote_server: Remote syslog server (required if remote_logging is True)
        log_rotation: Log rotation schedule (daily, weekly, monthly)

    Returns:
        JSON response with configuration status
    """
    try:
        client = get_opnsense_client()
        if not client:
            return "Error: OPNsense connection not configured. Use configure_opnsense_connection first."

        # Validate parameters
        valid_levels = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"]
        if log_level not in valid_levels:
            return json.dumps({
                "error": f"Invalid log level '{log_level}'. Valid levels: {valid_levels}"
            }, indent=2)

        valid_rotations = ["daily", "weekly", "monthly"]
        if log_rotation not in valid_rotations:
            return json.dumps({
                "error": f"Invalid log rotation '{log_rotation}'. Valid options: {valid_rotations}"
            }, indent=2)

        if remote_logging and not remote_server:
            return json.dumps({
                "error": "Remote server must be specified when remote logging is enabled"
            }, indent=2)

        # Get current settings first
        try:
            current_settings = await client.request("GET", API_DIAGNOSTICS_LOG_SETTINGS,
                                                  operation="get_current_log_settings")
        except (APIError, ResourceNotFoundError):
            current_settings = {}

        # Prepare configuration data
        config_data = {
            "log_level": log_level,
            "remote_logging": "1" if remote_logging else "0",
            "log_rotation": log_rotation
        }

        if remote_logging and remote_server:
            config_data["remote_server"] = remote_server

        try:
            # Try to apply settings via API
            set_response = await client.request("POST", API_DIAGNOSTICS_LOG_SET_SETTINGS,
                                              data=config_data, operation="configure_logging")

            return json.dumps({
                "configuration_status": "completed",
                "previous_settings": current_settings,
                "new_settings": config_data,
                "response": set_response
            }, indent=2)

        except (APIError, ResourceNotFoundError):
            return json.dumps({
                "configuration_status": "api_unavailable",
                "message": "Logging configuration API not available",
                "intended_settings": config_data,
                "recommendation": "Use OPNsense web interface: System > Settings > Logging"
            }, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "configure_logging", e)


@mcp.tool()
async def analyze_security_events(ctx: RequestContext,
                                 time_window: str = "24h",
                                 event_types: str = "all") -> str:
    """
    Analyze logs for security-related events and potential threats.

    Args:
        time_window: Time window for analysis (1h, 6h, 24h, 7d)
        event_types: Types of events to analyze (all, authentication, firewall, intrusion)

    Returns:
        JSON response with security event analysis
    """
    try:
        client = get_opnsense_client()
        if not client:
            return "Error: OPNsense connection not configured. Use configure_opnsense_connection first."

        analysis_results = {}

        # Define security event patterns to search for
        security_patterns = {
            "failed_authentication": ["authentication failure", "login failed", "invalid user", "auth fail"],
            "firewall_blocks": ["blocked", "denied", "drop"],
            "brute_force": ["multiple failed", "repeated attempts", "too many"],
            "port_scans": ["port scan", "probe", "reconnaissance"],
            "suspicious_ips": ["suspicious", "malicious", "blacklist"]
        }

        # Get logs from relevant sources
        log_sources = ["system", "firewall", "authentication", "access"]
        if event_types != "all":
            requested_types = [t.strip() for t in event_types.split(",")]
            log_sources = [t for t in log_sources if t in requested_types]

        for log_source in log_sources:
            try:
                # Get recent logs for analysis
                endpoint_map = {
                    "system": API_DIAGNOSTICS_LOG_SYSTEM,
                    "firewall": API_DIAGNOSTICS_LOG_FIREWALL,
                    "authentication": API_DIAGNOSTICS_LOG_AUTHENTICATION,
                    "access": API_DIAGNOSTICS_LOG_ACCESS
                }

                endpoint = endpoint_map.get(log_source)
                if not endpoint:
                    continue

                # Retrieve logs (larger sample for analysis)
                logs_response = await client.request("GET", endpoint,
                                                   params={"limit": 5000},
                                                   operation=f"analyze_{log_source}_security")

                # Extract log entries
                if isinstance(logs_response, dict) and "rows" in logs_response:
                    log_entries = logs_response["rows"]
                elif isinstance(logs_response, list):
                    log_entries = logs_response
                else:
                    log_entries = []

                # Analyze for security patterns
                source_analysis = {"total_entries": len(log_entries)}

                for pattern_name, pattern_keywords in security_patterns.items():
                    matching_entries = []

                    for entry in log_entries:
                        # Convert entry to searchable text
                        entry_text = str(entry).lower() if entry else ""

                        # Check if any pattern keywords match
                        if any(keyword.lower() in entry_text for keyword in pattern_keywords):
                            matching_entries.append(entry)

                    source_analysis[pattern_name] = {
                        "count": len(matching_entries),
                        "percentage": round((len(matching_entries) / max(len(log_entries), 1)) * 100, 2),
                        "sample_entries": matching_entries[:5]  # First 5 matches as samples
                    }

                analysis_results[log_source] = source_analysis

            except Exception as source_error:
                analysis_results[log_source] = {
                    "error": f"Failed to analyze {log_source}: {str(source_error)}",
                    "total_entries": 0
                }

        # Generate security summary
        total_events = sum(source.get("total_entries", 0) for source in analysis_results.values())
        high_risk_indicators = []

        # Check for high-risk patterns
        for source, data in analysis_results.items():
            if isinstance(data, dict):
                for pattern, details in data.items():
                    if isinstance(details, dict) and details.get("count", 0) > 10:
                        high_risk_indicators.append(f"{source}: {pattern} ({details['count']} events)")

        return json.dumps({
            "analysis_period": time_window,
            "event_types_analyzed": log_sources,
            "total_log_entries": total_events,
            "high_risk_indicators": high_risk_indicators,
            "detailed_analysis": analysis_results,
            "recommendation": "Review high-count security events and consider implementing additional security measures" if high_risk_indicators else "No significant security events detected"
        }, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "analyze_security_events", e)


@mcp.tool()
async def generate_log_report(ctx: RequestContext,
                             report_type: str = "summary",
                             time_period: str = "24h",
                             include_details: bool = False) -> str:
    """
    Generate comprehensive log reports for analysis and compliance.

    Args:
        report_type: Type of report (summary, detailed, security, compliance)
        time_period: Time period for report (1h, 6h, 24h, 7d, 30d)
        include_details: Whether to include detailed log entries in report

    Returns:
        JSON response with generated log report
    """
    try:
        client = get_opnsense_client()
        if not client:
            return "Error: OPNsense connection not configured. Use configure_opnsense_connection first."

        # Validate parameters
        valid_report_types = ["summary", "detailed", "security", "compliance"]
        if report_type not in valid_report_types:
            return json.dumps({
                "error": f"Invalid report type '{report_type}'. Valid types: {valid_report_types}"
            }, indent=2)

        report_data = {
            "report_type": report_type,
            "time_period": time_period,
            "generated_at": datetime.utcnow().isoformat(),
            "sections": {}
        }

        # Get data from multiple log sources
        log_sources = ["system", "firewall", "authentication", "access"]

        for source in log_sources:
            try:
                endpoint_map = {
                    "system": API_DIAGNOSTICS_LOG_SYSTEM,
                    "firewall": API_DIAGNOSTICS_LOG_FIREWALL,
                    "authentication": API_DIAGNOSTICS_LOG_AUTHENTICATION,
                    "access": API_DIAGNOSTICS_LOG_ACCESS
                }

                endpoint = endpoint_map.get(source)
                if not endpoint:
                    continue

                # Get logs for report
                limit = 10000 if include_details else 1000
                response = await client.request("GET", endpoint,
                                              params={"limit": limit},
                                              operation=f"report_{source}_logs")

                # Extract entries
                if isinstance(response, dict) and "rows" in response:
                    entries = response["rows"]
                elif isinstance(response, list):
                    entries = response
                else:
                    entries = []

                # Create section data based on report type
                section_data = {
                    "entry_count": len(entries),
                    "source": source
                }

                if report_type == "summary":
                    section_data["summary"] = f"{len(entries)} entries in {time_period}"

                elif report_type == "detailed" and include_details:
                    section_data["entries"] = entries[:100]  # Limit detailed entries

                elif report_type == "security":
                    # Focus on security-relevant entries
                    security_keywords = ["fail", "error", "block", "deny", "suspicious", "attack"]
                    security_entries = []

                    for entry in entries:
                        entry_text = str(entry).lower()
                        if any(keyword in entry_text for keyword in security_keywords):
                            security_entries.append(entry)

                    section_data["security_events"] = len(security_entries)
                    if include_details:
                        section_data["security_entries"] = security_entries[:50]

                elif report_type == "compliance":
                    # Focus on compliance-relevant information
                    section_data["compliance_summary"] = {
                        "logging_active": len(entries) > 0,
                        "entry_count": len(entries),
                        "time_coverage": time_period
                    }

                report_data["sections"][source] = section_data

            except Exception as source_error:
                report_data["sections"][source] = {
                    "error": f"Failed to generate report for {source}: {str(source_error)}",
                    "entry_count": 0
                }

        # Add report summary
        total_entries = sum(section.get("entry_count", 0) for section in report_data["sections"].values())
        report_data["report_summary"] = {
            "total_entries": total_entries,
            "sources_included": len([s for s in report_data["sections"] if not s.get("error")]),
            "sources_with_errors": len([s for s in report_data["sections"] if s.get("error")])
        }

        return json.dumps(report_data, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "generate_log_report", e)


# --- NAT (Network Address Translation) Management ---

@mcp.tool(name="nat_list_outbound_rules", description="List outbound NAT (source NAT) rules")
async def nat_list_outbound_rules(
    ctx: Context,
    search_phrase: str = "",
    page: int = 1,
    rows_per_page: int = 20
) -> str:
    """List outbound NAT (source NAT) rules.

    Args:
        ctx: MCP context
        search_phrase: Optional search phrase to filter rules
        page: Page number for pagination
        rows_per_page: Number of rows per page

    Returns:
        JSON string of outbound NAT rules
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        response = await opnsense_client.request(
            "POST",
            API_FIREWALL_SOURCE_NAT_SEARCH_RULE,
            data={
                "current": page,
                "rowCount": rows_per_page,
                "searchPhrase": search_phrase
            }
        )

        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in nat_list_outbound_rules: {str(e)}", exc_info=True)
        await ctx.error(f"Error fetching outbound NAT rules: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="nat_add_outbound_rule", description="Add an outbound NAT (source NAT) rule")
async def nat_add_outbound_rule(
    ctx: Context,
    description: str,
    interface: str,
    source: str = "any",
    destination: str = "any",
    target: str = "",
    enabled: bool = True
) -> str:
    """Add an outbound NAT (source NAT) rule.

    Args:
        ctx: MCP context
        description: Description of the NAT rule
        interface: Outgoing interface (e.g., "wan", "opt1")
        source: Source network/host (default: "any")
        destination: Destination network/host (default: "any")
        target: NAT target (blank for interface address)
        enabled: Whether the rule is enabled

    Returns:
        JSON string with the result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        # Prepare rule data
        rule_data = {
            "rule": {
                "description": description,
                "interface": interface,
                "source": source,
                "destination": destination,
                "target": target,
                "enabled": "1" if enabled else "0"
            }
        }

        # Add the rule
        add_result = await opnsense_client.request(
            "POST",
            API_FIREWALL_SOURCE_NAT_ADD_RULE,
            data=rule_data
        )

        # Apply changes
        await ctx.info("Outbound NAT rule added, applying changes...")
        apply_result = await opnsense_client.request(
            "POST",
            API_FIREWALL_FILTER_BASE_APPLY
        )

        return json.dumps({
            "add_result": add_result,
            "apply_result": apply_result
        }, indent=2)
    except Exception as e:
        logger.error(f"Error in nat_add_outbound_rule: {str(e)}", exc_info=True)
        await ctx.error(f"Error adding outbound NAT rule: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="nat_delete_outbound_rule", description="Delete an outbound NAT rule")
async def nat_delete_outbound_rule(ctx: Context, uuid: str) -> str:
    """Delete an outbound NAT rule.

    Args:
        ctx: MCP context
        uuid: UUID of the rule to delete

    Returns:
        JSON string with the result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        # Delete the rule
        delete_result = await opnsense_client.request(
            "POST",
            f"{API_FIREWALL_SOURCE_NAT_DEL_RULE}/{uuid}"
        )

        # Apply changes
        await ctx.info("Outbound NAT rule deleted, applying changes...")
        apply_result = await opnsense_client.request(
            "POST",
            API_FIREWALL_FILTER_BASE_APPLY
        )

        return json.dumps({
            "delete_result": delete_result,
            "apply_result": apply_result
        }, indent=2)
    except Exception as e:
        logger.error(f"Error in nat_delete_outbound_rule: {str(e)}", exc_info=True)
        await ctx.error(f"Error deleting outbound NAT rule: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="nat_toggle_outbound_rule", description="Enable or disable an outbound NAT rule")
async def nat_toggle_outbound_rule(ctx: Context, uuid: str, enabled: bool) -> str:
    """Enable or disable an outbound NAT rule.

    Args:
        ctx: MCP context
        uuid: UUID of the rule to toggle
        enabled: Whether to enable or disable the rule

    Returns:
        JSON string with the result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        # Toggle the rule
        toggle_result = await opnsense_client.request(
            "POST",
            f"{API_FIREWALL_SOURCE_NAT_TOGGLE_RULE}/{uuid}/{1 if enabled else 0}"
        )

        # Apply changes
        await ctx.info(f"Outbound NAT rule {'enabled' if enabled else 'disabled'}, applying changes...")
        apply_result = await opnsense_client.request(
            "POST",
            API_FIREWALL_FILTER_BASE_APPLY
        )

        return json.dumps({
            "toggle_result": toggle_result,
            "apply_result": apply_result
        }, indent=2)
    except Exception as e:
        logger.error(f"Error in nat_toggle_outbound_rule: {str(e)}", exc_info=True)
        await ctx.error(f"Error toggling outbound NAT rule: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="nat_list_one_to_one_rules", description="List one-to-one NAT rules")
async def nat_list_one_to_one_rules(
    ctx: Context,
    search_phrase: str = "",
    page: int = 1,
    rows_per_page: int = 20
) -> str:
    """List one-to-one NAT rules.

    Args:
        ctx: MCP context
        search_phrase: Optional search phrase to filter rules
        page: Page number for pagination
        rows_per_page: Number of rows per page

    Returns:
        JSON string of one-to-one NAT rules
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        response = await opnsense_client.request(
            "POST",
            API_FIREWALL_ONE_TO_ONE_SEARCH_RULE,
            data={
                "current": page,
                "rowCount": rows_per_page,
                "searchPhrase": search_phrase
            }
        )

        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in nat_list_one_to_one_rules: {str(e)}", exc_info=True)
        await ctx.error(f"Error fetching one-to-one NAT rules: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="nat_add_one_to_one_rule", description="Add a one-to-one NAT rule")
async def nat_add_one_to_one_rule(
    ctx: Context,
    description: str,
    interface: str,
    external_ip: str,
    internal_ip: str,
    enabled: bool = True
) -> str:
    """Add a one-to-one NAT rule.

    Args:
        ctx: MCP context
        description: Description of the NAT rule
        interface: Interface (e.g., "wan", "opt1")
        external_ip: External IP address
        internal_ip: Internal IP address
        enabled: Whether the rule is enabled

    Returns:
        JSON string with the result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        # Prepare rule data
        rule_data = {
            "rule": {
                "description": description,
                "interface": interface,
                "external": external_ip,
                "internal": internal_ip,
                "enabled": "1" if enabled else "0"
            }
        }

        # Add the rule
        add_result = await opnsense_client.request(
            "POST",
            API_FIREWALL_ONE_TO_ONE_ADD_RULE,
            data=rule_data
        )

        # Apply changes
        await ctx.info("One-to-one NAT rule added, applying changes...")
        apply_result = await opnsense_client.request(
            "POST",
            API_FIREWALL_FILTER_BASE_APPLY
        )

        return json.dumps({
            "add_result": add_result,
            "apply_result": apply_result
        }, indent=2)
    except Exception as e:
        logger.error(f"Error in nat_add_one_to_one_rule: {str(e)}", exc_info=True)
        await ctx.error(f"Error adding one-to-one NAT rule: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="nat_delete_one_to_one_rule", description="Delete a one-to-one NAT rule")
async def nat_delete_one_to_one_rule(ctx: Context, uuid: str) -> str:
    """Delete a one-to-one NAT rule.

    Args:
        ctx: MCP context
        uuid: UUID of the rule to delete

    Returns:
        JSON string with the result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        # Delete the rule
        delete_result = await opnsense_client.request(
            "POST",
            f"{API_FIREWALL_ONE_TO_ONE_DEL_RULE}/{uuid}"
        )

        # Apply changes
        await ctx.info("One-to-one NAT rule deleted, applying changes...")
        apply_result = await opnsense_client.request(
            "POST",
            API_FIREWALL_FILTER_BASE_APPLY
        )

        return json.dumps({
            "delete_result": delete_result,
            "apply_result": apply_result
        }, indent=2)
    except Exception as e:
        logger.error(f"Error in nat_delete_one_to_one_rule: {str(e)}", exc_info=True)
        await ctx.error(f"Error deleting one-to-one NAT rule: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="nat_get_port_forward_info", description="Information about port forwarding API availability")
async def nat_get_port_forward_info(ctx: Context) -> str:
    """Get information about port forwarding API availability.

    Args:
        ctx: MCP context

    Returns:
        Information about port forwarding limitations and workarounds
    """
    info = {
        "status": "Not Available",
        "message": "Dedicated port forwarding (destination NAT) API endpoints are not yet available in current OPNsense versions.",
        "expected_version": "26.1 (January 2026)",
        "github_issue": "https://github.com/opnsense/core/issues/8401",
        "current_alternatives": [
            {
                "method": "Web Interface",
                "description": "Use OPNsense web interface at Firewall → NAT → Port Forward",
                "pros": ["Full functionality", "User-friendly"],
                "cons": ["Manual process", "Not scriptable"]
            },
            {
                "method": "Browser Automation",
                "description": "Use browser automation tools to interact with web interface",
                "pros": ["Scriptable", "Uses existing interface"],
                "cons": ["Complex", "Fragile", "Requires browser"]
            },
            {
                "method": "Config File Management",
                "description": "Direct XML configuration file manipulation",
                "pros": ["Complete control"],
                "cons": ["Complex", "Risk of corruption", "Requires deep knowledge"]
            }
        ],
        "available_nat_features": {
            "outbound_nat": "✅ Available via API (source NAT)",
            "one_to_one_nat": "✅ Available via API",
            "port_forwarding": "❌ Not available via API (destination NAT)",
            "nat_reflection": "❌ Not available via API"
        },
        "recommendation": "Use available outbound NAT and one-to-one NAT APIs. For port forwarding, wait for OPNsense 26.1 or use web interface."
    }

    return json.dumps(info, indent=2)


# --- End NAT Management ---


# ========== DNS & DHCP MANAGEMENT ==========

# --- DHCP Server Management ---

@mcp.tool(name="dhcp_list_servers", description="List all DHCP server configurations")
async def dhcp_list_servers(ctx: RequestContext) -> str:
    """List all DHCP server configurations.

    Returns:
        JSON string of DHCP server configurations
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        response = await opnsense_client.request(
            "GET",
            API_DHCP_SERVER_SEARCH,
            operation="list_dhcp_servers"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dhcp_list_servers", e)


@mcp.tool(name="dhcp_get_server", description="Get a specific DHCP server configuration")
async def dhcp_get_server(
    ctx: RequestContext,
    interface: str
) -> str:
    """Get a specific DHCP server configuration by interface.

    Args:
        ctx: MCP context
        interface: Interface name (e.g., 'lan', 'opt1')

    Returns:
        JSON string of DHCP server configuration
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not interface:
        return json.dumps({"error": "Interface name is required"}, indent=2)

    try:
        response = await opnsense_client.request(
            "GET",
            f"{API_DHCP_SERVER_GET}/{interface}",
            operation=f"get_dhcp_server_{interface}"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dhcp_get_server", e)


@mcp.tool(name="dhcp_set_server", description="Configure DHCP server settings for an interface")
async def dhcp_set_server(
    ctx: RequestContext,
    interface: str,
    enabled: bool = True,
    range_from: str = "",
    range_to: str = "",
    gateway: str = "",
    dns_servers: str = "",
    domain_name: str = "",
    lease_time: int = 7200,
    description: str = ""
) -> str:
    """Configure DHCP server settings for a specific interface.

    Args:
        ctx: MCP context
        interface: Interface name (e.g., 'lan', 'opt1')
        enabled: Whether DHCP server is enabled
        range_from: Start of DHCP range (e.g., '192.168.1.100')
        range_to: End of DHCP range (e.g., '192.168.1.200')
        gateway: Gateway IP address
        dns_servers: DNS servers (comma-separated)
        domain_name: Domain name for DHCP clients
        lease_time: Lease time in seconds (default: 7200)
        description: Description of this DHCP server

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not interface:
        return json.dumps({"error": "Interface name is required"}, indent=2)

    try:
        # Prepare configuration data
        config_data = {
            "enabled": "1" if enabled else "0",
            "description": description
        }

        if range_from:
            config_data["range_from"] = range_from
        if range_to:
            config_data["range_to"] = range_to
        if gateway:
            config_data["gateway"] = gateway
        if dns_servers:
            config_data["dns_servers"] = dns_servers
        if domain_name:
            config_data["domain_name"] = domain_name
        if lease_time:
            config_data["lease_time"] = str(lease_time)

        # Set DHCP server configuration
        response = await opnsense_client.request(
            "POST",
            f"{API_DHCP_SERVER_SET}/{interface}",
            data=config_data,
            operation=f"set_dhcp_server_{interface}"
        )

        # Apply configuration
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_DHCP_RECONFIGURE,
                operation="apply_dhcp_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dhcp_set_server", e)


@mcp.tool(name="dhcp_list_static_mappings", description="List DHCP static mappings (reservations)")
async def dhcp_list_static_mappings(
    ctx: RequestContext,
    search_phrase: str = ""
) -> str:
    """List all DHCP static mappings (reservations).

    Args:
        ctx: MCP context
        search_phrase: Optional search phrase to filter mappings

    Returns:
        JSON string of DHCP static mappings
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        params = {}
        if search_phrase:
            params["searchPhrase"] = search_phrase

        response = await opnsense_client.request(
            "POST",
            API_DHCP_STATIC_MAPPING_SEARCH,
            data=params,
            operation="list_dhcp_static_mappings"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dhcp_list_static_mappings", e)


@mcp.tool(name="dhcp_get_static_mapping", description="Get a specific DHCP static mapping")
async def dhcp_get_static_mapping(
    ctx: RequestContext,
    uuid: str
) -> str:
    """Get a specific DHCP static mapping by UUID.

    Args:
        ctx: MCP context
        uuid: UUID of the static mapping

    Returns:
        JSON string of static mapping details
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        response = await opnsense_client.request(
            "GET",
            f"{API_DHCP_STATIC_MAPPING_GET}/{uuid}",
            operation=f"get_dhcp_static_mapping_{uuid[:8]}"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dhcp_get_static_mapping", e)


@mcp.tool(name="dhcp_add_static_mapping", description="Add a new DHCP static mapping (reservation)")
async def dhcp_add_static_mapping(
    ctx: RequestContext,
    interface: str,
    mac_address: str,
    ip_address: str,
    hostname: str = "",
    description: str = ""
) -> str:
    """Add a new DHCP static mapping (reservation).

    Args:
        ctx: MCP context
        interface: Interface name (e.g., 'lan', 'opt1')
        mac_address: MAC address of the device
        ip_address: IP address to assign
        hostname: Hostname for the device
        description: Description of this mapping

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not all([interface, mac_address, ip_address]):
        return json.dumps({
            "error": "Interface, MAC address, and IP address are required"
        }, indent=2)

    try:
        mapping_data = {
            "interface": interface,
            "mac": mac_address,
            "ip": ip_address
        }

        if hostname:
            mapping_data["hostname"] = hostname
        if description:
            mapping_data["description"] = description

        response = await opnsense_client.request(
            "POST",
            API_DHCP_STATIC_MAPPING_ADD,
            data={"static": mapping_data},
            operation="add_dhcp_static_mapping"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_DHCP_RECONFIGURE,
                operation="apply_dhcp_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dhcp_add_static_mapping", e)


@mcp.tool(name="dhcp_update_static_mapping", description="Update an existing DHCP static mapping")
async def dhcp_update_static_mapping(
    ctx: RequestContext,
    uuid: str,
    interface: str = "",
    mac_address: str = "",
    ip_address: str = "",
    hostname: str = "",
    description: str = ""
) -> str:
    """Update an existing DHCP static mapping.

    Args:
        ctx: MCP context
        uuid: UUID of the static mapping to update
        interface: Interface name (e.g., 'lan', 'opt1')
        mac_address: MAC address of the device
        ip_address: IP address to assign
        hostname: Hostname for the device
        description: Description of this mapping

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        # Get current mapping
        current = await opnsense_client.request(
            "GET",
            f"{API_DHCP_STATIC_MAPPING_GET}/{uuid}",
            operation=f"get_current_static_mapping_{uuid[:8]}"
        )

        if not current or "static" not in current:
            return json.dumps({"error": "Static mapping not found"}, indent=2)

        # Update fields
        mapping_data = current["static"]
        if interface:
            mapping_data["interface"] = interface
        if mac_address:
            mapping_data["mac"] = mac_address
        if ip_address:
            mapping_data["ip"] = ip_address
        if hostname:
            mapping_data["hostname"] = hostname
        if description:
            mapping_data["description"] = description

        response = await opnsense_client.request(
            "POST",
            f"{API_DHCP_STATIC_MAPPING_SET}/{uuid}",
            data={"static": mapping_data},
            operation=f"update_dhcp_static_mapping_{uuid[:8]}"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_DHCP_RECONFIGURE,
                operation="apply_dhcp_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dhcp_update_static_mapping", e)


@mcp.tool(name="dhcp_delete_static_mapping", description="Delete a DHCP static mapping")
async def dhcp_delete_static_mapping(
    ctx: RequestContext,
    uuid: str
) -> str:
    """Delete a DHCP static mapping by UUID.

    Args:
        ctx: MCP context
        uuid: UUID of the static mapping to delete

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        response = await opnsense_client.request(
            "POST",
            f"{API_DHCP_STATIC_MAPPING_DELETE}/{uuid}",
            operation=f"delete_dhcp_static_mapping_{uuid[:8]}"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_DHCP_RECONFIGURE,
                operation="apply_dhcp_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dhcp_delete_static_mapping", e)


@mcp.tool(name="dhcp_restart_service", description="Restart the DHCP service")
async def dhcp_restart_service(ctx: RequestContext) -> str:
    """Restart the DHCP service.

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        response = await opnsense_client.request(
            "POST",
            API_DHCP_SERVICE_RESTART,
            operation="restart_dhcp_service"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dhcp_restart_service", e)


# --- DNS Resolver (Unbound) Management ---

@mcp.tool(name="dns_resolver_get_settings", description="Get DNS resolver (Unbound) settings")
async def dns_resolver_get_settings(ctx: RequestContext) -> str:
    """Get DNS resolver (Unbound) configuration settings.

    Returns:
        JSON string of DNS resolver settings
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        response = await opnsense_client.request(
            "GET",
            API_UNBOUND_SETTINGS_GET,
            operation="get_dns_resolver_settings"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_resolver_get_settings", e)


@mcp.tool(name="dns_resolver_set_settings", description="Configure DNS resolver (Unbound) settings")
async def dns_resolver_set_settings(
    ctx: RequestContext,
    enabled: bool = True,
    port: int = 53,
    dnssec: bool = True,
    forwarding: bool = False,
    forward_tls_upstream: bool = False,
    cache_size: int = 4,
    cache_min_ttl: int = 0,
    cache_max_ttl: int = 86400,
    outgoing_interfaces: str = "",
    incoming_interfaces: str = ""
) -> str:
    """Configure DNS resolver (Unbound) settings.

    Args:
        ctx: MCP context
        enabled: Enable DNS resolver
        port: Port number (default: 53)
        dnssec: Enable DNSSEC validation
        forwarding: Enable forwarding mode
        forward_tls_upstream: Use TLS for upstream queries
        cache_size: Cache size in MB (default: 4)
        cache_min_ttl: Minimum TTL in seconds (default: 0)
        cache_max_ttl: Maximum TTL in seconds (default: 86400)
        outgoing_interfaces: Outgoing interfaces (comma-separated)
        incoming_interfaces: Incoming interfaces (comma-separated)

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        settings_data = {
            "general": {
                "enabled": "1" if enabled else "0",
                "port": str(port),
                "dnssec": "1" if dnssec else "0",
                "forwarding": "1" if forwarding else "0",
                "forward_tls_upstream": "1" if forward_tls_upstream else "0",
                "cache_size": str(cache_size),
                "cache_min_ttl": str(cache_min_ttl),
                "cache_max_ttl": str(cache_max_ttl)
            }
        }

        if outgoing_interfaces:
            settings_data["general"]["outgoing_interfaces"] = outgoing_interfaces
        if incoming_interfaces:
            settings_data["general"]["incoming_interfaces"] = incoming_interfaces

        response = await opnsense_client.request(
            "POST",
            API_UNBOUND_SETTINGS_SET,
            data=settings_data,
            operation="set_dns_resolver_settings"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_UNBOUND_SERVICE_RECONFIGURE,
                operation="apply_dns_resolver_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_resolver_set_settings", e)


@mcp.tool(name="dns_resolver_list_host_overrides", description="List DNS resolver host overrides")
async def dns_resolver_list_host_overrides(
    ctx: RequestContext,
    search_phrase: str = ""
) -> str:
    """List all DNS resolver host overrides.

    Args:
        ctx: MCP context
        search_phrase: Optional search phrase to filter overrides

    Returns:
        JSON string of host overrides
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        params = {}
        if search_phrase:
            params["searchPhrase"] = search_phrase

        response = await opnsense_client.request(
            "POST",
            API_UNBOUND_HOST_OVERRIDES_SEARCH,
            data=params,
            operation="list_dns_resolver_host_overrides"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_resolver_list_host_overrides", e)


@mcp.tool(name="dns_resolver_get_host_override", description="Get a specific DNS resolver host override")
async def dns_resolver_get_host_override(
    ctx: RequestContext,
    uuid: str
) -> str:
    """Get a specific DNS resolver host override by UUID.

    Args:
        ctx: MCP context
        uuid: UUID of the host override

    Returns:
        JSON string of host override details
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        response = await opnsense_client.request(
            "GET",
            f"{API_UNBOUND_HOST_OVERRIDES_GET}/{uuid}",
            operation=f"get_dns_resolver_host_override_{uuid[:8]}"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_resolver_get_host_override", e)


@mcp.tool(name="dns_resolver_add_host_override", description="Add a new DNS resolver host override")
async def dns_resolver_add_host_override(
    ctx: RequestContext,
    hostname: str,
    domain: str,
    ip_address: str,
    description: str = ""
) -> str:
    """Add a new DNS resolver host override.

    Args:
        ctx: MCP context
        hostname: Hostname to override
        domain: Domain name
        ip_address: IP address to resolve to
        description: Optional description

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not all([hostname, domain, ip_address]):
        return json.dumps({
            "error": "Hostname, domain, and IP address are required"
        }, indent=2)

    try:
        override_data = {
            "host": hostname,
            "domain": domain,
            "server": ip_address,
            "description": description
        }

        response = await opnsense_client.request(
            "POST",
            API_UNBOUND_HOST_OVERRIDES_ADD,
            data={"host": override_data},
            operation="add_dns_resolver_host_override"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_UNBOUND_SERVICE_RECONFIGURE,
                operation="apply_dns_resolver_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_resolver_add_host_override", e)


@mcp.tool(name="dns_resolver_update_host_override", description="Update an existing DNS resolver host override")
async def dns_resolver_update_host_override(
    ctx: RequestContext,
    uuid: str,
    hostname: str = "",
    domain: str = "",
    ip_address: str = "",
    description: str = ""
) -> str:
    """Update an existing DNS resolver host override.

    Args:
        ctx: MCP context
        uuid: UUID of the host override to update
        hostname: Hostname to override
        domain: Domain name
        ip_address: IP address to resolve to
        description: Optional description

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        # Get current override
        current = await opnsense_client.request(
            "GET",
            f"{API_UNBOUND_HOST_OVERRIDES_GET}/{uuid}",
            operation=f"get_current_host_override_{uuid[:8]}"
        )

        if not current or "host" not in current:
            return json.dumps({"error": "Host override not found"}, indent=2)

        # Update fields
        override_data = current["host"]
        if hostname:
            override_data["host"] = hostname
        if domain:
            override_data["domain"] = domain
        if ip_address:
            override_data["server"] = ip_address
        if description:
            override_data["description"] = description

        response = await opnsense_client.request(
            "POST",
            f"{API_UNBOUND_HOST_OVERRIDES_SET}/{uuid}",
            data={"host": override_data},
            operation=f"update_dns_resolver_host_override_{uuid[:8]}"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_UNBOUND_SERVICE_RECONFIGURE,
                operation="apply_dns_resolver_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_resolver_update_host_override", e)


@mcp.tool(name="dns_resolver_delete_host_override", description="Delete a DNS resolver host override")
async def dns_resolver_delete_host_override(
    ctx: RequestContext,
    uuid: str
) -> str:
    """Delete a DNS resolver host override by UUID.

    Args:
        ctx: MCP context
        uuid: UUID of the host override to delete

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        response = await opnsense_client.request(
            "POST",
            f"{API_UNBOUND_HOST_OVERRIDES_DELETE}/{uuid}",
            operation=f"delete_dns_resolver_host_override_{uuid[:8]}"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_UNBOUND_SERVICE_RECONFIGURE,
                operation="apply_dns_resolver_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_resolver_delete_host_override", e)


@mcp.tool(name="dns_resolver_list_domain_overrides", description="List DNS resolver domain overrides")
async def dns_resolver_list_domain_overrides(
    ctx: RequestContext,
    search_phrase: str = ""
) -> str:
    """List all DNS resolver domain overrides.

    Args:
        ctx: MCP context
        search_phrase: Optional search phrase to filter overrides

    Returns:
        JSON string of domain overrides
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        params = {}
        if search_phrase:
            params["searchPhrase"] = search_phrase

        response = await opnsense_client.request(
            "POST",
            API_UNBOUND_DOMAIN_OVERRIDES_SEARCH,
            data=params,
            operation="list_dns_resolver_domain_overrides"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_resolver_list_domain_overrides", e)


@mcp.tool(name="dns_resolver_add_domain_override", description="Add a new DNS resolver domain override")
async def dns_resolver_add_domain_override(
    ctx: RequestContext,
    domain: str,
    server: str,
    description: str = ""
) -> str:
    """Add a new DNS resolver domain override.

    Args:
        ctx: MCP context
        domain: Domain to override (e.g., 'example.com')
        server: DNS server to forward queries to
        description: Optional description

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not all([domain, server]):
        return json.dumps({
            "error": "Domain and server are required"
        }, indent=2)

    try:
        override_data = {
            "domain": domain,
            "server": server,
            "description": description
        }

        response = await opnsense_client.request(
            "POST",
            API_UNBOUND_DOMAIN_OVERRIDES_ADD,
            data={"domain": override_data},
            operation="add_dns_resolver_domain_override"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_UNBOUND_SERVICE_RECONFIGURE,
                operation="apply_dns_resolver_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_resolver_add_domain_override", e)


@mcp.tool(name="dns_resolver_restart_service", description="Restart the DNS resolver service")
async def dns_resolver_restart_service(ctx: RequestContext) -> str:
    """Restart the DNS resolver (Unbound) service.

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        response = await opnsense_client.request(
            "POST",
            API_UNBOUND_SERVICE_RESTART,
            operation="restart_dns_resolver_service"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_resolver_restart_service", e)


# --- DHCP Lease Management ---

@mcp.tool(name="dhcp_get_leases", description="Get current DHCP leases")
async def dhcp_get_leases(
    ctx: RequestContext,
    interface: str = ""
) -> str:
    """Get current DHCP leases from the server.

    Args:
        ctx: MCP context
        interface: Optional interface filter (e.g., 'lan', 'opt1')

    Returns:
        JSON string of current DHCP leases
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        # Use the general DHCP leases endpoint
        endpoint = API_DHCP_LEASES_SEARCH if not interface else f"{API_DHCP_LEASES_SEARCH}?interface={interface}"

        response = await opnsense_client.request(
            "GET",
            endpoint,
            operation=f"get_dhcp_leases{'_' + interface if interface else ''}"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dhcp_get_leases", e)


@mcp.tool(name="dhcp_search_leases", description="Search DHCP leases with filters")
async def dhcp_search_leases(
    ctx: RequestContext,
    search_phrase: str = "",
    interface: str = "",
    state: str = ""
) -> str:
    """Search DHCP leases with various filters.

    Args:
        ctx: MCP context
        search_phrase: Search phrase to filter leases
        interface: Interface filter (e.g., 'lan', 'opt1')
        state: Lease state filter (e.g., 'active', 'expired')

    Returns:
        JSON string of filtered DHCP leases
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        params = {}
        if search_phrase:
            params["searchPhrase"] = search_phrase
        if interface:
            params["interface"] = interface
        if state:
            params["state"] = state

        response = await opnsense_client.request(
            "POST",
            API_DHCP_LEASES_SEARCH,
            data=params,
            operation="search_dhcp_leases"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dhcp_search_leases", e)


@mcp.tool(name="dhcp_get_lease_statistics", description="Get DHCP lease statistics")
async def dhcp_get_lease_statistics(ctx: RequestContext) -> str:
    """Get statistics about DHCP leases across all interfaces.

    Returns:
        JSON string of DHCP lease statistics
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        # Get all leases
        response = await opnsense_client.request(
            "GET",
            API_DHCP_LEASES_SEARCH,
            operation="get_dhcp_lease_statistics"
        )

        if not response:
            return json.dumps({"error": "Unable to retrieve lease data"}, indent=2)

        # Process statistics
        stats = {
            "total_leases": 0,
            "active_leases": 0,
            "expired_leases": 0,
            "static_mappings": 0,
            "interfaces": {}
        }

        # If response contains lease data, process it
        if isinstance(response, dict) and "rows" in response:
            leases = response["rows"]
            stats["total_leases"] = len(leases)

            for lease in leases:
                # Count by state
                lease_state = lease.get("state", "unknown").lower()
                if "active" in lease_state:
                    stats["active_leases"] += 1
                elif "expired" in lease_state:
                    stats["expired_leases"] += 1

                # Count by interface
                interface = lease.get("interface", "unknown")
                if interface not in stats["interfaces"]:
                    stats["interfaces"][interface] = 0
                stats["interfaces"][interface] += 1

                # Count static mappings
                if lease.get("type") == "static":
                    stats["static_mappings"] += 1

        elif isinstance(response, list):
            stats["total_leases"] = len(response)
            # Basic counting for list format
            for lease in response:
                interface = lease.get("interface", "unknown")
                if interface not in stats["interfaces"]:
                    stats["interfaces"][interface] = 0
                stats["interfaces"][interface] += 1

        return json.dumps(stats, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dhcp_get_lease_statistics", e)


# --- DNS Forwarder (dnsmasq) Management ---

@mcp.tool(name="dns_forwarder_get_settings", description="Get DNS forwarder (dnsmasq) settings")
async def dns_forwarder_get_settings(ctx: RequestContext) -> str:
    """Get DNS forwarder (dnsmasq) configuration settings.

    Returns:
        JSON string of DNS forwarder settings
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        response = await opnsense_client.request(
            "GET",
            API_DNSMASQ_SETTINGS_GET,
            operation="get_dns_forwarder_settings"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_forwarder_get_settings", e)


@mcp.tool(name="dns_forwarder_set_settings", description="Configure DNS forwarder (dnsmasq) settings")
async def dns_forwarder_set_settings(
    ctx: RequestContext,
    enabled: bool = True,
    port: int = 53,
    domain: str = "",
    no_hosts: bool = False,
    strict_order: bool = False,
    no_dhcp_interface: str = ""
) -> str:
    """Configure DNS forwarder (dnsmasq) settings.

    Args:
        ctx: MCP context
        enabled: Enable DNS forwarder
        port: Port number (default: 53)
        domain: Local domain name
        no_hosts: Don't read /etc/hosts
        strict_order: Strict order of DNS servers
        no_dhcp_interface: Interfaces to exclude from DHCP

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        settings_data = {
            "general": {
                "enabled": "1" if enabled else "0",
                "port": str(port),
                "no_hosts": "1" if no_hosts else "0",
                "strict_order": "1" if strict_order else "0"
            }
        }

        if domain:
            settings_data["general"]["domain"] = domain
        if no_dhcp_interface:
            settings_data["general"]["no_dhcp_interface"] = no_dhcp_interface

        response = await opnsense_client.request(
            "POST",
            API_DNSMASQ_SETTINGS_SET,
            data=settings_data,
            operation="set_dns_forwarder_settings"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_DNSMASQ_SERVICE_RECONFIGURE,
                operation="apply_dns_forwarder_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_forwarder_set_settings", e)


@mcp.tool(name="dns_forwarder_list_hosts", description="List DNS forwarder host overrides")
async def dns_forwarder_list_hosts(
    ctx: RequestContext,
    search_phrase: str = ""
) -> str:
    """List all DNS forwarder host overrides.

    Args:
        ctx: MCP context
        search_phrase: Optional search phrase to filter hosts

    Returns:
        JSON string of host overrides
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        params = {}
        if search_phrase:
            params["searchPhrase"] = search_phrase

        response = await opnsense_client.request(
            "POST",
            API_DNSMASQ_HOSTS_SEARCH,
            data=params,
            operation="list_dns_forwarder_hosts"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_forwarder_list_hosts", e)


@mcp.tool(name="dns_forwarder_add_host", description="Add a new DNS forwarder host override")
async def dns_forwarder_add_host(
    ctx: RequestContext,
    hostname: str,
    domain: str,
    ip_address: str,
    description: str = ""
) -> str:
    """Add a new DNS forwarder host override.

    Args:
        ctx: MCP context
        hostname: Hostname to override
        domain: Domain name
        ip_address: IP address to resolve to
        description: Optional description

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not all([hostname, domain, ip_address]):
        return json.dumps({
            "error": "Hostname, domain, and IP address are required"
        }, indent=2)

    try:
        host_data = {
            "host": hostname,
            "domain": domain,
            "ip": ip_address,
            "description": description
        }

        response = await opnsense_client.request(
            "POST",
            API_DNSMASQ_HOSTS_ADD,
            data={"host": host_data},
            operation="add_dns_forwarder_host"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_DNSMASQ_SERVICE_RECONFIGURE,
                operation="apply_dns_forwarder_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_forwarder_add_host", e)


@mcp.tool(name="dns_forwarder_restart_service", description="Restart the DNS forwarder service")
async def dns_forwarder_restart_service(ctx: RequestContext) -> str:
    """Restart the DNS forwarder (dnsmasq) service.

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        response = await opnsense_client.request(
            "POST",
            API_DNSMASQ_SERVICE_RESTART,
            operation="restart_dns_forwarder_service"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_forwarder_restart_service", e)


# ========== INTERFACE & VLAN MANAGEMENT ==========

# --- Basic Interface Management ---

@mcp.tool(name="get_interface_details", description="Get detailed information for a specific interface")
async def get_interface_details(
    ctx: RequestContext,
    interface: str
) -> str:
    """Get detailed information for a specific interface.

    Args:
        ctx: MCP context
        interface: Interface identifier (e.g., 'lan', 'wan', 'opt1')

    Returns:
        JSON string of interface details
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not interface:
        return json.dumps({"error": "Interface identifier is required"}, indent=2)

    try:
        response = await opnsense_client.request(
            "GET",
            f"{API_INTERFACES_OVERVIEW_GET_INTERFACE}/{interface}",
            operation=f"get_interface_details_{interface}"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_interface_details", e)


@mcp.tool(name="reload_interface", description="Reload configuration for a specific interface")
async def reload_interface(
    ctx: RequestContext,
    interface: str
) -> str:
    """Reload configuration for a specific interface.

    Args:
        ctx: MCP context
        interface: Interface identifier to reload

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not interface:
        return json.dumps({"error": "Interface identifier is required"}, indent=2)

    try:
        response = await opnsense_client.request(
            "GET",
            f"{API_INTERFACES_OVERVIEW_RELOAD_INTERFACE}/{interface}",
            operation=f"reload_interface_{interface}"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "reload_interface", e)


@mcp.tool(name="export_interface_config", description="Export interface configuration")
async def export_interface_config(ctx: RequestContext) -> str:
    """Export current interface configuration.

    Returns:
        JSON string of interface configuration export
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        response = await opnsense_client.request(
            "GET",
            API_INTERFACES_OVERVIEW_EXPORT,
            operation="export_interface_config"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "export_interface_config", e)


# --- VLAN Management ---

@mcp.tool(name="list_vlan_interfaces", description="List all VLAN interfaces")
async def list_vlan_interfaces(
    ctx: RequestContext,
    search_phrase: str = ""
) -> str:
    """List all VLAN interfaces with optional search filtering.

    Args:
        ctx: MCP context
        search_phrase: Optional search phrase to filter VLANs

    Returns:
        JSON string of VLAN interfaces
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        params = {}
        if search_phrase:
            params["searchPhrase"] = search_phrase

        response = await opnsense_client.request(
            "POST",
            API_INTERFACES_VLAN_SEARCH,
            data=params,
            operation="list_vlan_interfaces"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "list_vlan_interfaces", e)


@mcp.tool(name="get_vlan_interface", description="Get VLAN interface configuration")
async def get_vlan_interface(
    ctx: RequestContext,
    uuid: str
) -> str:
    """Get specific VLAN interface configuration by UUID.

    Args:
        ctx: MCP context
        uuid: UUID of the VLAN interface

    Returns:
        JSON string of VLAN interface configuration
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        response = await opnsense_client.request(
            "GET",
            f"{API_INTERFACES_VLAN_GET}/{uuid}",
            operation=f"get_vlan_interface_{uuid[:8]}"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_vlan_interface", e)


@mcp.tool(name="create_vlan_interface", description="Create a new VLAN interface")
async def create_vlan_interface(
    ctx: RequestContext,
    parent_interface: str,
    vlan_tag: int,
    description: str = ""
) -> str:
    """Create a new VLAN interface.

    Args:
        ctx: MCP context
        parent_interface: Parent interface for the VLAN (e.g., 'igb0', 'em0')
        vlan_tag: VLAN tag (1-4094)
        description: Optional description for the VLAN

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not all([parent_interface, vlan_tag]):
        return json.dumps({
            "error": "Parent interface and VLAN tag are required"
        }, indent=2)

    # Validate VLAN tag range
    if not (1 <= vlan_tag <= 4094):
        return json.dumps({
            "error": "VLAN tag must be between 1 and 4094"
        }, indent=2)

    try:
        vlan_data = {
            "if": parent_interface,
            "tag": str(vlan_tag),
            "descr": description
        }

        response = await opnsense_client.request(
            "POST",
            API_INTERFACES_VLAN_ADD,
            data={"vlan": vlan_data},
            operation="create_vlan_interface"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_INTERFACES_VLAN_RECONFIGURE,
                operation="apply_vlan_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "create_vlan_interface", e)


@mcp.tool(name="update_vlan_interface", description="Update VLAN interface configuration")
async def update_vlan_interface(
    ctx: RequestContext,
    uuid: str,
    parent_interface: str = "",
    vlan_tag: int = 0,
    description: str = ""
) -> str:
    """Update existing VLAN interface configuration.

    Args:
        ctx: MCP context
        uuid: UUID of the VLAN interface to update
        parent_interface: Parent interface for the VLAN
        vlan_tag: VLAN tag (1-4094)
        description: Description for the VLAN

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    # Validate VLAN tag if provided
    if vlan_tag > 0 and not (1 <= vlan_tag <= 4094):
        return json.dumps({
            "error": "VLAN tag must be between 1 and 4094"
        }, indent=2)

    try:
        # Get current VLAN configuration
        current = await opnsense_client.request(
            "GET",
            f"{API_INTERFACES_VLAN_GET}/{uuid}",
            operation=f"get_current_vlan_{uuid[:8]}"
        )

        if not current or "vlan" not in current:
            return json.dumps({"error": "VLAN interface not found"}, indent=2)

        # Update fields
        vlan_data = current["vlan"]
        if parent_interface:
            vlan_data["if"] = parent_interface
        if vlan_tag > 0:
            vlan_data["tag"] = str(vlan_tag)
        if description is not None:  # Allow empty string to clear description
            vlan_data["descr"] = description

        response = await opnsense_client.request(
            "POST",
            f"{API_INTERFACES_VLAN_SET}/{uuid}",
            data={"vlan": vlan_data},
            operation=f"update_vlan_interface_{uuid[:8]}"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_INTERFACES_VLAN_RECONFIGURE,
                operation="apply_vlan_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "update_vlan_interface", e)


@mcp.tool(name="delete_vlan_interface", description="Delete a VLAN interface")
async def delete_vlan_interface(
    ctx: RequestContext,
    uuid: str
) -> str:
    """Delete a VLAN interface by UUID.

    Args:
        ctx: MCP context
        uuid: UUID of the VLAN interface to delete

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        response = await opnsense_client.request(
            "POST",
            f"{API_INTERFACES_VLAN_DEL}/{uuid}",
            operation=f"delete_vlan_interface_{uuid[:8]}"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_INTERFACES_VLAN_RECONFIGURE,
                operation="apply_vlan_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "delete_vlan_interface", e)


# --- Bridge Management ---

@mcp.tool(name="list_bridge_interfaces", description="List all bridge interfaces")
async def list_bridge_interfaces(
    ctx: RequestContext,
    search_phrase: str = ""
) -> str:
    """List all bridge interfaces with optional search filtering.

    Args:
        ctx: MCP context
        search_phrase: Optional search phrase to filter bridges

    Returns:
        JSON string of bridge interfaces
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        params = {}
        if search_phrase:
            params["searchPhrase"] = search_phrase

        response = await opnsense_client.request(
            "POST",
            API_INTERFACES_BRIDGE_SEARCH,
            data=params,
            operation="list_bridge_interfaces"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "list_bridge_interfaces", e)


@mcp.tool(name="get_bridge_interface", description="Get bridge interface configuration")
async def get_bridge_interface(
    ctx: RequestContext,
    uuid: str
) -> str:
    """Get specific bridge interface configuration by UUID.

    Args:
        ctx: MCP context
        uuid: UUID of the bridge interface

    Returns:
        JSON string of bridge interface configuration
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        response = await opnsense_client.request(
            "GET",
            f"{API_INTERFACES_BRIDGE_GET}/{uuid}",
            operation=f"get_bridge_interface_{uuid[:8]}"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_bridge_interface", e)


@mcp.tool(name="create_bridge_interface", description="Create a new bridge interface")
async def create_bridge_interface(
    ctx: RequestContext,
    description: str,
    member_interfaces: str = "",
    stp_enabled: bool = False
) -> str:
    """Create a new bridge interface.

    Args:
        ctx: MCP context
        description: Description for the bridge
        member_interfaces: Comma-separated list of member interfaces
        stp_enabled: Enable Spanning Tree Protocol

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not description:
        return json.dumps({
            "error": "Description is required"
        }, indent=2)

    try:
        bridge_data = {
            "descr": description,
            "stp": "1" if stp_enabled else "0"
        }

        if member_interfaces:
            bridge_data["members"] = member_interfaces

        response = await opnsense_client.request(
            "POST",
            API_INTERFACES_BRIDGE_ADD,
            data={"bridge": bridge_data},
            operation="create_bridge_interface"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_INTERFACES_BRIDGE_RECONFIGURE,
                operation="apply_bridge_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "create_bridge_interface", e)


@mcp.tool(name="update_bridge_interface", description="Update bridge interface configuration")
async def update_bridge_interface(
    ctx: RequestContext,
    uuid: str,
    description: str = "",
    member_interfaces: str = "",
    stp_enabled: bool = None
) -> str:
    """Update existing bridge interface configuration.

    Args:
        ctx: MCP context
        uuid: UUID of the bridge interface to update
        description: Description for the bridge
        member_interfaces: Comma-separated list of member interfaces
        stp_enabled: Enable/disable Spanning Tree Protocol

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        # Get current bridge configuration
        current = await opnsense_client.request(
            "GET",
            f"{API_INTERFACES_BRIDGE_GET}/{uuid}",
            operation=f"get_current_bridge_{uuid[:8]}"
        )

        if not current or "bridge" not in current:
            return json.dumps({"error": "Bridge interface not found"}, indent=2)

        # Update fields
        bridge_data = current["bridge"]
        if description:
            bridge_data["descr"] = description
        if member_interfaces is not None:  # Allow empty string to clear members
            bridge_data["members"] = member_interfaces
        if stp_enabled is not None:
            bridge_data["stp"] = "1" if stp_enabled else "0"

        response = await opnsense_client.request(
            "POST",
            f"{API_INTERFACES_BRIDGE_SET}/{uuid}",
            data={"bridge": bridge_data},
            operation=f"update_bridge_interface_{uuid[:8]}"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_INTERFACES_BRIDGE_RECONFIGURE,
                operation="apply_bridge_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "update_bridge_interface", e)


@mcp.tool(name="delete_bridge_interface", description="Delete a bridge interface")
async def delete_bridge_interface(
    ctx: RequestContext,
    uuid: str
) -> str:
    """Delete a bridge interface by UUID.

    Args:
        ctx: MCP context
        uuid: UUID of the bridge interface to delete

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        response = await opnsense_client.request(
            "POST",
            f"{API_INTERFACES_BRIDGE_DEL}/{uuid}",
            operation=f"delete_bridge_interface_{uuid[:8]}"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_INTERFACES_BRIDGE_RECONFIGURE,
                operation="apply_bridge_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "delete_bridge_interface", e)


# --- LAGG (Link Aggregation) Management ---

@mcp.tool(name="list_lagg_interfaces", description="List all LAGG (Link Aggregation) interfaces")
async def list_lagg_interfaces(
    ctx: RequestContext,
    search_phrase: str = ""
) -> str:
    """List all LAGG interfaces with optional search filtering.

    Args:
        ctx: MCP context
        search_phrase: Optional search phrase to filter LAGG interfaces

    Returns:
        JSON string of LAGG interfaces
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        params = {}
        if search_phrase:
            params["searchPhrase"] = search_phrase

        response = await opnsense_client.request(
            "POST",
            API_INTERFACES_LAGG_SEARCH,
            data=params,
            operation="list_lagg_interfaces"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "list_lagg_interfaces", e)


@mcp.tool(name="get_lagg_interface", description="Get LAGG interface configuration")
async def get_lagg_interface(
    ctx: RequestContext,
    uuid: str
) -> str:
    """Get specific LAGG interface configuration by UUID.

    Args:
        ctx: MCP context
        uuid: UUID of the LAGG interface

    Returns:
        JSON string of LAGG interface configuration
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        response = await opnsense_client.request(
            "GET",
            f"{API_INTERFACES_LAGG_GET}/{uuid}",
            operation=f"get_lagg_interface_{uuid[:8]}"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_lagg_interface", e)


@mcp.tool(name="create_lagg_interface", description="Create a new LAGG (Link Aggregation) interface")
async def create_lagg_interface(
    ctx: RequestContext,
    description: str,
    parent_interfaces: str,
    protocol: str = "lacp"
) -> str:
    """Create a new LAGG interface.

    Args:
        ctx: MCP context
        description: Description for the LAGG interface
        parent_interfaces: Comma-separated list of parent interfaces
        protocol: LAGG protocol (lacp, failover, loadbalance, roundrobin)

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not all([description, parent_interfaces]):
        return json.dumps({
            "error": "Description and parent interfaces are required"
        }, indent=2)

    # Validate protocol
    valid_protocols = ["lacp", "failover", "loadbalance", "roundrobin"]
    if protocol not in valid_protocols:
        return json.dumps({
            "error": f"Protocol must be one of: {', '.join(valid_protocols)}"
        }, indent=2)

    try:
        lagg_data = {
            "descr": description,
            "members": parent_interfaces,
            "proto": protocol
        }

        response = await opnsense_client.request(
            "POST",
            API_INTERFACES_LAGG_ADD,
            data={"lagg": lagg_data},
            operation="create_lagg_interface"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_INTERFACES_LAGG_RECONFIGURE,
                operation="apply_lagg_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "create_lagg_interface", e)


@mcp.tool(name="update_lagg_interface", description="Update LAGG interface configuration")
async def update_lagg_interface(
    ctx: RequestContext,
    uuid: str,
    description: str = "",
    parent_interfaces: str = "",
    protocol: str = ""
) -> str:
    """Update existing LAGG interface configuration.

    Args:
        ctx: MCP context
        uuid: UUID of the LAGG interface to update
        description: Description for the LAGG interface
        parent_interfaces: Comma-separated list of parent interfaces
        protocol: LAGG protocol (lacp, failover, loadbalance, roundrobin)

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    # Validate protocol if provided
    if protocol:
        valid_protocols = ["lacp", "failover", "loadbalance", "roundrobin"]
        if protocol not in valid_protocols:
            return json.dumps({
                "error": f"Protocol must be one of: {', '.join(valid_protocols)}"
            }, indent=2)

    try:
        # Get current LAGG configuration
        current = await opnsense_client.request(
            "GET",
            f"{API_INTERFACES_LAGG_GET}/{uuid}",
            operation=f"get_current_lagg_{uuid[:8]}"
        )

        if not current or "lagg" not in current:
            return json.dumps({"error": "LAGG interface not found"}, indent=2)

        # Update fields
        lagg_data = current["lagg"]
        if description:
            lagg_data["descr"] = description
        if parent_interfaces is not None:  # Allow empty string to clear members
            lagg_data["members"] = parent_interfaces
        if protocol:
            lagg_data["proto"] = protocol

        response = await opnsense_client.request(
            "POST",
            f"{API_INTERFACES_LAGG_SET}/{uuid}",
            data={"lagg": lagg_data},
            operation=f"update_lagg_interface_{uuid[:8]}"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_INTERFACES_LAGG_RECONFIGURE,
                operation="apply_lagg_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "update_lagg_interface", e)


@mcp.tool(name="delete_lagg_interface", description="Delete a LAGG interface")
async def delete_lagg_interface(
    ctx: RequestContext,
    uuid: str
) -> str:
    """Delete a LAGG interface by UUID.

    Args:
        ctx: MCP context
        uuid: UUID of the LAGG interface to delete

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        response = await opnsense_client.request(
            "POST",
            f"{API_INTERFACES_LAGG_DEL}/{uuid}",
            operation=f"delete_lagg_interface_{uuid[:8]}"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_INTERFACES_LAGG_RECONFIGURE,
                operation="apply_lagg_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "delete_lagg_interface", e)


# --- Virtual IP Management ---

@mcp.tool(name="list_virtual_ips", description="List all virtual IP addresses")
async def list_virtual_ips(
    ctx: RequestContext,
    search_phrase: str = ""
) -> str:
    """List all virtual IP addresses with optional search filtering.

    Args:
        ctx: MCP context
        search_phrase: Optional search phrase to filter virtual IPs

    Returns:
        JSON string of virtual IP addresses
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        params = {}
        if search_phrase:
            params["searchPhrase"] = search_phrase

        response = await opnsense_client.request(
            "POST",
            API_INTERFACES_VIP_SEARCH,
            data=params,
            operation="list_virtual_ips"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "list_virtual_ips", e)


@mcp.tool(name="get_virtual_ip", description="Get virtual IP configuration")
async def get_virtual_ip(
    ctx: RequestContext,
    uuid: str
) -> str:
    """Get specific virtual IP configuration by UUID.

    Args:
        ctx: MCP context
        uuid: UUID of the virtual IP

    Returns:
        JSON string of virtual IP configuration
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        response = await opnsense_client.request(
            "GET",
            f"{API_INTERFACES_VIP_GET}/{uuid}",
            operation=f"get_virtual_ip_{uuid[:8]}"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_virtual_ip", e)


@mcp.tool(name="create_virtual_ip", description="Create a new virtual IP address")
async def create_virtual_ip(
    ctx: RequestContext,
    interface: str,
    subnet: str,
    vip_type: str = "single",
    description: str = "",
    vhid: int = 0
) -> str:
    """Create a new virtual IP address.

    Args:
        ctx: MCP context
        interface: Interface to assign the virtual IP
        subnet: IP subnet (e.g., '192.168.1.100/24')
        vip_type: Virtual IP type (single, carp, proxyarp, other)
        description: Optional description
        vhid: VHID for CARP (if vip_type is 'carp')

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not all([interface, subnet]):
        return json.dumps({
            "error": "Interface and subnet are required"
        }, indent=2)

    # Validate VIP type
    valid_types = ["single", "carp", "proxyarp", "other"]
    if vip_type not in valid_types:
        return json.dumps({
            "error": f"VIP type must be one of: {', '.join(valid_types)}"
        }, indent=2)

    try:
        vip_data = {
            "interface": interface,
            "subnet": subnet,
            "type": vip_type,
            "descr": description
        }

        # Add VHID for CARP type
        if vip_type == "carp":
            if vhid <= 0:
                # Get an unused VHID automatically
                try:
                    vhid_response = await opnsense_client.request(
                        "GET",
                        API_INTERFACES_VIP_GET_UNUSED_VHID,
                        operation="get_unused_vhid"
                    )
                    if vhid_response and "vhid" in vhid_response:
                        vhid = vhid_response["vhid"]
                    else:
                        vhid = 1  # Default fallback
                except:
                    vhid = 1  # Default fallback

            vip_data["vhid"] = str(vhid)

        response = await opnsense_client.request(
            "POST",
            API_INTERFACES_VIP_ADD,
            data={"vip": vip_data},
            operation="create_virtual_ip"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_INTERFACES_VIP_RECONFIGURE,
                operation="apply_vip_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "create_virtual_ip", e)


@mcp.tool(name="update_virtual_ip", description="Update virtual IP configuration")
async def update_virtual_ip(
    ctx: RequestContext,
    uuid: str,
    interface: str = "",
    subnet: str = "",
    vip_type: str = "",
    description: str = "",
    vhid: int = 0
) -> str:
    """Update existing virtual IP configuration.

    Args:
        ctx: MCP context
        uuid: UUID of the virtual IP to update
        interface: Interface to assign the virtual IP
        subnet: IP subnet (e.g., '192.168.1.100/24')
        vip_type: Virtual IP type (single, carp, proxyarp, other)
        description: Description
        vhid: VHID for CARP (if vip_type is 'carp')

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    # Validate VIP type if provided
    if vip_type:
        valid_types = ["single", "carp", "proxyarp", "other"]
        if vip_type not in valid_types:
            return json.dumps({
                "error": f"VIP type must be one of: {', '.join(valid_types)}"
            }, indent=2)

    try:
        # Get current virtual IP configuration
        current = await opnsense_client.request(
            "GET",
            f"{API_INTERFACES_VIP_GET}/{uuid}",
            operation=f"get_current_vip_{uuid[:8]}"
        )

        if not current or "vip" not in current:
            return json.dumps({"error": "Virtual IP not found"}, indent=2)

        # Update fields
        vip_data = current["vip"]
        if interface:
            vip_data["interface"] = interface
        if subnet:
            vip_data["subnet"] = subnet
        if vip_type:
            vip_data["type"] = vip_type
        if description is not None:  # Allow empty string to clear description
            vip_data["descr"] = description
        if vhid > 0:
            vip_data["vhid"] = str(vhid)

        response = await opnsense_client.request(
            "POST",
            f"{API_INTERFACES_VIP_SET}/{uuid}",
            data={"vip": vip_data},
            operation=f"update_virtual_ip_{uuid[:8]}"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_INTERFACES_VIP_RECONFIGURE,
                operation="apply_vip_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "update_virtual_ip", e)


@mcp.tool(name="delete_virtual_ip", description="Delete a virtual IP address")
async def delete_virtual_ip(
    ctx: RequestContext,
    uuid: str
) -> str:
    """Delete a virtual IP address by UUID.

    Args:
        ctx: MCP context
        uuid: UUID of the virtual IP to delete

    Returns:
        JSON string of operation result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        response = await opnsense_client.request(
            "POST",
            f"{API_INTERFACES_VIP_DEL}/{uuid}",
            operation=f"delete_virtual_ip_{uuid[:8]}"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_INTERFACES_VIP_RECONFIGURE,
                operation="apply_vip_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "delete_virtual_ip", e)


@mcp.tool(name="get_unused_vhid", description="Get an unused VHID for CARP configuration")
async def get_unused_vhid(ctx: RequestContext) -> str:
    """Get an unused VHID (Virtual Host ID) for CARP configuration.

    Returns:
        JSON string with unused VHID
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        response = await opnsense_client.request(
            "GET",
            API_INTERFACES_VIP_GET_UNUSED_VHID,
            operation="get_unused_vhid"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_unused_vhid", e)


# ========== USER MANAGEMENT ==========

@mcp.tool(name="list_users", description="List all users in OPNsense")
async def list_users(ctx: Context) -> str:
    """List all users configured in OPNsense.

    Args:
        ctx: MCP context

    Returns:
        JSON string with list of all users
    """
    try:
        client = await get_opnsense_client()

        response = await client.request("POST", API_CORE_USER_SEARCH, operation="list_users")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "list_users", e)


@mcp.tool(name="get_user", description="Get details of a specific user")
async def get_user(ctx: Context, user_uuid: Optional[str] = None) -> str:
    """Get details of a specific user or all users.

    Args:
        ctx: MCP context
        user_uuid: UUID of specific user to retrieve (optional - if not provided, returns all users)

    Returns:
        JSON string with user details
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID if provided
        if user_uuid:
            validate_uuid(user_uuid, "user_uuid")
            endpoint = f"{API_CORE_USER_GET}/{user_uuid}"
        else:
            endpoint = API_CORE_USER_GET

        response = await client.request("GET", endpoint, operation="get_user")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_user", e)


@mcp.tool(name="create_user", description="Create a new user account")
async def create_user(
    ctx: Context,
    username: str,
    password: str,
    full_name: str = "",
    email: str = "",
    groups: Optional[str] = None,
    privileges: Optional[str] = None,
    enabled: bool = True,
    expires: Optional[str] = None,
    comment: str = ""
) -> str:
    """Create a new user account in OPNsense.

    Args:
        ctx: MCP context
        username: Unique username for the account
        password: Password for the user (will be hashed)
        full_name: Full name of the user (optional)
        email: Email address of the user (optional)
        groups: Comma-separated list of group names (optional)
        privileges: Comma-separated list of privilege names (optional)
        enabled: Whether the account should be enabled (default: True)
        expires: Expiration date in YYYY-MM-DD format (optional)
        comment: Additional comments about the user (optional)

    Returns:
        JSON string with creation result and new user UUID
    """
    try:
        client = await get_opnsense_client()

        # Validate required parameters
        if not username or not password:
            raise ValidationError("Username and password are required",
                                context={"username": username, "has_password": bool(password)})

        if len(username) < 3:
            raise ValidationError("Username must be at least 3 characters long",
                                context={"username": username})

        if len(password) < 6:
            raise ValidationError("Password must be at least 6 characters long")

        # Prepare user data
        user_data = {
            "user": {
                "enabled": "1" if enabled else "0",
                "name": username,
                "password": password,
                "full_name": full_name,
                "email": email,
                "comment": comment
            }
        }

        # Add groups if specified
        if groups:
            # Convert comma-separated string to list and validate group names
            group_list = [g.strip() for g in groups.split(",") if g.strip()]
            user_data["user"]["groups"] = ",".join(group_list)

        # Add privileges if specified
        if privileges:
            # Convert comma-separated string to list
            priv_list = [p.strip() for p in privileges.split(",") if p.strip()]
            user_data["user"]["priv"] = ",".join(priv_list)

        # Add expiration if specified
        if expires:
            # Basic date format validation
            import re
            if not re.match(r'^\d{4}-\d{2}-\d{2}$', expires):
                raise ValidationError("Expires must be in YYYY-MM-DD format",
                                    context={"expires": expires})
            user_data["user"]["expires"] = expires

        # Create the user
        response = await client.request("POST", API_CORE_USER_ADD,
                                      data=user_data, operation="create_user")

        # Reload configuration if creation was successful
        if response.get("result") == "saved":
            await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_user_create")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "create_user", e)


@mcp.tool(name="update_user", description="Update an existing user account")
async def update_user(
    ctx: Context,
    user_uuid: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    full_name: Optional[str] = None,
    email: Optional[str] = None,
    groups: Optional[str] = None,
    privileges: Optional[str] = None,
    enabled: Optional[bool] = None,
    expires: Optional[str] = None,
    comment: Optional[str] = None
) -> str:
    """Update an existing user account in OPNsense.

    Args:
        ctx: MCP context
        user_uuid: UUID of the user to update
        username: New username (optional)
        password: New password (optional)
        full_name: New full name (optional)
        email: New email address (optional)
        groups: Comma-separated list of group names (optional)
        privileges: Comma-separated list of privilege names (optional)
        enabled: Whether the account should be enabled (optional)
        expires: Expiration date in YYYY-MM-DD format (optional)
        comment: Additional comments about the user (optional)

    Returns:
        JSON string with update result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID
        validate_uuid(user_uuid, "user_uuid")

        # Get current user configuration
        current_user_response = await client.request("GET", f"{API_CORE_USER_GET}/{user_uuid}",
                                                   operation="get_user_for_update")

        if "user" not in current_user_response:
            raise ResourceNotFoundError(f"User with UUID {user_uuid} not found")

        current_user = current_user_response["user"]

        # Update only provided fields
        if username is not None:
            if len(username) < 3:
                raise ValidationError("Username must be at least 3 characters long",
                                    context={"username": username})
            current_user["name"] = username

        if password is not None:
            if len(password) < 6:
                raise ValidationError("Password must be at least 6 characters long")
            current_user["password"] = password

        if full_name is not None:
            current_user["full_name"] = full_name

        if email is not None:
            current_user["email"] = email

        if groups is not None:
            # Convert comma-separated string to list and validate group names
            group_list = [g.strip() for g in groups.split(",") if g.strip()]
            current_user["groups"] = ",".join(group_list)

        if privileges is not None:
            # Convert comma-separated string to list
            priv_list = [p.strip() for p in privileges.split(",") if p.strip()]
            current_user["priv"] = ",".join(priv_list)

        if enabled is not None:
            current_user["enabled"] = "1" if enabled else "0"

        if expires is not None:
            if expires:  # Only validate if not empty
                import re
                if not re.match(r'^\d{4}-\d{2}-\d{2}$', expires):
                    raise ValidationError("Expires must be in YYYY-MM-DD format or empty",
                                        context={"expires": expires})
            current_user["expires"] = expires

        if comment is not None:
            current_user["comment"] = comment

        # Prepare update data
        user_data = {"user": current_user}

        # Update the user
        response = await client.request("POST", f"{API_CORE_USER_SET}/{user_uuid}",
                                      data=user_data, operation="update_user")

        # Reload configuration if update was successful
        if response.get("result") == "saved":
            await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_user_update")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "update_user", e)


@mcp.tool(name="delete_user", description="Delete a user account")
async def delete_user(ctx: Context, user_uuid: str) -> str:
    """Delete a user account from OPNsense.

    This will remove the user account and all associated data including API keys.

    Args:
        ctx: MCP context
        user_uuid: UUID of the user to delete

    Returns:
        JSON string with deletion result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID
        validate_uuid(user_uuid, "user_uuid")

        # Delete the user
        response = await client.request("POST", f"{API_CORE_USER_DEL}/{user_uuid}",
                                      operation="delete_user")

        # Reload configuration if deletion was successful
        if response.get("result") == "deleted":
            await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_user_delete")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "delete_user", e)


@mcp.tool(name="toggle_user", description="Enable or disable a user account")
async def toggle_user(ctx: Context, user_uuid: str, enabled: bool) -> str:
    """Enable or disable a user account.

    Args:
        ctx: MCP context
        user_uuid: UUID of the user to toggle
        enabled: True to enable, False to disable

    Returns:
        JSON string with toggle result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID
        validate_uuid(user_uuid, "user_uuid")

        # Toggle the user
        enabled_int = 1 if enabled else 0
        response = await client.request("POST", f"{API_CORE_USER_TOGGLE}/{user_uuid}/{enabled_int}",
                                      operation="toggle_user")

        # Reload configuration if toggle was successful
        if response.get("result") == "saved":
            await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_user_toggle")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "toggle_user", e)


# ========== GROUP MANAGEMENT ==========

@mcp.tool(name="list_groups", description="List all groups in OPNsense")
async def list_groups(ctx: Context) -> str:
    """List all groups configured in OPNsense.

    Args:
        ctx: MCP context

    Returns:
        JSON string with list of all groups
    """
    try:
        client = await get_opnsense_client()

        response = await client.request("POST", API_CORE_GROUP_SEARCH, operation="list_groups")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "list_groups", e)


@mcp.tool(name="get_group", description="Get details of a specific group")
async def get_group(ctx: Context, group_uuid: Optional[str] = None) -> str:
    """Get details of a specific group or all groups.

    Args:
        ctx: MCP context
        group_uuid: UUID of specific group to retrieve (optional - if not provided, returns all groups)

    Returns:
        JSON string with group details
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID if provided
        if group_uuid:
            validate_uuid(group_uuid, "group_uuid")
            endpoint = f"{API_CORE_GROUP_GET}/{group_uuid}"
        else:
            endpoint = API_CORE_GROUP_GET

        response = await client.request("GET", endpoint, operation="get_group")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_group", e)


@mcp.tool(name="create_group", description="Create a new group")
async def create_group(
    ctx: Context,
    name: str,
    description: str = "",
    privileges: Optional[str] = None,
    members: Optional[str] = None
) -> str:
    """Create a new group in OPNsense.

    Args:
        ctx: MCP context
        name: Name of the group (must be unique)
        description: Description of the group (optional)
        privileges: Comma-separated list of privilege names (optional)
        members: Comma-separated list of usernames to add to group (optional)

    Returns:
        JSON string with creation result and new group UUID
    """
    try:
        client = await get_opnsense_client()

        # Validate required parameters
        if not name:
            raise ValidationError("Group name is required", context={"name": name})

        if len(name) < 2:
            raise ValidationError("Group name must be at least 2 characters long",
                                context={"name": name})

        # Prepare group data
        group_data = {
            "group": {
                "name": name,
                "description": description
            }
        }

        # Add privileges if specified
        if privileges:
            # Convert comma-separated string to list
            priv_list = [p.strip() for p in privileges.split(",") if p.strip()]
            group_data["group"]["priv"] = ",".join(priv_list)

        # Add members if specified
        if members:
            # Convert comma-separated string to list and validate usernames
            member_list = [m.strip() for m in members.split(",") if m.strip()]
            group_data["group"]["member"] = ",".join(member_list)

        # Create the group
        response = await client.request("POST", API_CORE_GROUP_ADD,
                                      data=group_data, operation="create_group")

        # Reload configuration if creation was successful
        if response.get("result") == "saved":
            await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_group_create")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "create_group", e)


@mcp.tool(name="update_group", description="Update an existing group")
async def update_group(
    ctx: Context,
    group_uuid: str,
    name: Optional[str] = None,
    description: Optional[str] = None,
    privileges: Optional[str] = None,
    members: Optional[str] = None
) -> str:
    """Update an existing group in OPNsense.

    Args:
        ctx: MCP context
        group_uuid: UUID of the group to update
        name: New name for the group (optional)
        description: New description for the group (optional)
        privileges: Comma-separated list of privilege names (optional)
        members: Comma-separated list of usernames in group (optional)

    Returns:
        JSON string with update result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID
        validate_uuid(group_uuid, "group_uuid")

        # Get current group configuration
        current_group_response = await client.request("GET", f"{API_CORE_GROUP_GET}/{group_uuid}",
                                                    operation="get_group_for_update")

        if "group" not in current_group_response:
            raise ResourceNotFoundError(f"Group with UUID {group_uuid} not found")

        current_group = current_group_response["group"]

        # Update only provided fields
        if name is not None:
            if len(name) < 2:
                raise ValidationError("Group name must be at least 2 characters long",
                                    context={"name": name})
            current_group["name"] = name

        if description is not None:
            current_group["description"] = description

        if privileges is not None:
            # Convert comma-separated string to list
            priv_list = [p.strip() for p in privileges.split(",") if p.strip()]
            current_group["priv"] = ",".join(priv_list)

        if members is not None:
            # Convert comma-separated string to list and validate usernames
            member_list = [m.strip() for m in members.split(",") if m.strip()]
            current_group["member"] = ",".join(member_list)

        # Prepare update data
        group_data = {"group": current_group}

        # Update the group
        response = await client.request("POST", f"{API_CORE_GROUP_SET}/{group_uuid}",
                                      data=group_data, operation="update_group")

        # Reload configuration if update was successful
        if response.get("result") == "saved":
            await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_group_update")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "update_group", e)


@mcp.tool(name="delete_group", description="Delete a group")
async def delete_group(ctx: Context, group_uuid: str) -> str:
    """Delete a group from OPNsense.

    This will remove the group and update all users who were members of this group.

    Args:
        ctx: MCP context
        group_uuid: UUID of the group to delete

    Returns:
        JSON string with deletion result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID
        validate_uuid(group_uuid, "group_uuid")

        # Delete the group
        response = await client.request("POST", f"{API_CORE_GROUP_DEL}/{group_uuid}",
                                      operation="delete_group")

        # Reload configuration if deletion was successful
        if response.get("result") == "deleted":
            await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_group_delete")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "delete_group", e)


@mcp.tool(name="add_user_to_group", description="Add a user to a group")
async def add_user_to_group(ctx: Context, group_uuid: str, username: str) -> str:
    """Add a user to an existing group.

    Args:
        ctx: MCP context
        group_uuid: UUID of the group to modify
        username: Username to add to the group

    Returns:
        JSON string with update result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID
        validate_uuid(group_uuid, "group_uuid")

        if not username:
            raise ValidationError("Username is required", context={"username": username})

        # Get current group configuration
        current_group_response = await client.request("GET", f"{API_CORE_GROUP_GET}/{group_uuid}",
                                                    operation="get_group_for_member_add")

        if "group" not in current_group_response:
            raise ResourceNotFoundError(f"Group with UUID {group_uuid} not found")

        current_group = current_group_response["group"]

        # Get current members
        current_members = []
        if "member" in current_group and current_group["member"]:
            current_members = [m.strip() for m in current_group["member"].split(",") if m.strip()]

        # Check if user is already a member
        if username in current_members:
            return json.dumps({"result": "no_change", "message": f"User '{username}' is already a member of the group"}, indent=2)

        # Add the new member
        current_members.append(username)
        current_group["member"] = ",".join(current_members)

        # Prepare update data
        group_data = {"group": current_group}

        # Update the group
        response = await client.request("POST", f"{API_CORE_GROUP_SET}/{group_uuid}",
                                      data=group_data, operation="add_user_to_group")

        # Reload configuration if update was successful
        if response.get("result") == "saved":
            await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_group_member_add")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "add_user_to_group", e)


@mcp.tool(name="remove_user_from_group", description="Remove a user from a group")
async def remove_user_from_group(ctx: Context, group_uuid: str, username: str) -> str:
    """Remove a user from an existing group.

    Args:
        ctx: MCP context
        group_uuid: UUID of the group to modify
        username: Username to remove from the group

    Returns:
        JSON string with update result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID
        validate_uuid(group_uuid, "group_uuid")

        if not username:
            raise ValidationError("Username is required", context={"username": username})

        # Get current group configuration
        current_group_response = await client.request("GET", f"{API_CORE_GROUP_GET}/{group_uuid}",
                                                    operation="get_group_for_member_remove")

        if "group" not in current_group_response:
            raise ResourceNotFoundError(f"Group with UUID {group_uuid} not found")

        current_group = current_group_response["group"]

        # Get current members
        current_members = []
        if "member" in current_group and current_group["member"]:
            current_members = [m.strip() for m in current_group["member"].split(",") if m.strip()]

        # Check if user is actually a member
        if username not in current_members:
            return json.dumps({"result": "no_change", "message": f"User '{username}' is not a member of the group"}, indent=2)

        # Remove the member
        current_members.remove(username)
        current_group["member"] = ",".join(current_members)

        # Prepare update data
        group_data = {"group": current_group}

        # Update the group
        response = await client.request("POST", f"{API_CORE_GROUP_SET}/{group_uuid}",
                                      data=group_data, operation="remove_user_from_group")

        # Reload configuration if update was successful
        if response.get("result") == "saved":
            await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_group_member_remove")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "remove_user_from_group", e)


# ========== AUTHENTICATION & PRIVILEGE MANAGEMENT ==========

@mcp.tool(name="list_privileges", description="List all available privileges in OPNsense")
async def list_privileges(ctx: Context) -> str:
    """List all available privileges and their descriptions in OPNsense.

    Args:
        ctx: MCP context

    Returns:
        JSON string with list of all available privileges
    """
    try:
        client = await get_opnsense_client()

        response = await client.request("GET", API_CORE_AUTH_PRIVILEGES, operation="list_privileges")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "list_privileges", e)


@mcp.tool(name="get_user_effective_privileges", description="Get effective privileges for a user")
async def get_user_effective_privileges(ctx: Context, username: str) -> str:
    """Get the effective privileges for a specific user (combines user and group privileges).

    Args:
        ctx: MCP context
        username: Username to get privileges for

    Returns:
        JSON string with user's effective privileges
    """
    try:
        client = await get_opnsense_client()

        if not username:
            raise ValidationError("Username is required", context={"username": username})

        # First get the user details to find their UUID
        users_response = await client.request("POST", API_CORE_USER_SEARCH, operation="search_user_for_privileges")

        user_uuid = None
        if "rows" in users_response:
            for user in users_response["rows"]:
                if user.get("name") == username:
                    user_uuid = user.get("uuid")
                    break

        if not user_uuid:
            raise ResourceNotFoundError(f"User '{username}' not found")

        # Get detailed user information including groups and privileges
        user_details_response = await client.request("GET", f"{API_CORE_USER_GET}/{user_uuid}",
                                                   operation="get_user_privileges")

        if "user" not in user_details_response:
            raise ResourceNotFoundError(f"User details for '{username}' not found")

        user_details = user_details_response["user"]

        # Collect all privileges
        effective_privileges = set()

        # Add direct user privileges
        if "priv" in user_details and user_details["priv"]:
            user_privs = [p.strip() for p in user_details["priv"].split(",") if p.strip()]
            effective_privileges.update(user_privs)

        # Add group privileges
        if "groups" in user_details and user_details["groups"]:
            group_names = [g.strip() for g in user_details["groups"].split(",") if g.strip()]

            # Get all groups to find UUIDs and privileges
            groups_response = await client.request("POST", API_CORE_GROUP_SEARCH, operation="search_groups_for_user_privileges")

            if "rows" in groups_response:
                for group in groups_response["rows"]:
                    if group.get("name") in group_names:
                        # Get detailed group information
                        group_uuid = group.get("uuid")
                        if group_uuid:
                            group_details_response = await client.request("GET", f"{API_CORE_GROUP_GET}/{group_uuid}",
                                                                        operation="get_group_privileges")
                            if "group" in group_details_response:
                                group_details = group_details_response["group"]
                                if "priv" in group_details and group_details["priv"]:
                                    group_privs = [p.strip() for p in group_details["priv"].split(",") if p.strip()]
                                    effective_privileges.update(group_privs)

        # Format result
        result = {
            "username": username,
            "user_uuid": user_uuid,
            "direct_privileges": [p.strip() for p in user_details.get("priv", "").split(",") if p.strip()],
            "group_memberships": [g.strip() for g in user_details.get("groups", "").split(",") if g.strip()],
            "effective_privileges": sorted(list(effective_privileges)),
            "privilege_count": len(effective_privileges)
        }

        return json.dumps(result, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_user_effective_privileges", e)


@mcp.tool(name="assign_privilege_to_user", description="Assign a privilege directly to a user")
async def assign_privilege_to_user(ctx: Context, username: str, privilege: str) -> str:
    """Assign a specific privilege directly to a user.

    Args:
        ctx: MCP context
        username: Username to assign privilege to
        privilege: Privilege name to assign

    Returns:
        JSON string with assignment result
    """
    try:
        client = await get_opnsense_client()

        if not username or not privilege:
            raise ValidationError("Username and privilege are required",
                                context={"username": username, "privilege": privilege})

        # Find the user
        users_response = await client.request("POST", API_CORE_USER_SEARCH, operation="search_user_for_privilege_assignment")

        user_uuid = None
        if "rows" in users_response:
            for user in users_response["rows"]:
                if user.get("name") == username:
                    user_uuid = user.get("uuid")
                    break

        if not user_uuid:
            raise ResourceNotFoundError(f"User '{username}' not found")

        # Get current user details
        user_details_response = await client.request("GET", f"{API_CORE_USER_GET}/{user_uuid}",
                                                   operation="get_user_for_privilege_assignment")

        if "user" not in user_details_response:
            raise ResourceNotFoundError(f"User details for '{username}' not found")

        current_user = user_details_response["user"]

        # Get current privileges
        current_privileges = []
        if "priv" in current_user and current_user["priv"]:
            current_privileges = [p.strip() for p in current_user["priv"].split(",") if p.strip()]

        # Check if privilege is already assigned
        if privilege in current_privileges:
            return json.dumps({"result": "no_change", "message": f"Privilege '{privilege}' is already assigned to user '{username}'"}, indent=2)

        # Add the new privilege
        current_privileges.append(privilege)
        current_user["priv"] = ",".join(current_privileges)

        # Update the user
        user_data = {"user": current_user}
        response = await client.request("POST", f"{API_CORE_USER_SET}/{user_uuid}",
                                      data=user_data, operation="assign_privilege_to_user")

        # Reload configuration if update was successful
        if response.get("result") == "saved":
            await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_privilege_assignment")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "assign_privilege_to_user", e)


@mcp.tool(name="revoke_privilege_from_user", description="Revoke a privilege directly from a user")
async def revoke_privilege_from_user(ctx: Context, username: str, privilege: str) -> str:
    """Revoke a specific privilege directly from a user.

    Args:
        ctx: MCP context
        username: Username to revoke privilege from
        privilege: Privilege name to revoke

    Returns:
        JSON string with revocation result
    """
    try:
        client = await get_opnsense_client()

        if not username or not privilege:
            raise ValidationError("Username and privilege are required",
                                context={"username": username, "privilege": privilege})

        # Find the user
        users_response = await client.request("POST", API_CORE_USER_SEARCH, operation="search_user_for_privilege_revocation")

        user_uuid = None
        if "rows" in users_response:
            for user in users_response["rows"]:
                if user.get("name") == username:
                    user_uuid = user.get("uuid")
                    break

        if not user_uuid:
            raise ResourceNotFoundError(f"User '{username}' not found")

        # Get current user details
        user_details_response = await client.request("GET", f"{API_CORE_USER_GET}/{user_uuid}",
                                                   operation="get_user_for_privilege_revocation")

        if "user" not in user_details_response:
            raise ResourceNotFoundError(f"User details for '{username}' not found")

        current_user = user_details_response["user"]

        # Get current privileges
        current_privileges = []
        if "priv" in current_user and current_user["priv"]:
            current_privileges = [p.strip() for p in current_user["priv"].split(",") if p.strip()]

        # Check if privilege is actually assigned
        if privilege not in current_privileges:
            return json.dumps({"result": "no_change", "message": f"Privilege '{privilege}' is not assigned to user '{username}'"}, indent=2)

        # Remove the privilege
        current_privileges.remove(privilege)
        current_user["priv"] = ",".join(current_privileges)

        # Update the user
        user_data = {"user": current_user}
        response = await client.request("POST", f"{API_CORE_USER_SET}/{user_uuid}",
                                      data=user_data, operation="revoke_privilege_from_user")

        # Reload configuration if update was successful
        if response.get("result") == "saved":
            await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_privilege_revocation")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "revoke_privilege_from_user", e)


@mcp.tool(name="list_auth_servers", description="List configured authentication servers")
async def list_auth_servers(ctx: Context) -> str:
    """List all configured authentication servers (LDAP, RADIUS, etc.).

    Args:
        ctx: MCP context

    Returns:
        JSON string with list of authentication servers
    """
    try:
        client = await get_opnsense_client()

        response = await client.request("GET", API_CORE_AUTH_SERVERS, operation="list_auth_servers")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "list_auth_servers", e)


@mcp.tool(name="test_user_authentication", description="Test user authentication against configured servers")
async def test_user_authentication(ctx: Context, username: str, auth_server: Optional[str] = None) -> str:
    """Test user authentication against a specific authentication server or all servers.

    Args:
        ctx: MCP context
        username: Username to test authentication for
        auth_server: Specific authentication server to test against (optional)

    Returns:
        JSON string with authentication test results
    """
    try:
        client = await get_opnsense_client()

        if not username:
            raise ValidationError("Username is required", context={"username": username})

        # Prepare test data
        test_data = {
            "username": username
        }

        if auth_server:
            test_data["auth_server"] = auth_server

        response = await client.request("POST", API_CORE_AUTH_TEST,
                                      data=test_data, operation="test_user_authentication")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "test_user_authentication", e)


# ========== USER MANAGEMENT HELPER TOOLS ==========

@mcp.tool()
async def create_admin_user(ctx: RequestContext, username: str, password: str,
                           full_name: str = "", email: str = "") -> str:
    """
    Create a new administrative user with full system privileges.

    Args:
        username: Username for the new admin user
        password: Password for the user
        full_name: Full name of the user (optional)
        email: Email address of the user (optional)

    Returns:
        JSON response with creation status and user details
    """
    try:
        client = get_opnsense_client()
        if not client:
            return "Error: OPNsense connection not configured. Use configure_opnsense_connection first."

        # Create the user first
        user_data = {
            "user": {
                "name": username,
                "password": password,
                "full_name": full_name or username,
                "email": email,
                "disabled": "0",
                "expires": "",
                "comment": "Administrative user created via MCP"
            }
        }

        response = await client.request("POST", API_CORE_USER_ADD,
                                      data=user_data, operation="create_admin_user")

        if response.get("result") != "saved":
            return json.dumps({"error": "Failed to create user", "response": response}, indent=2)

        user_uuid = response.get("uuid")
        if not user_uuid:
            return json.dumps({"error": "User created but UUID not returned", "response": response}, indent=2)

        # Get all available privileges
        privileges_response = await client.request("GET", API_CORE_AUTH_PRIVILEGES,
                                                 operation="get_privileges_for_admin")

        if "privileges" not in privileges_response:
            return json.dumps({
                "user_created": True,
                "uuid": user_uuid,
                "warning": "User created but could not retrieve privileges for assignment"
            }, indent=2)

        # Assign all privileges to make this a full admin
        all_privileges = list(privileges_response["privileges"].keys())
        privilege_string = ",".join(all_privileges)

        # Update user with all privileges
        update_data = {
            "user": {
                "name": username,
                "password": password,
                "full_name": full_name or username,
                "email": email,
                "disabled": "0",
                "expires": "",
                "comment": "Administrative user created via MCP",
                "priv": privilege_string
            }
        }

        await client.request("POST", f"{API_CORE_USER_SET}/{user_uuid}",
                           data=update_data, operation="assign_admin_privileges")

        # Reload configuration
        await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_admin_creation")

        return json.dumps({
            "result": "success",
            "message": f"Administrative user '{username}' created successfully",
            "uuid": user_uuid,
            "privileges_assigned": len(all_privileges),
            "full_admin": True
        }, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "create_admin_user", e)


@mcp.tool()
async def create_readonly_user(ctx: RequestContext, username: str, password: str,
                              full_name: str = "", email: str = "") -> str:
    """
    Create a new read-only user with limited system access.

    Args:
        username: Username for the new read-only user
        password: Password for the user
        full_name: Full name of the user (optional)
        email: Email address of the user (optional)

    Returns:
        JSON response with creation status and user details
    """
    try:
        client = get_opnsense_client()
        if not client:
            return "Error: OPNsense connection not configured. Use configure_opnsense_connection first."

        # Define read-only privileges (common monitoring/viewing privileges)
        readonly_privileges = [
            "page-all",                    # Basic page access
            "page-status-system",          # System status
            "page-status-interfaces",      # Interface status
            "page-status-logs",           # Log viewing
            "page-diagnostics-all",       # Diagnostic tools
            "page-status-dashboard",      # Dashboard access
            "page-firewall-rules",        # Firewall rule viewing (read-only)
            "page-interfaces-overview"    # Interface overview
        ]

        # Create user with read-only privileges
        user_data = {
            "user": {
                "name": username,
                "password": password,
                "full_name": full_name or username,
                "email": email,
                "disabled": "0",
                "expires": "",
                "comment": "Read-only user created via MCP",
                "priv": ",".join(readonly_privileges)
            }
        }

        response = await client.request("POST", API_CORE_USER_ADD,
                                      data=user_data, operation="create_readonly_user")

        if response.get("result") != "saved":
            return json.dumps({"error": "Failed to create read-only user", "response": response}, indent=2)

        # Reload configuration
        await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_readonly_creation")

        return json.dumps({
            "result": "success",
            "message": f"Read-only user '{username}' created successfully",
            "uuid": response.get("uuid"),
            "privileges_assigned": readonly_privileges,
            "access_level": "read-only"
        }, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "create_readonly_user", e)


@mcp.tool()
async def reset_user_password(ctx: RequestContext, username: str, new_password: str) -> str:
    """
    Reset a user's password by username.

    Args:
        username: Username of the user whose password to reset
        new_password: New password to set

    Returns:
        JSON response with password reset status
    """
    try:
        client = get_opnsense_client()
        if not client:
            return "Error: OPNsense connection not configured. Use configure_opnsense_connection first."

        # First, find the user by username
        search_response = await client.request("GET", API_CORE_USER_SEARCH,
                                             operation="search_user_for_password_reset")

        if "rows" not in search_response:
            return json.dumps({"error": "Failed to retrieve user list"}, indent=2)

        user_uuid = None
        user_data = None
        for user in search_response["rows"]:
            if user.get("name") == username:
                user_uuid = user.get("uuid")
                user_data = user
                break

        if not user_uuid:
            return json.dumps({"error": f"User '{username}' not found"}, indent=2)

        # Get full user details
        user_detail_response = await client.request("GET", f"{API_CORE_USER_GET}/{user_uuid}",
                                                   operation="get_user_details_for_password_reset")

        if "user" not in user_detail_response:
            return json.dumps({"error": "Failed to retrieve user details"}, indent=2)

        current_user = user_detail_response["user"]

        # Update user with new password (preserve all other settings)
        update_data = {
            "user": {
                "name": current_user.get("name", username),
                "password": new_password,
                "full_name": current_user.get("full_name", ""),
                "email": current_user.get("email", ""),
                "disabled": current_user.get("disabled", "0"),
                "expires": current_user.get("expires", ""),
                "comment": current_user.get("comment", ""),
                "priv": current_user.get("priv", ""),
                "groups": current_user.get("groups", "")
            }
        }

        response = await client.request("POST", f"{API_CORE_USER_SET}/{user_uuid}",
                                      data=update_data, operation="reset_user_password")

        if response.get("result") != "saved":
            return json.dumps({"error": "Failed to reset password", "response": response}, indent=2)

        # Reload configuration
        await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_password_reset")

        return json.dumps({
            "result": "success",
            "message": f"Password successfully reset for user '{username}'",
            "uuid": user_uuid
        }, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "reset_user_password", e)


@mcp.tool()
async def bulk_user_creation(ctx: RequestContext, user_template: str) -> str:
    """
    Create multiple users from a template specification.

    Args:
        user_template: JSON string containing user template and list of users to create.
                      Format: {
                        "template": {
                          "password": "default_password",
                          "privileges": ["priv1", "priv2"],
                          "groups": ["group1"],
                          "expires": "",
                          "disabled": "0"
                        },
                        "users": [
                          {"username": "user1", "full_name": "User One", "email": "user1@example.com"},
                          {"username": "user2", "full_name": "User Two", "email": "user2@example.com"}
                        ]
                      }

    Returns:
        JSON response with bulk creation results
    """
    try:
        client = get_opnsense_client()
        if not client:
            return "Error: OPNsense connection not configured. Use configure_opnsense_connection first."

        # Parse the template
        try:
            template_data = json.loads(user_template)
        except json.JSONDecodeError as e:
            return json.dumps({"error": f"Invalid JSON template: {str(e)}"}, indent=2)

        if "template" not in template_data or "users" not in template_data:
            return json.dumps({"error": "Template must contain 'template' and 'users' sections"}, indent=2)

        template = template_data["template"]
        users_to_create = template_data["users"]

        results = []
        successful_creations = 0

        for user_spec in users_to_create:
            try:
                username = user_spec.get("username")
                if not username:
                    results.append({"error": "Username required for each user", "user_spec": user_spec})
                    continue

                # Build user data from template and user-specific overrides
                user_data = {
                    "user": {
                        "name": username,
                        "password": user_spec.get("password", template.get("password", "")),
                        "full_name": user_spec.get("full_name", template.get("full_name", username)),
                        "email": user_spec.get("email", template.get("email", "")),
                        "disabled": user_spec.get("disabled", template.get("disabled", "0")),
                        "expires": user_spec.get("expires", template.get("expires", "")),
                        "comment": user_spec.get("comment", template.get("comment", "Bulk created via MCP")),
                        "priv": ",".join(user_spec.get("privileges", template.get("privileges", []))),
                        "groups": ",".join(user_spec.get("groups", template.get("groups", [])))
                    }
                }

                response = await client.request("POST", API_CORE_USER_ADD,
                                              data=user_data, operation=f"bulk_create_user_{username}")

                if response.get("result") == "saved":
                    results.append({
                        "username": username,
                        "status": "success",
                        "uuid": response.get("uuid")
                    })
                    successful_creations += 1
                else:
                    results.append({
                        "username": username,
                        "status": "failed",
                        "error": response.get("validations", "Unknown error")
                    })

            except Exception as user_error:
                results.append({
                    "username": user_spec.get("username", "unknown"),
                    "status": "failed",
                    "error": str(user_error)
                })

        # Reload configuration if any users were created
        if successful_creations > 0:
            await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_bulk_creation")

        return json.dumps({
            "result": "completed",
            "total_users": len(users_to_create),
            "successful_creations": successful_creations,
            "failed_creations": len(users_to_create) - successful_creations,
            "details": results
        }, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "bulk_user_creation", e)


@mcp.tool()
async def setup_user_group_template(ctx: RequestContext, template_name: str,
                                   privileges: list, description: str = "") -> str:
    """
    Create a user group template with predefined privileges for common roles.

    Args:
        template_name: Name for the group template
        privileges: List of privilege names to assign to the group
        description: Description of the group's purpose

    Returns:
        JSON response with group creation status
    """
    try:
        client = get_opnsense_client()
        if not client:
            return "Error: OPNsense connection not configured. Use configure_opnsense_connection first."

        # Validate privileges exist
        privileges_response = await client.request("GET", API_CORE_AUTH_PRIVILEGES,
                                                 operation="validate_privileges_for_template")

        if "privileges" not in privileges_response:
            return json.dumps({"error": "Could not retrieve available privileges"}, indent=2)

        available_privileges = set(privileges_response["privileges"].keys())
        invalid_privileges = [p for p in privileges if p not in available_privileges]

        if invalid_privileges:
            return json.dumps({
                "error": "Invalid privileges specified",
                "invalid_privileges": invalid_privileges,
                "available_privileges": list(available_privileges)
            }, indent=2)

        # Create the group
        group_data = {
            "group": {
                "name": template_name,
                "description": description or f"Template group: {template_name}",
                "priv": ",".join(privileges)
            }
        }

        response = await client.request("POST", API_CORE_GROUP_ADD,
                                      data=group_data, operation="create_group_template")

        if response.get("result") != "saved":
            return json.dumps({"error": "Failed to create group template", "response": response}, indent=2)

        # Reload configuration
        await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_template_creation")

        return json.dumps({
            "result": "success",
            "message": f"Group template '{template_name}' created successfully",
            "uuid": response.get("uuid"),
            "privileges_assigned": privileges,
            "privilege_count": len(privileges)
        }, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "setup_user_group_template", e)


# Entry point
if __name__ == "__main__":
    mcp.run()