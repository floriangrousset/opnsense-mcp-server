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

# Diagnostics
API_DIAGNOSTICS_LOG_FIREWALL = "/diagnostics/log/firewall"
API_DIAGNOSTICS_SYSTEM_PROCESSOR = "/diagnostics/system/processor"
API_DIAGNOSTICS_SYSTEM_MEMORY = "/diagnostics/system/memory"
API_DIAGNOSTICS_SYSTEM_STORAGE = "/diagnostics/system/storage"
API_DIAGNOSTICS_SYSTEM_TEMPERATURE = "/diagnostics/system/temperature"

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

# ========== TRAFFIC SHAPER API ENDPOINTS ==========

# Traffic Shaper Service Controller
API_TRAFFICSHAPER_SERVICE_FLUSHRELOAD = "/trafficshaper/service/flushreload"
API_TRAFFICSHAPER_SERVICE_RECONFIGURE = "/trafficshaper/service/reconfigure"
API_TRAFFICSHAPER_SERVICE_STATISTICS = "/trafficshaper/service/statistics"

# Traffic Shaper Settings - Pipes
API_TRAFFICSHAPER_SETTINGS_ADD_PIPE = "/trafficshaper/settings/add_pipe"
API_TRAFFICSHAPER_SETTINGS_DEL_PIPE = "/trafficshaper/settings/del_pipe"  # Needs /{uuid}
API_TRAFFICSHAPER_SETTINGS_GET_PIPE = "/trafficshaper/settings/get_pipe"  # Optional /{uuid}
API_TRAFFICSHAPER_SETTINGS_SET_PIPE = "/trafficshaper/settings/set_pipe"  # Needs /{uuid}
API_TRAFFICSHAPER_SETTINGS_TOGGLE_PIPE = "/trafficshaper/settings/toggle_pipe"  # Needs /{uuid}/{enabled}
API_TRAFFICSHAPER_SETTINGS_SEARCH_PIPES = "/trafficshaper/settings/search_pipes"

# Traffic Shaper Settings - Queues
API_TRAFFICSHAPER_SETTINGS_ADD_QUEUE = "/trafficshaper/settings/add_queue"
API_TRAFFICSHAPER_SETTINGS_DEL_QUEUE = "/trafficshaper/settings/del_queue"  # Needs /{uuid}
API_TRAFFICSHAPER_SETTINGS_GET_QUEUE = "/trafficshaper/settings/get_queue"  # Optional /{uuid}
API_TRAFFICSHAPER_SETTINGS_SET_QUEUE = "/trafficshaper/settings/set_queue"  # Needs /{uuid}
API_TRAFFICSHAPER_SETTINGS_TOGGLE_QUEUE = "/trafficshaper/settings/toggle_queue"  # Needs /{uuid}/{enabled}
API_TRAFFICSHAPER_SETTINGS_SEARCH_QUEUES = "/trafficshaper/settings/search_queues"

# Traffic Shaper Settings - Rules
API_TRAFFICSHAPER_SETTINGS_ADD_RULE = "/trafficshaper/settings/add_rule"
API_TRAFFICSHAPER_SETTINGS_DEL_RULE = "/trafficshaper/settings/del_rule"  # Needs /{uuid}
API_TRAFFICSHAPER_SETTINGS_GET_RULE = "/trafficshaper/settings/get_rule"  # Optional /{uuid}
API_TRAFFICSHAPER_SETTINGS_SET_RULE = "/trafficshaper/settings/set_rule"  # Needs /{uuid}
API_TRAFFICSHAPER_SETTINGS_TOGGLE_RULE = "/trafficshaper/settings/toggle_rule"  # Needs /{uuid}/{enabled}
API_TRAFFICSHAPER_SETTINGS_SEARCH_RULES = "/trafficshaper/settings/search_rules"

# Traffic Shaper Settings - General
API_TRAFFICSHAPER_SETTINGS_GET = "/trafficshaper/settings/get"
API_TRAFFICSHAPER_SETTINGS_SET = "/trafficshaper/settings/set"


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


# ========== TRAFFIC SHAPING AND QoS MANAGEMENT ==========

@mcp.tool(name="traffic_shaper_get_status", description="Get traffic shaper service status and statistics")
async def traffic_shaper_get_status(ctx: Context) -> str:
    """Get traffic shaper service status and detailed statistics.

    Args:
        ctx: MCP context

    Returns:
        JSON string containing traffic shaper status and statistics
    """
    try:
        client = await get_opnsense_client()

        # Get service status and statistics
        statistics_response = await client.request("GET", API_TRAFFICSHAPER_SERVICE_STATISTICS, operation="get_traffic_shaper_statistics")

        return json.dumps(statistics_response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_get_status", e)


@mcp.tool(name="traffic_shaper_reconfigure", description="Apply traffic shaper configuration changes")
async def traffic_shaper_reconfigure(ctx: Context) -> str:
    """Reconfigure and apply all traffic shaper changes.

    This should be called after making configuration changes to pipes, queues, or rules
    to ensure the changes take effect.

    Args:
        ctx: MCP context

    Returns:
        JSON string with reconfiguration status
    """
    try:
        client = await get_opnsense_client()

        # Reconfigure the traffic shaper service
        response = await client.request("POST", API_TRAFFICSHAPER_SERVICE_RECONFIGURE, operation="reconfigure_traffic_shaper")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_reconfigure", e)


@mcp.tool(name="traffic_shaper_get_settings", description="Get general traffic shaper settings and configuration")
async def traffic_shaper_get_settings(ctx: Context) -> str:
    """Get general traffic shaper settings and configuration.

    Args:
        ctx: MCP context

    Returns:
        JSON string with general traffic shaper settings
    """
    try:
        client = await get_opnsense_client()

        response = await client.request("GET", API_TRAFFICSHAPER_SETTINGS_GET, operation="get_traffic_shaper_settings")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_get_settings", e)


# ========== PIPE MANAGEMENT ==========

@mcp.tool(name="traffic_shaper_list_pipes", description="List all traffic shaper pipes with optional filtering")
async def traffic_shaper_list_pipes(ctx: Context) -> str:
    """List all traffic shaper pipes with their configurations.

    Args:
        ctx: MCP context

    Returns:
        JSON string with list of all pipes
    """
    try:
        client = await get_opnsense_client()

        response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_SEARCH_PIPES, operation="search_traffic_shaper_pipes")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_list_pipes", e)


@mcp.tool(name="traffic_shaper_get_pipe", description="Get details of a specific traffic shaper pipe")
async def traffic_shaper_get_pipe(ctx: Context, pipe_uuid: Optional[str] = None) -> str:
    """Get details of a specific traffic shaper pipe or all pipes.

    Args:
        ctx: MCP context
        pipe_uuid: UUID of specific pipe to retrieve (optional - if not provided, returns all pipes)

    Returns:
        JSON string with pipe details
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID if provided
        if pipe_uuid:
            validate_uuid(pipe_uuid, "pipe_uuid")
            endpoint = f"{API_TRAFFICSHAPER_SETTINGS_GET_PIPE}/{pipe_uuid}"
        else:
            endpoint = API_TRAFFICSHAPER_SETTINGS_GET_PIPE

        response = await client.request("GET", endpoint, operation="get_traffic_shaper_pipe")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_get_pipe", e)


@mcp.tool(name="traffic_shaper_create_pipe", description="Create a new traffic shaper pipe for bandwidth limiting")
async def traffic_shaper_create_pipe(
    ctx: Context,
    bandwidth: int,
    bandwidth_metric: str = "Mbit/s",
    queue_size: int = 50,
    scheduler: str = "FIFO",
    description: str = "",
    enabled: bool = True
) -> str:
    """Create a new traffic shaper pipe with specified bandwidth limits.

    Args:
        ctx: MCP context
        bandwidth: Bandwidth limit (positive integer)
        bandwidth_metric: Bandwidth unit (bit/s, Kbit/s, Mbit/s, Gbit/s)
        queue_size: Queue size in slots (2-100)
        scheduler: Scheduler algorithm (FIFO, DRR, QFQ, FQ-CoDel, FQ-PIE)
        description: Description for the pipe
        enabled: Whether the pipe should be enabled

    Returns:
        JSON string with creation result and new pipe UUID
    """
    try:
        client = await get_opnsense_client()

        # Validate parameters
        if bandwidth <= 0:
            raise ValidationError("Bandwidth must be a positive integer",
                                context={"bandwidth": bandwidth})

        if bandwidth_metric not in ["bit/s", "Kbit/s", "Mbit/s", "Gbit/s"]:
            raise ValidationError("Invalid bandwidth metric",
                                context={"bandwidth_metric": bandwidth_metric,
                                       "valid_options": ["bit/s", "Kbit/s", "Mbit/s", "Gbit/s"]})

        if not (2 <= queue_size <= 100):
            raise ValidationError("Queue size must be between 2 and 100",
                                context={"queue_size": queue_size})

        if scheduler not in ["FIFO", "DRR", "QFQ", "FQ-CoDel", "FQ-PIE"]:
            raise ValidationError("Invalid scheduler",
                                context={"scheduler": scheduler,
                                       "valid_options": ["FIFO", "DRR", "QFQ", "FQ-CoDel", "FQ-PIE"]})

        # Prepare pipe data
        pipe_data = {
            "pipe": {
                "enabled": "1" if enabled else "0",
                "bandwidth": str(bandwidth),
                "bandwidthMetric": bandwidth_metric,
                "queue": str(queue_size),
                "scheduler": scheduler,
                "description": description
            }
        }

        # Create the pipe
        response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_ADD_PIPE,
                                      data=pipe_data, operation="create_traffic_shaper_pipe")

        # Apply configuration if creation was successful
        if response.get("result") == "saved":
            await client.request("POST", API_TRAFFICSHAPER_SERVICE_RECONFIGURE, operation="reconfigure_after_pipe_create")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_create_pipe", e)


@mcp.tool(name="traffic_shaper_update_pipe", description="Update an existing traffic shaper pipe configuration")
async def traffic_shaper_update_pipe(
    ctx: Context,
    pipe_uuid: str,
    bandwidth: Optional[int] = None,
    bandwidth_metric: Optional[str] = None,
    queue_size: Optional[int] = None,
    scheduler: Optional[str] = None,
    description: Optional[str] = None,
    enabled: Optional[bool] = None
) -> str:
    """Update an existing traffic shaper pipe configuration.

    Args:
        ctx: MCP context
        pipe_uuid: UUID of the pipe to update
        bandwidth: Bandwidth limit (positive integer, optional)
        bandwidth_metric: Bandwidth unit (bit/s, Kbit/s, Mbit/s, Gbit/s, optional)
        queue_size: Queue size in slots (2-100, optional)
        scheduler: Scheduler algorithm (FIFO, DRR, QFQ, FQ-CoDel, FQ-PIE, optional)
        description: Description for the pipe (optional)
        enabled: Whether the pipe should be enabled (optional)

    Returns:
        JSON string with update result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID
        validate_uuid(pipe_uuid, "pipe_uuid")

        # Get current pipe configuration
        current_pipe_response = await client.request("GET", f"{API_TRAFFICSHAPER_SETTINGS_GET_PIPE}/{pipe_uuid}",
                                                   operation="get_pipe_for_update")

        if "pipe" not in current_pipe_response:
            raise ResourceNotFoundError(f"Pipe with UUID {pipe_uuid} not found")

        current_pipe = current_pipe_response["pipe"]

        # Update only provided fields
        if bandwidth is not None:
            if bandwidth <= 0:
                raise ValidationError("Bandwidth must be a positive integer",
                                    context={"bandwidth": bandwidth})
            current_pipe["bandwidth"] = str(bandwidth)

        if bandwidth_metric is not None:
            if bandwidth_metric not in ["bit/s", "Kbit/s", "Mbit/s", "Gbit/s"]:
                raise ValidationError("Invalid bandwidth metric",
                                    context={"bandwidth_metric": bandwidth_metric})
            current_pipe["bandwidthMetric"] = bandwidth_metric

        if queue_size is not None:
            if not (2 <= queue_size <= 100):
                raise ValidationError("Queue size must be between 2 and 100",
                                    context={"queue_size": queue_size})
            current_pipe["queue"] = str(queue_size)

        if scheduler is not None:
            if scheduler not in ["FIFO", "DRR", "QFQ", "FQ-CoDel", "FQ-PIE"]:
                raise ValidationError("Invalid scheduler",
                                    context={"scheduler": scheduler})
            current_pipe["scheduler"] = scheduler

        if description is not None:
            current_pipe["description"] = description

        if enabled is not None:
            current_pipe["enabled"] = "1" if enabled else "0"

        # Prepare update data
        pipe_data = {"pipe": current_pipe}

        # Update the pipe
        response = await client.request("POST", f"{API_TRAFFICSHAPER_SETTINGS_SET_PIPE}/{pipe_uuid}",
                                      data=pipe_data, operation="update_traffic_shaper_pipe")

        # Apply configuration if update was successful
        if response.get("result") == "saved":
            await client.request("POST", API_TRAFFICSHAPER_SERVICE_RECONFIGURE, operation="reconfigure_after_pipe_update")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_update_pipe", e)


@mcp.tool(name="traffic_shaper_delete_pipe", description="Delete a traffic shaper pipe")
async def traffic_shaper_delete_pipe(ctx: Context, pipe_uuid: str) -> str:
    """Delete a traffic shaper pipe.

    Note: This will also delete any queues and rules that reference this pipe.

    Args:
        ctx: MCP context
        pipe_uuid: UUID of the pipe to delete

    Returns:
        JSON string with deletion result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID
        validate_uuid(pipe_uuid, "pipe_uuid")

        # Delete the pipe
        response = await client.request("POST", f"{API_TRAFFICSHAPER_SETTINGS_DEL_PIPE}/{pipe_uuid}",
                                      operation="delete_traffic_shaper_pipe")

        # Apply configuration if deletion was successful
        if response.get("result") == "deleted":
            await client.request("POST", API_TRAFFICSHAPER_SERVICE_RECONFIGURE, operation="reconfigure_after_pipe_delete")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_delete_pipe", e)


@mcp.tool(name="traffic_shaper_toggle_pipe", description="Enable or disable a traffic shaper pipe")
async def traffic_shaper_toggle_pipe(ctx: Context, pipe_uuid: str, enabled: bool) -> str:
    """Enable or disable a traffic shaper pipe.

    Args:
        ctx: MCP context
        pipe_uuid: UUID of the pipe to toggle
        enabled: True to enable, False to disable

    Returns:
        JSON string with toggle result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID
        validate_uuid(pipe_uuid, "pipe_uuid")

        # Toggle the pipe
        enabled_int = 1 if enabled else 0
        response = await client.request("POST", f"{API_TRAFFICSHAPER_SETTINGS_TOGGLE_PIPE}/{pipe_uuid}/{enabled_int}",
                                      operation="toggle_traffic_shaper_pipe")

        # Apply configuration if toggle was successful
        if response.get("result") == "saved":
            await client.request("POST", API_TRAFFICSHAPER_SERVICE_RECONFIGURE, operation="reconfigure_after_pipe_toggle")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_toggle_pipe", e)


# Entry point
if __name__ == "__main__":
    mcp.run()