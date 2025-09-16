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
from typing import Dict, List, Any, Optional, Union, Tuple, TypedDict
import urllib.parse
from datetime import datetime, timedelta
from enum import Enum
import httpx
from mcp.server.fastmcp import FastMCP, Context
from mcp import types


# Configure logging with enhanced format
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s",
)
logger = logging.getLogger("opnsense-mcp")


# ========== EXCEPTION HIERARCHY ==========

class OPNsenseError(Exception):
    """Base exception for all OPNsense-related errors."""

    def __init__(self, message: str, error_code: Optional[str] = None, context: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.context = context or {}
        self.timestamp = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for structured logging."""
        return {
            "error_type": self.__class__.__name__,
            "error_code": self.error_code,
            "message": self.message,
            "context": self.context,
            "timestamp": self.timestamp.isoformat()
        }


class AuthenticationError(OPNsenseError):
    """Raised when authentication with OPNsense fails."""
    pass


class AuthorizationError(OPNsenseError):
    """Raised when user doesn't have permission for the requested operation."""
    pass


class ConnectionError(OPNsenseError):
    """Raised when connection to OPNsense cannot be established."""
    pass


class ConfigurationError(OPNsenseError):
    """Raised when OPNsense configuration is invalid or missing."""
    pass


class ValidationError(OPNsenseError):
    """Raised when input parameters are invalid."""
    pass


class APIError(OPNsenseError):
    """Raised when OPNsense API returns an error response."""

    def __init__(self, message: str, status_code: Optional[int] = None, response_data: Optional[Dict] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.status_code = status_code
        self.response_data = response_data or {}


class TimeoutError(OPNsenseError):
    """Raised when API request times out."""
    pass


class ResourceNotFoundError(OPNsenseError):
    """Raised when requested resource doesn't exist."""
    pass


class RateLimitError(OPNsenseError):
    """Raised when API rate limit is exceeded."""
    pass


# ========== ERROR RESPONSE SYSTEM ==========

class ErrorSeverity(str, Enum):
    """Enumeration for error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorResponse:
    """Structured error response system."""

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
        elif isinstance(self.error, ConnectionError):
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
            details["response_data"] = self.error.response_data

        return details


# ========== RETRY MECHANISM ==========

class RetryConfig:
    """Configuration for retry mechanism."""

    def __init__(self, max_attempts: int = 3, base_delay: float = 1.0, max_delay: float = 60.0,
                 exponential_backoff: bool = True, retryable_errors: Optional[List[type]] = None):
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_backoff = exponential_backoff
        self.retryable_errors = retryable_errors or [ConnectionError, TimeoutError, APIError]


async def retry_with_backoff(func, *args, retry_config: RetryConfig = None, **kwargs):
    """Retry function with exponential backoff."""
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

            # Calculate delay
            if retry_config.exponential_backoff:
                delay = min(retry_config.base_delay * (2 ** attempt), retry_config.max_delay)
            else:
                delay = retry_config.base_delay

            logger.info(f"Attempt {attempt + 1} failed, retrying in {delay}s: {str(e)}")
            await asyncio.sleep(delay)

    # All attempts failed
    raise last_exception


# ========== LOGGING FRAMEWORK ==========

class RequestResponseLogger:
    """Framework for logging API requests and responses."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def log_request(self, method: str, url: str, headers: Optional[Dict] = None,
                   data: Optional[Dict] = None, operation: str = "unknown"):
        """Log API request details."""
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
        """Log API response details."""
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


class OPNsenseConfig(TypedDict, total=False):
    """Configuration for OPNsense connection."""
    url: str
    api_key: str
    api_secret: str
    verify_ssl: bool


class OPNsenseClient:
    """Client for interacting with OPNsense API."""
    
    def __init__(self, config: OPNsenseConfig):
        """Initialize OPNsense API client.
        
        Args:
            config: Configuration for OPNsense connection
        """
        self.base_url = config["url"].rstrip("/")
        self.api_key = config["api_key"]
        self.api_secret = config["api_secret"]
        self.verify_ssl = config.get("verify_ssl", True)
        self.client = httpx.AsyncClient(verify=self.verify_ssl)
        
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
        """Make a request to the OPNsense API with enhanced error handling.

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
            AuthenticationError: For authentication failures (401)
            AuthorizationError: For authorization failures (403)
            ResourceNotFoundError: For not found errors (404)
            RateLimitError: For rate limit errors (429)
            APIError: For other HTTP errors
            ConnectionError: For network connection issues
            TimeoutError: For request timeouts
        """
        # Validate inputs
        if not method or not endpoint:
            raise ValidationError("Method and endpoint are required",
                                context={"method": method, "endpoint": endpoint})

        if method.upper() not in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
            raise ValidationError(f"Unsupported HTTP method: {method}",
                                context={"method": method})

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

                # Handle HTTP errors
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
                                       context={"status_code": 429, "endpoint": endpoint})
                elif not (200 <= response.status_code < 300):
                    request_logger.log_response(response.status_code, response_size, duration_ms, operation)
                    try:
                        error_data = response.json()
                    except:
                        error_data = {"error": response.text}

                    raise APIError(f"API error: {response.status_code}",
                                 status_code=response.status_code,
                                 response_data=error_data,
                                 context={"endpoint": endpoint})

                # Parse JSON response
                try:
                    result = response.json()
                    request_logger.log_response(response.status_code, response_size, duration_ms, operation)
                    return result
                except json.JSONDecodeError as e:
                    request_logger.log_response(response.status_code, response_size, duration_ms, operation, e)
                    raise APIError(f"Invalid JSON response from OPNsense API: {str(e)}",
                                 status_code=response.status_code,
                                 context={"endpoint": endpoint, "json_error": str(e)})

            except httpx.TimeoutException as e:
                duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
                request_logger.log_response(0, 0, duration_ms, operation, e)
                raise TimeoutError(f"Request timed out after {timeout}s",
                                 context={"timeout": timeout, "endpoint": endpoint})

            except httpx.ConnectError as e:
                duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
                request_logger.log_response(0, 0, duration_ms, operation, e)
                raise ConnectionError(f"Cannot connect to OPNsense at {self.base_url}",
                                    context={"base_url": self.base_url, "endpoint": endpoint, "error": str(e)})

            except httpx.RequestError as e:
                duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
                request_logger.log_response(0, 0, duration_ms, operation, e)
                raise ConnectionError(f"Network error: {str(e)}",
                                    context={"endpoint": endpoint, "error": str(e)})

        # Use retry mechanism if configured
        if retry_config:
            return await retry_with_backoff(_make_request, retry_config=retry_config)
        else:
            return await _make_request()


# Initialize MCP server
mcp = FastMCP("OPNsense MCP Server", description="Manage OPNsense firewalls via MCP")


# Set up global client instance that will be populated during initialization
opnsense_client: Optional[OPNsenseClient] = None


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


def check_client_configured() -> None:
    """Check if OPNsense client is configured.

    Raises:
        ConfigurationError: If client is not configured
    """
    if opnsense_client is None:
        raise ConfigurationError(
            "OPNsense connection not configured. Use configure_opnsense_connection first.",
            context={"required_action": "configure_connection"}
        )


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


def validate_firewall_parameters(action: str, interface: str, direction: str,
                               ipprotocol: str, protocol: str, operation: str) -> None:
    """Validate common firewall rule parameters.

    Args:
        action: Rule action (pass, block, reject)
        interface: Network interface
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
        check_client_configured()

        # Get all available modules first
        response = await opnsense_client.request("GET", API_CORE_MENU_GET_ITEMS, operation="get_api_endpoints")

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
    except Exception as e:
        return await handle_tool_error(ctx, "get_api_endpoints", e)


@mcp.tool(name="get_system_status", description="Get OPNsense system status")
async def get_system_status(ctx: Context) -> str:
    """Get OPNsense system status.

    Args:
        ctx: MCP context

    Returns:
        Formatted system status information
    """
    try:
        check_client_configured()

        # Get firmware status with retry for resilience
        retry_config = RetryConfig(max_attempts=2, base_delay=1.0)
        firmware = await opnsense_client.request("GET", API_CORE_FIRMWARE_STATUS,
                                                operation="get_firmware_status", retry_config=retry_config)

        # Get system information
        system_info = await opnsense_client.request("GET", API_CORE_SYSTEM_INFO,
                                                   operation="get_system_info")

        # Get service status
        services = await opnsense_client.request(
            "POST",
            API_CORE_SERVICE_SEARCH,
            data={"current": 1, "rowCount": -1, "searchPhrase": ""},
            operation="search_services"
        )

        # Format and return the combined status
        status = {
            "firmware": firmware,
            "system": system_info,
            "services": services.get("rows", [])
        }

        return json.dumps(status, indent=2)
    except Exception as e:
        return await handle_tool_error(ctx, "get_system_status", e)


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
    """Add a new firewall rule.
    
    Args:
        ctx: MCP context
        description: Rule description
        action: Rule action (pass, block, reject)
        interface: Network interface
        direction: Traffic direction (in, out)
        ipprotocol: IP protocol (inet for IPv4, inet6 for IPv6)
        protocol: Transport protocol (tcp, udp, any)
        source_net: Source network/host
        destination_net: Destination network/host
        destination_port: Destination port(s)
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
        logger.error(f"Error in firewall_add_rule: {str(e)}", exc_info=True)
        await ctx.error(f"Error adding firewall rule: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="firewall_delete_rule", description="Delete a firewall rule by UUID")
async def firewall_delete_rule(ctx: Context, uuid: str) -> str:
    """Delete a firewall rule by UUID.
    
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
            f"{API_FIREWALL_FILTER_DEL_RULE}/{uuid}"
        )
        
        # Apply changes
        await ctx.info("Rule deleted, applying changes...")
        apply_result = await opnsense_client.request(
            "POST",
            API_FIREWALL_FILTER_APPLY
        )
        
        return json.dumps({
            "delete_result": delete_result,
            "apply_result": apply_result
        }, indent=2)
    except Exception as e:
        logger.error(f"Error in firewall_delete_rule (uuid: {uuid}): {str(e)}", exc_info=True)
        await ctx.error(f"Error deleting firewall rule: {str(e)}")
        return f"Error: {str(e)}"


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


@mcp.tool(name="configure_opnsense_connection", description="Configure the OPNsense connection")
async def configure_opnsense_connection(
    ctx: Context,
    url: str,
    api_key: str,
    api_secret: str,
    verify_ssl: bool = True
) -> str:
    """Configure the OPNsense connection.
    
    Args:
        ctx: MCP context
        url: OPNsense base URL (e.g., "https://192.168.1.1")
        api_key: API key
        api_secret: API secret
        verify_ssl: Whether to verify SSL certificates
        
    Returns:
        Success message
    """
    global opnsense_client
    
    try:
        # Test the connection first
        config = OPNsenseConfig(
            url=url,
            api_key=api_key,
            api_secret=api_secret,
            verify_ssl=verify_ssl
        )
        
        test_client = OPNsenseClient(config)
        
        # Try to make a simple API call to verify connection
        await test_client.request("GET", API_CORE_FIRMWARE_STATUS)
        
        # If the above call succeeds, save the configuration
        if opnsense_client:
            await opnsense_client.close()
            
        opnsense_client = test_client
        
        return "OPNsense connection configured successfully"
    except Exception as e:
        logger.error(f"Error in configure_opnsense_connection (url: {url}): {str(e)}", exc_info=True)
        await ctx.error(f"Error configuring OPNsense connection: {str(e)}")
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


# Entry point
if __name__ == "__main__":
    mcp.run()