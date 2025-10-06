"""
OPNsense MCP Server - API Client

This module provides the main client class for interacting with the OPNsense API.
"""

import base64
import json
import logging
import ssl
from datetime import datetime
from typing import Dict, Any, Optional, TYPE_CHECKING

import httpx
import certifi

from .models import OPNsenseConfig
from .retry import RetryConfig, retry_with_backoff
from .exceptions import (
    ValidationError,
    AuthenticationError,
    AuthorizationError,
    ResourceNotFoundError,
    RateLimitError,
    APIError,
    NetworkError,
    TimeoutError as OPNsenseTimeoutError
)

if TYPE_CHECKING:
    from .connection import ConnectionPool

logger = logging.getLogger("opnsense-mcp")


class RequestResponseLogger:
    """Framework for logging API requests and responses with sensitive data protection."""

    def __init__(self, logger: logging.Logger):
        """Initialize request/response logger.

        Args:
            logger: Logger instance to use for logging
        """
        self.logger = logger

    def log_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict] = None,
        data: Optional[Dict] = None,
        operation: str = "unknown"
    ):
        """Log API request details with sensitive data sanitization.

        Args:
            method: HTTP method
            url: Request URL
            headers: Request headers
            data: Request payload
            operation: Operation name for context
        """
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

    def log_response(
        self,
        status_code: int,
        response_size: Optional[int] = None,
        duration_ms: Optional[float] = None,
        operation: str = "unknown",
        error: Optional[Exception] = None
    ):
        """Log API response details with performance metrics.

        Args:
            status_code: HTTP status code
            response_size: Size of response in bytes
            duration_ms: Request duration in milliseconds
            operation: Operation name for context
            error: Exception if request failed
        """
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


class OPNsenseClient:
    """Client for interacting with OPNsense API."""

    def _create_ssl_context(self, verify_ssl: bool) -> ssl.SSLContext:
        """
        Create SSL context with security hardening.

        Args:
            verify_ssl: Whether to verify SSL certificates

        Returns:
            Configured SSL context

        Notes:
            - When verify_ssl=False, logs prominent security warning
            - When verify_ssl=True, enforces TLS 1.2+ and certificate validation
            - Uses certifi for up-to-date CA bundle
        """
        if not verify_ssl:
            logger.warning(
                "🔓 SSL CERTIFICATE VERIFICATION IS DISABLED! 🔓\n"
                "Connection is vulnerable to Man-in-the-Middle (MITM) attacks.\n"
                "This should ONLY be used in isolated lab environments.\n"
                "NEVER disable SSL verification in production or internet-facing deployments."
            )
            # Create context but disable verification
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return context

        # Production-grade SSL context
        context = ssl.create_default_context(cafile=certifi.where())
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        # Enforce TLS 1.2+ (disable older vulnerable protocols)
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        logger.debug("SSL verification enabled with TLS 1.2+ enforcement")
        return context

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

        # Create SSL context with security hardening
        ssl_context = self._create_ssl_context(self.verify_ssl)

        # Enhanced client configuration with secure SSL
        self.client = httpx.AsyncClient(
            verify=ssl_context if self.verify_ssl else False,
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

        logger.info(
            f"Initialized OPNsense client for {self.base_url} "
            f"(SSL verification: {'enabled' if self.verify_ssl else 'DISABLED'})"
        )

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
            OPNsenseTimeoutError: For request timeouts
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
                raise OPNsenseTimeoutError(f"Request timed out after {timeout}s",
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
