"""Utilities domain for OPNsense MCP Server.

This module provides utility tools for advanced operations:
- Custom API call execution
- Low-level API access
"""

import json
import logging

from mcp.server.fastmcp import Context

from ..core.exceptions import ValidationError
from ..main import mcp
from ..shared.constants import DANGEROUS_ENDPOINTS, SAFE_ENDPOINTS_PATTERNS
from ..shared.error_sanitizer import log_error_safely
from .configuration import get_opnsense_client

# Configure logging
logger = logging.getLogger(__name__)


def validate_endpoint_safety(endpoint: str, method: str) -> None:
    """
    Validate API endpoint for safety before execution.

    Prevents accidental execution of dangerous endpoints that could cause:
    - System reboots/poweroff
    - Factory resets
    - Bulk deletions
    - Irreversible configuration changes

    Args:
        endpoint: API endpoint path to validate
        method: HTTP method (GET, POST, etc.)

    Raises:
        ValidationError: If endpoint is classified as dangerous

    Notes:
        - CRITICAL endpoints are always blocked
        - HIGH/MEDIUM endpoints are blocked for POST/PUT/DELETE methods
        - Read-only operations (GET) are generally allowed
        - Use dedicated tools for dangerous operations instead
    """
    # Normalize endpoint (remove /api prefix if present, ensure starts with /)
    normalized = endpoint
    if normalized.startswith("/api/"):
        normalized = normalized[4:]  # Remove "/api" prefix
    if not normalized.startswith("/"):
        normalized = "/" + normalized

    # Check if endpoint matches safe patterns (read-only operations)
    if method.upper() == "GET":
        for pattern in SAFE_ENDPOINTS_PATTERNS:
            if pattern in normalized:
                return  # Safe read-only operation

    # Check against dangerous endpoints
    for dangerous_endpoint, risk_level in DANGEROUS_ENDPOINTS.items():
        if normalized.startswith(dangerous_endpoint) or dangerous_endpoint in normalized:
            # CRITICAL endpoints are never allowed
            if risk_level == "CRITICAL":
                raise ValidationError(
                    f"Endpoint '{endpoint}' is classified as {risk_level} risk and cannot "
                    f"be called via exec_api_call. This endpoint performs irreversible "
                    f"system-wide changes. Use OPNsense web interface for this operation.",
                    context={
                        "endpoint": endpoint,
                        "risk_level": risk_level,
                        "reason": "Prevents accidental system-wide destructive actions",
                    },
                )

            # HIGH/MEDIUM endpoints are blocked for write operations
            if method.upper() in ["POST", "PUT", "DELETE", "PATCH"]:
                raise ValidationError(
                    f"Endpoint '{endpoint}' is classified as {risk_level} risk and cannot "
                    f"be called with {method} via exec_api_call. Use dedicated MCP tools "
                    f"for this operation (e.g., firewall_delete_rule, delete_user, etc.).",
                    context={
                        "endpoint": endpoint,
                        "method": method,
                        "risk_level": risk_level,
                        "reason": "Prevents accidental destructive operations",
                    },
                )

    # Warn about write operations to unknown endpoints
    if method.upper() in ["POST", "PUT", "DELETE", "PATCH"]:
        logger.warning(
            f"Executing {method} to unclassified endpoint {endpoint}. "
            f"This may modify firewall configuration. Use with caution."
        )


@mcp.tool(
    name="exec_api_call",
    description="Execute a custom API call to OPNsense. ⚠️ ADVANCED: Use with caution",
)
async def exec_api_call(
    ctx: Context,
    method: str,
    endpoint: str,
    data: str | None = None,
    params: str | None = None,
) -> str:
    """Execute a custom API call to OPNsense.

    Provides direct access to any OPNsense API endpoint for advanced use cases
    not covered by specific tools. This is a power-user tool that allows calling
    any API endpoint with custom parameters.

    Args:
        ctx: MCP context
        method: HTTP method to use. Options:
            - "GET": Retrieve data
            - "POST": Submit data or trigger actions
        endpoint: API endpoint path (e.g., "/core/firmware/status")
            - Must start with "/"
            - Example: "/api/firewall/filter/searchRule"
        data: JSON string of POST data (optional)
            - Only used with POST requests
            - Must be valid JSON
            - Example: '{"enabled": "1", "action": "pass"}'
        params: JSON string of query parameters for GET (optional)
            - Used for filtering or pagination
            - Must be valid JSON
            - Example: '{"current": 1, "rowCount": 100}'

    Returns:
        JSON string containing the API response

    Example:
        >>> # Get firmware status
        >>> await exec_api_call(ctx, "GET", "/core/firmware/status")

        >>> # Search firewall rules with pagination
        >>> await exec_api_call(
        ...     ctx,
        ...     "POST",
        ...     "/api/firewall/filter/searchRule",
        ...     data='{"current": 1, "rowCount": 100}'
        ... )

        >>> # Get system information with parameters
        >>> await exec_api_call(
        ...     ctx,
        ...     "GET",
        ...     "/api/core/system/status",
        ...     params='{"detailed": true}'
        ... )

    Notes:
        - Use with caution - this provides direct API access
        - Invalid endpoints will return error responses
        - Some endpoints require specific POST data formats
        - Refer to OPNsense API documentation for endpoint details
    """
    try:
        client = await get_opnsense_client()
    except Exception:
        return "OPNsense client not initialized. Please configure the server first."

    if not client:
        return "OPNsense client not initialized. Please configure the server first."

    # Validate endpoint safety before execution
    try:
        validate_endpoint_safety(endpoint, method)
    except ValidationError as e:
        error_msg = f"Safety validation failed: {e.message}"
        logger.warning(f"Blocked dangerous endpoint: {endpoint} ({method})")
        await ctx.error(error_msg)
        return f"Error: {error_msg}"

    data_dict = None
    params_dict = None
    try:
        # Parse JSON strings if provided
        data_dict = json.loads(data) if data else None
        params_dict = json.loads(params) if params else None

        # Execute the API request
        response = await client.request(method, endpoint, data=data_dict, params=params_dict)

        return json.dumps(response, indent=2)
    except json.JSONDecodeError as e:
        # Determine which parameter caused the error
        failed_param = "data" if (data and data_dict is None) else "params"
        error_msg = f"Invalid JSON in {failed_param}: {e!s}"
        logger.error(f"Error in exec_api_call: {error_msg}")
        await ctx.error(error_msg)
        return f"Error: {error_msg}"
    except Exception as e:
        # Use error sanitizer for safe error messages
        safe_msg = log_error_safely(logger, e, "exec_api_call")
        await ctx.error(safe_msg)
        return f"Error: {safe_msg}"
