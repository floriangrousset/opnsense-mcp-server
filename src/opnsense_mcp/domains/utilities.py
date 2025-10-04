"""Utilities domain for OPNsense MCP Server.

This module provides utility tools for advanced operations:
- Custom API call execution
- Low-level API access
"""

import json
import logging
from typing import Optional

from fastmcp import Context
from ..core.client import get_opnsense_client
from ..core.mcp_server import mcp

# Configure logging
logger = logging.getLogger(__name__)


@mcp.tool(name="exec_api_call", description="Execute a custom API call to OPNsense")
async def exec_api_call(
    ctx: Context,
    method: str,
    endpoint: str,
    data: Optional[str] = None,
    params: Optional[str] = None
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
    client = get_opnsense_client()
    if not client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        # Parse JSON strings if provided
        data_dict = json.loads(data) if data else None
        params_dict = json.loads(params) if params else None

        # Execute the API request
        response = await client.request(
            method,
            endpoint,
            data=data_dict,
            params=params_dict
        )

        return json.dumps(response, indent=2)
    except json.JSONDecodeError as e:
        error_msg = f"Invalid JSON in {'data' if data and not data_dict else 'params'}: {str(e)}"
        logger.error(f"Error in exec_api_call: {error_msg}")
        await ctx.error(error_msg)
        return f"Error: {error_msg}"
    except Exception as e:
        logger.error(f"Error in exec_api_call (method: {method}, endpoint: {endpoint}): {str(e)}", exc_info=True)
        await ctx.error(f"Error executing API call: {str(e)}")
        return f"Error: {str(e)}"
