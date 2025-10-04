"""
OPNsense MCP Server - Configuration Domain

This module provides tools for configuring the OPNsense connection and exploring
available API endpoints. It handles initial setup, authentication, and API discovery.
"""

import json
import logging
from typing import Optional

from mcp.server.fastmcp import Context

from ..main import mcp, server_state
from ..core import (
    OPNsenseClient,
    OPNsenseConfig,
    ConfigurationError,
    AuthenticationError,
    NetworkError,
    APIError,
    ValidationError,
)
from ..shared.constants import API_CORE_MENU_GET_ITEMS

logger = logging.getLogger("opnsense-mcp")


# ========== HELPER FUNCTIONS ==========

async def get_opnsense_client() -> OPNsenseClient:
    """Get OPNsense client from server state with validation."""
    return await server_state.get_client()


# ========== CONFIGURATION TOOLS ==========

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
