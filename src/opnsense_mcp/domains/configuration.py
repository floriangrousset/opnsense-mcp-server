"""
OPNsense MCP Server - Configuration Domain

This module provides tools for configuring the OPNsense connection and exploring
available API endpoints. It handles initial setup, authentication, and API discovery.
"""

import json
import logging

from mcp.server.fastmcp import Context

from ..core import (
    APIError,
    AuthenticationError,
    ConfigurationError,
    NetworkError,
    OPNsenseClient,
)
from ..core.config_loader import ConfigLoader
from ..main import mcp, server_state
from ..shared.constants import API_CORE_MENU_GET_ITEMS

logger = logging.getLogger("opnsense-mcp")


# ========== HELPER FUNCTIONS ==========


async def get_opnsense_client() -> OPNsenseClient:
    """Get OPNsense client from server state with validation."""
    return await server_state.get_client()


# ========== CONFIGURATION TOOLS ==========


@mcp.tool(
    name="configure_opnsense_connection",
    description="Configure OPNsense connection using locally stored credentials (secure - never sends credentials to LLM)",
)
async def configure_opnsense_connection(ctx: Context, profile: str = "default") -> str:
    """Configure the OPNsense connection using locally stored credentials.

    **SECURITY:** Credentials are loaded from local storage only and never sent to the LLM.
    This ensures your firewall credentials remain secure and private.

    **Setup Required:** Before using this tool, credentials must be configured using:
    1. CLI command: `opnsense-mcp setup` (recommended)
    2. Environment variables: OPNSENSE_URL, OPNSENSE_API_KEY, OPNSENSE_API_SECRET
    3. Config file: ~/.opnsense-mcp/config.json

    **Profile Support:** Multiple firewall profiles can be configured (default, production, staging, etc.)
    and selected by name. This enables managing multiple OPNsense instances securely.

    Args:
        ctx: MCP context
        profile: Profile name to load credentials from (default: "default")
                 Must be configured via 'opnsense-mcp setup --profile <name>'

    Returns:
        Success message with connection details (no credentials exposed)

    Examples:
        - "Configure OPNsense connection" → loads 'default' profile
        - "Configure OPNsense connection using profile production" → loads 'production' profile
        - "Connect to my staging OPNsense" → loads 'staging' profile
    """
    try:
        # Load configuration from secure local storage
        logger.info(f"Loading OPNsense configuration for profile: {profile}")
        config = ConfigLoader.load(profile)

        # Get non-sensitive profile info for logging
        profile_info = ConfigLoader.get_profile_info(profile)
        logger.info(f"Loaded profile '{profile}' - URL: {profile_info['url']}")

        # Initialize server state with loaded configuration
        await server_state.initialize(config)

        # Track current profile for credential rotation detection
        server_state._current_profile = profile

        await ctx.info(f"OPNsense connection configured successfully using profile '{profile}'")

        return (
            f"✅ OPNsense connection configured successfully!\n\n"
            f"Profile: {profile}\n"
            f"URL: {profile_info['url']}\n"
            f"SSL Verification: {'Enabled' if profile_info['verify_ssl'] else 'Disabled'}\n\n"
            f"🔒 Security: Credentials loaded from local storage (never exposed to LLM)\n"
            f"📍 Source: {ConfigLoader.DEFAULT_CONFIG_FILE}"
        )

    except ConfigurationError as e:
        error_msg = f"Configuration error: {e!s}"
        logger.error(error_msg, exc_info=True)
        await ctx.error(error_msg)

        # Provide helpful guidance
        return (
            f"❌ Configuration Error: {e!s}\n\n"
            f"📖 Setup Instructions:\n"
            f"1. Run: opnsense-mcp setup --profile {profile}\n"
            f"2. Or set environment variables: OPNSENSE_URL, OPNSENSE_API_KEY, OPNSENSE_API_SECRET\n"
            f"3. Or create config file: {ConfigLoader.DEFAULT_CONFIG_FILE}\n\n"
            f"💡 Tip: Use 'opnsense-mcp list-profiles' to see configured profiles"
        )

    except AuthenticationError as e:
        error_msg = f"Authentication failed: {e!s}"
        logger.error(error_msg, exc_info=True)
        await ctx.error(error_msg)
        return (
            f"❌ Authentication Error: {e!s}\n\n"
            f"The credentials for profile '{profile}' appear to be invalid.\n"
            f"Please verify:\n"
            f"• API key and secret are correct\n"
            f"• API user has necessary permissions\n\n"
            f"Run: opnsense-mcp setup --profile {profile} (to update credentials)"
        )

    except NetworkError as e:
        error_msg = f"Network error: {e!s}"
        logger.error(error_msg, exc_info=True)
        await ctx.error(error_msg)
        return (
            f"❌ Network Error: {e!s}\n\n"
            f"Could not reach OPNsense at the configured URL.\n"
            f"Please verify:\n"
            f"• OPNsense URL is correct and accessible\n"
            f"• Firewall is online and reachable\n"
            f"• Network connectivity is working\n\n"
            f"Run: opnsense-mcp test-connection --profile {profile} (to diagnose)"
        )

    except Exception as e:
        error_msg = f"Unexpected error configuring OPNsense connection: {e!s}"
        logger.error(f"Unexpected error for profile '{profile}': {e!s}", exc_info=True)
        await ctx.error(error_msg)
        return f"❌ Error: {e!s}"


@mcp.tool(name="get_api_endpoints", description="List available API endpoints from OPNsense")
async def get_api_endpoints(ctx: Context, module: str | None = None) -> str:
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
            available_modules = list(response.keys())
            return f"Module '{module}' not found. Available modules: {available_modules}"
        # Return all modules and endpoints
        return json.dumps(response, indent=2)

    except ConfigurationError as e:
        await ctx.error(str(e))
        return f"Configuration Error: {e!s}"
    except (AuthenticationError, NetworkError, APIError) as e:
        logger.error(f"Error in get_api_endpoints: {e!s}", exc_info=True)
        await ctx.error(f"Error fetching API endpoints: {e!s}")
        return f"Error: {e!s}"
    except Exception as e:
        logger.error(f"Unexpected error in get_api_endpoints: {e!s}", exc_info=True)
        await ctx.error(f"Unexpected error: {e!s}")
        return f"Error: {e!s}"
