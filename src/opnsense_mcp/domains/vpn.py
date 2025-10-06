"""VPN management domain for OPNsense MCP Server.

This module provides tools for managing VPN connections including:
- OpenVPN
- IPsec
- WireGuard
"""

import json
import logging

from mcp.server.fastmcp import Context

from ..main import mcp
from .configuration import get_opnsense_client

# Configure logging
logger = logging.getLogger(__name__)

# API Constants
API_OPENVPN_SERVICE_STATUS = "/openvpn/service/getStatus"
API_IPSEC_SERVICE_STATUS = "/ipsec/service/status"
API_WIREGUARD_SERVICE_SHOW = "/wireguard/service/show"


@mcp.tool(name="get_vpn_connections", description="Get VPN connection status")
async def get_vpn_connections(ctx: Context, vpn_type: str = "OpenVPN") -> str:
    """Get VPN connection status.

    Retrieves current status and connection information for VPN services
    including OpenVPN, IPsec, and WireGuard.

    Args:
        ctx: MCP context
        vpn_type: Type of VPN to query. Options:
            - "OpenVPN" (default)
            - "IPsec"
            - "WireGuard"

    Returns:
        JSON string containing VPN connection status information including:
        - Active connections
        - Connection state
        - Client information
        - Traffic statistics

    Example:
        >>> await get_vpn_connections(ctx, "OpenVPN")
        {
          "connections": [...],
          "status": "active"
        }
    """
    client = await get_opnsense_client()
    if not client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        if vpn_type.lower() == "openvpn":
            response = await client.request("GET", API_OPENVPN_SERVICE_STATUS)
        elif vpn_type.lower() == "ipsec":
            response = await client.request("GET", API_IPSEC_SERVICE_STATUS)
        elif vpn_type.lower() == "wireguard":
            response = await client.request("GET", API_WIREGUARD_SERVICE_SHOW)
        else:
            return f"Unsupported VPN type: {vpn_type}. Supported types: OpenVPN, IPsec, WireGuard"

        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in get_vpn_connections (type: {vpn_type}): {e!s}", exc_info=True)
        await ctx.error(f"Error fetching VPN connections: {e!s}")
        return f"Error: {e!s}"
