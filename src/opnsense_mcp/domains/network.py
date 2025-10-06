"""
OPNsense MCP Server - Network Domain

This module provides comprehensive network interface management tools for OPNsense,
including physical interfaces, VLANs, bridges, link aggregation (LAGG), and virtual IPs.

The Network domain enables management of:
- Interface Information: Get interface details, status, and configuration
- VLAN Management: Create and manage 802.1Q VLAN interfaces
- Bridge Management: Configure layer-2 bridges with STP support
- LAGG Management: Set up link aggregation for redundancy and performance
- Virtual IP Management: Configure CARP, proxy ARP, and other virtual IPs

All configuration changes trigger automatic reconfiguration to apply settings immediately.
"""

import json
import logging
import re

from mcp.server.fastmcp import Context

from ..main import mcp
from ..shared.constants import (
    # DHCP Leases
    API_DHCP_LEASES_SEARCH,
    API_INTERFACES_BRIDGE_ADD,
    API_INTERFACES_BRIDGE_DEL,
    API_INTERFACES_BRIDGE_GET,
    API_INTERFACES_BRIDGE_RECONFIGURE,
    # Bridge Management
    API_INTERFACES_BRIDGE_SEARCH,
    API_INTERFACES_BRIDGE_SET,
    API_INTERFACES_LAGG_ADD,
    API_INTERFACES_LAGG_DEL,
    API_INTERFACES_LAGG_GET,
    API_INTERFACES_LAGG_RECONFIGURE,
    # LAGG Management
    API_INTERFACES_LAGG_SEARCH,
    API_INTERFACES_LAGG_SET,
    API_INTERFACES_OVERVIEW_EXPORT,
    API_INTERFACES_OVERVIEW_GET_INTERFACE,
    # Interface Overview
    API_INTERFACES_OVERVIEW_INFO,
    API_INTERFACES_OVERVIEW_RELOAD_INTERFACE,
    API_INTERFACES_VIP_ADD,
    API_INTERFACES_VIP_DEL,
    API_INTERFACES_VIP_GET,
    API_INTERFACES_VIP_GET_UNUSED_VHID,
    API_INTERFACES_VIP_RECONFIGURE,
    # Virtual IP Management
    API_INTERFACES_VIP_SEARCH,
    API_INTERFACES_VIP_SET,
    API_INTERFACES_VLAN_ADD,
    API_INTERFACES_VLAN_DEL,
    API_INTERFACES_VLAN_GET,
    API_INTERFACES_VLAN_RECONFIGURE,
    # VLAN Management
    API_INTERFACES_VLAN_SEARCH,
    API_INTERFACES_VLAN_SET,
)
from ..shared.error_handlers import handle_tool_error
from .configuration import get_opnsense_client

logger = logging.getLogger("opnsense-mcp")


# ========== HELPER FUNCTIONS ==========


def is_valid_uuid(uuid: str) -> bool:
    """Validate UUID format.

    Args:
        uuid: UUID string to validate

    Returns:
        True if valid UUID format, False otherwise
    """
    uuid_pattern = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
    )
    return bool(uuid_pattern.match(uuid))


# ========== INTERFACE MANAGEMENT ==========


@mcp.tool(name="get_interfaces", description="Get network interfaces")
async def get_interfaces(ctx: Context) -> str:
    """Get network interfaces.

    Args:
        ctx: MCP context

    Returns:
        JSON string of network interfaces
    """
    try:
        client = await get_opnsense_client()
        response = await client.request("GET", API_INTERFACES_OVERVIEW_INFO)
        return json.dumps(response, indent=2)
    except Exception as e:
        return await handle_tool_error(ctx, "get_interfaces", e)


@mcp.tool(name="get_dhcp_leases", description="Get DHCP leases")
async def get_dhcp_leases(ctx: Context) -> str:
    """Get DHCP leases.

    Args:
        ctx: MCP context

    Returns:
        JSON string of DHCP leases
    """
    try:
        client = await get_opnsense_client()
        response = await client.request("GET", API_DHCP_LEASES_SEARCH)
        return json.dumps(response, indent=2)
    except Exception as e:
        return await handle_tool_error(ctx, "get_dhcp_leases", e)


@mcp.tool(
    name="get_interface_details", description="Get detailed information for a specific interface"
)
async def get_interface_details(ctx: Context, interface: str) -> str:
    """Get detailed information for a specific interface.

    Args:
        ctx: MCP context
        interface: Interface identifier (e.g., 'lan', 'wan', 'opt1')

    Returns:
        JSON string of interface details
    """
    if not interface:
        return json.dumps({"error": "Interface identifier is required"}, indent=2)

    try:
        client = await get_opnsense_client()
        response = await client.request(
            "GET",
            f"{API_INTERFACES_OVERVIEW_GET_INTERFACE}/{interface}",
            operation=f"get_interface_details_{interface}",
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_interface_details", e)


@mcp.tool(name="reload_interface", description="Reload configuration for a specific interface")
async def reload_interface(ctx: Context, interface: str) -> str:
    """Reload configuration for a specific interface.

    Args:
        ctx: MCP context
        interface: Interface identifier to reload

    Returns:
        JSON string of operation result
    """
    if not interface:
        return json.dumps({"error": "Interface identifier is required"}, indent=2)

    try:
        client = await get_opnsense_client()
        response = await client.request(
            "GET",
            f"{API_INTERFACES_OVERVIEW_RELOAD_INTERFACE}/{interface}",
            operation=f"reload_interface_{interface}",
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "reload_interface", e)


@mcp.tool(name="export_interface_config", description="Export interface configuration")
async def export_interface_config(ctx: Context) -> str:
    """Export current interface configuration.

    Returns:
        JSON string of interface configuration export
    """
    try:
        client = await get_opnsense_client()
        response = await client.request(
            "GET", API_INTERFACES_OVERVIEW_EXPORT, operation="export_interface_config"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "export_interface_config", e)


# ========== VLAN MANAGEMENT ==========


@mcp.tool(name="list_vlan_interfaces", description="List all VLAN interfaces")
async def list_vlan_interfaces(ctx: Context, search_phrase: str = "") -> str:
    """List all VLAN interfaces with optional search filtering.

    Args:
        ctx: MCP context
        search_phrase: Optional search phrase to filter VLANs

    Returns:
        JSON string of VLAN interfaces
    """
    try:
        client = await get_opnsense_client()
        params = {}
        if search_phrase:
            params["searchPhrase"] = search_phrase

        response = await client.request(
            "POST", API_INTERFACES_VLAN_SEARCH, data=params, operation="list_vlan_interfaces"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "list_vlan_interfaces", e)


@mcp.tool(name="get_vlan_interface", description="Get VLAN interface configuration")
async def get_vlan_interface(ctx: Context, uuid: str) -> str:
    """Get specific VLAN interface configuration by UUID.

    Args:
        ctx: MCP context
        uuid: UUID of the VLAN interface

    Returns:
        JSON string of VLAN interface configuration
    """
    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        client = await get_opnsense_client()
        response = await client.request(
            "GET", f"{API_INTERFACES_VLAN_GET}/{uuid}", operation=f"get_vlan_interface_{uuid[:8]}"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_vlan_interface", e)


@mcp.tool(name="create_vlan_interface", description="Create a new VLAN interface")
async def create_vlan_interface(
    ctx: Context, parent_interface: str, vlan_tag: int, description: str = ""
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
    if not all([parent_interface, vlan_tag]):
        return json.dumps({"error": "Parent interface and VLAN tag are required"}, indent=2)

    # Validate VLAN tag range
    if not (1 <= vlan_tag <= 4094):
        return json.dumps({"error": "VLAN tag must be between 1 and 4094"}, indent=2)

    try:
        client = await get_opnsense_client()
        vlan_data = {"if": parent_interface, "tag": str(vlan_tag), "descr": description}

        response = await client.request(
            "POST",
            API_INTERFACES_VLAN_ADD,
            data={"vlan": vlan_data},
            operation="create_vlan_interface",
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await client.request(
                "POST", API_INTERFACES_VLAN_RECONFIGURE, operation="apply_vlan_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "create_vlan_interface", e)


@mcp.tool(name="update_vlan_interface", description="Update VLAN interface configuration")
async def update_vlan_interface(
    ctx: Context, uuid: str, parent_interface: str = "", vlan_tag: int = 0, description: str = ""
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
    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    # Validate VLAN tag if provided
    if vlan_tag > 0 and not (1 <= vlan_tag <= 4094):
        return json.dumps({"error": "VLAN tag must be between 1 and 4094"}, indent=2)

    try:
        client = await get_opnsense_client()
        # Get current VLAN configuration
        current = await client.request(
            "GET", f"{API_INTERFACES_VLAN_GET}/{uuid}", operation=f"get_current_vlan_{uuid[:8]}"
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

        response = await client.request(
            "POST",
            f"{API_INTERFACES_VLAN_SET}/{uuid}",
            data={"vlan": vlan_data},
            operation=f"update_vlan_interface_{uuid[:8]}",
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await client.request(
                "POST", API_INTERFACES_VLAN_RECONFIGURE, operation="apply_vlan_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "update_vlan_interface", e)


@mcp.tool(name="delete_vlan_interface", description="Delete a VLAN interface")
async def delete_vlan_interface(ctx: Context, uuid: str) -> str:
    """Delete a VLAN interface by UUID.

    Args:
        ctx: MCP context
        uuid: UUID of the VLAN interface to delete

    Returns:
        JSON string of operation result
    """
    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        client = await get_opnsense_client()
        response = await client.request(
            "POST",
            f"{API_INTERFACES_VLAN_DEL}/{uuid}",
            operation=f"delete_vlan_interface_{uuid[:8]}",
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await client.request(
                "POST", API_INTERFACES_VLAN_RECONFIGURE, operation="apply_vlan_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "delete_vlan_interface", e)


# ========== BRIDGE MANAGEMENT ==========


@mcp.tool(name="list_bridge_interfaces", description="List all bridge interfaces")
async def list_bridge_interfaces(ctx: Context, search_phrase: str = "") -> str:
    """List all bridge interfaces with optional search filtering.

    Args:
        ctx: MCP context
        search_phrase: Optional search phrase to filter bridges

    Returns:
        JSON string of bridge interfaces
    """
    try:
        client = await get_opnsense_client()
        params = {}
        if search_phrase:
            params["searchPhrase"] = search_phrase

        response = await client.request(
            "POST", API_INTERFACES_BRIDGE_SEARCH, data=params, operation="list_bridge_interfaces"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "list_bridge_interfaces", e)


@mcp.tool(name="get_bridge_interface", description="Get bridge interface configuration")
async def get_bridge_interface(ctx: Context, uuid: str) -> str:
    """Get specific bridge interface configuration by UUID.

    Args:
        ctx: MCP context
        uuid: UUID of the bridge interface

    Returns:
        JSON string of bridge interface configuration
    """
    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        client = await get_opnsense_client()
        response = await client.request(
            "GET",
            f"{API_INTERFACES_BRIDGE_GET}/{uuid}",
            operation=f"get_bridge_interface_{uuid[:8]}",
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_bridge_interface", e)


@mcp.tool(name="create_bridge_interface", description="Create a new bridge interface")
async def create_bridge_interface(
    ctx: Context, description: str, member_interfaces: str = "", stp_enabled: bool = False
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
    if not description:
        return json.dumps({"error": "Description is required"}, indent=2)

    try:
        client = await get_opnsense_client()
        bridge_data = {"descr": description, "stp": "1" if stp_enabled else "0"}

        if member_interfaces:
            bridge_data["members"] = member_interfaces

        response = await client.request(
            "POST",
            API_INTERFACES_BRIDGE_ADD,
            data={"bridge": bridge_data},
            operation="create_bridge_interface",
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await client.request(
                "POST", API_INTERFACES_BRIDGE_RECONFIGURE, operation="apply_bridge_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "create_bridge_interface", e)


@mcp.tool(name="update_bridge_interface", description="Update bridge interface configuration")
async def update_bridge_interface(
    ctx: Context,
    uuid: str,
    description: str = "",
    member_interfaces: str = "",
    stp_enabled: bool = None,
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
    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        client = await get_opnsense_client()
        # Get current bridge configuration
        current = await client.request(
            "GET", f"{API_INTERFACES_BRIDGE_GET}/{uuid}", operation=f"get_current_bridge_{uuid[:8]}"
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

        response = await client.request(
            "POST",
            f"{API_INTERFACES_BRIDGE_SET}/{uuid}",
            data={"bridge": bridge_data},
            operation=f"update_bridge_interface_{uuid[:8]}",
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await client.request(
                "POST", API_INTERFACES_BRIDGE_RECONFIGURE, operation="apply_bridge_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "update_bridge_interface", e)


@mcp.tool(name="delete_bridge_interface", description="Delete a bridge interface")
async def delete_bridge_interface(ctx: Context, uuid: str) -> str:
    """Delete a bridge interface by UUID.

    Args:
        ctx: MCP context
        uuid: UUID of the bridge interface to delete

    Returns:
        JSON string of operation result
    """
    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        client = await get_opnsense_client()
        response = await client.request(
            "POST",
            f"{API_INTERFACES_BRIDGE_DEL}/{uuid}",
            operation=f"delete_bridge_interface_{uuid[:8]}",
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await client.request(
                "POST", API_INTERFACES_BRIDGE_RECONFIGURE, operation="apply_bridge_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "delete_bridge_interface", e)


# ========== LAGG (LINK AGGREGATION) MANAGEMENT ==========


@mcp.tool(name="list_lagg_interfaces", description="List all LAGG (Link Aggregation) interfaces")
async def list_lagg_interfaces(ctx: Context, search_phrase: str = "") -> str:
    """List all LAGG interfaces with optional search filtering.

    Args:
        ctx: MCP context
        search_phrase: Optional search phrase to filter LAGG interfaces

    Returns:
        JSON string of LAGG interfaces
    """
    try:
        client = await get_opnsense_client()
        params = {}
        if search_phrase:
            params["searchPhrase"] = search_phrase

        response = await client.request(
            "POST", API_INTERFACES_LAGG_SEARCH, data=params, operation="list_lagg_interfaces"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "list_lagg_interfaces", e)


@mcp.tool(name="get_lagg_interface", description="Get LAGG interface configuration")
async def get_lagg_interface(ctx: Context, uuid: str) -> str:
    """Get specific LAGG interface configuration by UUID.

    Args:
        ctx: MCP context
        uuid: UUID of the LAGG interface

    Returns:
        JSON string of LAGG interface configuration
    """
    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        client = await get_opnsense_client()
        response = await client.request(
            "GET", f"{API_INTERFACES_LAGG_GET}/{uuid}", operation=f"get_lagg_interface_{uuid[:8]}"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_lagg_interface", e)


@mcp.tool(
    name="create_lagg_interface", description="Create a new LAGG (Link Aggregation) interface"
)
async def create_lagg_interface(
    ctx: Context, description: str, parent_interfaces: str, protocol: str = "lacp"
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
    if not all([description, parent_interfaces]):
        return json.dumps({"error": "Description and parent interfaces are required"}, indent=2)

    # Validate protocol
    valid_protocols = ["lacp", "failover", "loadbalance", "roundrobin"]
    if protocol not in valid_protocols:
        return json.dumps(
            {"error": f"Protocol must be one of: {', '.join(valid_protocols)}"}, indent=2
        )

    try:
        client = await get_opnsense_client()
        lagg_data = {"descr": description, "members": parent_interfaces, "proto": protocol}

        response = await client.request(
            "POST",
            API_INTERFACES_LAGG_ADD,
            data={"lagg": lagg_data},
            operation="create_lagg_interface",
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await client.request(
                "POST", API_INTERFACES_LAGG_RECONFIGURE, operation="apply_lagg_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "create_lagg_interface", e)


@mcp.tool(name="update_lagg_interface", description="Update LAGG interface configuration")
async def update_lagg_interface(
    ctx: Context, uuid: str, description: str = "", parent_interfaces: str = "", protocol: str = ""
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
    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    # Validate protocol if provided
    if protocol:
        valid_protocols = ["lacp", "failover", "loadbalance", "roundrobin"]
        if protocol not in valid_protocols:
            return json.dumps(
                {"error": f"Protocol must be one of: {', '.join(valid_protocols)}"}, indent=2
            )

    try:
        client = await get_opnsense_client()
        # Get current LAGG configuration
        current = await client.request(
            "GET", f"{API_INTERFACES_LAGG_GET}/{uuid}", operation=f"get_current_lagg_{uuid[:8]}"
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

        response = await client.request(
            "POST",
            f"{API_INTERFACES_LAGG_SET}/{uuid}",
            data={"lagg": lagg_data},
            operation=f"update_lagg_interface_{uuid[:8]}",
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await client.request(
                "POST", API_INTERFACES_LAGG_RECONFIGURE, operation="apply_lagg_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "update_lagg_interface", e)


@mcp.tool(name="delete_lagg_interface", description="Delete a LAGG interface")
async def delete_lagg_interface(ctx: Context, uuid: str) -> str:
    """Delete a LAGG interface by UUID.

    Args:
        ctx: MCP context
        uuid: UUID of the LAGG interface to delete

    Returns:
        JSON string of operation result
    """
    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        client = await get_opnsense_client()
        response = await client.request(
            "POST",
            f"{API_INTERFACES_LAGG_DEL}/{uuid}",
            operation=f"delete_lagg_interface_{uuid[:8]}",
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await client.request(
                "POST", API_INTERFACES_LAGG_RECONFIGURE, operation="apply_lagg_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "delete_lagg_interface", e)


# ========== VIRTUAL IP MANAGEMENT ==========


@mcp.tool(name="list_virtual_ips", description="List all virtual IP addresses")
async def list_virtual_ips(ctx: Context, search_phrase: str = "") -> str:
    """List all virtual IP addresses with optional search filtering.

    Args:
        ctx: MCP context
        search_phrase: Optional search phrase to filter virtual IPs

    Returns:
        JSON string of virtual IP addresses
    """
    try:
        client = await get_opnsense_client()
        params = {}
        if search_phrase:
            params["searchPhrase"] = search_phrase

        response = await client.request(
            "POST", API_INTERFACES_VIP_SEARCH, data=params, operation="list_virtual_ips"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "list_virtual_ips", e)


@mcp.tool(name="get_virtual_ip", description="Get virtual IP configuration")
async def get_virtual_ip(ctx: Context, uuid: str) -> str:
    """Get specific virtual IP configuration by UUID.

    Args:
        ctx: MCP context
        uuid: UUID of the virtual IP

    Returns:
        JSON string of virtual IP configuration
    """
    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        client = await get_opnsense_client()
        response = await client.request(
            "GET", f"{API_INTERFACES_VIP_GET}/{uuid}", operation=f"get_virtual_ip_{uuid[:8]}"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_virtual_ip", e)


@mcp.tool(name="create_virtual_ip", description="Create a new virtual IP address")
async def create_virtual_ip(
    ctx: Context,
    interface: str,
    subnet: str,
    vip_type: str = "single",
    description: str = "",
    vhid: int = 0,
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
    if not all([interface, subnet]):
        return json.dumps({"error": "Interface and subnet are required"}, indent=2)

    # Validate VIP type
    valid_types = ["single", "carp", "proxyarp", "other"]
    if vip_type not in valid_types:
        return json.dumps({"error": f"VIP type must be one of: {', '.join(valid_types)}"}, indent=2)

    try:
        client = await get_opnsense_client()
        vip_data = {
            "interface": interface,
            "subnet": subnet,
            "type": vip_type,
            "descr": description,
        }

        # Add VHID for CARP type
        if vip_type == "carp":
            if vhid <= 0:
                # Get an unused VHID automatically
                try:
                    vhid_response = await client.request(
                        "GET", API_INTERFACES_VIP_GET_UNUSED_VHID, operation="get_unused_vhid"
                    )
                    if vhid_response and "vhid" in vhid_response:
                        vhid = vhid_response["vhid"]
                    else:
                        vhid = 1  # Default fallback
                except:
                    vhid = 1  # Default fallback

            vip_data["vhid"] = str(vhid)

        response = await client.request(
            "POST", API_INTERFACES_VIP_ADD, data={"vip": vip_data}, operation="create_virtual_ip"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await client.request(
                "POST", API_INTERFACES_VIP_RECONFIGURE, operation="apply_vip_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "create_virtual_ip", e)


@mcp.tool(name="update_virtual_ip", description="Update virtual IP configuration")
async def update_virtual_ip(
    ctx: Context,
    uuid: str,
    interface: str = "",
    subnet: str = "",
    vip_type: str = "",
    description: str = "",
    vhid: int = 0,
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
    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    # Validate VIP type if provided
    if vip_type:
        valid_types = ["single", "carp", "proxyarp", "other"]
        if vip_type not in valid_types:
            return json.dumps(
                {"error": f"VIP type must be one of: {', '.join(valid_types)}"}, indent=2
            )

    try:
        client = await get_opnsense_client()
        # Get current virtual IP configuration
        current = await client.request(
            "GET", f"{API_INTERFACES_VIP_GET}/{uuid}", operation=f"get_current_vip_{uuid[:8]}"
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

        response = await client.request(
            "POST",
            f"{API_INTERFACES_VIP_SET}/{uuid}",
            data={"vip": vip_data},
            operation=f"update_virtual_ip_{uuid[:8]}",
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await client.request(
                "POST", API_INTERFACES_VIP_RECONFIGURE, operation="apply_vip_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "update_virtual_ip", e)


@mcp.tool(name="delete_virtual_ip", description="Delete a virtual IP address")
async def delete_virtual_ip(ctx: Context, uuid: str) -> str:
    """Delete a virtual IP address by UUID.

    Args:
        ctx: MCP context
        uuid: UUID of the virtual IP to delete

    Returns:
        JSON string of operation result
    """
    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        client = await get_opnsense_client()
        response = await client.request(
            "POST", f"{API_INTERFACES_VIP_DEL}/{uuid}", operation=f"delete_virtual_ip_{uuid[:8]}"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await client.request(
                "POST", API_INTERFACES_VIP_RECONFIGURE, operation="apply_vip_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "delete_virtual_ip", e)


@mcp.tool(name="get_unused_vhid", description="Get an unused VHID for CARP configuration")
async def get_unused_vhid(ctx: Context) -> str:
    """Get an unused VHID (Virtual Host ID) for CARP configuration.

    Returns:
        JSON string with unused VHID
    """
    try:
        client = await get_opnsense_client()
        response = await client.request(
            "GET", API_INTERFACES_VIP_GET_UNUSED_VHID, operation="get_unused_vhid"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_unused_vhid", e)
