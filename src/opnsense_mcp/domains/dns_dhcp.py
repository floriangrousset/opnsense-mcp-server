"""
DNS & DHCP Management Domain

This module provides comprehensive network services management for DHCP server
configuration and DNS resolution services in OPNsense.

Features:
- DHCP server management (per-interface configuration)
- DHCP static mappings (MAC-to-IP reservations)
- DHCP lease monitoring and statistics
- DNS Resolver (Unbound) configuration and host/domain overrides
- DNS Forwarder (dnsmasq) configuration and host management
- Automatic service reconfiguration after changes
"""

import json
import re
from typing import Optional

from mcp.server.fastmcp import Context
from ..main import mcp
from .configuration import get_opnsense_client
from ..shared.error_handlers import handle_tool_error, validate_uuid
from ..shared.constants import (
    # DHCP Server
    API_DHCP_SERVER_SEARCH,
    API_DHCP_SERVER_GET,
    API_DHCP_SERVER_SET,
    API_DHCP_SERVICE_RESTART,
    API_DHCP_SERVICE_RECONFIGURE,

    # DHCP Static Mappings
    API_DHCP_STATIC_SEARCH,
    API_DHCP_STATIC_GET,
    API_DHCP_STATIC_ADD,
    API_DHCP_STATIC_SET,
    API_DHCP_STATIC_DEL,

    # DHCP Leases
    API_DHCP_LEASES_SEARCH,

    # DNS Resolver (Unbound)
    API_DNS_RESOLVER_SETTINGS,
    API_DNS_RESOLVER_SET_SETTINGS,
    API_DNS_RESOLVER_SERVICE_RESTART,
    API_DNS_RESOLVER_SERVICE_RECONFIGURE,
    API_DNS_RESOLVER_HOST_SEARCH,
    API_DNS_RESOLVER_HOST_GET,
    API_DNS_RESOLVER_HOST_ADD,
    API_DNS_RESOLVER_HOST_SET,
    API_DNS_RESOLVER_HOST_DEL,
    API_DNS_RESOLVER_DOMAIN_SEARCH,
    API_DNS_RESOLVER_DOMAIN_ADD,

    # DNS Forwarder (dnsmasq)
    API_DNS_FORWARDER_SETTINGS,
    API_DNS_FORWARDER_SET_SETTINGS,
    API_DNS_FORWARDER_SERVICE_RESTART,
    API_DNS_FORWARDER_SERVICE_RECONFIGURE,
    API_DNS_FORWARDER_HOST_SEARCH,
    API_DNS_FORWARDER_HOST_ADD,
)


# ========== HELPER FUNCTIONS ==========

def is_valid_uuid(uuid: str) -> bool:
    """Check if string is a valid UUID format.

    Args:
        uuid: String to validate

    Returns:
        True if valid UUID format, False otherwise
    """
    if not uuid:
        return False
    uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
    return bool(uuid_pattern.match(uuid))


# ========== DHCP SERVER MANAGEMENT ==========

@mcp.tool(name="dhcp_list_servers", description="List all DHCP server configurations")
async def dhcp_list_servers(ctx: Context) -> str:
    """List all DHCP server configurations.

    Returns:
        JSON string of DHCP server configurations
    """
    opnsense_client = get_opnsense_client()
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
    ctx: Context,
    interface: str
) -> str:
    """Get a specific DHCP server configuration by interface.

    Args:
        ctx: MCP context
        interface: Interface name (e.g., 'lan', 'opt1')

    Returns:
        JSON string of DHCP server configuration
    """
    opnsense_client = get_opnsense_client()
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
    ctx: Context,
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
    opnsense_client = get_opnsense_client()
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
                API_DHCP_SERVICE_RECONFIGURE,
                operation="apply_dhcp_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dhcp_set_server", e)


@mcp.tool(name="dhcp_restart_service", description="Restart the DHCP service")
async def dhcp_restart_service(ctx: Context) -> str:
    """Restart the DHCP service.

    Returns:
        JSON string of operation result
    """
    opnsense_client = get_opnsense_client()
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


# ========== DHCP STATIC MAPPINGS ==========

@mcp.tool(name="dhcp_list_static_mappings", description="List DHCP static mappings (reservations)")
async def dhcp_list_static_mappings(
    ctx: Context,
    search_phrase: str = ""
) -> str:
    """List all DHCP static mappings (reservations).

    Args:
        ctx: MCP context
        search_phrase: Optional search phrase to filter mappings

    Returns:
        JSON string of DHCP static mappings
    """
    opnsense_client = get_opnsense_client()
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        params = {}
        if search_phrase:
            params["searchPhrase"] = search_phrase

        response = await opnsense_client.request(
            "POST",
            API_DHCP_STATIC_SEARCH,
            data=params,
            operation="list_dhcp_static_mappings"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dhcp_list_static_mappings", e)


@mcp.tool(name="dhcp_get_static_mapping", description="Get a specific DHCP static mapping")
async def dhcp_get_static_mapping(
    ctx: Context,
    uuid: str
) -> str:
    """Get a specific DHCP static mapping by UUID.

    Args:
        ctx: MCP context
        uuid: UUID of the static mapping

    Returns:
        JSON string of static mapping details
    """
    opnsense_client = get_opnsense_client()
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        response = await opnsense_client.request(
            "GET",
            f"{API_DHCP_STATIC_GET}/{uuid}",
            operation=f"get_dhcp_static_mapping_{uuid[:8]}"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dhcp_get_static_mapping", e)


@mcp.tool(name="dhcp_add_static_mapping", description="Add a new DHCP static mapping (reservation)")
async def dhcp_add_static_mapping(
    ctx: Context,
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
    opnsense_client = get_opnsense_client()
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
            API_DHCP_STATIC_ADD,
            data={"static": mapping_data},
            operation="add_dhcp_static_mapping"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_DHCP_SERVICE_RECONFIGURE,
                operation="apply_dhcp_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dhcp_add_static_mapping", e)


@mcp.tool(name="dhcp_update_static_mapping", description="Update an existing DHCP static mapping")
async def dhcp_update_static_mapping(
    ctx: Context,
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
    opnsense_client = get_opnsense_client()
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        # Get current mapping
        current = await opnsense_client.request(
            "GET",
            f"{API_DHCP_STATIC_GET}/{uuid}",
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
            f"{API_DHCP_STATIC_SET}/{uuid}",
            data={"static": mapping_data},
            operation=f"update_dhcp_static_mapping_{uuid[:8]}"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_DHCP_SERVICE_RECONFIGURE,
                operation="apply_dhcp_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dhcp_update_static_mapping", e)


@mcp.tool(name="dhcp_delete_static_mapping", description="Delete a DHCP static mapping")
async def dhcp_delete_static_mapping(
    ctx: Context,
    uuid: str
) -> str:
    """Delete a DHCP static mapping by UUID.

    Args:
        ctx: MCP context
        uuid: UUID of the static mapping to delete

    Returns:
        JSON string of operation result
    """
    opnsense_client = get_opnsense_client()
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        response = await opnsense_client.request(
            "POST",
            f"{API_DHCP_STATIC_DEL}/{uuid}",
            operation=f"delete_dhcp_static_mapping_{uuid[:8]}"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_DHCP_SERVICE_RECONFIGURE,
                operation="apply_dhcp_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dhcp_delete_static_mapping", e)


# ========== DHCP LEASE MANAGEMENT ==========

@mcp.tool(name="dhcp_get_leases", description="Get current DHCP leases")
async def dhcp_get_leases(
    ctx: Context,
    interface: str = ""
) -> str:
    """Get current DHCP leases from the server.

    Args:
        ctx: MCP context
        interface: Optional interface filter (e.g., 'lan', 'opt1')

    Returns:
        JSON string of current DHCP leases
    """
    opnsense_client = get_opnsense_client()
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
    ctx: Context,
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
    opnsense_client = get_opnsense_client()
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
async def dhcp_get_lease_statistics(ctx: Context) -> str:
    """Get statistics about DHCP leases across all interfaces.

    Returns:
        JSON string of DHCP lease statistics
    """
    opnsense_client = get_opnsense_client()
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


# ========== DNS RESOLVER (UNBOUND) MANAGEMENT ==========

@mcp.tool(name="dns_resolver_get_settings", description="Get DNS resolver (Unbound) settings")
async def dns_resolver_get_settings(ctx: Context) -> str:
    """Get DNS resolver (Unbound) configuration settings.

    Returns:
        JSON string of DNS resolver settings
    """
    opnsense_client = get_opnsense_client()
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        response = await opnsense_client.request(
            "GET",
            API_DNS_RESOLVER_SETTINGS,
            operation="get_dns_resolver_settings"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_resolver_get_settings", e)


@mcp.tool(name="dns_resolver_set_settings", description="Configure DNS resolver (Unbound) settings")
async def dns_resolver_set_settings(
    ctx: Context,
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
    opnsense_client = get_opnsense_client()
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
            API_DNS_RESOLVER_SET_SETTINGS,
            data=settings_data,
            operation="set_dns_resolver_settings"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_DNS_RESOLVER_SERVICE_RECONFIGURE,
                operation="apply_dns_resolver_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_resolver_set_settings", e)


@mcp.tool(name="dns_resolver_restart_service", description="Restart the DNS resolver service")
async def dns_resolver_restart_service(ctx: Context) -> str:
    """Restart the DNS resolver (Unbound) service.

    Returns:
        JSON string of operation result
    """
    opnsense_client = get_opnsense_client()
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        response = await opnsense_client.request(
            "POST",
            API_DNS_RESOLVER_SERVICE_RESTART,
            operation="restart_dns_resolver_service"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_resolver_restart_service", e)


# ========== DNS RESOLVER HOST OVERRIDES ==========

@mcp.tool(name="dns_resolver_list_host_overrides", description="List DNS resolver host overrides")
async def dns_resolver_list_host_overrides(
    ctx: Context,
    search_phrase: str = ""
) -> str:
    """List all DNS resolver host overrides.

    Args:
        ctx: MCP context
        search_phrase: Optional search phrase to filter overrides

    Returns:
        JSON string of host overrides
    """
    opnsense_client = get_opnsense_client()
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        params = {}
        if search_phrase:
            params["searchPhrase"] = search_phrase

        response = await opnsense_client.request(
            "POST",
            API_DNS_RESOLVER_HOST_SEARCH,
            data=params,
            operation="list_dns_resolver_host_overrides"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_resolver_list_host_overrides", e)


@mcp.tool(name="dns_resolver_get_host_override", description="Get a specific DNS resolver host override")
async def dns_resolver_get_host_override(
    ctx: Context,
    uuid: str
) -> str:
    """Get a specific DNS resolver host override by UUID.

    Args:
        ctx: MCP context
        uuid: UUID of the host override

    Returns:
        JSON string of host override details
    """
    opnsense_client = get_opnsense_client()
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        response = await opnsense_client.request(
            "GET",
            f"{API_DNS_RESOLVER_HOST_GET}/{uuid}",
            operation=f"get_dns_resolver_host_override_{uuid[:8]}"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_resolver_get_host_override", e)


@mcp.tool(name="dns_resolver_add_host_override", description="Add a new DNS resolver host override")
async def dns_resolver_add_host_override(
    ctx: Context,
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
    opnsense_client = get_opnsense_client()
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
            API_DNS_RESOLVER_HOST_ADD,
            data={"host": override_data},
            operation="add_dns_resolver_host_override"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_DNS_RESOLVER_SERVICE_RECONFIGURE,
                operation="apply_dns_resolver_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_resolver_add_host_override", e)


@mcp.tool(name="dns_resolver_update_host_override", description="Update an existing DNS resolver host override")
async def dns_resolver_update_host_override(
    ctx: Context,
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
    opnsense_client = get_opnsense_client()
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        # Get current override
        current = await opnsense_client.request(
            "GET",
            f"{API_DNS_RESOLVER_HOST_GET}/{uuid}",
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
            f"{API_DNS_RESOLVER_HOST_SET}/{uuid}",
            data={"host": override_data},
            operation=f"update_dns_resolver_host_override_{uuid[:8]}"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_DNS_RESOLVER_SERVICE_RECONFIGURE,
                operation="apply_dns_resolver_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_resolver_update_host_override", e)


@mcp.tool(name="dns_resolver_delete_host_override", description="Delete a DNS resolver host override")
async def dns_resolver_delete_host_override(
    ctx: Context,
    uuid: str
) -> str:
    """Delete a DNS resolver host override by UUID.

    Args:
        ctx: MCP context
        uuid: UUID of the host override to delete

    Returns:
        JSON string of operation result
    """
    opnsense_client = get_opnsense_client()
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    if not uuid or not is_valid_uuid(uuid):
        return json.dumps({"error": "Valid UUID is required"}, indent=2)

    try:
        response = await opnsense_client.request(
            "POST",
            f"{API_DNS_RESOLVER_HOST_DEL}/{uuid}",
            operation=f"delete_dns_resolver_host_override_{uuid[:8]}"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_DNS_RESOLVER_SERVICE_RECONFIGURE,
                operation="apply_dns_resolver_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_resolver_delete_host_override", e)


# ========== DNS RESOLVER DOMAIN OVERRIDES ==========

@mcp.tool(name="dns_resolver_list_domain_overrides", description="List DNS resolver domain overrides")
async def dns_resolver_list_domain_overrides(
    ctx: Context,
    search_phrase: str = ""
) -> str:
    """List all DNS resolver domain overrides.

    Args:
        ctx: MCP context
        search_phrase: Optional search phrase to filter overrides

    Returns:
        JSON string of domain overrides
    """
    opnsense_client = get_opnsense_client()
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        params = {}
        if search_phrase:
            params["searchPhrase"] = search_phrase

        response = await opnsense_client.request(
            "POST",
            API_DNS_RESOLVER_DOMAIN_SEARCH,
            data=params,
            operation="list_dns_resolver_domain_overrides"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_resolver_list_domain_overrides", e)


@mcp.tool(name="dns_resolver_add_domain_override", description="Add a new DNS resolver domain override")
async def dns_resolver_add_domain_override(
    ctx: Context,
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
    opnsense_client = get_opnsense_client()
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
            API_DNS_RESOLVER_DOMAIN_ADD,
            data={"domain": override_data},
            operation="add_dns_resolver_domain_override"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_DNS_RESOLVER_SERVICE_RECONFIGURE,
                operation="apply_dns_resolver_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_resolver_add_domain_override", e)


# ========== DNS FORWARDER (DNSMASQ) MANAGEMENT ==========

@mcp.tool(name="dns_forwarder_get_settings", description="Get DNS forwarder (dnsmasq) settings")
async def dns_forwarder_get_settings(ctx: Context) -> str:
    """Get DNS forwarder (dnsmasq) configuration settings.

    Returns:
        JSON string of DNS forwarder settings
    """
    opnsense_client = get_opnsense_client()
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        response = await opnsense_client.request(
            "GET",
            API_DNS_FORWARDER_SETTINGS,
            operation="get_dns_forwarder_settings"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_forwarder_get_settings", e)


@mcp.tool(name="dns_forwarder_set_settings", description="Configure DNS forwarder (dnsmasq) settings")
async def dns_forwarder_set_settings(
    ctx: Context,
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
    opnsense_client = get_opnsense_client()
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
            API_DNS_FORWARDER_SET_SETTINGS,
            data=settings_data,
            operation="set_dns_forwarder_settings"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_DNS_FORWARDER_SERVICE_RECONFIGURE,
                operation="apply_dns_forwarder_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_forwarder_set_settings", e)


@mcp.tool(name="dns_forwarder_list_hosts", description="List DNS forwarder host overrides")
async def dns_forwarder_list_hosts(
    ctx: Context,
    search_phrase: str = ""
) -> str:
    """List all DNS forwarder host overrides.

    Args:
        ctx: MCP context
        search_phrase: Optional search phrase to filter hosts

    Returns:
        JSON string of host overrides
    """
    opnsense_client = get_opnsense_client()
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        params = {}
        if search_phrase:
            params["searchPhrase"] = search_phrase

        response = await opnsense_client.request(
            "POST",
            API_DNS_FORWARDER_HOST_SEARCH,
            data=params,
            operation="list_dns_forwarder_hosts"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_forwarder_list_hosts", e)


@mcp.tool(name="dns_forwarder_add_host", description="Add a new DNS forwarder host override")
async def dns_forwarder_add_host(
    ctx: Context,
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
    opnsense_client = get_opnsense_client()
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
            API_DNS_FORWARDER_HOST_ADD,
            data={"host": host_data},
            operation="add_dns_forwarder_host"
        )

        # Apply configuration if successful
        if response and not response.get("error"):
            await opnsense_client.request(
                "POST",
                API_DNS_FORWARDER_SERVICE_RECONFIGURE,
                operation="apply_dns_forwarder_config"
            )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_forwarder_add_host", e)


@mcp.tool(name="dns_forwarder_restart_service", description="Restart the DNS forwarder service")
async def dns_forwarder_restart_service(ctx: Context) -> str:
    """Restart the DNS forwarder (dnsmasq) service.

    Returns:
        JSON string of operation result
    """
    opnsense_client = get_opnsense_client()
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    try:
        response = await opnsense_client.request(
            "POST",
            API_DNS_FORWARDER_SERVICE_RESTART,
            operation="restart_dns_forwarder_service"
        )

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "dns_forwarder_restart_service", e)
