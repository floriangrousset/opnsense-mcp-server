"""
OPNsense MCP Server - NAT (Network Address Translation) Domain

This module provides comprehensive NAT management capabilities for OPNsense firewalls.
NAT is used to translate network addresses, enabling features like:
- Outbound NAT (Source NAT): Translates internal private IPs to public IPs for internet access
- One-to-One NAT: Maps external IP addresses 1:1 with internal IP addresses
- Port Forwarding: Maps external ports to internal services (API coming in OPNsense 26.1)

The module supports:
- Listing and searching NAT rules with pagination
- Creating, updating, and deleting NAT rules
- Enabling/disabling rules without deletion
- Automatic configuration application after changes
"""

import json
import logging
from typing import Optional

from mcp.server.fastmcp import Context

from ..main import mcp
from ..shared.constants import (
    API_FIREWALL_SOURCE_NAT_SEARCH_RULE,
    API_FIREWALL_SOURCE_NAT_ADD_RULE,
    API_FIREWALL_SOURCE_NAT_DEL_RULE,
    API_FIREWALL_SOURCE_NAT_TOGGLE_RULE,
    API_FIREWALL_ONE_TO_ONE_SEARCH_RULE,
    API_FIREWALL_ONE_TO_ONE_ADD_RULE,
    API_FIREWALL_ONE_TO_ONE_DEL_RULE,
    API_FIREWALL_FILTER_BASE_APPLY,
)
from .configuration import get_opnsense_client

logger = logging.getLogger("opnsense-mcp")


# ========== OUTBOUND NAT (SOURCE NAT) MANAGEMENT ==========

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
    try:
        opnsense_client = await get_opnsense_client()

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
    try:
        opnsense_client = await get_opnsense_client()

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
    try:
        opnsense_client = await get_opnsense_client()

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
    try:
        opnsense_client = await get_opnsense_client()

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


# ========== ONE-TO-ONE NAT MANAGEMENT ==========

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
    try:
        opnsense_client = await get_opnsense_client()

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
    try:
        opnsense_client = await get_opnsense_client()

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
    try:
        opnsense_client = await get_opnsense_client()

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


# ========== PORT FORWARDING INFO ==========

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
