"""
OPNsense MCP Server - Firewall Domain

This module provides tools for managing OPNsense firewall rules and aliases.
It handles firewall rule creation, modification, deletion, and alias management
for IP address grouping and simplified rule management.
"""

import json
import logging
import urllib.parse
from typing import Optional

from mcp.server.fastmcp import Context

from ..main import mcp
from ..core import OPNsenseClient, ValidationError
from ..shared.constants import (
    API_FIREWALL_FILTER_SEARCH_RULE,
    API_FIREWALL_FILTER_ADD_RULE,
    API_FIREWALL_FILTER_DEL_RULE,
    API_FIREWALL_FILTER_TOGGLE_RULE,
    API_FIREWALL_FILTER_APPLY,
    API_FIREWALL_ALIAS_SEARCH_ITEM,
    API_FIREWALL_ALIAS_UTIL_ADD,
    API_FIREWALL_ALIAS_UTIL_DELETE,
    API_FIREWALL_ALIAS_RECONFIGURE,
    API_DIAGNOSTICS_LOG_FIREWALL,
)
from ..shared.error_handlers import (
    handle_tool_error,
    validate_uuid,
    validate_firewall_parameters,
    ErrorSeverity,
)
from ..core.retry import RetryConfig
from .configuration import get_opnsense_client

logger = logging.getLogger("opnsense-mcp")


# ========== FIREWALL RULE TOOLS ==========

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
    try:
        client = await get_opnsense_client()

        response = await client.request(
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
    """Add a new firewall rule with comprehensive validation and error handling.

    Args:
        ctx: MCP context
        description: Rule description
        action: Rule action (pass, block, reject)
        interface: Network interface
        direction: Traffic direction (in, out)
        ipprotocol: IP protocol (inet for IPv4, inet6 for IPv6)
        protocol: Transport protocol (tcp, udp, icmp, any)
        source_net: Source network/host
        destination_net: Destination network/host
        destination_port: Destination port(s)
        enabled: Whether the rule is enabled

    Returns:
        JSON string with the result
    """
    try:
        client = await get_opnsense_client()

        # Validate firewall rule parameters
        validate_firewall_parameters(action, direction, ipprotocol, protocol, "firewall_add_rule")

        # Validate description
        if not description or len(description.strip()) == 0:
            raise ValidationError("Rule description is required",
                                context={"operation": "firewall_add_rule", "parameter": "description"})

        # Additional validation for specific protocols and ports
        if protocol in ["tcp", "udp"] and destination_port and not destination_port.replace("-", "").replace(",", "").replace(" ", "").isdigit():
            # Simple port validation - could be enhanced
            if not all(part.strip().isdigit() or "-" in part for part in destination_port.split(",")):
                raise ValidationError(f"Invalid port format: {destination_port}",
                                    context={"operation": "firewall_add_rule", "parameter": "destination_port", "value": destination_port})
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
        add_result = await client.request(
            "POST",
            API_FIREWALL_FILTER_ADD_RULE,
            data=rule_data
        )

        # Apply changes
        await ctx.info("Rule added, applying changes...")
        apply_result = await client.request(
            "POST",
            API_FIREWALL_FILTER_APPLY
        )

        return json.dumps({
            "add_result": add_result,
            "apply_result": apply_result
        }, indent=2)
    except Exception as e:
        return await handle_tool_error(ctx, "firewall_add_rule", e, ErrorSeverity.HIGH)


@mcp.tool(name="firewall_delete_rule", description="Delete a firewall rule by UUID")
async def firewall_delete_rule(ctx: Context, uuid: str) -> str:
    """Delete a firewall rule by UUID with enhanced validation and error handling.

    Args:
        ctx: MCP context
        uuid: UUID of the rule to delete

    Returns:
        JSON string with the result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID format
        validate_uuid(uuid, "firewall_delete_rule")
        # Delete the rule
        delete_result = await client.request(
            "POST",
            f"{API_FIREWALL_FILTER_DEL_RULE}/{uuid}",
            operation="delete_firewall_rule"
        )

        # Apply changes with retry for reliability
        await ctx.info("Rule deleted, applying changes...")
        retry_config = RetryConfig(max_attempts=2, base_delay=1.0)
        apply_result = await client.request(
            "POST",
            API_FIREWALL_FILTER_APPLY,
            operation="apply_firewall_changes",
            retry_config=retry_config
        )

        return json.dumps({
            "delete_result": delete_result,
            "apply_result": apply_result
        }, indent=2)
    except Exception as e:
        return await handle_tool_error(ctx, "firewall_delete_rule", e, ErrorSeverity.HIGH)


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
    try:
        client = await get_opnsense_client()

        # Toggle the rule
        toggle_result = await client.request(
            "POST",
            f"{API_FIREWALL_FILTER_TOGGLE_RULE}/{uuid}/{1 if enabled else 0}"
        )

        # Apply changes
        await ctx.info(f"Rule {'enabled' if enabled else 'disabled'}, applying changes...")
        apply_result = await client.request(
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


# ========== FIREWALL ALIAS TOOLS ==========

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
    try:
        client = await get_opnsense_client()

        response = await client.request(
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
    try:
        client = await get_opnsense_client()

        # Add to alias
        add_result = await client.request(
            "POST",
            f"{API_FIREWALL_ALIAS_UTIL_ADD}/{alias_name}/{urllib.parse.quote_plus(address)}"
        )

        # Reconfigure aliases
        await ctx.info("Entry added, applying changes...")
        reconfigure_result = await client.request(
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
    try:
        client = await get_opnsense_client()

        # Delete from alias
        delete_result = await client.request(
            "POST",
            f"{API_FIREWALL_ALIAS_UTIL_DELETE}/{alias_name}/{urllib.parse.quote_plus(address)}"
        )

        # Reconfigure aliases
        await ctx.info("Entry deleted, applying changes...")
        reconfigure_result = await client.request(
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


# ========== FIREWALL LOG TOOLS ==========

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
    try:
        client = await get_opnsense_client()

        response = await client.request(
            "GET",
            API_DIAGNOSTICS_LOG_FIREWALL,
            params={"limit": count, "filter": filter_text}
        )

        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in get_firewall_logs: {str(e)}", exc_info=True)
        await ctx.error(f"Error fetching firewall logs: {str(e)}")
        return f"Error: {str(e)}"
