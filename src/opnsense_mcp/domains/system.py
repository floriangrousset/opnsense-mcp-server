"""
OPNsense MCP Server - System Domain

This module provides system management tools for OPNsense including system status monitoring,
health metrics, service management, plugin management, backups, and security auditing.

Tools included:
- get_system_status: Get OPNsense system status
- get_system_health: Get system health metrics (CPU, memory, disk, temperature)
- get_system_routes: Get system routing table
- restart_service: Restart an OPNsense service
- backup_config: Create a backup of the OPNsense configuration
- list_plugins: List installed plugins
- install_plugin: Install a plugin
- perform_firewall_audit: Perform comprehensive security audit
"""

import json
import logging
from typing import Any

from mcp.server.fastmcp import Context

from ..core import OPNsenseClient
from ..core.exceptions import (
    APIError,
    AuthenticationError,
    ConfigurationError,
    NetworkError,
)
from ..main import mcp
from ..shared.constants import (
    API_CORE_BACKUP_DOWNLOAD,
    API_CORE_FIRMWARE_INSTALL,
    API_CORE_FIRMWARE_PLUGINS,
    API_CORE_FIRMWARE_STATUS,
    API_CORE_SERVICE_RESTART,
    API_CORE_SERVICE_SEARCH,
    API_CORE_SYSTEM_INFO,
    API_DIAGNOSTICS_SYSTEM_MEMORY,
    API_DIAGNOSTICS_SYSTEM_PROCESSOR,
    API_DIAGNOSTICS_SYSTEM_STORAGE,
    API_DIAGNOSTICS_SYSTEM_TEMPERATURE,
    API_FIREWALL_FILTER_SEARCH_RULE,
    API_INTERFACES_OVERVIEW_INFO,
    API_ROUTES_GET,
)
from .configuration import get_opnsense_client

logger = logging.getLogger("opnsense-mcp")


# ========== HELPER FUNCTIONS ==========


async def _get_all_rules(client: OPNsenseClient) -> list[dict[str, Any]]:
    """Helper to fetch all firewall rules using pagination."""
    all_rules = []
    current_page = 1
    rows_per_page = 500  # Fetch in larger batches
    while True:
        try:
            response = await client.request(
                "POST",
                API_FIREWALL_FILTER_SEARCH_RULE,
                data={"current": current_page, "rowCount": rows_per_page, "searchPhrase": ""},
            )
            rules = response.get("rows", [])
            if not rules:
                break
            all_rules.extend(rules)
            if len(rules) < rows_per_page:
                break  # Last page
            current_page += 1
        except Exception as e:
            logger.error(
                f"Error fetching page {current_page} of firewall rules: {e}", exc_info=True
            )
            # Return what we have so far, audit can proceed with partial data
            break
    return all_rules


async def _get_wan_interfaces(client: OPNsenseClient) -> list[str]:
    """Helper to identify WAN interfaces."""
    wan_interfaces = []
    try:
        interfaces_info = await client.request("GET", API_INTERFACES_OVERVIEW_INFO)
        for if_name, if_data in interfaces_info.items():
            # Heuristic: Interface is likely WAN if it has a gateway and isn't loopback/internal
            # OPNsense often names the default WAN 'wan' but users can rename it.
            # Checking for a non-empty gateway field is a common indicator.
            if (if_data.get("gateway") and if_data.get("gateway") != "none") or (
                if_name.lower() == "wan" and not wan_interfaces
            ):
                wan_interfaces.append(if_name)
    except Exception as e:
        logger.error(f"Error fetching interfaces info for audit: {e}", exc_info=True)

    # If still no WAN identified, maybe return a default guess? For now, return empty.
    if not wan_interfaces:
        logger.warning("Could not reliably identify WAN interfaces for audit.")

    return wan_interfaces


# ========== SYSTEM TOOLS ==========


@mcp.tool(name="get_system_status", description="Get OPNsense system status")
async def get_system_status(ctx: Context) -> str:
    """Get OPNsense system status.

    Args:
        ctx: MCP context

    Returns:
        Formatted system status information
    """
    try:
        client = await get_opnsense_client()

        # Get firmware status
        firmware = await client.request("GET", API_CORE_FIRMWARE_STATUS)

        # Get system information
        system_info = await client.request("GET", API_CORE_SYSTEM_INFO)

        # Get service status
        services = await client.request(
            "POST", API_CORE_SERVICE_SEARCH, data={"current": 1, "rowCount": -1, "searchPhrase": ""}
        )

        # Format and return the combined status
        status = {"firmware": firmware, "system": system_info, "services": services.get("rows", [])}

        return json.dumps(status, indent=2)

    except ConfigurationError as e:
        await ctx.error(str(e))
        return f"Configuration Error: {e!s}"
    except (AuthenticationError, NetworkError, APIError) as e:
        logger.error(f"Error in get_system_status: {e!s}", exc_info=True)
        await ctx.error(f"Error fetching system status: {e!s}")
        return f"Error: {e!s}"
    except Exception as e:
        logger.error(f"Unexpected error in get_system_status: {e!s}", exc_info=True)
        await ctx.error(f"Unexpected error: {e!s}")
        return f"Error: {e!s}"


@mcp.tool(name="get_system_health", description="Get system health metrics")
async def get_system_health(ctx: Context) -> str:
    """Get system health metrics.

    Args:
        ctx: MCP context

    Returns:
        JSON string of system health metrics
    """
    try:
        client = await get_opnsense_client()

        # Get multiple health metrics
        cpu = await client.request("GET", API_DIAGNOSTICS_SYSTEM_PROCESSOR)
        memory = await client.request("GET", API_DIAGNOSTICS_SYSTEM_MEMORY)
        disk = await client.request("GET", API_DIAGNOSTICS_SYSTEM_STORAGE)
        temperature = await client.request("GET", API_DIAGNOSTICS_SYSTEM_TEMPERATURE)

        # Combine results
        return json.dumps(
            {"cpu": cpu, "memory": memory, "disk": disk, "temperature": temperature}, indent=2
        )
    except ConfigurationError as e:
        await ctx.error(str(e))
        return f"Configuration Error: {e!s}"
    except (AuthenticationError, NetworkError, APIError) as e:
        logger.error(f"Error in get_system_health: {e!s}", exc_info=True)
        await ctx.error(f"Error fetching system health: {e!s}")
        return f"Error: {e!s}"
    except Exception as e:
        logger.error(f"Error in get_system_health: {e!s}", exc_info=True)
        await ctx.error(f"Error fetching system health: {e!s}")
        return f"Error: {e!s}"


@mcp.tool(name="get_system_routes", description="Get system routing table")
async def get_system_routes(ctx: Context) -> str:
    """Get system routing table.

    Args:
        ctx: MCP context

    Returns:
        JSON string of system routes
    """
    try:
        client = await get_opnsense_client()

        response = await client.request("GET", API_ROUTES_GET)
        return json.dumps(response, indent=2)
    except ConfigurationError as e:
        await ctx.error(str(e))
        return f"Configuration Error: {e!s}"
    except (AuthenticationError, NetworkError, APIError) as e:
        logger.error(f"Error in get_system_routes: {e!s}", exc_info=True)
        await ctx.error(f"Error fetching system routes: {e!s}")
        return f"Error: {e!s}"
    except Exception as e:
        logger.error(f"Error in get_system_routes: {e!s}", exc_info=True)
        await ctx.error(f"Error fetching system routes: {e!s}")
        return f"Error: {e!s}"


@mcp.tool(name="restart_service", description="Restart an OPNsense service")
async def restart_service(ctx: Context, service_name: str) -> str:
    """Restart an OPNsense service.

    Args:
        ctx: MCP context
        service_name: Name of the service to restart

    Returns:
        JSON string with the result
    """
    try:
        client = await get_opnsense_client()

        response = await client.request("POST", f"{API_CORE_SERVICE_RESTART}/{service_name}")

        return json.dumps(response, indent=2)
    except ConfigurationError as e:
        await ctx.error(str(e))
        return f"Configuration Error: {e!s}"
    except (AuthenticationError, NetworkError, APIError) as e:
        logger.error(f"Error in restart_service (service: {service_name}): {e!s}", exc_info=True)
        await ctx.error(f"Error restarting service: {e!s}")
        return f"Error: {e!s}"
    except Exception as e:
        logger.error(f"Error in restart_service (service: {service_name}): {e!s}", exc_info=True)
        await ctx.error(f"Error restarting service: {e!s}")
        return f"Error: {e!s}"


@mcp.tool(name="backup_config", description="Create a backup of the OPNsense configuration")
async def backup_config(ctx: Context) -> str:
    """Create a backup of the OPNsense configuration.

    Args:
        ctx: MCP context

    Returns:
        JSON string with the result
    """
    try:
        client = await get_opnsense_client()

        response = await client.request("POST", API_CORE_BACKUP_DOWNLOAD)
        return json.dumps(response, indent=2)
    except ConfigurationError as e:
        await ctx.error(str(e))
        return f"Configuration Error: {e!s}"
    except (AuthenticationError, NetworkError, APIError) as e:
        logger.error(f"Error in backup_config: {e!s}", exc_info=True)
        await ctx.error(f"Error creating backup: {e!s}")
        return f"Error: {e!s}"
    except Exception as e:
        logger.error(f"Error in backup_config: {e!s}", exc_info=True)
        await ctx.error(f"Error creating backup: {e!s}")
        return f"Error: {e!s}"


@mcp.tool(name="list_plugins", description="List installed plugins")
async def list_plugins(ctx: Context) -> str:
    """List installed plugins.

    Args:
        ctx: MCP context

    Returns:
        JSON string of installed plugins
    """
    try:
        client = await get_opnsense_client()

        response = await client.request("GET", API_CORE_FIRMWARE_PLUGINS)
        return json.dumps(response, indent=2)
    except ConfigurationError as e:
        await ctx.error(str(e))
        return f"Configuration Error: {e!s}"
    except (AuthenticationError, NetworkError, APIError) as e:
        logger.error(f"Error in list_plugins: {e!s}", exc_info=True)
        await ctx.error(f"Error listing plugins: {e!s}")
        return f"Error: {e!s}"
    except Exception as e:
        logger.error(f"Error in list_plugins: {e!s}", exc_info=True)
        await ctx.error(f"Error listing plugins: {e!s}")
        return f"Error: {e!s}"


@mcp.tool(name="install_plugin", description="Install a plugin")
async def install_plugin(ctx: Context, plugin_name: str) -> str:
    """Install a plugin.

    Args:
        ctx: MCP context
        plugin_name: Name of the plugin to install

    Returns:
        JSON string with the result
    """
    try:
        client = await get_opnsense_client()

        response = await client.request("POST", f"{API_CORE_FIRMWARE_INSTALL}/{plugin_name}")

        return json.dumps(response, indent=2)
    except ConfigurationError as e:
        await ctx.error(str(e))
        return f"Configuration Error: {e!s}"
    except (AuthenticationError, NetworkError, APIError) as e:
        logger.error(f"Error in install_plugin (plugin: {plugin_name}): {e!s}", exc_info=True)
        await ctx.error(f"Error installing plugin: {e!s}")
        return f"Error: {e!s}"
    except Exception as e:
        logger.error(f"Error in install_plugin (plugin: {plugin_name}): {e!s}", exc_info=True)
        await ctx.error(f"Error installing plugin: {e!s}")
        return f"Error: {e!s}"


@mcp.tool(
    name="perform_firewall_audit",
    description="Performs a basic security audit of the OPNsense configuration.",
)
async def perform_firewall_audit(ctx: Context) -> str:
    """Performs a basic security audit of the OPNsense configuration.

    Checks for common potential security issues like outdated firmware/plugins,
    management access from WAN, overly permissive rules, etc.

    Args:
        ctx: MCP context

    Returns:
        JSON string containing a list of audit findings.
    """
    try:
        client = await get_opnsense_client()

        findings = []
        await ctx.info("Starting OPNsense firewall audit...")

        # --- Fetch Data ---
        await ctx.info("Fetching required data (firmware, rules, interfaces, services)...")
        firmware_status = await client.request("GET", API_CORE_FIRMWARE_STATUS)
        all_rules = await _get_all_rules(client)
        wan_interfaces = await _get_wan_interfaces(client)
        services_response = await client.request(
            "POST",
            API_CORE_SERVICE_SEARCH,
            data={"current": 1, "rowCount": -1, "searchPhrase": ""},  # Fetch all services
        )
        running_services = {
            svc["name"]: svc for svc in services_response.get("rows", []) if svc.get("running") == 1
        }

        await ctx.info(f"Identified WAN interfaces: {wan_interfaces or 'None'}")
        await ctx.info(f"Fetched {len(all_rules)} firewall rules.")

        # --- Perform Checks ---

        # 1. Firmware Update Check
        if firmware_status.get("status") == "update_available":
            findings.append(
                {
                    "check": "Firmware Update",
                    "severity": "Medium",
                    "description": f"Firmware update available. Current: {firmware_status.get('product_version', 'N/A')}, New: {firmware_status.get('product_new_version', 'N/A')}",
                    "recommendation": "Consider updating OPNsense firmware via the GUI (System -> Firmware -> Updates).",
                }
            )
        else:
            findings.append(
                {
                    "check": "Firmware Update",
                    "severity": "Info",
                    "description": "Firmware appears to be up-to-date.",
                    "recommendation": None,
                }
            )

        # 2. Plugin Update Check
        plugin_updates = firmware_status.get("upgrade_packages", [])
        if plugin_updates:
            plugin_names = [p.get("name", "N/A") for p in plugin_updates]
            findings.append(
                {
                    "check": "Plugin Updates",
                    "severity": "Medium",
                    "description": f"Updates available for {len(plugin_updates)} plugins: {', '.join(plugin_names)}",
                    "recommendation": "Consider updating plugins via the GUI (System -> Firmware -> Updates).",
                }
            )
        else:
            findings.append(
                {
                    "check": "Plugin Updates",
                    "severity": "Info",
                    "description": "Installed plugins appear to be up-to-date.",
                    "recommendation": None,
                }
            )

        # 3. WAN Management Access Check
        management_ports = {"80", "443", "22"}  # HTTP, HTTPS, SSH
        insecure_protocols = {"21", "23"}  # FTP, Telnet
        wan_mgmt_rules = []
        wan_insecure_proto_rules = []
        wan_any_any_rules = []
        block_rules_no_log = []

        for rule in all_rules:
            # Skip disabled rules
            if not rule.get("enabled", "0") == "1":
                continue

            interface = rule.get("interface")
            is_wan_rule = interface in wan_interfaces

            # Check logging on block/reject rules
            if rule.get("action") in ["block", "reject"] and not rule.get("log", "0") == "1":
                block_rules_no_log.append(rule.get("descr", rule.get("uuid", "N/A")))

            if not is_wan_rule:
                continue  # Only check WAN rules for the following

            # Basic parsing - assumes 'any' if specific fields are missing/empty
            src_net = rule.get("source_net", "any")
            dst_net = rule.get("destination_net", "any")
            dst_port = rule.get("destination_port", "any")
            protocol = rule.get("protocol", "any").lower()
            action = rule.get("action")

            # Check Any-Any rule
            if action == "pass" and src_net == "any" and dst_net == "any" and dst_port == "any":
                wan_any_any_rules.append(rule.get("descr", rule.get("uuid", "N/A")))

            # Check Management Access
            # Simplified: Checks if dest port is one of the management ports
            # Doesn't check destination address (assumes firewall itself)
            if action == "pass" and dst_port in management_ports:
                wan_mgmt_rules.append(rule.get("descr", rule.get("uuid", "N/A")))

            # Check Insecure Protocols
            if action == "pass" and dst_port in insecure_protocols:
                wan_insecure_proto_rules.append(rule.get("descr", rule.get("uuid", "N/A")))

        if wan_mgmt_rules:
            findings.append(
                {
                    "check": "WAN Management Access",
                    "severity": "High",
                    "description": f"Potential firewall rules allowing management access (HTTP/HTTPS/SSH) from WAN found: {', '.join(wan_mgmt_rules)}",
                    "recommendation": "Review these rules. Exposing management interfaces to the WAN is highly discouraged. Use VPNs for remote access.",
                }
            )

        if wan_any_any_rules:
            findings.append(
                {
                    "check": "WAN Allow Any-Any",
                    "severity": "High",
                    "description": f"Potential 'allow any source to any destination' rules found on WAN interface(s): {', '.join(wan_any_any_rules)}",
                    "recommendation": "Review these rules. 'Allow any-any' rules on WAN are extremely dangerous and likely misconfigured.",
                }
            )

        if wan_insecure_proto_rules:
            findings.append(
                {
                    "check": "WAN Insecure Protocols",
                    "severity": "High",
                    "description": f"Potential rules allowing insecure protocols (e.g., Telnet, FTP) from WAN found: {', '.join(wan_insecure_proto_rules)}",
                    "recommendation": "Review these rules. Avoid using insecure protocols, especially over the WAN.",
                }
            )

        if block_rules_no_log:
            findings.append(
                {
                    "check": "Firewall Log Settings",
                    "severity": "Low",
                    "description": f"{len(block_rules_no_log)} firewall rule(s) that block or reject traffic do not have logging enabled (Examples: {', '.join(block_rules_no_log[:3])}{'...' if len(block_rules_no_log) > 3 else ''}).",
                    "recommendation": "Consider enabling logging on block/reject rules (especially the default deny, if applicable) to monitor potential malicious activity.",
                }
            )
        else:
            findings.append(
                {
                    "check": "Firewall Log Settings",
                    "severity": "Info",
                    "description": "Block/reject rules checked appear to have logging enabled.",
                    "recommendation": None,
                }
            )

        # 4. Check for enabled UPnP service
        if "miniupnpd" in running_services:
            findings.append(
                {
                    "check": "UPnP Service",
                    "severity": "Low",
                    "description": "The UPnP (Universal Plug and Play) service is enabled and running.",
                    "recommendation": "Ensure UPnP is intentionally enabled and configured securely if needed. Disable it if unused, as it can potentially open ports automatically.",
                }
            )

        await ctx.info("Firewall audit checks complete.")

    except ConfigurationError as e:
        await ctx.error(str(e))
        return f"Configuration Error: {e!s}"
    except Exception as e:
        logger.error(f"Error during firewall audit: {e!s}", exc_info=True)
        await ctx.error(f"Error performing firewall audit: {e!s}")
        # Return partial findings if any were collected before the error
        if findings:
            findings.append(
                {
                    "check": "Audit Error",
                    "severity": "Critical",
                    "description": f"An error occurred during the audit: {e!s}. Results may be incomplete.",
                    "recommendation": "Check server logs for details.",
                }
            )
            return json.dumps({"audit_findings": findings}, indent=2)
        return json.dumps({"error": f"Failed to perform audit: {e!s}"}, indent=2)

    return json.dumps({"audit_findings": findings}, indent=2)
