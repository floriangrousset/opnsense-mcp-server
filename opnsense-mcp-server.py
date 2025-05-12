#!/usr/bin/env python3
"""
OPNsense MCP Server

A Model Context Protocol (MCP) server implementation for managing OPNsense firewalls.
This server allows Claude and other MCP-compatible clients to interact with all features
exposed by the OPNsense API. This server is designed to be run on a local machine and
not exposed to the public internet. Please see the README.md file for more information.
"""

import os
import json
import logging
import asyncio
import base64
from typing import Dict, List, Any, Optional, Union, Tuple, TypedDict
import urllib.parse
import httpx
from mcp.server.fastmcp import FastMCP, Context
from mcp import types


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("opnsense-mcp")


# API Endpoint Constants
# Core
API_CORE_MENU_GET_ITEMS = "/core/menu/getItems"
API_CORE_FIRMWARE_STATUS = "/core/firmware/status"
API_CORE_SYSTEM_INFO = "/core/system/info"
API_CORE_SERVICE_SEARCH = "/core/service/search"
API_CORE_SERVICE_RESTART = "/core/service/restart"  # Needs /{service_name}
API_CORE_BACKUP_DOWNLOAD = "/core/backup/download"
API_CORE_FIRMWARE_PLUGINS = "/core/firmware/plugins"
API_CORE_FIRMWARE_INSTALL = "/core/firmware/install"  # Needs /{plugin_name}

# Firewall
API_FIREWALL_FILTER_SEARCH_RULE = "/firewall/filter/searchRule"
API_FIREWALL_FILTER_ADD_RULE = "/firewall/filter/addRule"
API_FIREWALL_FILTER_DEL_RULE = "/firewall/filter/delRule"    # Needs /{uuid}
API_FIREWALL_FILTER_TOGGLE_RULE = "/firewall/filter/toggleRule" # Needs /{uuid}/{enabled_int}
API_FIREWALL_FILTER_APPLY = "/firewall/filter/apply"
API_FIREWALL_ALIAS_SEARCH_ITEM = "/firewall/alias/searchItem"
API_FIREWALL_ALIAS_UTIL_ADD = "/firewall/alias_util/add"      # Needs /{alias_name}/{address}
API_FIREWALL_ALIAS_UTIL_DELETE = "/firewall/alias_util/delete"  # Needs /{alias_name}/{address}
API_FIREWALL_ALIAS_RECONFIGURE = "/firewall/alias/reconfigure"

# Interfaces
API_INTERFACES_OVERVIEW_INFO = "/interfaces/overview/interfacesInfo"

# DHCP
API_DHCP_LEASES_SEARCH = "/dhcp/leases/searchLease"

# Diagnostics
API_DIAGNOSTICS_LOG_FIREWALL = "/diagnostics/log/firewall"
API_DIAGNOSTICS_SYSTEM_PROCESSOR = "/diagnostics/system/processor"
API_DIAGNOSTICS_SYSTEM_MEMORY = "/diagnostics/system/memory"
API_DIAGNOSTICS_SYSTEM_STORAGE = "/diagnostics/system/storage"
API_DIAGNOSTICS_SYSTEM_TEMPERATURE = "/diagnostics/system/temperature"

# Routes
API_ROUTES_GET = "/routes/routes/get"

# VPN
API_OPENVPN_SERVICE_STATUS = "/openvpn/service/getStatus"
API_IPSEC_SERVICE_STATUS = "/ipsec/service/status"
API_WIREGUARD_SERVICE_SHOW = "/wireguard/service/show"


class OPNsenseConfig(TypedDict, total=False):
    """Configuration for OPNsense connection."""
    url: str
    api_key: str
    api_secret: str
    verify_ssl: bool


class OPNsenseClient:
    """Client for interacting with OPNsense API."""
    
    def __init__(self, config: OPNsenseConfig):
        """Initialize OPNsense API client.
        
        Args:
            config: Configuration for OPNsense connection
        """
        self.base_url = config["url"].rstrip("/")
        self.api_key = config["api_key"]
        self.api_secret = config["api_secret"]
        self.verify_ssl = config.get("verify_ssl", True)
        self.client = httpx.AsyncClient(verify=self.verify_ssl)
        
        # Set up Basic Auth
        auth_str = f"{self.api_key}:{self.api_secret}"
        self.auth_header = base64.b64encode(auth_str.encode()).decode()
        
        logger.info(f"Initialized OPNsense client for {self.base_url}")
    
    async def close(self):
        """Close the httpx client."""
        await self.client.aclose()
    
    async def request(
        self, 
        method: str, 
        endpoint: str, 
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Make a request to the OPNsense API.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (e.g., "/core/firmware/status")
            data: Request payload for POST requests
            params: Query parameters for GET requests
            
        Returns:
            Response from the API as a dictionary
        """
        url = f"{self.base_url}/api{endpoint}"
        headers = {
            "Authorization": f"Basic {self.auth_header}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        try:
            logger.debug(f"Making {method} request to {url}")
            if method.upper() == "GET":
                response = await self.client.get(url, headers=headers, params=params)
            elif method.upper() == "POST":
                response = await self.client.post(url, headers=headers, json=data)
            else:
                # For other methods like DELETE, PUT if ever needed.
                # httpx.request allows specifying the method directly.
                # response = await self.client.request(method.upper(), url, headers=headers, json=data if data else None)
                logger.error(f"Unsupported HTTP method in OPNsenseClient.request: {method}")
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error: {e.response.text}", exc_info=True)
            raise
        except httpx.RequestError as e:
            logger.error(f"Request error: {e}", exc_info=True)
            raise
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}", exc_info=True)
            raise
        except Exception as e: # Catch-all for unexpected errors during the request itself
            logger.error(f"Unexpected error in OPNsenseClient.request: {e}", exc_info=True)
            raise


# Initialize MCP server
mcp = FastMCP("OPNsense MCP Server", description="Manage OPNsense firewalls via MCP")


# Set up global client instance that will be populated during initialization
opnsense_client: Optional[OPNsenseClient] = None


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
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        # Get all available modules first
        response = await opnsense_client.request("GET", API_CORE_MENU_GET_ITEMS)
        
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
    except Exception as e:
        logger.error(f"Error in get_api_endpoints: {str(e)}", exc_info=True)
        await ctx.error(f"Error fetching API endpoints: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="get_system_status", description="Get OPNsense system status")
async def get_system_status(ctx: Context) -> str:
    """Get OPNsense system status.
    
    Args:
        ctx: MCP context
        
    Returns:
        Formatted system status information
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        # Get firmware status
        firmware = await opnsense_client.request("GET", API_CORE_FIRMWARE_STATUS)
        
        # Get system information
        system_info = await opnsense_client.request("GET", API_CORE_SYSTEM_INFO)
        
        # Get service status
        services = await opnsense_client.request(
            "POST", 
            API_CORE_SERVICE_SEARCH,
            data={"current": 1, "rowCount": -1, "searchPhrase": ""}
        )
        
        # Format and return the combined status
        status = {
            "firmware": firmware,
            "system": system_info,
            "services": services.get("rows", [])
        }
        
        return json.dumps(status, indent=2)
    except Exception as e:
        logger.error(f"Error in get_system_status: {str(e)}", exc_info=True)
        await ctx.error(f"Error fetching system status: {str(e)}")
        return f"Error: {str(e)}"


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
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        response = await opnsense_client.request(
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
    """Add a new firewall rule.
    
    Args:
        ctx: MCP context
        description: Rule description
        action: Rule action (pass, block, reject)
        interface: Network interface
        direction: Traffic direction (in, out)
        ipprotocol: IP protocol (inet for IPv4, inet6 for IPv6)
        protocol: Transport protocol (tcp, udp, any)
        source_net: Source network/host
        destination_net: Destination network/host
        destination_port: Destination port(s)
        enabled: Whether the rule is enabled
        
    Returns:
        JSON string with the result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
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
        add_result = await opnsense_client.request(
            "POST",
            API_FIREWALL_FILTER_ADD_RULE,
            data=rule_data
        )
        
        # Apply changes
        await ctx.info("Rule added, applying changes...")
        apply_result = await opnsense_client.request(
            "POST",
            API_FIREWALL_FILTER_APPLY
        )
        
        return json.dumps({
            "add_result": add_result,
            "apply_result": apply_result
        }, indent=2)
    except Exception as e:
        logger.error(f"Error in firewall_add_rule: {str(e)}", exc_info=True)
        await ctx.error(f"Error adding firewall rule: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="firewall_delete_rule", description="Delete a firewall rule by UUID")
async def firewall_delete_rule(ctx: Context, uuid: str) -> str:
    """Delete a firewall rule by UUID.
    
    Args:
        ctx: MCP context
        uuid: UUID of the rule to delete
        
    Returns:
        JSON string with the result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        # Delete the rule
        delete_result = await opnsense_client.request(
            "POST",
            f"{API_FIREWALL_FILTER_DEL_RULE}/{uuid}"
        )
        
        # Apply changes
        await ctx.info("Rule deleted, applying changes...")
        apply_result = await opnsense_client.request(
            "POST",
            API_FIREWALL_FILTER_APPLY
        )
        
        return json.dumps({
            "delete_result": delete_result,
            "apply_result": apply_result
        }, indent=2)
    except Exception as e:
        logger.error(f"Error in firewall_delete_rule (uuid: {uuid}): {str(e)}", exc_info=True)
        await ctx.error(f"Error deleting firewall rule: {str(e)}")
        return f"Error: {str(e)}"


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
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        # Toggle the rule
        toggle_result = await opnsense_client.request(
            "POST",
            f"{API_FIREWALL_FILTER_TOGGLE_RULE}/{uuid}/{1 if enabled else 0}"
        )
        
        # Apply changes
        await ctx.info(f"Rule {'enabled' if enabled else 'disabled'}, applying changes...")
        apply_result = await opnsense_client.request(
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


@mcp.tool(name="get_interfaces", description="Get network interfaces")
async def get_interfaces(ctx: Context) -> str:
    """Get network interfaces.
    
    Args:
        ctx: MCP context
        
    Returns:
        JSON string of network interfaces
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        response = await opnsense_client.request("GET", API_INTERFACES_OVERVIEW_INFO)
        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in get_interfaces: {str(e)}", exc_info=True)
        await ctx.error(f"Error fetching interfaces: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="get_dhcp_leases", description="Get DHCP leases")
async def get_dhcp_leases(ctx: Context) -> str:
    """Get DHCP leases.
    
    Args:
        ctx: MCP context
        
    Returns:
        JSON string of DHCP leases
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        response = await opnsense_client.request("GET", API_DHCP_LEASES_SEARCH)
        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in get_dhcp_leases: {str(e)}", exc_info=True)
        await ctx.error(f"Error fetching DHCP leases: {str(e)}")
        return f"Error: {str(e)}"


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
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        response = await opnsense_client.request(
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
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        # Add to alias
        add_result = await opnsense_client.request(
            "POST",
            f"{API_FIREWALL_ALIAS_UTIL_ADD}/{alias_name}/{urllib.parse.quote_plus(address)}"
        )
        
        # Reconfigure aliases
        await ctx.info("Entry added, applying changes...")
        reconfigure_result = await opnsense_client.request(
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
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        # Delete from alias
        delete_result = await opnsense_client.request(
            "POST",
            f"{API_FIREWALL_ALIAS_UTIL_DELETE}/{alias_name}/{urllib.parse.quote_plus(address)}"
        )
        
        # Reconfigure aliases
        await ctx.info("Entry deleted, applying changes...")
        reconfigure_result = await opnsense_client.request(
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


@mcp.tool(name="exec_api_call", description="Execute a custom API call to OPNsense")
async def exec_api_call(
    ctx: Context,
    method: str,
    endpoint: str,
    data: Optional[str] = None,
    params: Optional[str] = None
) -> str:
    """Execute a custom API call to OPNsense.
    
    Args:
        ctx: MCP context
        method: HTTP method (GET, POST)
        endpoint: API endpoint (e.g., "/core/firmware/status")
        data: JSON string of POST data (optional)
        params: JSON string of query parameters for GET (optional)
        
    Returns:
        JSON string with the API response
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        data_dict = json.loads(data) if data else None
        params_dict = json.loads(params) if params else None
        
        response = await opnsense_client.request(
            method,
            endpoint,
            data=data_dict,
            params=params_dict
        )
        
        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in exec_api_call (method: {method}, endpoint: {endpoint}): {str(e)}", exc_info=True)
        await ctx.error(f"Error executing API call: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="configure_opnsense_connection", description="Configure the OPNsense connection")
async def configure_opnsense_connection(
    ctx: Context,
    url: str,
    api_key: str,
    api_secret: str,
    verify_ssl: bool = True
) -> str:
    """Configure the OPNsense connection.
    
    Args:
        ctx: MCP context
        url: OPNsense base URL (e.g., "https://192.168.1.1")
        api_key: API key
        api_secret: API secret
        verify_ssl: Whether to verify SSL certificates
        
    Returns:
        Success message
    """
    global opnsense_client
    
    try:
        # Test the connection first
        config = OPNsenseConfig(
            url=url,
            api_key=api_key,
            api_secret=api_secret,
            verify_ssl=verify_ssl
        )
        
        test_client = OPNsenseClient(config)
        
        # Try to make a simple API call to verify connection
        await test_client.request("GET", API_CORE_FIRMWARE_STATUS)
        
        # If the above call succeeds, save the configuration
        if opnsense_client:
            await opnsense_client.close()
            
        opnsense_client = test_client
        
        return "OPNsense connection configured successfully"
    except Exception as e:
        logger.error(f"Error in configure_opnsense_connection (url: {url}): {str(e)}", exc_info=True)
        await ctx.error(f"Error configuring OPNsense connection: {str(e)}")
        return f"Error: {str(e)}"


# More tools for other OPNsense modules can be added here


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
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        response = await opnsense_client.request(
            "GET",
            API_DIAGNOSTICS_LOG_FIREWALL,
            params={"limit": count, "filter": filter_text}
        )
        
        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in get_firewall_logs: {str(e)}", exc_info=True)
        await ctx.error(f"Error fetching firewall logs: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="restart_service", description="Restart an OPNsense service")
async def restart_service(ctx: Context, service_name: str) -> str:
    """Restart an OPNsense service.
    
    Args:
        ctx: MCP context
        service_name: Name of the service to restart
        
    Returns:
        JSON string with the result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        response = await opnsense_client.request(
            "POST",
            f"{API_CORE_SERVICE_RESTART}/{service_name}"
        )
        
        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in restart_service (service: {service_name}): {str(e)}", exc_info=True)
        await ctx.error(f"Error restarting service: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="backup_config", description="Create a backup of the OPNsense configuration")
async def backup_config(ctx: Context) -> str:
    """Create a backup of the OPNsense configuration.
    
    Args:
        ctx: MCP context
        
    Returns:
        JSON string with the result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        response = await opnsense_client.request("POST", API_CORE_BACKUP_DOWNLOAD)
        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in backup_config: {str(e)}", exc_info=True)
        await ctx.error(f"Error creating backup: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="get_system_routes", description="Get system routing table")
async def get_system_routes(ctx: Context) -> str:
    """Get system routing table.
    
    Args:
        ctx: MCP context
        
    Returns:
        JSON string of system routes
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        response = await opnsense_client.request("GET", API_ROUTES_GET)
        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in get_system_routes: {str(e)}", exc_info=True)
        await ctx.error(f"Error fetching system routes: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="get_system_health", description="Get system health metrics")
async def get_system_health(ctx: Context) -> str:
    """Get system health metrics.
    
    Args:
        ctx: MCP context
        
    Returns:
        JSON string of system health metrics
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        # Get multiple health metrics
        cpu = await opnsense_client.request("GET", API_DIAGNOSTICS_SYSTEM_PROCESSOR)
        memory = await opnsense_client.request("GET", API_DIAGNOSTICS_SYSTEM_MEMORY)
        disk = await opnsense_client.request("GET", API_DIAGNOSTICS_SYSTEM_STORAGE)
        temperature = await opnsense_client.request("GET", API_DIAGNOSTICS_SYSTEM_TEMPERATURE)
        
        # Combine results
        return json.dumps({
            "cpu": cpu,
            "memory": memory,
            "disk": disk,
            "temperature": temperature
        }, indent=2)
    except Exception as e:
        logger.error(f"Error in get_system_health: {str(e)}", exc_info=True)
        await ctx.error(f"Error fetching system health: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="list_plugins", description="List installed plugins")
async def list_plugins(ctx: Context) -> str:
    """List installed plugins.
    
    Args:
        ctx: MCP context
        
    Returns:
        JSON string of installed plugins
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        response = await opnsense_client.request("GET", API_CORE_FIRMWARE_PLUGINS)
        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in list_plugins: {str(e)}", exc_info=True)
        await ctx.error(f"Error listing plugins: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="install_plugin", description="Install a plugin")
async def install_plugin(ctx: Context, plugin_name: str) -> str:
    """Install a plugin.
    
    Args:
        ctx: MCP context
        plugin_name: Name of the plugin to install
        
    Returns:
        JSON string with the result
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        response = await opnsense_client.request(
            "POST",
            f"{API_CORE_FIRMWARE_INSTALL}/{plugin_name}"
        )
        
        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in install_plugin (plugin: {plugin_name}): {str(e)}", exc_info=True)
        await ctx.error(f"Error installing plugin: {str(e)}")
        return f"Error: {str(e)}"


@mcp.tool(name="get_vpn_connections", description="Get VPN connection status")
async def get_vpn_connections(ctx: Context, vpn_type: str = "OpenVPN") -> str:
    """Get VPN connection status.
    
    Args:
        ctx: MCP context
        vpn_type: Type of VPN (OpenVPN, IPsec, WireGuard)
        
    Returns:
        JSON string of VPN connections
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."
    
    try:
        if vpn_type.lower() == "openvpn":
            response = await opnsense_client.request("GET", API_OPENVPN_SERVICE_STATUS)
        elif vpn_type.lower() == "ipsec":
            response = await opnsense_client.request("GET", API_IPSEC_SERVICE_STATUS)
        elif vpn_type.lower() == "wireguard":
            response = await opnsense_client.request("GET", API_WIREGUARD_SERVICE_SHOW)
        else:
            return f"Unsupported VPN type: {vpn_type}"
        
        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error(f"Error in get_vpn_connections (type: {vpn_type}): {str(e)}", exc_info=True)
        await ctx.error(f"Error fetching VPN connections: {str(e)}")
        return f"Error: {str(e)}"


# --- Firewall Audit Feature ---

async def _get_all_rules(client: OPNsenseClient) -> List[Dict[str, Any]]:
    """Helper to fetch all firewall rules using pagination."""
    all_rules = []
    current_page = 1
    rows_per_page = 500  # Fetch in larger batches
    while True:
        try:
            response = await client.request(
                "POST",
                API_FIREWALL_FILTER_SEARCH_RULE,
                data={
                    "current": current_page,
                    "rowCount": rows_per_page,
                    "searchPhrase": ""
                }
            )
            rules = response.get("rows", [])
            if not rules:
                break
            all_rules.extend(rules)
            if len(rules) < rows_per_page:
                break # Last page
            current_page += 1
        except Exception as e:
            logger.error(f"Error fetching page {current_page} of firewall rules: {e}", exc_info=True)
            # Return what we have so far, audit can proceed with partial data
            break 
    return all_rules

async def _get_wan_interfaces(client: OPNsenseClient) -> List[str]:
    """Helper to identify WAN interfaces."""
    wan_interfaces = []
    try:
        interfaces_info = await client.request("GET", API_INTERFACES_OVERVIEW_INFO)
        for if_name, if_data in interfaces_info.items():
            # Heuristic: Interface is likely WAN if it has a gateway and isn't loopback/internal
            # OPNsense often names the default WAN 'wan' but users can rename it.
            # Checking for a non-empty gateway field is a common indicator.
            if if_data.get("gateway") and if_data.get("gateway") != "none":
                 wan_interfaces.append(if_name)
            # Fallback: Explicitly check for common WAN names if gateway check fails 
            elif if_name.lower() == 'wan' and not wan_interfaces: 
                 wan_interfaces.append(if_name)
    except Exception as e:
        logger.error(f"Error fetching interfaces info for audit: {e}", exc_info=True)
    
    # If still no WAN identified, maybe return a default guess? For now, return empty. 
    if not wan_interfaces:
        logger.warning("Could not reliably identify WAN interfaces for audit.")
        
    return wan_interfaces

@mcp.tool(name="perform_firewall_audit", description="Performs a basic security audit of the OPNsense configuration.")
async def perform_firewall_audit(ctx: Context) -> str:
    """Performs a basic security audit of the OPNsense configuration.

    Checks for common potential security issues like outdated firmware/plugins, 
    management access from WAN, overly permissive rules, etc.

    Args:
        ctx: MCP context

    Returns:
        JSON string containing a list of audit findings.
    """
    if not opnsense_client:
        return "OPNsense client not initialized. Please configure the server first."

    findings = []
    await ctx.info("Starting OPNsense firewall audit...")

    try:
        # --- Fetch Data --- 
        await ctx.info("Fetching required data (firmware, rules, interfaces, services)...")
        firmware_status = await opnsense_client.request("GET", API_CORE_FIRMWARE_STATUS)
        all_rules = await _get_all_rules(opnsense_client)
        wan_interfaces = await _get_wan_interfaces(opnsense_client)
        services_response = await opnsense_client.request(
            "POST", 
            API_CORE_SERVICE_SEARCH,
            data={"current": 1, "rowCount": -1, "searchPhrase": ""} # Fetch all services
        )
        running_services = {svc['name']: svc for svc in services_response.get("rows", []) if svc.get('running') == 1}

        await ctx.info(f"Identified WAN interfaces: {wan_interfaces or 'None'}")
        await ctx.info(f"Fetched {len(all_rules)} firewall rules.")

        # --- Perform Checks --- 

        # 1. Firmware Update Check
        if firmware_status.get("status") == "update_available":
            findings.append({
                "check": "Firmware Update",
                "severity": "Medium",
                "description": f"Firmware update available. Current: {firmware_status.get('product_version', 'N/A')}, New: {firmware_status.get('product_new_version', 'N/A')}",
                "recommendation": "Consider updating OPNsense firmware via the GUI (System -> Firmware -> Updates)."
            })
        else:
            findings.append({
                "check": "Firmware Update",
                "severity": "Info",
                "description": "Firmware appears to be up-to-date.",
                "recommendation": None
            })

        # 2. Plugin Update Check
        plugin_updates = firmware_status.get("upgrade_packages", [])
        if plugin_updates:
            plugin_names = [p.get('name', 'N/A') for p in plugin_updates]
            findings.append({
                "check": "Plugin Updates",
                "severity": "Medium",
                "description": f"Updates available for {len(plugin_updates)} plugins: {', '.join(plugin_names)}",
                "recommendation": "Consider updating plugins via the GUI (System -> Firmware -> Updates)."
            })
        else:
             findings.append({
                "check": "Plugin Updates",
                "severity": "Info",
                "description": "Installed plugins appear to be up-to-date.",
                "recommendation": None
            })

        # 3. WAN Management Access Check
        management_ports = {'80', '443', '22'} # HTTP, HTTPS, SSH
        insecure_protocols = {'21', '23'} # FTP, Telnet
        wan_mgmt_rules = []
        wan_insecure_proto_rules = []
        wan_any_any_rules = []
        block_rules_no_log = []

        for rule in all_rules:
            # Skip disabled rules
            if not rule.get('enabled', '0') == '1': 
                continue

            interface = rule.get('interface')
            is_wan_rule = interface in wan_interfaces

            # Check logging on block/reject rules
            if rule.get('action') in ['block', 'reject'] and not rule.get('log', '0') == '1':
                 block_rules_no_log.append(rule.get("descr", rule.get("uuid", "N/A")))

            if not is_wan_rule:
                continue # Only check WAN rules for the following
                
            # Basic parsing - assumes 'any' if specific fields are missing/empty
            src_net = rule.get("source_net", "any")
            dst_net = rule.get("destination_net", "any")
            dst_port = rule.get("destination_port", "any")
            protocol = rule.get("protocol", "any").lower()
            action = rule.get('action')

            # Check Any-Any rule
            if action == 'pass' and src_net == 'any' and dst_net == 'any' and dst_port == 'any':
                wan_any_any_rules.append(rule.get("descr", rule.get("uuid", "N/A")))

            # Check Management Access
            # Simplified: Checks if dest port is one of the management ports
            # Doesn't check destination address (assumes firewall itself)
            if action == 'pass' and dst_port in management_ports:
                wan_mgmt_rules.append(rule.get("descr", rule.get("uuid", "N/A")))

            # Check Insecure Protocols
            if action == 'pass' and dst_port in insecure_protocols:
                 wan_insecure_proto_rules.append(rule.get("descr", rule.get("uuid", "N/A")))

        if wan_mgmt_rules:
            findings.append({
                "check": "WAN Management Access",
                "severity": "High",
                "description": f"Potential firewall rules allowing management access (HTTP/HTTPS/SSH) from WAN found: {', '.join(wan_mgmt_rules)}",
                "recommendation": "Review these rules. Exposing management interfaces to the WAN is highly discouraged. Use VPNs for remote access."
            })
        
        if wan_any_any_rules:
            findings.append({
                "check": "WAN Allow Any-Any",
                "severity": "High",
                "description": f"Potential 'allow any source to any destination' rules found on WAN interface(s): {', '.join(wan_any_any_rules)}",
                "recommendation": "Review these rules. 'Allow any-any' rules on WAN are extremely dangerous and likely misconfigured."
            })
            
        if wan_insecure_proto_rules:
            findings.append({
                "check": "WAN Insecure Protocols",
                "severity": "High",
                "description": f"Potential rules allowing insecure protocols (e.g., Telnet, FTP) from WAN found: {', '.join(wan_insecure_proto_rules)}",
                "recommendation": "Review these rules. Avoid using insecure protocols, especially over the WAN."
            })
        
        if block_rules_no_log:
            findings.append({
                "check": "Firewall Log Settings",
                "severity": "Low",
                "description": f"{len(block_rules_no_log)} firewall rule(s) that block or reject traffic do not have logging enabled (Examples: {', '.join(block_rules_no_log[:3])}{'...' if len(block_rules_no_log) > 3 else ''}).",
                "recommendation": "Consider enabling logging on block/reject rules (especially the default deny, if applicable) to monitor potential malicious activity."
            })
        else:
             findings.append({
                "check": "Firewall Log Settings",
                "severity": "Info",
                "description": "Block/reject rules checked appear to have logging enabled.",
                "recommendation": None
            })

        # 4. Check for enabled UPnP service
        if "miniupnpd" in running_services:
             findings.append({
                "check": "UPnP Service",
                "severity": "Low",
                "description": "The UPnP (Universal Plug and Play) service is enabled and running.",
                "recommendation": "Ensure UPnP is intentionally enabled and configured securely if needed. Disable it if unused, as it can potentially open ports automatically."
            })

        await ctx.info("Firewall audit checks complete.")

    except Exception as e:
        logger.error(f"Error during firewall audit: {str(e)}", exc_info=True)
        await ctx.error(f"Error performing firewall audit: {str(e)}")
        # Return partial findings if any were collected before the error
        if findings:
             findings.append({
                "check": "Audit Error",
                "severity": "Critical",
                "description": f"An error occurred during the audit: {str(e)}. Results may be incomplete.",
                "recommendation": "Check server logs for details."
            })
             return json.dumps({"audit_findings": findings}, indent=2)
        else:
             return json.dumps({"error": f"Failed to perform audit: {str(e)}"}, indent=2)

    return json.dumps({"audit_findings": findings}, indent=2)


# --- End Firewall Audit Feature ---


# Entry point
if __name__ == "__main__":
    mcp.run()