#!/usr/bin/env python3
"""
OPNsense MCP Server

A Model Context Protocol (MCP) server implementation for managing OPNsense firewalls.
This server allows Claude and other MCP-compatible clients to interact with all features
exposed by the OPNsense API.

Author: Claude (based on user request)
Date: May 12, 2025
"""

import os
import json
import logging
import asyncio
import base64
from typing import Dict, List, Any, Optional, Union, Tuple, TypedDict
import urllib.parse
import httpx
from mcp import FastMCP, Context, ResourceRequest, types


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("opnsense-mcp")


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
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error: {e}")
            raise
        except httpx.RequestError as e:
            logger.error(f"Request error: {e}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
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
        response = await opnsense_client.request("GET", "/core/menu/getItems")
        
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
        firmware = await opnsense_client.request("GET", "/core/firmware/status")
        
        # Get system information
        system_info = await opnsense_client.request("GET", "/core/system/info")
        
        # Get service status
        services = await opnsense_client.request(
            "POST", 
            "/core/service/search",
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
            "/firewall/filter/searchRule",
            data={
                "current": page,
                "rowCount": rows_per_page,
                "searchPhrase": search_phrase
            }
        )
        
        return json.dumps(response, indent=2)
    except Exception as e:
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
            "/firewall/filter/addRule",
            data=rule_data
        )
        
        # Apply changes
        await ctx.info("Rule added, applying changes...")
        apply_result = await opnsense_client.request(
            "POST",
            "/firewall/filter/apply"
        )
        
        return json.dumps({
            "add_result": add_result,
            "apply_result": apply_result
        }, indent=2)
    except Exception as e:
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
            f"/firewall/filter/delRule/{uuid}"
        )
        
        # Apply changes
        await ctx.info("Rule deleted, applying changes...")
        apply_result = await opnsense_client.request(
            "POST",
            "/firewall/filter/apply"
        )
        
        return json.dumps({
            "delete_result": delete_result,
            "apply_result": apply_result
        }, indent=2)
    except Exception as e:
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
            f"/firewall/filter/toggleRule/{uuid}/{1 if enabled else 0}"
        )
        
        # Apply changes
        await ctx.info(f"Rule {'enabled' if enabled else 'disabled'}, applying changes...")
        apply_result = await opnsense_client.request(
            "POST",
            "/firewall/filter/apply"
        )
        
        return json.dumps({
            "toggle_result": toggle_result,
            "apply_result": apply_result
        }, indent=2)
    except Exception as e:
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
        response = await opnsense_client.request("GET", "/interfaces/overview/interfacesInfo")
        return json.dumps(response, indent=2)
    except Exception as e:
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
        response = await opnsense_client.request("GET", "/dhcp/leases/searchLease")
        return json.dumps(response, indent=2)
    except Exception as e:
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
            "/firewall/alias/searchItem",
            data={
                "current": page,
                "rowCount": rows_per_page,
                "searchPhrase": search_phrase
            }
        )
        
        return json.dumps(response, indent=2)
    except Exception as e:
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
            f"/firewall/alias_util/add/{alias_name}/{address}"
        )
        
        # Reconfigure aliases
        await ctx.info("Entry added, applying changes...")
        reconfigure_result = await opnsense_client.request(
            "POST",
            "/firewall/alias/reconfigure"
        )
        
        return json.dumps({
            "add_result": add_result,
            "reconfigure_result": reconfigure_result
        }, indent=2)
    except Exception as e:
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
            f"/firewall/alias_util/delete/{alias_name}/{address}"
        )
        
        # Reconfigure aliases
        await ctx.info("Entry deleted, applying changes...")
        reconfigure_result = await opnsense_client.request(
            "POST",
            "/firewall/alias/reconfigure"
        )
        
        return json.dumps({
            "delete_result": delete_result,
            "reconfigure_result": reconfigure_result
        }, indent=2)
    except Exception as e:
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
        await test_client.request("GET", "/core/firmware/status")
        
        # If the above call succeeds, save the configuration
        if opnsense_client:
            await opnsense_client.close()
            
        opnsense_client = test_client
        
        return "OPNsense connection configured successfully"
    except Exception as e:
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
            "/diagnostics/log/firewall",
            params={"limit": count, "filter": filter_text}
        )
        
        return json.dumps(response, indent=2)
    except Exception as e:
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
            f"/core/service/restart/{service_name}"
        )
        
        return json.dumps(response, indent=2)
    except Exception as e:
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
        response = await opnsense_client.request("POST", "/core/backup/download")
        return json.dumps(response, indent=2)
    except Exception as e:
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
        response = await opnsense_client.request("GET", "/routes/routes/get")
        return json.dumps(response, indent=2)
    except Exception as e:
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
        cpu = await opnsense_client.request("GET", "/diagnostics/system/processor")
        memory = await opnsense_client.request("GET", "/diagnostics/system/memory")
        disk = await opnsense_client.request("GET", "/diagnostics/system/storage")
        temperature = await opnsense_client.request("GET", "/diagnostics/system/temperature")
        
        # Combine results
        return json.dumps({
            "cpu": cpu,
            "memory": memory,
            "disk": disk,
            "temperature": temperature
        }, indent=2)
    except Exception as e:
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
        response = await opnsense_client.request("GET", "/core/firmware/plugins")
        return json.dumps(response, indent=2)
    except Exception as e:
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
            f"/core/firmware/install/{plugin_name}"
        )
        
        return json.dumps(response, indent=2)
    except Exception as e:
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
            response = await opnsense_client.request("GET", "/openvpn/service/getStatus")
        elif vpn_type.lower() == "ipsec":
            response = await opnsense_client.request("GET", "/ipsec/service/status")
        elif vpn_type.lower() == "wireguard":
            response = await opnsense_client.request("GET", "/wireguard/service/show")
        else:
            return f"Unsupported VPN type: {vpn_type}"
        
        return json.dumps(response, indent=2)
    except Exception as e:
        await ctx.error(f"Error fetching VPN connections: {str(e)}")
        return f"Error: {str(e)}"


# Entry point
if __name__ == "__main__":
    mcp.run()