# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an OPNsense MCP (Model Context Protocol) Server - a Python application that enables AI clients like Claude Desktop to manage OPNsense firewalls through natural language. The server translates AI requests into OPNsense API calls.

## Key Architecture

- **Single Python file**: `opnsense-mcp-server.py` contains the entire MCP server implementation
- **FastMCP framework**: Uses Anthropic's FastMCP library for MCP protocol handling
- **OPNsenseClient class**: Handles authentication and API communication with OPNsense firewalls
- **Tool-based architecture**: Each function decorated with `@mcp.tool()` represents a capability exposed to AI clients
- **Global client**: Uses a global `opnsense_client` instance that gets configured via the `configure_opnsense_connection` tool

## Development Commands

### Setup Environment
```bash
# Install uv (Python package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create virtual environment
uv venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install dependencies
uv pip install -r requirements.txt
```

### Running the Server
```bash
# Make executable (Linux/macOS)
chmod +x opnsense-mcp-server.py

# Run directly
python opnsense-mcp-server.py
```

### Docker Support
```bash
# Build image
docker build -t opnsense-mcp-server .

# Run with docker-compose
docker-compose up -d
```

## Key Implementation Details

### Authentication
- Uses HTTP Basic Auth with base64-encoded API key/secret
- Configured via `configure_opnsense_connection` tool at runtime
- No persistent configuration storage

### Error Handling
- All tools check for initialized client before proceeding
- Comprehensive exception logging with context
- Returns user-friendly error messages

### API Patterns
- Constants defined for all OPNsense API endpoints
- Consistent request/response handling in `OPNsenseClient.request()`
- POST requests for configuration changes are followed by "apply" calls where needed

### Tool Categories
- **Configuration**: `configure_opnsense_connection`
- **System Info**: `get_system_status`, `get_system_health`, `get_api_endpoints`
- **Firewall**: `firewall_get_rules`, `firewall_add_rule`, `firewall_delete_rule`, `firewall_toggle_rule`
- **Network**: `get_interfaces`, `get_dhcp_leases`, `get_system_routes`
- **Aliases**: `get_firewall_aliases`, `add_to_alias`, `delete_from_alias`
- **NAT Management**:
  - **Outbound NAT**: `nat_list_outbound_rules`, `nat_add_outbound_rule`, `nat_delete_outbound_rule`, `nat_toggle_outbound_rule`
  - **One-to-One NAT**: `nat_list_one_to_one_rules`, `nat_add_one_to_one_rule`, `nat_delete_one_to_one_rule`
  - **Port Forwarding Info**: `nat_get_port_forward_info` (explains current limitations)
- **Services**: `restart_service`, `list_plugins`, `install_plugin`
- **VPN**: `get_vpn_connections` (OpenVPN, IPsec, WireGuard)
- **Logs**: `get_firewall_logs`
- **Backup**: `backup_config`
- **Security**: `perform_firewall_audit`
- **Traffic Shaping & QoS**:
  - **Core Management**: `traffic_shaper_get_status`, `traffic_shaper_reconfigure`, `traffic_shaper_get_settings`
  - **Pipe Management**: `traffic_shaper_list_pipes`, `traffic_shaper_get_pipe`, `traffic_shaper_create_pipe`, `traffic_shaper_update_pipe`, `traffic_shaper_delete_pipe`, `traffic_shaper_toggle_pipe`
  - **Queue Management**: `traffic_shaper_list_queues`, `traffic_shaper_get_queue`, `traffic_shaper_create_queue`, `traffic_shaper_update_queue`, `traffic_shaper_delete_queue`, `traffic_shaper_toggle_queue`
  - **Rule Management**: `traffic_shaper_list_rules`, `traffic_shaper_get_rule`, `traffic_shaper_create_rule`, `traffic_shaper_update_rule`, `traffic_shaper_delete_rule`, `traffic_shaper_toggle_rule`
  - **Common Use Cases**: `traffic_shaper_limit_user_bandwidth`, `traffic_shaper_prioritize_voip`, `traffic_shaper_setup_gaming_priority`, `traffic_shaper_create_guest_limits`
- **Custom**: `exec_api_call` for arbitrary API endpoints

### Traffic Shaping & QoS Architecture

The traffic shaping implementation follows OPNsense's hierarchical QoS model:

**Architecture Hierarchy:**
- **Pipes**: Define hard bandwidth limits with configurable schedulers (FIFO, DRR, QFQ, FQ-CoDel, FQ-PIE)
- **Queues**: Provide weighted bandwidth sharing within pipes (1-100 weight)
- **Rules**: Apply shaping policies to specific traffic flows based on interface, protocol, source/destination

**Key Features:**
- **Comprehensive Validation**: Parameter validation for bandwidth metrics, queue sizes, schedulers
- **Relationship Management**: Automatic validation of pipe-queue-rule dependencies
- **Flexible Targeting**: Rules can target either pipes (hard limits) or queues (weighted sharing)
- **Auto-Configuration**: Automatic service reconfiguration after all changes
- **Common Use Cases**: High-level helpers for typical scenarios (per-user limits, VoIP priority, gaming optimization, guest networks)

**Supported Bandwidth Metrics:** bit/s, Kbit/s, Mbit/s, Gbit/s
**Supported Schedulers:** FIFO, DRR, QFQ, FQ-CoDel (recommended), FQ-PIE

### Security Audit Feature

The `perform_firewall_audit` tool performs automated security checks:

- Firmware/plugin update status
- WAN management access exposure
- Overly permissive firewall rules
- Insecure protocol usage
- Logging configuration

## Claude Desktop Integration

The `setup-claude.sh` script automatically configures Claude Desktop to use this MCP server by modifying the `claude_desktop_config.json` file with the appropriate server entry.
