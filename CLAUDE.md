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
- **User & Group Management**:
  - **User CRUD**: `list_users`, `get_user`, `create_user`, `update_user`, `delete_user`, `toggle_user`
  - **Group CRUD**: `list_groups`, `get_group`, `create_group`, `update_group`, `delete_group`
  - **Group Membership**: `add_user_to_group`, `remove_user_from_group`
  - **Authentication**: `list_privileges`, `get_user_effective_privileges`, `assign_privilege_to_user`, `revoke_privilege_from_user`
  - **Auth Servers**: `list_auth_servers`, `test_user_authentication`
  - **Helper Tools**: `create_admin_user`, `create_readonly_user`, `reset_user_password`, `bulk_user_creation`, `setup_user_group_template`
- **Logging & Log Management**:
  - **Core Logging**: `get_system_logs`, `get_service_logs` (squid, haproxy, openvpn, ipsec, dhcp, dns)
  - **Log Search**: `search_logs` (cross-log search with filtering)
  - **Log Export**: `export_logs` (JSON, CSV, text formats with date ranges)
  - **Log Statistics**: `get_log_statistics` (analysis with counts, patterns, trends)
  - **Log Management**: `clear_logs`, `configure_logging` (levels, remote logging, rotation)
  - **Security Analysis**: `analyze_security_events` (threat detection, pattern analysis)
  - **Reporting**: `generate_log_report` (summary, detailed, security, compliance reports)
- **DNS & DHCP Management**:
  - **DHCP Server**: `dhcp_list_servers`, `dhcp_get_server`, `dhcp_set_server`, `dhcp_restart_service`
  - **DHCP Static Mappings**: `dhcp_list_static_mappings`, `dhcp_get_static_mapping`, `dhcp_add_static_mapping`, `dhcp_update_static_mapping`, `dhcp_delete_static_mapping`
  - **DHCP Leases**: `dhcp_get_leases`, `dhcp_search_leases`, `dhcp_get_lease_statistics`
  - **DNS Resolver (Unbound)**: `dns_resolver_get_settings`, `dns_resolver_set_settings`, `dns_resolver_restart_service`
  - **DNS Host Overrides**: `dns_resolver_list_host_overrides`, `dns_resolver_get_host_override`, `dns_resolver_add_host_override`, `dns_resolver_update_host_override`, `dns_resolver_delete_host_override`
  - **DNS Domain Overrides**: `dns_resolver_list_domain_overrides`, `dns_resolver_add_domain_override`
  - **DNS Forwarder (dnsmasq)**: `dns_forwarder_get_settings`, `dns_forwarder_set_settings`, `dns_forwarder_list_hosts`, `dns_forwarder_add_host`, `dns_forwarder_restart_service`
- **Services**: `restart_service`, `list_plugins`, `install_plugin`
- **VPN**: `get_vpn_connections` (OpenVPN, IPsec, WireGuard)
- **Backup**: `backup_config`
- **Security**: `perform_firewall_audit`
- **Custom**: `exec_api_call` for arbitrary API endpoints

### Security Audit Feature

The `perform_firewall_audit` tool performs automated security checks:

- Firmware/plugin update status
- WAN management access exposure
- Overly permissive firewall rules
- Insecure protocol usage
- Logging configuration

### User & Group Management

Comprehensive user management system with RBAC (Role-Based Access Control) support:

#### Core Features
- **Full CRUD Operations**: Complete lifecycle management for users and groups
- **Privilege System**: Fine-grained permission control with effective privilege calculation
- **Group Membership**: Dynamic user-to-group assignment and removal
- **Authentication Testing**: Validation against local and external auth servers (LDAP, RADIUS)

#### Helper Tools for Common Scenarios
- **`create_admin_user`**: One-step creation of administrative users with full system privileges
- **`create_readonly_user`**: Creates monitoring users with predefined view-only permissions
- **`reset_user_password`**: Secure password reset preserving all other user settings
- **`bulk_user_creation`**: Template-driven mass user creation with JSON configuration
- **`setup_user_group_template`**: Creates privilege groups for consistent role-based access

#### Implementation Details
- **UUID-based Resource Management**: All operations use OPNsense UUIDs for reliable identification
- **Configuration Reload**: Automatic config reload after changes for immediate effect
- **Error Handling**: Comprehensive validation with detailed error messages
- **Duplicate Prevention**: Smart handling of redundant operations (already member, privilege already assigned)
- **Effective Privileges**: Combines user and group privileges using set operations for accurate permission calculation

### Logging & Log Management

Comprehensive logging system providing full visibility into OPNsense operations and security events:

#### Core Logging Capabilities
- **Multi-Source Log Access**: System, firewall, authentication, service-specific logs (DHCP, DNS, OpenVPN, IPsec, Squid, HAProxy)
- **Advanced Filtering**: Severity levels, text filtering, date ranges, and cross-log search
- **Real-time Analysis**: Live log streaming and pattern detection
- **Export Functionality**: JSON, CSV, and text formats for external analysis

#### Security & Analysis Tools
- **`analyze_security_events`**: Automated threat detection for brute force attacks, port scans, failed authentication
- **`search_logs`**: Cross-log search with case sensitivity controls and result limiting
- **Pattern Recognition**: Built-in detection for security indicators and suspicious activities
- **Statistical Analysis**: Entry counts, trends, and performance metrics across time periods

#### Management & Configuration
- **`configure_logging`**: Adjust log levels, enable remote syslog, configure rotation schedules
- **`clear_logs`**: Secure log clearing with explicit confirmation requirements
- **Compliance Reporting**: Generate reports for audit and compliance requirements
- **Log Statistics**: Automated analysis of log volume, patterns, and system health

#### Implementation Features
- **API-First Design**: Uses native OPNsense logging APIs with intelligent fallbacks
- **Graceful Degradation**: Falls back to log retrieval when specialized APIs unavailable
- **Comprehensive Error Handling**: Validates parameters and provides clear error messages
- **Security-Focused**: Built-in threat detection and high-risk indicator identification
- **Scalable Architecture**: Handles large log volumes with pagination and limiting

### DNS & DHCP Management

Comprehensive network services management for DHCP server configuration and DNS resolution services:

#### DHCP Server Management
- **Server Configuration**: Per-interface DHCP server setup with range, gateway, DNS, and lease time configuration
- **Static Mappings**: MAC-to-IP address reservations for consistent device addressing
- **Lease Management**: Real-time lease monitoring, statistics, and filtering capabilities
- **Service Control**: DHCP service restart and configuration application

#### DNS Resolver (Unbound) Management
- **Core Settings**: DNSSEC, forwarding, caching, and interface binding configuration
- **Host Overrides**: Custom hostname-to-IP mappings for local network resources
- **Domain Overrides**: Forward specific domains to designated DNS servers
- **Performance Tuning**: Cache size, TTL limits, and query optimization settings

#### DNS Forwarder (dnsmasq) Management
- **Legacy Support**: Alternative DNS service for specific use cases
- **Host Management**: Simple hostname resolution for local devices
- **Configuration Control**: Port, domain, and host file management

#### DHCP Lease Analysis
- **Real-time Monitoring**: Current lease status across all interfaces
- **Statistical Analysis**: Active/expired lease counts and interface distribution
- **Search Capabilities**: Filter leases by interface, state, or search terms

#### Implementation Features
- **Interface-Aware**: All operations respect network interface boundaries
- **Automatic Application**: Configuration changes automatically reload services
- **UUID Management**: Reliable resource identification for updates and deletions
- **Comprehensive Validation**: Input validation and error handling for all operations
- **Service Integration**: Seamless coordination between DHCP and DNS services

## Claude Desktop Integration

The `setup-claude.sh` script automatically configures Claude Desktop to use this MCP server by modifying the `claude_desktop_config.json` file with the appropriate server entry.
- For every new feature development iteration: 1. move to develop branch and pull the latest 2. create a new branch for the feature to implement 3. implement and make multiple commits to that branch during the implementation of the feature 4. once done with implementing create a pull request of feature branch to develop branch 5. ask me to merge the pull request before you can move to the next feature to implement.