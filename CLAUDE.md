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
- **Interface & VLAN Management**:
  - **Interface Control**: `get_interface_details`, `reload_interface`, `export_interface_config`
  - **VLAN Management**: `list_vlans`, `get_vlan`, `create_vlan_interface`, `update_vlan`, `delete_vlan`, `reconfigure_vlans`
  - **Bridge Management**: `list_bridges`, `get_bridge`, `create_bridge`, `update_bridge`, `delete_bridge`
  - **LAGG Management**: `list_lagg_interfaces`, `get_lagg`, `create_lagg`, `update_lagg`, `delete_lagg`, `reconfigure_lagg`
  - **Virtual IP Management**: `list_virtual_ips`, `get_virtual_ip`, `create_virtual_ip`, `update_virtual_ip`, `delete_virtual_ip`, `reconfigure_virtual_ips`, `get_next_carp_vhid`
- **Certificate Management**:
  - **Certificate Authority (CA)**: `list_certificate_authorities`, `get_certificate_authority`, `create_certificate_authority`, `delete_certificate_authority`, `export_certificate_authority`
  - **Certificates**: `list_certificates`, `get_certificate`, `import_certificate`, `delete_certificate`, `export_certificate`
  - **Certificate Signing Requests (CSR)**: `list_certificate_signing_requests`, `get_certificate_signing_request`, `create_certificate_signing_request`, `delete_certificate_signing_request`
  - **ACME (Let's Encrypt) Accounts**: `list_acme_accounts`, `get_acme_account`, `create_acme_account`, `delete_acme_account`
  - **ACME Certificates**: `list_acme_certificates`, `get_acme_certificate`, `create_acme_certificate`, `sign_acme_certificate`, `revoke_acme_certificate`, `delete_acme_certificate`
  - **Certificate Validation**: `analyze_certificate_expiration`, `validate_certificate_chain`, `get_certificate_usage`
- **Services**: `restart_service`, `list_plugins`, `install_plugin`
- **VPN**: `get_vpn_connections` (OpenVPN, IPsec, WireGuard)
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

### Interface & VLAN Management

Comprehensive network interface management for physical interfaces, VLANs, bridges, LAGG, and virtual IPs:

#### Interface Control
- **Interface Details**: Detailed status and configuration information for specific interfaces
- **Interface Reload**: On-demand interface reconfiguration and status refresh
- **Configuration Export**: Export current interface configurations for backup/analysis

#### VLAN Management
- **VLAN CRUD Operations**: Complete lifecycle management for VLAN interfaces with tag validation (1-4094)
- **Parent Interface Support**: Create VLANs on any physical or bridge interface
- **Bulk Reconfiguration**: Apply all VLAN changes simultaneously for consistent network state

#### Bridge Interface Management
- **Bridge Creation**: Layer 2 bridge interfaces for network segmentation
- **STP Support**: Spanning Tree Protocol configuration for loop prevention
- **Member Management**: Add/remove physical and VLAN interfaces to bridges
- **Advanced Settings**: Bridge priority, hello time, forward delay, max age configuration

#### LAGG Interface Management
- **Link Aggregation**: Combine multiple interfaces for redundancy and performance
- **Protocol Support**: LACP, failover, loadbalance, roundrobin protocols
- **Member Management**: Dynamic addition/removal of physical interfaces
- **Load Balancing**: Advanced load balancing algorithms for optimal traffic distribution

#### Virtual IP Management
- **High Availability**: CARP (Common Address Redundancy Protocol) for failover
- **Proxy ARP**: Transparent IP address handling for network services
- **Auto-VHID Assignment**: Automatic CARP Virtual Host ID assignment with conflict detection
- **Multi-Interface Support**: Virtual IPs across different network interfaces

#### Implementation Features
- **UUID-Based Management**: Reliable resource identification using OPNsense UUIDs
- **Automatic Reconfiguration**: Configuration changes trigger automatic interface reload
- **Comprehensive Validation**: VLAN tag ranges, protocol validation, IP address format checking
- **Conflict Detection**: Prevents VLAN tag conflicts and CARP VHID collisions
- **Graceful Error Handling**: Detailed error messages with context for troubleshooting
- **Network Topology Awareness**: Understanding of interface relationships and dependencies

### Certificate Management

Comprehensive SSL/TLS certificate lifecycle management including Certificate Authorities, certificates, CSRs, and Let's Encrypt automation:

#### Certificate Authority Management
- **CA Lifecycle**: Create, manage, and export Certificate Authorities with configurable parameters
- **Distinguished Name Support**: Full DN configuration with country, state, city, organization details
- **Cryptographic Options**: Configurable digest algorithms (SHA-256/384/512) and key lengths (2048/4096 bits)
- **Certificate Lifetime**: Customizable CA certificate validity periods

#### Certificate Management
- **Certificate Import/Export**: Support for PEM format certificate and private key import/export
- **Certificate Lifecycle**: Complete CRUD operations for certificate management
- **Format Validation**: Built-in PEM format validation for certificates and private keys
- **Certificate Details**: Comprehensive certificate information including issuer, subject, and validity dates

#### Certificate Signing Request (CSR) Management
- **CSR Generation**: Create certificate signing requests with full DN support
- **Cryptographic Configuration**: Configurable digest algorithms and RSA key lengths
- **External CA Integration**: Generate CSRs for external Certificate Authority signing

#### ACME (Let's Encrypt) Integration
- **Account Management**: Create and manage Let's Encrypt accounts with email validation
- **Certificate Automation**: Automated certificate issuance and renewal for domain validation
- **Multi-Domain Support**: Support for Subject Alternative Names (SANs) in certificates
- **Auto-Renewal**: Configurable automatic certificate renewal to prevent expiration
- **Certificate Lifecycle**: Complete ACME certificate signing, revocation, and deletion

#### Certificate Validation & Monitoring
- **Expiration Analysis**: Automated certificate expiration monitoring with configurable warning thresholds
- **Chain Validation**: Certificate trust chain validation and completeness checking
- **Usage Analysis**: Certificate inventory and usage recommendations for cleanup
- **Self-Signed Detection**: Identification of self-signed certificates with security recommendations
- **Private Key Validation**: Verification of certificate-private key pairs for SSL/TLS services

#### Implementation Features
- **UUID-Based Management**: Reliable resource identification using OPNsense UUIDs
- **Automatic Service Integration**: Configuration changes automatically trigger service reconfiguration
- **Comprehensive Validation**: Input validation for all certificate parameters including email formats, country codes, and key lengths
- **Security Best Practices**: Built-in security recommendations and validation for production environments
- **Error Handling**: Detailed error messages with context for certificate management troubleshooting
- **PEM Format Support**: Native support for industry-standard PEM certificate and key formats

## Claude Desktop Integration

The `setup-claude.sh` script automatically configures Claude Desktop to use this MCP server by modifying the `claude_desktop_config.json` file with the appropriate server entry.

## Workflow Reminder

- For every new feature development iteration: 1. move to develop branch and pull the latest 2. create a new branch for the feature to implement 3. implement and make multiple commits to that branch during the implementation of the feature 4. once done with implementing create a pull request of feature branch to develop branch 5. ask me to merge the pull request before you can move to the next feature to implement.