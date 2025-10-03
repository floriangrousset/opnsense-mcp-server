# OPNsense MCP Server Rearchitecting Plan

## Overview
Transform the monolithic 9,529-line single-file architecture into a modular, domain-driven structure inspired by Cloudflare's MCP server approach. Split 166 tools across specialized modules while maintaining backward compatibility.

## Architecture Comparison

### Current State
- **Structure**: Single file (`opnsense-mcp-server.py`)
- **Size**: 9,529 lines, 341.5KB
- **Tools**: 166 MCP tools in one namespace
- **Maintainability**: Difficult to navigate, test, and extend

### Target State (Cloudflare-inspired)
- **Structure**: Modular package with domain-specific modules
- **Separation**: Core infrastructure + domain modules + shared utilities
- **Tools**: Grouped by feature domain (12 modules)
- **Maintainability**: Easy to navigate, test, and extend independently

## New Directory Structure

```
opnsense-mcp-server/
├── src/
│   ├── opnsense_mcp/
│   │   ├── __init__.py                    # Package initialization
│   │   ├── main.py                        # FastMCP server setup & entry point
│   │   ├── core/                          # Core infrastructure
│   │   │   ├── __init__.py
│   │   │   ├── client.py                  # OPNsenseClient class
│   │   │   ├── exceptions.py              # Exception hierarchy
│   │   │   ├── models.py                  # Pydantic models & config
│   │   │   ├── connection.py              # ConnectionPool & rate limiting
│   │   │   ├── retry.py                   # Retry mechanisms
│   │   │   └── state.py                   # ServerState management
│   │   ├── shared/                        # Shared utilities
│   │   │   ├── __init__.py
│   │   │   ├── constants.py               # API endpoint constants
│   │   │   ├── error_handlers.py          # Error handling helpers
│   │   │   ├── logging_utils.py           # Logging utilities
│   │   │   └── validators.py              # Common validators
│   │   └── domains/                       # Feature-specific modules
│   │       ├── __init__.py
│   │       ├── configuration.py           # Connection & setup (2 tools)
│   │       ├── system.py                  # System management (8 tools)
│   │       ├── firewall.py                # Firewall rules (5 tools)
│   │       ├── nat.py                     # NAT management (7 tools)
│   │       ├── network.py                 # Interfaces, VLANs, bridges, LAGG, VIPs (20 tools)
│   │       ├── dns_dhcp.py                # DNS & DHCP services (28 tools)
│   │       ├── certificates.py            # Certificate management (25 tools)
│   │       ├── users.py                   # User & group management (31 tools)
│   │       ├── logging.py                 # Log management & analysis (11 tools)
│   │       ├── traffic_shaping.py         # QoS & traffic shaping (23 tools)
│   │       ├── vpn.py                     # VPN connections (1 tool)
│   │       └── utilities.py               # Plugins, backup, audit (4 tools)
├── tests/                                  # Unit & integration tests
│   ├── __init__.py
│   ├── test_core/
│   ├── test_domains/
│   └── conftest.py
├── docs/                                   # Module-specific documentation
│   ├── architecture.md
│   ├── domains/
│   └── migration_guide.md
├── opnsense-mcp-server.py                 # Backward compatibility wrapper
├── requirements.txt
├── pyproject.toml                          # Modern Python project config
├── setup.py                                # Package setup
├── CLAUDE.md
├── README.md
├── PLAN.md                                 # This document
└── setup-claude.sh
```

## Module Breakdown (166 Tools → 12 Domains)

### 1. **Configuration Module** (`domains/configuration.py`) - 2 tools
- `configure_opnsense_connection`
- `get_api_endpoints`

### 2. **System Module** (`domains/system.py`) - 8 tools
- `get_system_status`, `get_system_health`, `get_system_routes`
- `restart_service`, `backup_config`
- `list_plugins`, `install_plugin`
- `perform_firewall_audit`

### 3. **Firewall Module** (`domains/firewall.py`) - 8 tools
- `firewall_get_rules`, `firewall_add_rule`, `firewall_delete_rule`, `firewall_toggle_rule`
- `get_firewall_aliases`, `add_to_alias`, `delete_from_alias`
- `get_firewall_logs`

### 4. **NAT Module** (`domains/nat.py`) - 7 tools
- `nat_list_outbound_rules`, `nat_add_outbound_rule`, `nat_delete_outbound_rule`, `nat_toggle_outbound_rule`
- `nat_list_one_to_one_rules`, `nat_add_one_to_one_rule`, `nat_delete_one_to_one_rule`
- `nat_get_port_forward_info`

### 5. **Network Module** (`domains/network.py`) - 20 tools
- Interfaces: `get_interfaces`, `get_interface_details`, `reload_interface`, `export_interface_config`, `get_dhcp_leases`
- VLANs: `list_vlan_interfaces`, `get_vlan_interface`, `create_vlan_interface`, `update_vlan_interface`, `delete_vlan_interface`
- Bridges: `list_bridge_interfaces`, `get_bridge_interface`, `create_bridge_interface`, `update_bridge_interface`, `delete_bridge_interface`
- LAGG: `list_lagg_interfaces`, `get_lagg_interface`, `create_lagg_interface`, `update_lagg_interface`, `delete_lagg_interface`
- VIPs: `list_virtual_ips`, `get_virtual_ip`, `create_virtual_ip`, `update_virtual_ip`, `delete_virtual_ip`, `get_unused_vhid`

### 6. **DNS & DHCP Module** (`domains/dns_dhcp.py`) - 28 tools
- DHCP Server: `dhcp_list_servers`, `dhcp_get_server`, `dhcp_set_server`, `dhcp_restart_service`
- Static Mappings: `dhcp_list_static_mappings`, `dhcp_get_static_mapping`, `dhcp_add_static_mapping`, `dhcp_update_static_mapping`, `dhcp_delete_static_mapping`
- Leases: `dhcp_get_leases`, `dhcp_search_leases`, `dhcp_get_lease_statistics`
- DNS Resolver: `dns_resolver_get_settings`, `dns_resolver_set_settings`, `dns_resolver_restart_service`
- Host Overrides: `dns_resolver_list_host_overrides`, `dns_resolver_get_host_override`, `dns_resolver_add_host_override`, `dns_resolver_update_host_override`, `dns_resolver_delete_host_override`
- Domain Overrides: `dns_resolver_list_domain_overrides`, `dns_resolver_add_domain_override`
- DNS Forwarder: `dns_forwarder_get_settings`, `dns_forwarder_set_settings`, `dns_forwarder_list_hosts`, `dns_forwarder_add_host`, `dns_forwarder_restart_service`

### 7. **Certificates Module** (`domains/certificates.py`) - 25 tools
- CAs: `list_certificate_authorities`, `get_certificate_authority`, `create_certificate_authority`, `delete_certificate_authority`, `export_certificate_authority`
- Certificates: `list_certificates`, `get_certificate`, `import_certificate`, `delete_certificate`, `export_certificate`
- CSRs: `list_certificate_signing_requests`, `get_certificate_signing_request`, `create_certificate_signing_request`, `delete_certificate_signing_request`
- ACME Accounts: `list_acme_accounts`, `get_acme_account`, `create_acme_account`, `delete_acme_account`
- ACME Certificates: `list_acme_certificates`, `get_acme_certificate`, `create_acme_certificate`, `sign_acme_certificate`, `revoke_acme_certificate`, `delete_acme_certificate`
- Validation: `analyze_certificate_expiration`, `validate_certificate_chain`, `get_certificate_usage`

### 8. **Users Module** (`domains/users.py`) - 31 tools
- Users: `list_users`, `get_user`, `create_user`, `update_user`, `delete_user`, `toggle_user`
- Groups: `list_groups`, `get_group`, `create_group`, `update_group`, `delete_group`
- Membership: `add_user_to_group`, `remove_user_from_group`
- Privileges: `list_privileges`, `get_user_effective_privileges`, `assign_privilege_to_user`, `revoke_privilege_from_user`
- Auth Servers: `list_auth_servers`, `test_user_authentication`
- Helpers: `create_admin_user`, `create_readonly_user`, `reset_user_password`, `bulk_user_creation`, `setup_user_group_template`

### 9. **Logging Module** (`domains/logging.py`) - 11 tools
- Core: `get_system_logs`, `get_service_logs`
- Search: `search_logs`, `export_logs`
- Analysis: `get_log_statistics`, `analyze_security_events`, `generate_log_report`
- Management: `clear_logs`, `configure_logging`

### 10. **Traffic Shaping Module** (`domains/traffic_shaping.py`) - 23 tools
- Core: `traffic_shaper_get_status`, `traffic_shaper_get_settings`, `traffic_shaper_reconfigure`
- Pipes: `traffic_shaper_list_pipes`, `traffic_shaper_get_pipe`, `traffic_shaper_create_pipe`, `traffic_shaper_update_pipe`, `traffic_shaper_delete_pipe`, `traffic_shaper_toggle_pipe`
- Queues: `traffic_shaper_list_queues`, `traffic_shaper_get_queue`, `traffic_shaper_create_queue`, `traffic_shaper_update_queue`, `traffic_shaper_delete_queue`, `traffic_shaper_toggle_queue`
- Rules: `traffic_shaper_list_rules`, `traffic_shaper_get_rule`, `traffic_shaper_create_rule`, `traffic_shaper_update_rule`, `traffic_shaper_delete_rule`, `traffic_shaper_toggle_rule`
- Helpers: `traffic_shaper_limit_user_bandwidth`, `traffic_shaper_prioritize_voip`, `traffic_shaper_setup_gaming_priority`, `traffic_shaper_create_guest_limits`

### 11. **VPN Module** (`domains/vpn.py`) - 1 tool
- `get_vpn_connections`

### 12. **Utilities Module** (`domains/utilities.py`) - 4 tools
- `exec_api_call` (custom API calls)
- Remaining system utilities

## Implementation Phases

### ✅ Phase 0: Planning
- Create PLAN.md
- **Commit**: "docs: add comprehensive modular architecture plan"

### ✅ Phase 1: Foundation
**Goal**: Set up project structure and core infrastructure
- Create directory structure
- Extract and modularize:
  - Exception hierarchy → `core/exceptions.py`
  - Pydantic models → `core/models.py`
  - OPNsenseClient → `core/client.py`
  - ConnectionPool → `core/connection.py`
  - Retry logic → `core/retry.py`
  - ServerState → `core/state.py`
- Extract API constants → `shared/constants.py`
- Extract error handlers → `shared/error_handlers.py`
- Create `main.py` with FastMCP initialization
- **Commit**: "feat: establish modular project structure and core infrastructure"

### Phase 2: Configuration Domain
**Goal**: First domain module as template
- Create `domains/configuration.py`
- Migrate 2 configuration tools
- Test integration with core
- **Commit**: "feat: add configuration domain module"

### Phase 3: System Domain
**Goal**: System management tools
- Create `domains/system.py`
- Migrate 8 system management tools
- **Commit**: "feat: add system domain module with 8 tools"

### Phase 4: Firewall Domain
**Goal**: Firewall rule management
- Create `domains/firewall.py`
- Migrate firewall rules and alias tools
- **Commit**: "feat: add firewall domain module with rules and aliases"

### Phase 5: NAT Domain
**Goal**: NAT management
- Create `domains/nat.py`
- Migrate 7 NAT tools
- **Commit**: "feat: add NAT domain module with 7 tools"

### Phase 6: Network Domain
**Goal**: Interface, VLAN, bridge, LAGG, VIP management
- Create `domains/network.py`
- Migrate 20 network tools
- **Commit**: "feat: add network domain module with 20 tools"

### Phase 7: DNS & DHCP Domain
**Goal**: DNS and DHCP services
- Create `domains/dns_dhcp.py`
- Migrate 28 DNS/DHCP tools
- **Commit**: "feat: add DNS & DHCP domain module with 28 tools"

### Phase 8: Certificates Domain
**Goal**: Certificate lifecycle management
- Create `domains/certificates.py`
- Migrate 25 certificate tools
- **Commit**: "feat: add certificates domain module with 25 tools"

### Phase 9: Users Domain
**Goal**: User, group, and authentication management
- Create `domains/users.py`
- Migrate 31 user management tools
- **Commit**: "feat: add users domain module with 31 tools"

### Phase 10: Logging Domain
**Goal**: Log management and analysis
- Create `domains/logging.py`
- Migrate 11 logging tools
- **Commit**: "feat: add logging domain module with 11 tools"

### Phase 11: Traffic Shaping Domain
**Goal**: QoS and traffic shaping
- Create `domains/traffic_shaping.py`
- Migrate 23 traffic shaping tools
- **Commit**: "feat: add traffic shaping domain module with 23 tools"

### Phase 12: VPN & Utilities Domains
**Goal**: Complete migration
- Create `domains/vpn.py` - 1 tool
- Create `domains/utilities.py` - 4 tools
- **Commit**: "feat: add VPN and utilities domain modules"

### Phase 13: Backward Compatibility
**Goal**: Ensure smooth transition
- Update root `opnsense-mcp-server.py` as wrapper that imports from `src/opnsense_mcp/main.py`
- Test all 166 tools work identically
- **Commit**: "feat: add backward compatibility wrapper"

### Phase 14: Testing & Documentation
**Goal**: Quality assurance
- Add unit tests for each domain
- Add integration tests
- Create `docs/architecture.md`
- Create `docs/migration_guide.md`
- Update CLAUDE.md with new structure
- Update README.md
- **Commit**: "docs: add comprehensive documentation and tests"

### Phase 15: Packaging & Distribution
**Goal**: Modern Python packaging
- Create `pyproject.toml`
- Create `setup.py`
- Update `requirements.txt`
- Test pip installation
- **Commit**: "feat: add modern Python packaging configuration"

## Benefits of New Architecture

### Maintainability
- ✅ **Focused modules**: Each domain ~200-600 lines vs 9,529 lines
- ✅ **Clear boundaries**: Easy to find and modify specific functionality
- ✅ **Independent testing**: Test each domain in isolation

### Scalability
- ✅ **Easy extension**: Add new tools to appropriate domain module
- ✅ **Team collaboration**: Multiple developers can work on different domains
- ✅ **Future-ready**: Can split into separate MCP servers if needed (like Cloudflare)

### Code Quality
- ✅ **Reduced complexity**: Smaller, focused files
- ✅ **Better imports**: Clear dependency structure
- ✅ **Improved navigation**: IDE tools work better with smaller modules

### Backward Compatibility
- ✅ **Zero breaking changes**: Existing users continue working unchanged
- ✅ **Gradual migration**: Users can migrate at their own pace
- ✅ **Same API surface**: All 166 tools remain accessible

## Success Criteria

1. ✅ All 166 tools migrated and functional
2. ✅ No breaking changes for existing users
3. ✅ Test coverage for all domains
4. ✅ Documentation updated
5. ✅ Package installable via pip
6. ✅ Root `opnsense-mcp-server.py` works as before
7. ✅ Each phase committed to git separately

## Estimated Timeline

- **Total Phases**: 16 (including Phase 0)
- **Commits per Phase**: 1
- **Total Commits**: ~16
- **Implementation Time**: Each phase designed to be completable and committable independently

This plan transforms the monolithic architecture into a maintainable, scalable, domain-driven design while preserving complete backward compatibility.
