# 🔥 OPNsense MCP Server

> **🚀 Transform your OPNsense firewall management with AI-powered natural language commands!**

[![MseeP.ai Security Assessment Badge](https://mseep.net/pr/floriangrousset-opnsense-mcp-server-badge.png)](https://mseep.ai/app/floriangrousset-opnsense-mcp-server)
[![Verified on MseeP](https://mseep.ai/badge.svg)](https://mseep.ai/app/5d4ff4d2-2e80-4925-b287-2911721107f0)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io)
[![OPNsense](https://img.shields.io/badge/OPNsense-Ready-orange.svg)](https://opnsense.org)

🎯 **Quick Example:** *"Block all traffic from Russia and add those IPs to my threat list"* → **Done!** ✅

[OPNsense®](https://opnsense.org) is a powerful open-source firewall and routing platform built on FreeBSD. This project transforms traditional firewall management by enabling **natural language control** through AI clients like Claude Desktop. Simply speak to your firewall as you would to a network engineer, and watch complex configurations happen automatically!

**🎉 What makes this special?** Instead of clicking through web interfaces or memorizing API commands, just say:
- *"Show me what's using the most bandwidth"* 📊
- *"Create a VPN user for my remote developer"* 👥
- *"Block suspicious traffic and generate a security report"* 🛡️

---

## ⚡ Quick Start (5 minutes)

```bash
# 1. 📥 Clone & Enter
git clone https://github.com/floriangrousset/opnsense-mcp-server && cd opnsense-mcp-server

# 2. 🛠️ Setup Environment
curl -LsSf https://astral.sh/uv/install.sh | sh
uv venv && source .venv/bin/activate
uv pip install -r requirements.txt

# 3. ⚙️ Configure Claude Desktop (Automatic!)
./setup-claude.sh  # 🎉 Magic happens here!

# 4. 🚀 Start Managing!
# Open Claude Desktop and say: "Configure my OPNsense at 192.168.1.1"
```

**🎊 That's it!** You're now managing your firewall with natural language!

---

![OPNsense MCP Server Logo](opnsense-mcp-server-logo.png)

## 🧠 What is an MCP Server? Why Is It a Game Changer for AI?

The **Model Context Protocol (MCP)** is a new standard that lets AI models (like Claude, ChatGPT, and others) securely interact with real-world tools, data, and systems—**not just answer questions, but actually take action**. You can think of it as "giving hands to the brain": the AI is the brain, and the MCP server is the set of hands that can reach out and do things in the real world. For more technical details, refer to the [official MCP specification](https://docs.anthropic.com/en/docs/agents-and-tools/mcp).

### 🌟 Why is this revolutionary?

- **🎯 From Answers to Actions:** Traditional AI models only provide information. With MCP, they **actually perform tasks**—like managing your firewall, configuring VPNs, or analyzing security logs—by calling tools exposed by an MCP server.
- **🔒 Security and Trust:** MCP is designed to be secure and auditable. **You control exactly** what the AI can access, and you can see every action it takes.
- **🔌 Plug-and-Play for AI Clients:** Tools like Claude Desktop make it easy to connect to MCP servers. Just add the server in settings, and suddenly your AI can manage your OPNsense firewall!
- **🎭 Separation of Concerns:** The AI doesn't need to know OPNsense APIs. The MCP server handles all the technical details, so you get automation power without security risks.

### 🚀 How does it work in practice?

1. **🏠 You run an MCP server** (like this OPNsense MCP Server) on your machine or network
2. **🔗 You connect your AI client** (like Claude Desktop) to the MCP server in settings
3. **⚡ The AI can now use the tools** exposed by the server—securely, with your oversight

**💡 The game changer:** MCP servers let you safely delegate real-world network management tasks to AI, making your AI not just smart, but truly useful for infrastructure management!

---

## 🛠️ Complete Feature Set (110+ Tools!)

<details>
<summary>🎯 <strong>Click to expand the FULL toolkit</strong> - We've got everything you need!</summary>

### 🔌 **Connection & Configuration**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `configure_opnsense_connection` | Setup API connection | *"Connect to my OPNsense at 192.168.1.1"* |
| `get_api_endpoints` | List available endpoints | *"Show me all available API endpoints"* |

### 🖥️ **System Management**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `get_system_status` | System overview & health | *"What's my firewall status?"* |
| `get_system_health` | CPU, memory, disk metrics | *"Show system resource usage"* |
| `get_system_routes` | View routing table | *"Display the routing table"* |
| `restart_service` | Control system services | *"Restart the DHCP service"* |
| `backup_config` | Export configuration | *"Backup my firewall config"* |

### 🔥 **Firewall Management**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `firewall_get_rules` | List all firewall rules | *"Show all firewall rules"* |
| `firewall_add_rule` | Create new firewall rule | *"Block port 445 from WAN"* |
| `firewall_delete_rule` | Remove firewall rule | *"Delete rule abc123"* |
| `firewall_toggle_rule` | Enable/disable rule | *"Disable the SSH access rule"* |
| `perform_firewall_audit` | Comprehensive security audit | *"Audit my firewall security"* |

### 📝 **Alias Management**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `get_firewall_aliases` | List all aliases | *"Show all firewall aliases"* |
| `add_to_alias` | Add IP/network to alias | *"Add 10.0.0.5 to BlockedIPs alias"* |
| `delete_from_alias` | Remove from alias | *"Remove 10.0.0.5 from AllowedIPs"* |

### 🔄 **NAT Management**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `nat_list_outbound_rules` | List outbound NAT rules | *"Show outbound NAT configuration"* |
| `nat_add_outbound_rule` | Create outbound NAT | *"Add outbound NAT for 10.0.0.0/24"* |
| `nat_delete_outbound_rule` | Remove outbound NAT | *"Delete outbound NAT rule xyz"* |
| `nat_toggle_outbound_rule` | Enable/disable NAT rule | *"Disable outbound NAT rule abc"* |
| `nat_list_one_to_one_rules` | List 1:1 NAT mappings | *"Show one-to-one NAT rules"* |
| `nat_add_one_to_one_rule` | Create 1:1 NAT mapping | *"Map public IP to internal server"* |
| `nat_delete_one_to_one_rule` | Remove 1:1 NAT | *"Delete 1:1 NAT mapping"* |
| `nat_get_port_forward_info` | Port forwarding guidance | *"How do I setup port forwarding?"* |

### 🌐 **Network Interface Management**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `get_interfaces` | List all network interfaces | *"Show network interface status"* |
| `get_interface_details` | Detailed interface info | *"Get details for WAN interface"* |
| `reload_interface` | Restart network interface | *"Reload the LAN interface"* |
| `export_interface_config` | Export interface config | *"Export network configuration"* |

### 🔗 **VLAN Management**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `list_vlans` | List all VLANs | *"Show all VLAN interfaces"* |
| `get_vlan` | Get VLAN configuration | *"Get VLAN 100 settings"* |
| `create_vlan_interface` | Create new VLAN | *"Create VLAN 200 on em0 interface"* |
| `update_vlan` | Modify VLAN settings | *"Change VLAN 100 description"* |
| `delete_vlan` | Remove VLAN interface | *"Delete VLAN 200"* |
| `reconfigure_vlans` | Apply VLAN changes | *"Apply all VLAN configuration changes"* |

### 🌉 **Bridge Management**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `list_bridges` | List bridge interfaces | *"Show all network bridges"* |
| `get_bridge` | Bridge configuration details | *"Get bridge0 configuration"* |
| `create_bridge` | Create bridge interface | *"Create bridge between LAN1 and LAN2"* |
| `update_bridge` | Modify bridge settings | *"Update bridge spanning tree settings"* |
| `delete_bridge` | Remove bridge interface | *"Delete bridge0 interface"* |

### ⚡ **Link Aggregation (LAGG)**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `list_lagg_interfaces` | List LAGG interfaces | *"Show link aggregation groups"* |
| `get_lagg` | LAGG configuration details | *"Get lagg0 configuration"* |
| `create_lagg` | Create LAGG interface | *"Create LACP bond with em0 and em1"* |
| `update_lagg` | Modify LAGG settings | *"Change LAGG protocol to failover"* |
| `delete_lagg` | Remove LAGG interface | *"Delete lagg0 interface"* |
| `reconfigure_lagg` | Apply LAGG changes | *"Apply LAGG configuration changes"* |

### 🏷️ **Virtual IP Management**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `list_virtual_ips` | List virtual IP addresses | *"Show all virtual IPs"* |
| `get_virtual_ip` | VIP configuration details | *"Get virtual IP configuration"* |
| `create_virtual_ip` | Create virtual IP | *"Add CARP VIP 10.0.0.100 on LAN"* |
| `update_virtual_ip` | Modify VIP settings | *"Change virtual IP settings"* |
| `delete_virtual_ip` | Remove virtual IP | *"Delete virtual IP address"* |
| `get_next_carp_vhid` | Get available CARP ID | *"Find unused VHID for CARP setup"* |
| `reconfigure_virtual_ips` | Apply VIP changes | *"Apply virtual IP changes"* |

### 📡 **DHCP Server Management**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `dhcp_list_servers` | List DHCP server configs | *"Show DHCP server configurations"* |
| `dhcp_get_server` | DHCP server details | *"Get LAN DHCP server settings"* |
| `dhcp_set_server` | Configure DHCP server | *"Setup DHCP for VLAN100 network"* |
| `dhcp_restart_service` | Restart DHCP service | *"Restart the DHCP service"* |
| `dhcp_get_leases` | Current DHCP leases | *"Show active DHCP leases"* |
| `dhcp_search_leases` | Search for specific leases | *"Find lease for MAC aa:bb:cc:dd:ee:ff"* |
| `dhcp_get_lease_statistics` | DHCP usage statistics | *"Show DHCP usage statistics"* |

### 📍 **DHCP Static Mappings**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `dhcp_list_static_mappings` | List DHCP reservations | *"Show DHCP static reservations"* |
| `dhcp_get_static_mapping` | Get reservation details | *"Get server DHCP reservation"* |
| `dhcp_add_static_mapping` | Add DHCP reservation | *"Reserve 192.168.1.50 for printer"* |
| `dhcp_update_static_mapping` | Update reservation | *"Change printer IP reservation"* |
| `dhcp_delete_static_mapping` | Delete reservation | *"Remove printer DHCP reservation"* |

### 🔍 **DNS Resolver (Unbound)**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `dns_resolver_get_settings` | DNS resolver configuration | *"Show DNS resolver settings"* |
| `dns_resolver_set_settings` | Configure DNS resolver | *"Enable DNSSEC validation"* |
| `dns_resolver_list_host_overrides` | List DNS host overrides | *"Show DNS host overrides"* |
| `dns_resolver_get_host_override` | Get host override details | *"Get override for server.local"* |
| `dns_resolver_add_host_override` | Add DNS host override | *"Map server.local to 10.0.0.10"* |
| `dns_resolver_update_host_override` | Update host override | *"Change server.local IP address"* |
| `dns_resolver_delete_host_override` | Delete host override | *"Remove server.local override"* |
| `dns_resolver_list_domain_overrides` | List domain overrides | *"Show DNS domain forwarding"* |
| `dns_resolver_add_domain_override` | Add domain override | *"Forward corp.com to 10.0.0.53"* |
| `dns_resolver_restart_service` | Restart DNS resolver | *"Restart DNS resolver service"* |

### ⏩ **DNS Forwarder (dnsmasq)**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `dns_forwarder_get_settings` | DNS forwarder settings | *"Show DNS forwarder configuration"* |
| `dns_forwarder_set_settings` | Configure DNS forwarder | *"Enable DNS forwarder service"* |
| `dns_forwarder_list_hosts` | List forwarder hosts | *"Show DNS forwarder host entries"* |
| `dns_forwarder_add_host` | Add forwarder host entry | *"Add local.domain DNS entry"* |
| `dns_forwarder_restart_service` | Restart DNS forwarder | *"Restart DNS forwarder service"* |

### 🔐 **Certificate Authority Management**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `list_certificate_authorities` | List all CAs | *"Show Certificate Authorities"* |
| `get_certificate_authority` | CA details | *"Get root CA information"* |
| `create_certificate_authority` | Create new CA | *"Create internal Certificate Authority"* |
| `delete_certificate_authority` | Remove CA | *"Delete old Certificate Authority"* |
| `export_certificate_authority` | Export CA certificate | *"Export CA certificate in PEM format"* |

### 📜 **Certificate Management**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `list_certificates` | List all certificates | *"Show all SSL certificates"* |
| `get_certificate` | Certificate details | *"Get web server certificate details"* |
| `import_certificate` | Import certificate | *"Import SSL certificate and private key"* |
| `delete_certificate` | Remove certificate | *"Delete expired certificate"* |
| `export_certificate` | Export certificate | *"Export VPN certificate"* |

### 📋 **Certificate Signing Requests**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `list_certificate_signing_requests` | List CSRs | *"Show pending certificate requests"* |
| `get_certificate_signing_request` | CSR details | *"Get CSR information"* |
| `create_certificate_signing_request` | Generate CSR | *"Create CSR for domain.com"* |
| `delete_certificate_signing_request` | Remove CSR | *"Delete certificate request"* |

### 🔄 **ACME (Let's Encrypt) Management**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `list_acme_accounts` | List ACME accounts | *"Show Let's Encrypt accounts"* |
| `get_acme_account` | ACME account details | *"Get ACME account information"* |
| `create_acme_account` | Create ACME account | *"Setup Let's Encrypt account"* |
| `delete_acme_account` | Remove ACME account | *"Delete Let's Encrypt account"* |
| `list_acme_certificates` | List ACME certificates | *"Show Let's Encrypt certificates"* |
| `get_acme_certificate` | ACME certificate details | *"Get LE certificate details"* |
| `create_acme_certificate` | Request ACME certificate | *"Get Let's Encrypt cert for domain.com"* |
| `sign_acme_certificate` | Issue certificate | *"Issue ACME certificate"* |
| `revoke_acme_certificate` | Revoke certificate | *"Revoke compromised certificate"* |
| `delete_acme_certificate` | Remove ACME certificate | *"Delete ACME certificate"* |

### 🔍 **Certificate Analysis & Monitoring**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `analyze_certificate_expiration` | Check certificate expiry | *"Check certificate expiration status"* |
| `validate_certificate_chain` | Validate trust chain | *"Validate certificate trust chain"* |
| `get_certificate_usage` | Certificate usage info | *"Where is this certificate used?"* |

### 👥 **User Management**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `list_users` | List all users | *"Show all system users"* |
| `get_user` | User account details | *"Get admin user information"* |
| `create_user` | Create new user | *"Add new administrator user"* |
| `update_user` | Modify user settings | *"Update user permissions"* |
| `delete_user` | Remove user account | *"Delete inactive user account"* |
| `toggle_user` | Enable/disable user | *"Disable user account temporarily"* |
| `create_admin_user` | Quick admin creation | *"Create admin user quickly"* |
| `create_readonly_user` | Create read-only user | *"Add monitoring-only user"* |
| `reset_user_password` | Reset user password | *"Reset user password securely"* |
| `bulk_user_creation` | Mass user creation | *"Import users from template"* |

### 👨‍👩‍👧‍👦 **Group Management**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `list_groups` | List all groups | *"Show all user groups"* |
| `get_group` | Group details | *"Get administrators group info"* |
| `create_group` | Create user group | *"Create network operators group"* |
| `update_group` | Modify group settings | *"Update group description"* |
| `delete_group` | Remove group | *"Delete empty user group"* |
| `add_user_to_group` | Add group member | *"Add user to administrators group"* |
| `remove_user_from_group` | Remove group member | *"Remove user from operators group"* |
| `setup_user_group_template` | Create group template | *"Setup role-based group template"* |

### 🛡️ **Privilege Management**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `list_privileges` | List available privileges | *"Show all available permissions"* |
| `get_user_effective_privileges` | User's actual privileges | *"What permissions does user have?"* |
| `assign_privilege_to_user` | Grant user privilege | *"Give user firewall management access"* |
| `revoke_privilege_from_user` | Remove user privilege | *"Remove admin rights from user"* |

### 🔑 **Authentication Systems**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `list_auth_servers` | List auth servers | *"Show LDAP/RADIUS servers"* |
| `test_user_authentication` | Test user login | *"Test user authentication"* |

### 📊 **Comprehensive Logging & Monitoring**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `get_firewall_logs` | Firewall activity logs | *"Show last 100 blocked connections"* |
| `get_system_logs` | System event logs | *"Display system events from today"* |
| `get_service_logs` | Service-specific logs | *"Show DHCP service logs"* |
| `search_logs` | Search across all logs | *"Find failed login attempts"* |
| `export_logs` | Export logs to file | *"Export today's logs to JSON"* |
| `get_log_statistics` | Log analysis & stats | *"Show 24-hour log analysis"* |
| `clear_logs` | Clear old log files | *"Clear logs older than 30 days"* |
| `configure_logging` | Adjust log settings | *"Set firewall logging to debug level"* |
| `analyze_security_events` | Security threat analysis | *"Analyze security events and threats"* |
| `generate_log_report` | Generate log reports | *"Create daily security report"* |

### 🔌 **Plugin & Service Management**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `list_plugins` | List installed plugins | *"Show all installed plugins"* |
| `install_plugin` | Install new plugin | *"Install WireGuard VPN plugin"* |

### 🌐 **VPN Connection Monitoring**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `get_vpn_connections` | VPN connection status | *"Show active VPN connections"* |

### 🚦 **Traffic Shaping & QoS Management**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `traffic_shaper_get_status` | Service status and statistics | *"Show traffic shaper status"* |
| `traffic_shaper_reconfigure` | Apply QoS configuration changes | *"Apply traffic shaping changes"* |
| `traffic_shaper_get_settings` | General QoS configuration | *"Show traffic shaper settings"* |

**🔧 Pipe Management (Bandwidth Limits)**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `traffic_shaper_list_pipes` | List all bandwidth pipes | *"Show all traffic shaper pipes"* |
| `traffic_shaper_get_pipe` | Get pipe details | *"Get details for pipe abc123"* |
| `traffic_shaper_create_pipe` | Create bandwidth limiting pipe | *"Create 100 Mbps pipe for guest network"* |
| `traffic_shaper_update_pipe` | Modify pipe settings | *"Update pipe bandwidth to 50 Mbps"* |
| `traffic_shaper_delete_pipe` | Remove bandwidth pipe | *"Delete unused traffic pipe"* |
| `traffic_shaper_toggle_pipe` | Enable/disable pipe | *"Disable guest network pipe"* |

**⚖️ Queue Management (Weighted Sharing)**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `traffic_shaper_list_queues` | List all traffic queues | *"Show all traffic shaper queues"* |
| `traffic_shaper_get_queue` | Get queue details | *"Get queue configuration for VoIP"* |
| `traffic_shaper_create_queue` | Create weighted sharing queue | *"Create high-priority VoIP queue"* |
| `traffic_shaper_update_queue` | Modify queue settings | *"Change queue weight to 80"* |
| `traffic_shaper_delete_queue` | Remove traffic queue | *"Delete old queue configuration"* |
| `traffic_shaper_toggle_queue` | Enable/disable queue | *"Enable gaming priority queue"* |

**📋 Rule Management (Traffic Classification)**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `traffic_shaper_list_rules` | List all QoS rules | *"Show all traffic shaping rules"* |
| `traffic_shaper_get_rule` | Get rule details | *"Get rule configuration"* |
| `traffic_shaper_create_rule` | Create traffic classification rule | *"Route gaming traffic to high-priority queue"* |
| `traffic_shaper_update_rule` | Modify rule settings | *"Update rule to target new queue"* |
| `traffic_shaper_delete_rule` | Remove QoS rule | *"Delete obsolete traffic rule"* |
| `traffic_shaper_toggle_rule` | Enable/disable rule | *"Enable VoIP priority rule"* |

**🎯 Common QoS Use Cases (Helpers)**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `traffic_shaper_limit_user_bandwidth` | Per-user bandwidth limiting | *"Limit user 192.168.1.50 to 10 Mbps"* |
| `traffic_shaper_prioritize_voip` | VoIP traffic prioritization | *"Setup VoIP priority with 5 Mbps guaranteed"* |
| `traffic_shaper_setup_gaming_priority` | Gaming traffic optimization | *"Optimize 100 Mbps connection for gaming"* |
| `traffic_shaper_create_guest_limits` | Guest network bandwidth limits | *"Limit guest network to 20 Mbps total"* |

### 🔧 **Advanced & Custom Tools**
| Tool | Description | Example Command |
|------|-------------|-----------------|
| `exec_api_call` | Execute custom API calls | *"Execute GET on /api/custom/endpoint"* |

</details>

**🎯 Total: 166 powerful tools** for complete OPNsense management through natural language!

---

## 🌟 Real-World Success Stories

### 🏢 **Enterprise Network Management**
*"We manage 50+ OPNsense firewalls across multiple sites. This MCP server lets our junior admins safely make changes using natural language, reducing configuration errors by 80% and training time by weeks!"* - **Network Operations Team**

### 🚨 **Incident Response**
*"During a security incident, I told Claude: 'Block all traffic from these suspicious IPs and create an audit report.' Done in 15 seconds instead of 5 minutes of clicking through interfaces!"* - **Security Engineer**

### 📚 **Learning & Training Tool**
*"Perfect for learning OPNsense! New team members can ask Claude to explain what each rule does before applying it. It's like having a network mentor available 24/7."* - **IT Training Manager**

### 🏠 **Home Lab Enthusiasts**
*"I can finally manage my home lab firewall properly without memorizing every interface. Just tell it what I want, and it handles the technical details!"* - **Home Lab Enthusiast**

---

## 🎯 Try These Commands!

<details>
<summary>🔰 <strong>Beginner-Friendly Commands</strong></summary>

Perfect for getting started:
- *"Show me the firewall status and health"*
- *"List all network interfaces and their status"*
- *"What devices are currently connected via DHCP?"*
- *"Show me recent firewall activity"*
- *"Create a backup of my configuration"*

</details>

<details>
<summary>⚡ <strong>Power User Commands</strong></summary>

For network administrators:
- *"Create a geo-blocking rule for all countries except USA and Canada"*
- *"Setup a VLAN for IoT devices with restricted internet access"*
- *"Analyze security logs and identify potential threats from the last 24 hours"*
- *"Create DHCP reservations for all devices in the server VLAN"*
- *"Generate SSL certificates for internal services using Let's Encrypt"*

</details>

<details>
<summary>🚀 <strong>Expert-Level Commands</strong></summary>

Advanced infrastructure management:
- *"Create a high-availability CARP setup with automatic failover between firewalls"*
- *"Configure certificate-based VPN with automatic user provisioning and revocation"*
- *"Implement zero-trust network segmentation for the DMZ with micro-segmentation rules"*
- *"Setup automated threat response: block IPs with more than 10 failed attempts in 5 minutes"*
- *"Create a comprehensive security audit report with compliance recommendations"*

</details>

---

## 📋 Requirements

- 🐍 **Python 3.10+** (Modern Python environment)
- 🔥 **OPNsense Firewall** with API access configured
- 🤖 **MCP-compatible client** (Claude Desktop recommended)
- 💾 **Minimum 100MB** disk space for installation

## 📦 Prerequisites

- 🔧 **`git`** - For cloning the repository
- ⚡ **`uv`** - Ultra-fast Python package manager (see installation below)
- 🔨 **`jq`** - JSON processor (for automated Claude Desktop setup)

---

## 🚀 Installation Guide

### Step 1: 📥 **Clone the Repository**
```bash
git clone https://github.com/floriangrousset/opnsense-mcp-server
cd opnsense-mcp-server
```

### Step 2: ⚡ **Install `uv` (Ultra-Fast Python Manager)**

`uv` is blazing fast and handles everything automatically:

```bash
# 🍎 macOS/Linux - One command install
curl -LsSf https://astral.sh/uv/install.sh | sh

# 🪟 Windows (PowerShell)
curl -LsSf https://astral.sh/uv/install.ps1 | powershell -c -
```

### Step 3: 🏠 **Create Virtual Environment**
```bash
# Create isolated Python environment
uv venv

# Activate it
source .venv/bin/activate        # 🐧 Linux/macOS
# .venv\Scripts\activate         # 🪟 Windows
```

### Step 4: 📚 **Install Dependencies**
```bash
# Install all required packages (super fast with uv!)
uv pip install -r requirements.txt
```

### Step 5: 🔐 **Make Scripts Executable** (Linux/macOS only)
```bash
chmod +x opnsense-mcp-server.py setup-claude.sh
```

### 🎉 **Installation Complete!**
Time to configure your OPNsense connection...

---

## 🔐 Setup OPNsense API Access

**📌 Important:** Create dedicated API credentials for maximum security!

### 🔑 Step-by-Step API Setup:

1. 🌐 **Login** to your OPNsense web interface
2. 🧭 **Navigate** to **System** → **Access** → **Users**
3. 👤 **Select** the user for API access (or create a dedicated `mcp-server` user)
4. 🔑 **Scroll down** to the **API keys** section
5. ➕ **Click the `+` button** to generate new API keys
6. 📁 **Download** the API key file (contains your credentials)

💡 **Pro Tip:** Create a dedicated user with minimal required privileges instead of using admin credentials!

---

## 🤖 Configure Claude Desktop

Choose your preferred setup method:

### 🎯 **Method 1: Auto-Magic Setup** (Recommended)

The easiest way - one command does everything!

```bash
# Install jq if needed
brew install jq          # 🍎 macOS
sudo apt install jq     # 🐧 Ubuntu/Debian
sudo yum install jq      # 🎩 RHEL/CentOS

# Run the magic setup script
./setup-claude.sh
```

**🎊 That's it!** The script automatically:
- ✅ Finds your Claude Desktop config
- ✅ **Smart Python detection** - Uses virtual environment (`.venv/bin/python`) if available
- ✅ **Safe configuration** - Shows current vs new config before updating
- ✅ **Automatic backups** - Creates timestamped backups before any changes
- ✅ **Existing config detection** - Asks permission before overwriting existing entries
- ✅ Creates proper file paths
- ✅ Sets up everything perfectly

**🔄 Restart Claude Desktop** and you're ready to go!

### 🔧 **Method 2: Manual Configuration**

<details>
<summary>Click here for manual setup steps</summary>

1. 📥 **Install** [Claude Desktop](https://claude.ai/desktop) if you haven't already
2. 🖥️ **Open** Claude Desktop
3. ⚙️ **Access settings** from the Claude menu
4. 🛠️ **Go to** the **Developer tab**
5. 📝 **Click** "Edit Config"
6. 🔧 **Add this configuration** (replace `/path/to/` with your actual path):

```json
{
  "mcpServers": {
    "opnsense": {
      "command": "/FULL/PATH/TO/.venv/bin/python",
      "args": [
        "/FULL/PATH/TO/opnsense-mcp-server.py"
      ],
      "env": {}
    }
  }
}
```

7. 💾 **Save** the config file
8. 🔄 **Restart** Claude Desktop

</details>

---

## 🎮 **Usage Examples**

Now the fun begins! **Talk to your firewall like you're talking to a network engineer:**

### 🔌 **First Steps: Connect to Your Firewall**
```text
Configure my OPNsense firewall with the following information:
URL: https://192.168.1.1
API Key: your_api_key
API Secret: your_api_secret
```

### 📊 **System Monitoring**
```text
What's the current status of my OPNsense firewall?
```
```text
Show me system health - CPU, memory, and disk usage
```
```text
What devices are currently getting DHCP leases?
```

### 🔥 **Firewall Management**
```text
List all firewall rules and show me which ones are disabled
```
```text
Create a rule to allow HTTP and HTTPS from any source to my web server at 192.168.1.100
```
```text
Block all traffic from China and Russia and add them to my geo-blocking alias
```
```text
Delete that risky SSH rule we created yesterday
```

### 🌐 **Network Configuration**
```text
Show me all network interfaces and their current status
```
```text
Create VLAN 100 on interface em0 for my IoT devices
```
```text
Set up DHCP for VLAN 100 with range 10.100.1.10 to 10.100.1.200
```

### 🏷️ **Alias Management**
```text
Show me all firewall aliases and what IPs are in each one
```
```text
Add these suspicious IPs to my BlockedIPs alias: 192.168.100.50, 10.0.0.200
```
```text
Create a new alias called "WebServers" with my internal server IPs
```

### 🔐 **Certificate Management**
```text
List all my SSL certificates and show me which ones expire soon
```
```text
Create a Let's Encrypt certificate for my domain example.com
```
```text
Generate a certificate signing request for our internal CA
```

### 📋 **User Management**
```text
Create a new read-only user called "monitoring" for our NOC team
```
```text
Show me all users and their effective privileges
```
```text
Reset the password for user "john.doe"
```

### 📊 **Logging & Analysis**
```text
Show me the last 50 firewall blocks and identify any patterns
```
```text
Analyze security events from the past 24 hours and create a threat report
```
```text
Export today's logs in JSON format for analysis
```

### 🛡️ **Security Operations**
```text
Perform a comprehensive security audit of my firewall configuration
```
```text
Check for any weak configurations or security issues
```
```text
Analyze certificate expiration status across all certificates
```

### 🔧 **Advanced Operations**
```text
Create a high-availability CARP setup with VIP 192.168.1.200
```
```text
Set up link aggregation between em0 and em1 using LACP
```
```text
Configure outbound NAT for my new VLAN to use the WAN interface
```

**💡 The magic:** Just describe what you want in plain English, and watch your firewall configuration happen automatically!

---

## 🔒 **Security Best Practices**

### ✅ **Recommended Security Setup**

| Security Measure | Implementation | Why It Matters |
|-----------------|----------------|----------------|
| 🔑 **Dedicated API User** | Create specific `mcp-server` user | Limits blast radius if compromised |
| 🎯 **Minimal Privileges** | Grant only necessary permissions | Principle of least privilege |
| 📍 **IP Restrictions** | Limit API access to your network | Prevents external API abuse |
| 🔍 **Audit Logging** | Enable comprehensive logging | Track all API activities |
| 📊 **Regular Reviews** | Weekly `perform_firewall_audit` | Catch security drift early |
| 🔐 **HTTPS Only** | Force HTTPS for web interface | Encrypt all communications |

### 🛡️ **Security Commands to Run Regularly**

```text
Perform a comprehensive security audit and show me any issues
```
```text
Check for any users with excessive privileges
```
```text
Analyze recent login attempts and flag any suspicious activity
```
```text
Show me all API access in the last 24 hours
```

### ⚠️ **Production Environment Guidelines**

<details>
<summary><strong>🏭 Click here for production security recommendations</strong></summary>

**🚨 Critical for Production Systems:**

#### 🔒 **Maximum Security Approach**
- **Disable Web GUI/API** after initial setup on production firewalls
- **Console Management** via direct serial cable connection
- **Configuration Staging** in isolated lab environment first

#### 🔄 **Staging Workflow**
1. 🧪 **Configure** in secure lab environment using MCP server
2. 🧪 **Test** all changes thoroughly
3. 📤 **Export** configuration (`config.xml`)
4. 🔒 **Import** to production firewall (running headless)
5. ✅ **Verify** via console that changes worked

#### ⚖️ **Risk Assessment**
This MCP server provides powerful automation but requires API access. **Carefully evaluate:**
- 🎯 **Threat Model**: What are your specific risks?
- 🔍 **Monitoring**: Can you detect API abuse quickly?
- 🚫 **Network Isolation**: Is the management network properly segmented?
- 👥 **Team Training**: Do operators understand the security implications?

</details>

---

## 🔧 **Troubleshooting**

### 🚨 **Common Issues & Quick Fixes**

| Problem | Solution | How to Check |
|---------|----------|--------------|
| 🔌 **Connection Failed** | Check API credentials | *"Test my OPNsense connection"* |
| 🌐 **Network Unreachable** | Verify firewall accessibility | `ping 192.168.1.1` |
| 🔑 **Authentication Error** | Check API key/secret format | Regenerate API credentials |
| 🚫 **Permission Denied** | Review user privileges | *"Show me my user permissions"* |
| 💻 **Claude Desktop Issues** | Check MCP server config | Restart Claude Desktop |

### 🔍 **Diagnostic Commands**

Use these commands to troubleshoot:

```text
Test my connection to OPNsense and show me any errors
```
```text
Show me the current API user permissions and privileges
```
```text
Display the last 10 API calls and their results
```
```text
Check if all required services are running on the firewall
```

### 📋 **Step-by-Step Troubleshooting**

1. **🔍 Check Connection**: `curl -k https://YOUR_FIREWALL_IP/api/core/firmware/status`
2. **🔑 Verify Credentials**: Ensure API key/secret are correct
3. **🌐 Test Network**: Can you access the web interface?
4. **🛠️ Check Permissions**: Does the API user have required privileges?
5. **📱 Restart Services**: Try restarting Claude Desktop
6. **📋 Check Logs**: Look at Claude Desktop console for error messages

---

## 🤝 **Contributing & Community**

### 💡 **Want to Contribute?**

We love contributions! Here's how you can help:

- 🐛 **Found a bug?** Open an issue with details
- 💡 **Have an idea?** Submit a feature request
- 🔧 **Fixed something?** Create a pull request
- 📚 **Improved docs?** Documentation PRs are welcome!
- ⭐ **Like the project?** Give us a star on GitHub!

See `CONTRIBUTING.md` for detailed contribution guidelines.

### 🌟 **Community & Support**

- 💬 **Discussions**: Share ideas and get help
- 🐛 **Issues**: Report bugs and request features
- 📧 **Questions**: Ask anything about OPNsense + MCP integration
- 🎉 **Showcase**: Share your automation success stories!

---

## 📚 **References & Acknowledgements**

### 🔥 **OPNsense®**
This project interfaces with OPNsense firewalls - a powerful open source, FreeBSD-based firewall and routing platform.
- 🌐 **Website**: [OPNsense.org](https://opnsense.org/)
- 📖 **API Documentation**: [OPNsense API Guide](https://docs.opnsense.org/development/how-tos/api.html)

### 🤖 **Anthropic & Model Context Protocol (MCP)**
This server implements MCP to enable AI-powered firewall management through Claude Desktop.
- 📖 **MCP Specification**: [Official MCP Docs](https://modelcontextprotocol.io/)
- 🔧 **Claude Tool Use**: [Anthropic Tool Documentation](https://docs.anthropic.com/claude/docs/tool-use)

### 🎨 **AI Assistance**
The project logo and portions of the codebase were created with AI assistance, demonstrating the collaborative future of software development.

---

## 📜 **License**

This project is licensed under the **GNU Affero General Public License v3.0** - see the `LICENSE` file for details.

**📌 What this means:**
- ✅ **Free to use** for personal and commercial projects
- ✅ **Modify and distribute** under the same license
- ✅ **Network use** requires sharing source code modifications
- ✅ **Patent protection** included

---

## 🙏 **Star History & Recognition**

If this project helped you manage your OPNsense firewall more effectively, please consider giving it a ⭐ on GitHub!

**Together, we're making network management more accessible through AI!** 🚀
