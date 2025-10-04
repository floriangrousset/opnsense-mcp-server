"""
OPNsense MCP Server - API Endpoint Constants

This module contains all OPNsense API endpoint constants used throughout the server.
All endpoints are relative to the base URL and should be prefixed with '/api' when making requests.
"""

# Core System APIs
API_CORE_MENU_GET_ITEMS = "/core/menu/getItems"
API_CORE_FIRMWARE_STATUS = "/core/firmware/status"
API_CORE_SYSTEM_INFO = "/core/system/info"
API_CORE_SERVICE_SEARCH = "/core/service/search"
API_CORE_SERVICE_RESTART = "/core/service/restart"  # Needs /{service_name}
API_CORE_BACKUP_DOWNLOAD = "/core/backup/download"
API_CORE_FIRMWARE_PLUGINS = "/core/firmware/plugins"
API_CORE_FIRMWARE_INSTALL = "/core/firmware/install"  # Needs /{plugin_name}

# Firewall Filter Rules
API_FIREWALL_FILTER_SEARCH_RULE = "/firewall/filter/searchRule"
API_FIREWALL_FILTER_ADD_RULE = "/firewall/filter/addRule"
API_FIREWALL_FILTER_DEL_RULE = "/firewall/filter/delRule"    # Needs /{uuid}
API_FIREWALL_FILTER_TOGGLE_RULE = "/firewall/filter/toggleRule" # Needs /{uuid}/{enabled_int}
API_FIREWALL_FILTER_APPLY = "/firewall/filter/apply"

# Firewall Aliases
API_FIREWALL_ALIAS_SEARCH_ITEM = "/firewall/alias/searchItem"
API_FIREWALL_ALIAS_UTIL_ADD = "/firewall/alias_util/add"      # Needs /{alias_name}/{address}
API_FIREWALL_ALIAS_UTIL_DELETE = "/firewall/alias_util/delete"  # Needs /{alias_name}/{address}
API_FIREWALL_ALIAS_RECONFIGURE = "/firewall/alias/reconfigure"

# Interfaces Overview
API_INTERFACES_OVERVIEW_INFO = "/interfaces/overview/interfacesInfo"
API_INTERFACES_OVERVIEW_GET_INTERFACE = "/interfaces/overview/getInterface"  # /{interface}
API_INTERFACES_OVERVIEW_RELOAD_INTERFACE = "/interfaces/overview/reloadInterface"  # /{identifier}
API_INTERFACES_OVERVIEW_EXPORT = "/interfaces/overview/export"

# Bridge Management
API_INTERFACES_BRIDGE_SEARCH = "/interfaces/bridge_settings/search_item"
API_INTERFACES_BRIDGE_GET = "/interfaces/bridge_settings/get_item"  # /{uuid}
API_INTERFACES_BRIDGE_ADD = "/interfaces/bridge_settings/add_item"
API_INTERFACES_BRIDGE_SET = "/interfaces/bridge_settings/set_item"  # /{uuid}
API_INTERFACES_BRIDGE_DEL = "/interfaces/bridge_settings/del_item"  # /{uuid}
API_INTERFACES_BRIDGE_RECONFIGURE = "/interfaces/bridge_settings/reconfigure"

# LAGG (Link Aggregation) Management
API_INTERFACES_LAGG_SEARCH = "/interfaces/lagg_settings/search_item"
API_INTERFACES_LAGG_GET = "/interfaces/lagg_settings/get_item"  # /{uuid}
API_INTERFACES_LAGG_ADD = "/interfaces/lagg_settings/add_item"
API_INTERFACES_LAGG_SET = "/interfaces/lagg_settings/set_item"  # /{uuid}
API_INTERFACES_LAGG_DEL = "/interfaces/lagg_settings/del_item"  # /{uuid}
API_INTERFACES_LAGG_RECONFIGURE = "/interfaces/lagg_settings/reconfigure"

# VLAN Management
API_INTERFACES_VLAN_SEARCH = "/interfaces/vlan_settings/search_item"
API_INTERFACES_VLAN_GET = "/interfaces/vlan_settings/get_item"  # /{uuid}
API_INTERFACES_VLAN_ADD = "/interfaces/vlan_settings/add_item"
API_INTERFACES_VLAN_SET = "/interfaces/vlan_settings/set_item"  # /{uuid}
API_INTERFACES_VLAN_DEL = "/interfaces/vlan_settings/del_item"  # /{uuid}
API_INTERFACES_VLAN_RECONFIGURE = "/interfaces/vlan_settings/reconfigure"

# VXLAN Management
API_INTERFACES_VXLAN_SEARCH = "/interfaces/vxlan_settings/search_item"
API_INTERFACES_VXLAN_GET = "/interfaces/vxlan_settings/get_item"  # /{uuid}
API_INTERFACES_VXLAN_ADD = "/interfaces/vxlan_settings/add_item"
API_INTERFACES_VXLAN_SET = "/interfaces/vxlan_settings/set_item"  # /{uuid}
API_INTERFACES_VXLAN_DEL = "/interfaces/vxlan_settings/del_item"  # /{uuid}
API_INTERFACES_VXLAN_RECONFIGURE = "/interfaces/vxlan_settings/reconfigure"

# Virtual IP (VIP) Management
API_INTERFACES_VIP_SEARCH = "/interfaces/vip_settings/search_item"
API_INTERFACES_VIP_GET = "/interfaces/vip_settings/get_item"  # /{uuid}
API_INTERFACES_VIP_ADD = "/interfaces/vip_settings/add_item"
API_INTERFACES_VIP_SET = "/interfaces/vip_settings/set_item"  # /{uuid}
API_INTERFACES_VIP_DEL = "/interfaces/vip_settings/del_item"  # /{uuid}
API_INTERFACES_VIP_GET_UNUSED_VHID = "/interfaces/vip_settings/get_unused_vhid"
API_INTERFACES_VIP_RECONFIGURE = "/interfaces/vip_settings/reconfigure"

# Loopback Interface Management
API_INTERFACES_LOOPBACK_SEARCH = "/interfaces/loopback_settings/search_item"
API_INTERFACES_LOOPBACK_GET = "/interfaces/loopback_settings/get_item"  # /{uuid}
API_INTERFACES_LOOPBACK_ADD = "/interfaces/loopback_settings/add_item"
API_INTERFACES_LOOPBACK_SET = "/interfaces/loopback_settings/set_item"  # /{uuid}
API_INTERFACES_LOOPBACK_DEL = "/interfaces/loopback_settings/del_item"  # /{uuid}
API_INTERFACES_LOOPBACK_RECONFIGURE = "/interfaces/loopback_settings/reconfigure"

# GIF Tunnel Management
API_INTERFACES_GIF_SEARCH = "/interfaces/gif_settings/search_item"
API_INTERFACES_GIF_GET = "/interfaces/gif_settings/get_item"  # /{uuid}
API_INTERFACES_GIF_ADD = "/interfaces/gif_settings/add_item"
API_INTERFACES_GIF_SET = "/interfaces/gif_settings/set_item"  # /{uuid}
API_INTERFACES_GIF_DEL = "/interfaces/gif_settings/del_item"  # /{uuid}
API_INTERFACES_GIF_RECONFIGURE = "/interfaces/gif_settings/reconfigure"

# GRE Tunnel Management
API_INTERFACES_GRE_SEARCH = "/interfaces/gre_settings/search_item"
API_INTERFACES_GRE_GET = "/interfaces/gre_settings/get_item"  # /{uuid}
API_INTERFACES_GRE_ADD = "/interfaces/gre_settings/add_item"
API_INTERFACES_GRE_SET = "/interfaces/gre_settings/set_item"  # /{uuid}
API_INTERFACES_GRE_DEL = "/interfaces/gre_settings/del_item"  # /{uuid}
API_INTERFACES_GRE_RECONFIGURE = "/interfaces/gre_settings/reconfigure"

# Certificate Authority Management
API_CERTIFICATES_CA_SEARCH = "/certificates/ca/search"
API_CERTIFICATES_CA_GET = "/certificates/ca/get"  # /{uuid}
API_CERTIFICATES_CA_ADD = "/certificates/ca/add"
API_CERTIFICATES_CA_SET = "/certificates/ca/set"  # /{uuid}
API_CERTIFICATES_CA_DEL = "/certificates/ca/del"  # /{uuid}
API_CERTIFICATES_CA_EXPORT = "/certificates/ca/export"  # /{uuid}

# Certificate Management
API_CERTIFICATES_CERT_SEARCH = "/certificates/cert/search"
API_CERTIFICATES_CERT_GET = "/certificates/cert/get"  # /{uuid}
API_CERTIFICATES_CERT_ADD = "/certificates/cert/add"
API_CERTIFICATES_CERT_SET = "/certificates/cert/set"  # /{uuid}
API_CERTIFICATES_CERT_DEL = "/certificates/cert/del"  # /{uuid}
API_CERTIFICATES_CERT_EXPORT = "/certificates/cert/export"  # /{uuid}

# Certificate Signing Request (CSR) Management
API_CERTIFICATES_CSR_SEARCH = "/certificates/csr/search"
API_CERTIFICATES_CSR_GET = "/certificates/csr/get"  # /{uuid}
API_CERTIFICATES_CSR_ADD = "/certificates/csr/add"
API_CERTIFICATES_CSR_SET = "/certificates/csr/set"  # /{uuid}
API_CERTIFICATES_CSR_DEL = "/certificates/csr/del"  # /{uuid}

# Certificate Revocation List (CRL) Management
API_CERTIFICATES_CRL_SEARCH = "/certificates/crl/search"
API_CERTIFICATES_CRL_GET = "/certificates/crl/get"  # /{uuid}
API_CERTIFICATES_CRL_ADD = "/certificates/crl/add"
API_CERTIFICATES_CRL_SET = "/certificates/crl/set"  # /{uuid}
API_CERTIFICATES_CRL_DEL = "/certificates/crl/del"  # /{uuid}

# ACME (Let's Encrypt) Account Management
API_CERTIFICATES_ACME_ACCOUNTS_SEARCH = "/certificates/acme_accounts/search"
API_CERTIFICATES_ACME_ACCOUNTS_GET = "/certificates/acme_accounts/get"  # /{uuid}
API_CERTIFICATES_ACME_ACCOUNTS_ADD = "/certificates/acme_accounts/add"
API_CERTIFICATES_ACME_ACCOUNTS_SET = "/certificates/acme_accounts/set"  # /{uuid}
API_CERTIFICATES_ACME_ACCOUNTS_DEL = "/certificates/acme_accounts/del"  # /{uuid}

# ACME Certificate Management
API_CERTIFICATES_ACME_CERTS_SEARCH = "/certificates/acme_certs/search"
API_CERTIFICATES_ACME_CERTS_GET = "/certificates/acme_certs/get"  # /{uuid}
API_CERTIFICATES_ACME_CERTS_ADD = "/certificates/acme_certs/add"
API_CERTIFICATES_ACME_CERTS_SET = "/certificates/acme_certs/set"  # /{uuid}
API_CERTIFICATES_ACME_CERTS_DEL = "/certificates/acme_certs/del"  # /{uuid}
API_CERTIFICATES_ACME_CERTS_SIGN = "/certificates/acme_certs/sign"  # /{uuid}
API_CERTIFICATES_ACME_CERTS_REVOKE = "/certificates/acme_certs/revoke"  # /{uuid}

# ACME Challenge Management
API_CERTIFICATES_ACME_CHALLENGES_SEARCH = "/certificates/acme_challenges/search"
API_CERTIFICATES_ACME_CHALLENGES_GET = "/certificates/acme_challenges/get"  # /{uuid}
API_CERTIFICATES_ACME_CHALLENGES_ADD = "/certificates/acme_challenges/add"
API_CERTIFICATES_ACME_CHALLENGES_SET = "/certificates/acme_challenges/set"  # /{uuid}
API_CERTIFICATES_ACME_CHALLENGES_DEL = "/certificates/acme_challenges/del"  # /{uuid}

# ACME Validation Management
API_CERTIFICATES_ACME_VALIDATIONS_SEARCH = "/certificates/acme_validations/search"
API_CERTIFICATES_ACME_VALIDATIONS_GET = "/certificates/acme_validations/get"  # /{uuid}
API_CERTIFICATES_ACME_VALIDATIONS_ADD = "/certificates/acme_validations/add"
API_CERTIFICATES_ACME_VALIDATIONS_SET = "/certificates/acme_validations/set"  # /{uuid}
API_CERTIFICATES_ACME_VALIDATIONS_DEL = "/certificates/acme_validations/del"  # /{uuid}

# Certificate Service Configuration
API_CERTIFICATES_SERVICE_RECONFIGURE = "/certificates/service/reconfigure"

# DHCP Server Configuration
API_DHCP_LEASES_SEARCH = "/dhcp/leases/searchLease"
API_DHCP_SERVER_SEARCH = "/dhcp/server/search"
API_DHCP_SERVER_GET = "/dhcp/server/get"  # Optional /{uuid}
API_DHCP_SERVER_ADD = "/dhcp/server/add"
API_DHCP_SERVER_SET = "/dhcp/server/set"  # Needs /{uuid}
API_DHCP_SERVER_DEL = "/dhcp/server/del"  # Needs /{uuid}
API_DHCP_SERVER_TOGGLE = "/dhcp/server/toggle"  # Needs /{uuid}/{enabled}

# DHCP Static Mapping
API_DHCP_STATIC_SEARCH = "/dhcp/static/search"
API_DHCP_STATIC_GET = "/dhcp/static/get"  # Optional /{uuid}
API_DHCP_STATIC_ADD = "/dhcp/static/add"
API_DHCP_STATIC_SET = "/dhcp/static/set"  # Needs /{uuid}
API_DHCP_STATIC_DEL = "/dhcp/static/del"  # Needs /{uuid}

# DHCP Service Control
API_DHCP_SERVICE_STATUS = "/dhcp/service/status"
API_DHCP_SERVICE_START = "/dhcp/service/start"
API_DHCP_SERVICE_STOP = "/dhcp/service/stop"
API_DHCP_SERVICE_RESTART = "/dhcp/service/restart"
API_DHCP_SERVICE_RECONFIGURE = "/dhcp/service/reconfigure"

# DNS Resolver (Unbound) Configuration
API_DNS_RESOLVER_SETTINGS = "/dns/resolver/settings"
API_DNS_RESOLVER_SET_SETTINGS = "/dns/resolver/setSettings"

# DNS Resolver Host Overrides
API_DNS_RESOLVER_HOST_SEARCH = "/dns/resolver/searchHost"
API_DNS_RESOLVER_HOST_GET = "/dns/resolver/getHost"  # Optional /{uuid}
API_DNS_RESOLVER_HOST_ADD = "/dns/resolver/addHost"
API_DNS_RESOLVER_HOST_SET = "/dns/resolver/setHost"  # Needs /{uuid}
API_DNS_RESOLVER_HOST_DEL = "/dns/resolver/delHost"  # Needs /{uuid}

# DNS Resolver Domain Overrides
API_DNS_RESOLVER_DOMAIN_SEARCH = "/dns/resolver/searchDomain"
API_DNS_RESOLVER_DOMAIN_GET = "/dns/resolver/getDomain"  # Optional /{uuid}
API_DNS_RESOLVER_DOMAIN_ADD = "/dns/resolver/addDomain"
API_DNS_RESOLVER_DOMAIN_SET = "/dns/resolver/setDomain"  # Needs /{uuid}
API_DNS_RESOLVER_DOMAIN_DEL = "/dns/resolver/delDomain"  # Needs /{uuid}

# DNS Forwarder (dnsmasq) Configuration
API_DNS_FORWARDER_SETTINGS = "/dns/forwarder/settings"
API_DNS_FORWARDER_SET_SETTINGS = "/dns/forwarder/setSettings"

# DNS Forwarder Host Configuration
API_DNS_FORWARDER_HOST_SEARCH = "/dns/forwarder/searchHost"
API_DNS_FORWARDER_HOST_GET = "/dns/forwarder/getHost"  # Optional /{uuid}
API_DNS_FORWARDER_HOST_ADD = "/dns/forwarder/addHost"
API_DNS_FORWARDER_HOST_SET = "/dns/forwarder/setHost"  # Needs /{uuid}
API_DNS_FORWARDER_HOST_DEL = "/dns/forwarder/delHost"  # Needs /{uuid}

# DNS Resolver Service Control
API_DNS_RESOLVER_SERVICE_STATUS = "/dns/resolver/status"
API_DNS_RESOLVER_SERVICE_START = "/dns/resolver/start"
API_DNS_RESOLVER_SERVICE_STOP = "/dns/resolver/stop"
API_DNS_RESOLVER_SERVICE_RESTART = "/dns/resolver/restart"
API_DNS_RESOLVER_SERVICE_RECONFIGURE = "/dns/resolver/reconfigure"

# DNS Forwarder Service Control
API_DNS_FORWARDER_SERVICE_STATUS = "/dns/forwarder/status"
API_DNS_FORWARDER_SERVICE_START = "/dns/forwarder/start"
API_DNS_FORWARDER_SERVICE_STOP = "/dns/forwarder/stop"
API_DNS_FORWARDER_SERVICE_RESTART = "/dns/forwarder/restart"
API_DNS_FORWARDER_SERVICE_RECONFIGURE = "/dns/forwarder/reconfigure"

# Diagnostics and Logging
API_DIAGNOSTICS_LOG_FIREWALL = "/diagnostics/log/firewall"
API_DIAGNOSTICS_SYSTEM_PROCESSOR = "/diagnostics/system/processor"
API_DIAGNOSTICS_SYSTEM_MEMORY = "/diagnostics/system/memory"
API_DIAGNOSTICS_SYSTEM_STORAGE = "/diagnostics/system/storage"
API_DIAGNOSTICS_SYSTEM_TEMPERATURE = "/diagnostics/system/temperature"
API_DIAGNOSTICS_LOG_SYSTEM = "/diagnostics/log/system"
API_DIAGNOSTICS_LOG_SYSTEM_SEARCH = "/diagnostics/log/system/search"
API_DIAGNOSTICS_LOG_ACCESS = "/diagnostics/log/access"
API_DIAGNOSTICS_LOG_AUTHENTICATION = "/diagnostics/log/authentication"
API_DIAGNOSTICS_LOG_DHCP = "/diagnostics/log/dhcp"
API_DIAGNOSTICS_LOG_DNS = "/diagnostics/log/dns"
API_DIAGNOSTICS_LOG_OPENVPN = "/diagnostics/log/openvpn"
API_DIAGNOSTICS_LOG_IPSEC = "/diagnostics/log/ipsec"
API_DIAGNOSTICS_LOG_SQUID = "/diagnostics/log/squid"
API_DIAGNOSTICS_LOG_HAPROXY = "/diagnostics/log/haproxy"

# Log Management
API_DIAGNOSTICS_LOG_CLEAR = "/diagnostics/log/clear"  # Needs /{log_type}
API_DIAGNOSTICS_LOG_EXPORT = "/diagnostics/log/export"  # Needs /{log_type}
API_DIAGNOSTICS_LOG_STATS = "/diagnostics/log/stats"  # Needs /{log_type}
API_DIAGNOSTICS_LOG_TAIL = "/diagnostics/log/tail"  # Needs /{log_type}
API_DIAGNOSTICS_LOG_SETTINGS = "/diagnostics/log/settings"
API_DIAGNOSTICS_LOG_SET_SETTINGS = "/diagnostics/log/setSettings"
API_DIAGNOSTICS_LOG_STREAM = "/diagnostics/log/stream"  # Needs /{log_type}
API_DIAGNOSTICS_LOG_FIREWALL_STREAM = "/diagnostics/log/firewall/stream"
API_DIAGNOSTICS_LOG_PATTERNS = "/diagnostics/log/patterns"  # Needs /{log_type}
API_DIAGNOSTICS_LOG_SUMMARY = "/diagnostics/log/summary"  # Needs /{log_type}
API_DIAGNOSTICS_LOG_SEARCH_ALL = "/diagnostics/log/search"

# Routing
API_ROUTES_GET = "/routes/routes/get"

# VPN Services
API_OPENVPN_SERVICE_STATUS = "/openvpn/service/getStatus"
API_IPSEC_SERVICE_STATUS = "/ipsec/service/status"
API_WIREGUARD_SERVICE_SHOW = "/wireguard/service/show"

# NAT - Source NAT (Outbound NAT)
API_FIREWALL_SOURCE_NAT_SEARCH_RULE = "/firewall/source_nat/search_rule"
API_FIREWALL_SOURCE_NAT_GET_RULE = "/firewall/source_nat/get_rule"  # Needs /{uuid}
API_FIREWALL_SOURCE_NAT_ADD_RULE = "/firewall/source_nat/add_rule"
API_FIREWALL_SOURCE_NAT_SET_RULE = "/firewall/source_nat/set_rule"  # Needs /{uuid}
API_FIREWALL_SOURCE_NAT_DEL_RULE = "/firewall/source_nat/del_rule"  # Needs /{uuid}
API_FIREWALL_SOURCE_NAT_TOGGLE_RULE = "/firewall/source_nat/toggle_rule"  # Needs /{uuid}/{enabled}

# NAT - One-to-One NAT
API_FIREWALL_ONE_TO_ONE_SEARCH_RULE = "/firewall/one_to_one/search_rule"
API_FIREWALL_ONE_TO_ONE_GET_RULE = "/firewall/one_to_one/get_rule"  # Needs /{uuid}
API_FIREWALL_ONE_TO_ONE_ADD_RULE = "/firewall/one_to_one/add_rule"
API_FIREWALL_ONE_TO_ONE_SET_RULE = "/firewall/one_to_one/set_rule"  # Needs /{uuid}
API_FIREWALL_ONE_TO_ONE_DEL_RULE = "/firewall/one_to_one/del_rule"  # Needs /{uuid}
API_FIREWALL_ONE_TO_ONE_TOGGLE_RULE = "/firewall/one_to_one/toggle_rule"  # Needs /{uuid}/{enabled}

# Firewall Configuration Management
API_FIREWALL_FILTER_BASE_APPLY = "/firewall/filter_base/apply"
API_FIREWALL_FILTER_BASE_SAVEPOINT = "/firewall/filter_base/savepoint"
API_FIREWALL_FILTER_BASE_REVERT = "/firewall/filter_base/revert"

# User Management
API_CORE_USER_SEARCH = "/core/user/searchUser"
API_CORE_USER_GET = "/core/user/getUser"  # Optional /{uuid}
API_CORE_USER_ADD = "/core/user/addUser"
API_CORE_USER_SET = "/core/user/setUser"  # Needs /{uuid}
API_CORE_USER_DEL = "/core/user/delUser"  # Needs /{uuid}
API_CORE_USER_TOGGLE = "/core/user/toggleUser"  # Needs /{uuid}/{enabled}

# Group Management
API_CORE_GROUP_SEARCH = "/core/group/searchGroup"
API_CORE_GROUP_GET = "/core/group/getGroup"  # Optional /{uuid}
API_CORE_GROUP_ADD = "/core/group/addGroup"
API_CORE_GROUP_SET = "/core/group/setGroup"  # Needs /{uuid}
API_CORE_GROUP_DEL = "/core/group/delGroup"  # Needs /{uuid}

# Authentication and Authorization
API_CORE_AUTH_PRIVILEGES = "/core/auth/privileges"
API_CORE_AUTH_SERVERS = "/core/auth/authServers"
API_CORE_AUTH_TEST = "/core/auth/testAuthentication"
API_CORE_CONFIG_RELOAD = "/core/config/reload"

# Traffic Shaper - Service Control
API_TRAFFICSHAPER_SERVICE_FLUSHRELOAD = "/trafficshaper/service/flushreload"
API_TRAFFICSHAPER_SERVICE_RECONFIGURE = "/trafficshaper/service/reconfigure"
API_TRAFFICSHAPER_SERVICE_STATISTICS = "/trafficshaper/service/statistics"

# Traffic Shaper - Pipe Management
API_TRAFFICSHAPER_SETTINGS_ADD_PIPE = "/trafficshaper/settings/add_pipe"
API_TRAFFICSHAPER_SETTINGS_DEL_PIPE = "/trafficshaper/settings/del_pipe"  # Needs /{uuid}
API_TRAFFICSHAPER_SETTINGS_GET_PIPE = "/trafficshaper/settings/get_pipe"  # Optional /{uuid}
API_TRAFFICSHAPER_SETTINGS_SET_PIPE = "/trafficshaper/settings/set_pipe"  # Needs /{uuid}
API_TRAFFICSHAPER_SETTINGS_TOGGLE_PIPE = "/trafficshaper/settings/toggle_pipe"  # Needs /{uuid}/{enabled}
API_TRAFFICSHAPER_SETTINGS_SEARCH_PIPES = "/trafficshaper/settings/search_pipes"

# Traffic Shaper - Queue Management
API_TRAFFICSHAPER_SETTINGS_ADD_QUEUE = "/trafficshaper/settings/add_queue"
API_TRAFFICSHAPER_SETTINGS_DEL_QUEUE = "/trafficshaper/settings/del_queue"  # Needs /{uuid}
API_TRAFFICSHAPER_SETTINGS_GET_QUEUE = "/trafficshaper/settings/get_queue"  # Optional /{uuid}
API_TRAFFICSHAPER_SETTINGS_SET_QUEUE = "/trafficshaper/settings/set_queue"  # Needs /{uuid}
API_TRAFFICSHAPER_SETTINGS_TOGGLE_QUEUE = "/trafficshaper/settings/toggle_queue"  # Needs /{uuid}/{enabled}
API_TRAFFICSHAPER_SETTINGS_SEARCH_QUEUES = "/trafficshaper/settings/search_queues"

# Traffic Shaper - Rule Management
API_TRAFFICSHAPER_SETTINGS_ADD_RULE = "/trafficshaper/settings/add_rule"
API_TRAFFICSHAPER_SETTINGS_DEL_RULE = "/trafficshaper/settings/del_rule"  # Needs /{uuid}
API_TRAFFICSHAPER_SETTINGS_GET_RULE = "/trafficshaper/settings/get_rule"  # Optional /{uuid}
API_TRAFFICSHAPER_SETTINGS_SET_RULE = "/trafficshaper/settings/set_rule"  # Needs /{uuid}
API_TRAFFICSHAPER_SETTINGS_TOGGLE_RULE = "/trafficshaper/settings/toggle_rule"  # Needs /{uuid}/{enabled}
API_TRAFFICSHAPER_SETTINGS_SEARCH_RULES = "/trafficshaper/settings/search_rules"

# Traffic Shaper - General Settings
API_TRAFFICSHAPER_SETTINGS_GET = "/trafficshaper/settings/get"
API_TRAFFICSHAPER_SETTINGS_SET = "/trafficshaper/settings/set"
