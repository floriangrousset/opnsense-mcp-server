"""
Mock API responses for OPNsense API endpoints.

This module contains realistic mock responses for various OPNsense API endpoints
used throughout the test suite.
"""



# ========== System Responses ==========

MOCK_SYSTEM_STATUS = {
    "uptime": "5 days, 3 hours, 42 minutes",
    "cpu_load": [0.15, 0.20, 0.18],
    "memory_usage": {"total": 16384, "free": 8192, "used": 8192, "percent": 50.0},
    "disk_usage": {"total": 500000, "free": 250000, "used": 250000, "percent": 50.0},
}

MOCK_SYSTEM_HEALTH = {
    "cpu": {"temperature": 45.5, "usage_percent": 25.3},
    "memory": {"total_mb": 16384, "used_mb": 8192, "free_mb": 8192},
    "disk": {"filesystem": "/", "size_gb": 488.3, "used_gb": 244.1, "available_gb": 244.2},
}

MOCK_FIRMWARE_STATUS = {
    "product_name": "OPNsense",
    "product_version": "24.1.1",
    "last_check": "2024-10-04T12:00:00Z",
    "status": "up-to-date",
}

# ========== Firewall Responses ==========

MOCK_FIREWALL_RULES = {
    "rows": [
        {
            "uuid": "rule-uuid-001",
            "enabled": "1",
            "sequence": "1",
            "action": "pass",
            "interface": "lan",
            "protocol": "tcp",
            "source": "any",
            "destination": "any",
            "destination_port": "80,443",
            "description": "Allow HTTP/HTTPS",
        },
        {
            "uuid": "rule-uuid-002",
            "enabled": "1",
            "sequence": "2",
            "action": "block",
            "interface": "wan",
            "protocol": "any",
            "source": "any",
            "destination": "any",
            "description": "Block all from WAN",
        },
    ],
    "rowCount": 2,
}

MOCK_FIREWALL_ALIASES = {
    "aliases": {
        "alias": [
            {
                "uuid": "alias-uuid-001",
                "enabled": "1",
                "name": "WebServers",
                "type": "host",
                "content": "192.168.1.10\n192.168.1.11",
                "description": "Web server IP addresses",
            },
            {
                "uuid": "alias-uuid-002",
                "enabled": "1",
                "name": "BlockedIPs",
                "type": "network",
                "content": "10.0.0.0/8\n172.16.0.0/12",
                "description": "Blocked IP ranges",
            },
        ]
    }
}

# ========== NAT Responses ==========

MOCK_NAT_OUTBOUND_RULES = {
    "rows": [
        {
            "uuid": "nat-uuid-001",
            "enabled": "1",
            "interface": "wan",
            "source": "192.168.1.0/24",
            "destination": "any",
            "target": "wan_address",
            "description": "NAT LAN to WAN",
        }
    ],
    "rowCount": 1,
}

MOCK_NAT_ONE_TO_ONE_RULES = {
    "rows": [
        {
            "uuid": "nat-121-uuid-001",
            "enabled": "1",
            "interface": "wan",
            "external": "203.0.113.10",
            "internal": "192.168.1.100",
            "description": "1:1 NAT for web server",
        }
    ],
    "rowCount": 1,
}

# ========== Network Responses ==========

MOCK_INTERFACES = {
    "interfaces": {
        "lan": {
            "if": "em0",
            "descr": "LAN",
            "ipaddr": "192.168.1.1",
            "subnet": "24",
            "status": "up",
        },
        "wan": {
            "if": "em1",
            "descr": "WAN",
            "ipaddr": "203.0.113.1",
            "subnet": "24",
            "status": "up",
        },
    }
}

MOCK_VLANS = {
    "vlan": [
        {"uuid": "vlan-uuid-001", "if": "em0", "tag": "100", "pcp": "0", "description": "IoT VLAN"},
        {
            "uuid": "vlan-uuid-002",
            "if": "em0",
            "tag": "200",
            "pcp": "0",
            "description": "Guest VLAN",
        },
    ]
}

# ========== DHCP Responses ==========

MOCK_DHCP_LEASES = {
    "leases": [
        {
            "address": "192.168.1.100",
            "mac": "aa:bb:cc:dd:ee:ff",
            "hostname": "test-device",
            "starts": "2024-10-04 10:00:00",
            "ends": "2024-10-04 22:00:00",
            "state": "active",
        },
        {
            "address": "192.168.1.101",
            "mac": "11:22:33:44:55:66",
            "hostname": "laptop-001",
            "starts": "2024-10-04 09:00:00",
            "ends": "2024-10-04 21:00:00",
            "state": "active",
        },
    ]
}

MOCK_DHCP_SERVER_CONFIG = {
    "dhcpd": {
        "lan": {
            "enable": "1",
            "range": {"from": "192.168.1.100", "to": "192.168.1.200"},
            "gateway": "192.168.1.1",
            "dns": ["8.8.8.8", "8.8.4.4"],
            "domain": "local.lan",
        }
    }
}

# ========== DNS Responses ==========

MOCK_DNS_RESOLVER_SETTINGS = {
    "general": {"enabled": "1", "port": "53", "dnssec": "1"},
    "advanced": {"cache": {"size": "256", "ttl_min": "60", "ttl_max": "86400"}},
}

MOCK_DNS_HOST_OVERRIDES = {
    "hosts": [
        {
            "uuid": "host-uuid-001",
            "enabled": "1",
            "host": "server",
            "domain": "local.lan",
            "ip": "192.168.1.10",
            "description": "Internal server",
        }
    ]
}

# ========== Certificate Responses ==========

MOCK_CERTIFICATES = {
    "certificates": [
        {
            "uuid": "cert-uuid-001",
            "descr": "Web Server Certificate",
            "subject": {"CN": "server.local.lan", "O": "Test Organization"},
            "issuer": {"CN": "Test CA", "O": "Test Organization"},
            "valid_from": "2024-01-01 00:00:00",
            "valid_to": "2025-01-01 00:00:00",
            "in_use": True,
        }
    ]
}

MOCK_CERTIFICATE_AUTHORITIES = {
    "ca": [
        {
            "uuid": "ca-uuid-001",
            "descr": "Root CA",
            "subject": {"CN": "Test Root CA", "O": "Test Organization"},
            "valid_from": "2024-01-01 00:00:00",
            "valid_to": "2034-01-01 00:00:00",
        }
    ]
}

# ========== User Responses ==========

MOCK_USERS = {
    "users": [
        {
            "uuid": "user-uuid-001",
            "name": "admin",
            "descr": "Administrator",
            "email": "admin@example.com",
            "disabled": "0",
            "groups": ["admins"],
            "priv": ["page-all"],
        },
        {
            "uuid": "user-uuid-002",
            "name": "readonly",
            "descr": "Read-only user",
            "email": "readonly@example.com",
            "disabled": "0",
            "groups": ["operators"],
            "priv": ["page-dashboard-all"],
        },
    ]
}

MOCK_GROUPS = {
    "groups": [
        {
            "uuid": "group-uuid-001",
            "name": "admins",
            "description": "Administrators",
            "member": ["user-uuid-001"],
            "priv": ["page-all"],
        },
        {
            "uuid": "group-uuid-002",
            "name": "operators",
            "description": "Operators",
            "member": ["user-uuid-002"],
            "priv": ["page-dashboard-all"],
        },
    ]
}

MOCK_PRIVILEGES = {
    "privileges": [
        {"name": "page-all", "descr": "All pages"},
        {"name": "page-dashboard-all", "descr": "Dashboard pages"},
        {"name": "page-firewall-all", "descr": "Firewall pages"},
        {"name": "page-system-all", "descr": "System pages"},
    ]
}

# ========== Traffic Shaping Responses ==========

MOCK_TRAFFIC_SHAPER_PIPES = {
    "pipe": [
        {
            "uuid": "pipe-uuid-001",
            "enabled": "1",
            "number": "1",
            "bandwidth": "100",
            "bandwidthMetric": "Mbit",
            "queue": "100",
            "scheduler": "fq_codel",
            "description": "100Mbps pipe",
        }
    ]
}

MOCK_TRAFFIC_SHAPER_QUEUES = {
    "queue": [
        {
            "uuid": "queue-uuid-001",
            "enabled": "1",
            "number": "1",
            "pipe": "1",
            "weight": "50",
            "description": "Medium priority queue",
        }
    ]
}

# ========== VPN Responses ==========

MOCK_VPN_CONNECTIONS = {
    "openvpn": [
        {"name": "Site-to-Site VPN", "status": "up", "mode": "p2p", "remote": "203.0.113.50"}
    ],
    "ipsec": [
        {
            "name": "IPsec Tunnel",
            "status": "established",
            "local": "192.168.1.1",
            "remote": "203.0.113.60",
        }
    ],
    "wireguard": [],
}

# ========== Logging Responses ==========

MOCK_SYSTEM_LOGS = {
    "log": [
        {"timestamp": "2024-10-04 12:00:00", "severity": "info", "message": "System started"},
        {"timestamp": "2024-10-04 12:01:00", "severity": "warning", "message": "High CPU usage"},
        {"timestamp": "2024-10-04 12:02:00", "severity": "info", "message": "Service restarted"},
    ]
}

MOCK_FIREWALL_LOGS = {
    "log": [
        {
            "timestamp": "2024-10-04 12:00:00",
            "action": "block",
            "interface": "wan",
            "protocol": "tcp",
            "src_ip": "203.0.113.100",
            "dst_ip": "192.168.1.1",
            "dst_port": "22",
        }
    ]
}

# ========== Generic Success/Error Responses ==========

MOCK_SUCCESS_RESPONSE = {"result": "saved", "uuid": "test-uuid-123"}

MOCK_ERROR_RESPONSE = {"result": "failed", "validations": {"field.name": "This field is required"}}

MOCK_APPLY_SUCCESS = {"status": "ok", "message": "Configuration applied successfully"}
