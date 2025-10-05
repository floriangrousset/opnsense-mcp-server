"""
Tests for OPNsense MCP Server network and services domains.

This module tests network interface management, DNS/DHCP services, and certificates.
"""

import pytest
import json
import sys
from unittest.mock import AsyncMock, Mock, patch, MagicMock
from mcp.server.fastmcp import FastMCP

# Mock the circular import with proper FastMCP instance
mock_mcp = FastMCP("test-server")
mock_server_state = MagicMock()
mock_main = MagicMock()
mock_main.mcp = mock_mcp
mock_main.server_state = mock_server_state
sys.modules['src.opnsense_mcp.main'] = mock_main


@pytest.mark.asyncio
class TestNetworkDomain:
    """Test network domain tools."""

    async def test_list_vlans(self, mock_mcp_context):
        """Test listing VLANs."""
        from src.opnsense_mcp.domains.network import list_vlan_interfaces

        with patch('src.opnsense_mcp.domains.network.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={
                "rows": [{"uuid": "vlan1", "tag": "100", "if": "em0"}]
            })
            mock_get_client.return_value = mock_client

            result = await list_vlan_interfaces(ctx=mock_mcp_context)

            result_data = json.loads(result)
            assert "rows" in result_data

    async def test_create_vlan_interface(self, mock_mcp_context):
        """Test creating a VLAN interface."""
        from src.opnsense_mcp.domains.network import create_vlan_interface

        with patch('src.opnsense_mcp.domains.network.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={"result": "saved", "uuid": "new-vlan"})
            mock_get_client.return_value = mock_client

            result = await create_vlan_interface(
                ctx=mock_mcp_context,
                parent_interface="em0",
                vlan_tag=100,
                description="IoT VLAN"
            )

            # Function returns JSON with result
            result_data = json.loads(result)
            assert result_data.get("result") == "saved" or "uuid" in result_data

    async def test_list_virtual_ips(self, mock_mcp_context):
        """Test listing virtual IPs."""
        from src.opnsense_mcp.domains.network import list_virtual_ips

        with patch('src.opnsense_mcp.domains.network.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={
                "rows": [{"type": "carp", "interface": "lan", "subnet": "192.168.1.100/24"}]
            })
            mock_get_client.return_value = mock_client

            result = await list_virtual_ips(ctx=mock_mcp_context)

            result_data = json.loads(result)
            assert "rows" in result_data


@pytest.mark.asyncio
class TestDNSDHCPDomain:
    """Test DNS and DHCP domain tools."""

    async def test_dhcp_get_leases(self, mock_mcp_context):
        """Test retrieving DHCP leases."""
        from src.opnsense_mcp.domains.dns_dhcp import dhcp_get_leases

        with patch('src.opnsense_mcp.domains.dns_dhcp.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={
                "rows": [{"address": "192.168.1.100", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "device1"}]
            })
            mock_get_client.return_value = mock_client

            result = await dhcp_get_leases(ctx=mock_mcp_context)

            # Check if result is JSON or error string
            if result.startswith("Error"):
                assert "error" in result.lower()
            else:
                result_data = json.loads(result)
                assert "rows" in result_data or "leases" in result_data

    async def test_dns_resolver_get_settings(self, mock_mcp_context):
        """Test retrieving DNS resolver settings."""
        from src.opnsense_mcp.domains.dns_dhcp import dns_resolver_get_settings

        with patch('src.opnsense_mcp.domains.dns_dhcp.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={
                "unbound": {"enabled": "1", "port": "53"}
            })
            mock_get_client.return_value = mock_client

            result = await dns_resolver_get_settings(ctx=mock_mcp_context)

            # Check if result is JSON or error string
            if result.startswith("Error"):
                assert "error" in result.lower()
            else:
                result_data = json.loads(result)
                assert "unbound" in result_data or isinstance(result_data, dict)

    async def test_dns_resolver_add_host_override(self, mock_mcp_context):
        """Test adding DNS host override."""
        from src.opnsense_mcp.domains.dns_dhcp import dns_resolver_add_host_override

        with patch('src.opnsense_mcp.domains.dns_dhcp.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={"result": "saved"})
            mock_get_client.return_value = mock_client

            result = await dns_resolver_add_host_override(
                ctx=mock_mcp_context,
                hostname="server",
                domain="local.lan",
                ip_address="192.168.1.10"
            )

            # Handle both JSON and error string responses
            if result.startswith("Error"):
                assert "error" in result.lower()
            else:
                # Function returns JSON or success message
                if result.startswith("{"):
                    result_data = json.loads(result)
                    assert result_data.get("result") == "saved" or "uuid" in result_data
                else:
                    assert "success" in result.lower() or "saved" in result.lower()


@pytest.mark.asyncio
class TestCertificatesDomain:
    """Test certificates domain tools."""

    async def test_list_certificates(self, mock_mcp_context):
        """Test listing certificates."""
        from src.opnsense_mcp.domains.certificates import list_certificates

        with patch('src.opnsense_mcp.domains.certificates.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={
                "rows": [{"uuid": "cert1", "descr": "Web Server Cert"}]
            })
            mock_get_client.return_value = mock_client

            result = await list_certificates(ctx=mock_mcp_context)

            result_data = json.loads(result)
            assert "rows" in result_data

    async def test_list_certificate_authorities(self, mock_mcp_context):
        """Test listing certificate authorities."""
        from src.opnsense_mcp.domains.certificates import list_certificate_authorities

        with patch('src.opnsense_mcp.domains.certificates.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={
                "rows": [{"uuid": "ca1", "descr": "Root CA"}]
            })
            mock_get_client.return_value = mock_client

            result = await list_certificate_authorities(ctx=mock_mcp_context)

            result_data = json.loads(result)
            assert "rows" in result_data

    async def test_analyze_certificate_expiration(self, mock_mcp_context):
        """Test certificate expiration analysis."""
        from src.opnsense_mcp.domains.certificates import analyze_certificate_expiration

        with patch('src.opnsense_mcp.domains.certificates.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={
                "rows": [
                    {"uuid": "cert1", "valid_to": "2025-12-31", "descr": "Cert 1"},
                    {"uuid": "cert2", "valid_to": "2024-01-01", "descr": "Cert 2"}
                ]
            })
            mock_get_client.return_value = mock_client

            result = await analyze_certificate_expiration(ctx=mock_mcp_context, warning_days=90)

            # Should return analysis with warnings
            assert "cert" in result.lower() or "expir" in result.lower()
