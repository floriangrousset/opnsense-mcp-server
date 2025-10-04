"""
Tests for OPNsense MCP Server utilities and VPN domains.

This module tests utility tools and VPN management.
"""

import pytest
import json
from unittest.mock import AsyncMock, Mock, patch


@pytest.mark.asyncio
class TestUtilitiesDomain:
    """Test utilities domain tools."""

    async def test_exec_api_call_get(self, mock_mcp_context):
        """Test executing a custom GET API call."""
        from src.opnsense_mcp.domains.utilities import exec_api_call

        with patch('src.opnsense_mcp.domains.utilities.get_opnsense_client') as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={"status": "ok", "data": "test"})
            mock_get_client.return_value = mock_client

            result = await exec_api_call(
                ctx=mock_mcp_context,
                method="GET",
                endpoint="/core/system/status"
            )

            result_data = json.loads(result)
            assert result_data["status"] == "ok"

    async def test_exec_api_call_post_with_data(self, mock_mcp_context):
        """Test executing a custom POST API call with data."""
        from src.opnsense_mcp.domains.utilities import exec_api_call

        with patch('src.opnsense_mcp.domains.utilities.get_opnsense_client') as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={"result": "saved"})
            mock_get_client.return_value = mock_client

            result = await exec_api_call(
                ctx=mock_mcp_context,
                method="POST",
                endpoint="/test/endpoint",
                data_json='{"key": "value"}'
            )

            result_data = json.loads(result)
            assert result_data["result"] == "saved"

    async def test_exec_api_call_invalid_json(self, mock_mcp_context):
        """Test handling of invalid JSON in data parameter."""
        from src.opnsense_mcp.domains.utilities import exec_api_call

        result = await exec_api_call(
            ctx=mock_mcp_context,
            method="POST",
            endpoint="/test",
            data_json='invalid json{'
        )

        assert "error" in result.lower() or "invalid" in result.lower()


@pytest.mark.asyncio
class TestVPNDomain:
    """Test VPN domain tools."""

    async def test_get_vpn_connections(self, mock_mcp_context):
        """Test retrieving VPN connections."""
        from src.opnsense_mcp.domains.vpn import get_vpn_connections

        with patch('src.opnsense_mcp.domains.vpn.get_opnsense_client') as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(side_effect=[
                {"rows": [{"name": "OpenVPN1", "status": "up"}]},  # OpenVPN
                {"rows": [{"name": "IPsec1", "status": "established"}]},  # IPsec
                {"rows": []}  # WireGuard
            ])
            mock_get_client.return_value = mock_client

            result = await get_vpn_connections(ctx=mock_mcp_context)

            result_data = json.loads(result)
            assert "openvpn" in result_data or "ipsec" in result_data

    async def test_get_vpn_connections_partial_failure(self, mock_mcp_context):
        """Test VPN retrieval with some services failing."""
        from src.opnsense_mcp.domains.vpn import get_vpn_connections

        with patch('src.opnsense_mcp.domains.vpn.get_opnsense_client') as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(side_effect=[
                {"rows": [{"name": "OpenVPN1"}]},  # OpenVPN success
                Exception("IPsec not available"),  # IPsec fail
                {"rows": []}  # WireGuard success
            ])
            mock_get_client.return_value = mock_client

            result = await get_vpn_connections(ctx=mock_mcp_context)

            # Should still return partial data
            result_data = json.loads(result)
            assert isinstance(result_data, dict)
