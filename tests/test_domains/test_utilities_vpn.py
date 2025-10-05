"""
Tests for OPNsense MCP Server utilities and VPN domains.

This module tests utility tools and VPN management.
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
class TestUtilitiesDomain:
    """Test utilities domain tools."""

    async def test_exec_api_call_get(self, mock_mcp_context):
        """Test executing a custom GET API call."""
        from src.opnsense_mcp.domains.utilities import exec_api_call

        with patch('src.opnsense_mcp.domains.utilities.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
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

        with patch('src.opnsense_mcp.domains.utilities.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={"result": "saved"})
            mock_get_client.return_value = mock_client

            result = await exec_api_call(
                ctx=mock_mcp_context,
                method="POST",
                endpoint="/test/endpoint",
                data='{"key": "value"}'
            )

            result_data = json.loads(result)
            assert result_data["result"] == "saved"

    async def test_exec_api_call_invalid_json(self, mock_mcp_context):
        """Test handling of invalid JSON in data parameter."""
        from src.opnsense_mcp.domains.utilities import exec_api_call

        with patch('src.opnsense_mcp.domains.utilities.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_get_client.return_value = mock_client

            result = await exec_api_call(
                ctx=mock_mcp_context,
                method="POST",
                endpoint="/test",
                data='invalid json{'
            )

            assert "error" in result.lower() and "invalid" in result.lower()


@pytest.mark.asyncio
class TestVPNDomain:
    """Test VPN domain tools."""

    async def test_get_vpn_connections(self, mock_mcp_context):
        """Test retrieving VPN connections."""
        from src.opnsense_mcp.domains.vpn import get_vpn_connections

        with patch('src.opnsense_mcp.domains.vpn.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            # Function only makes ONE call for default vpn_type="OpenVPN"
            mock_client.request = AsyncMock(return_value={
                "rows": [{"name": "OpenVPN1", "status": "up"}]
            })
            mock_get_client.return_value = mock_client

            result = await get_vpn_connections(ctx=mock_mcp_context)

            result_data = json.loads(result)
            assert "rows" in result_data
            assert mock_client.request.call_count == 1

    async def test_get_vpn_connections_partial_failure(self, mock_mcp_context):
        """Test VPN retrieval when API fails."""
        from src.opnsense_mcp.domains.vpn import get_vpn_connections

        with patch('src.opnsense_mcp.domains.vpn.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            # API call fails, function returns error string
            mock_client.request = AsyncMock(side_effect=Exception("VPN service not available"))
            mock_get_client.return_value = mock_client

            result = await get_vpn_connections(ctx=mock_mcp_context)

            # Should return error string
            assert "error" in result.lower()
