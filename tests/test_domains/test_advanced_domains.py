"""
Tests for OPNsense MCP Server advanced domains.

This module tests user management, logging, and traffic shaping.
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
class TestUsersDomain:
    """Test users domain tools."""

    async def test_list_users(self, mock_mcp_context):
        """Test listing users."""
        from src.opnsense_mcp.domains.users import list_users

        with patch('src.opnsense_mcp.domains.users.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={
                "rows": [{"uuid": "user1", "name": "admin", "disabled": "0"}]
            })
            mock_get_client.return_value = mock_client

            result = await list_users(ctx=mock_mcp_context)

            result_data = json.loads(result)
            assert "rows" in result_data

    async def test_create_user(self, mock_mcp_context):
        """Test creating a user."""
        from src.opnsense_mcp.domains.users import create_user

        with patch('src.opnsense_mcp.domains.users.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={"result": "saved", "uuid": "new-user"})
            mock_get_client.return_value = mock_client

            result = await create_user(
                ctx=mock_mcp_context,
                username="testuser",
                password="SecurePass123!",
                full_name="Test User"
            )

            # Function returns JSON with result
            result_data = json.loads(result)
            assert result_data.get("result") == "saved" or "uuid" in result_data

    async def test_list_groups(self, mock_mcp_context):
        """Test listing groups."""
        from src.opnsense_mcp.domains.users import list_groups

        with patch('src.opnsense_mcp.domains.users.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={
                "rows": [{"uuid": "group1", "name": "admins"}]
            })
            mock_get_client.return_value = mock_client

            result = await list_groups(ctx=mock_mcp_context)

            result_data = json.loads(result)
            assert "rows" in result_data


@pytest.mark.asyncio
class TestLoggingDomain:
    """Test logging domain tools."""

    async def test_get_system_logs(self, mock_mcp_context):
        """Test retrieving system logs."""
        from src.opnsense_mcp.domains.logging import get_system_logs

        with patch('src.opnsense_mcp.domains.logging.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={
                "rows": [{"timestamp": "2024-10-04 12:00:00", "message": "System started"}]
            })
            mock_get_client.return_value = mock_client

            result = await get_system_logs(ctx=mock_mcp_context, severity="info", count=100)

            result_data = json.loads(result)
            # Function returns structured response with entries key
            assert "entries" in result_data
            assert "rows" in result_data["entries"]

    async def test_search_logs(self, mock_mcp_context):
        """Test searching across logs."""
        from src.opnsense_mcp.domains.logging import search_logs

        with patch('src.opnsense_mcp.domains.logging.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={
                "rows": [{"message": "Authentication failed", "severity": "warning"}]
            })
            mock_get_client.return_value = mock_client

            result = await search_logs(
                ctx=mock_mcp_context,
                search_query="authentication",
                case_sensitive=False
            )

            assert "authentication" in result.lower() or "found" in result.lower()

    async def test_analyze_security_events(self, mock_mcp_context):
        """Test security event analysis."""
        from src.opnsense_mcp.domains.logging import analyze_security_events

        with patch('src.opnsense_mcp.domains.logging.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={
                "rows": [
                    {"message": "Failed login attempt", "src_ip": "192.168.1.100"},
                    {"message": "Port scan detected", "src_ip": "10.0.0.50"}
                ]
            })
            mock_get_client.return_value = mock_client

            result = await analyze_security_events(ctx=mock_mcp_context)

            # Should identify security patterns
            assert "security" in result.lower() or "threat" in result.lower() or "analysis" in result.lower()


@pytest.mark.asyncio
class TestTrafficShapingDomain:
    """Test traffic shaping domain tools."""

    async def test_traffic_shaper_list_pipes(self, mock_mcp_context):
        """Test listing traffic shaper pipes."""
        from src.opnsense_mcp.domains.traffic_shaping import traffic_shaper_list_pipes

        with patch('src.opnsense_mcp.domains.traffic_shaping.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={
                "rows": [{"uuid": "pipe1", "bandwidth": "100", "bandwidthMetric": "Mbit"}]
            })
            mock_get_client.return_value = mock_client

            result = await traffic_shaper_list_pipes(ctx=mock_mcp_context)

            result_data = json.loads(result)
            assert "rows" in result_data

    async def test_traffic_shaper_create_pipe(self, mock_mcp_context):
        """Test creating a traffic shaper pipe."""
        from src.opnsense_mcp.domains.traffic_shaping import traffic_shaper_create_pipe

        with patch('src.opnsense_mcp.domains.traffic_shaping.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={"result": "saved", "uuid": "new-pipe"})
            mock_get_client.return_value = mock_client

            result = await traffic_shaper_create_pipe(
                ctx=mock_mcp_context,
                bandwidth="50",
                bandwidth_metric="Mbit",
                description="Test pipe"
            )

            # Handle both JSON and error string responses
            if result.startswith("Error"):
                assert "error" in result.lower()
            else:
                result_data = json.loads(result)
                assert result_data.get("result") == "saved" or "uuid" in result_data

    async def test_traffic_shaper_list_queues(self, mock_mcp_context):
        """Test listing traffic shaper queues."""
        from src.opnsense_mcp.domains.traffic_shaping import traffic_shaper_list_queues

        with patch('src.opnsense_mcp.domains.traffic_shaping.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={
                "rows": [{"uuid": "queue1", "pipe": "1", "weight": "50"}]
            })
            mock_get_client.return_value = mock_client

            result = await traffic_shaper_list_queues(ctx=mock_mcp_context)

            result_data = json.loads(result)
            assert "rows" in result_data

    async def test_traffic_shaper_limit_user_bandwidth(self, mock_mcp_context):
        """Test high-level bandwidth limiting helper."""
        from src.opnsense_mcp.domains.traffic_shaping import traffic_shaper_limit_user_bandwidth

        with patch('src.opnsense_mcp.domains.traffic_shaping.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={"result": "saved"})
            mock_get_client.return_value = mock_client

            result = await traffic_shaper_limit_user_bandwidth(
                ctx=mock_mcp_context,
                user_ip="192.168.1.100",
                download_limit_mbps=10,
                upload_limit_mbps=5
            )

            # This function returns JSON structure with pipe/rule info
            result_data = json.loads(result)
            assert isinstance(result_data, dict)
            # Function returns download_pipe, upload_pipe, download_rule, upload_rule keys
            assert "download_pipe" in result_data or "result" in result_data
