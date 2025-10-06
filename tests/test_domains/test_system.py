"""
Tests for OPNsense MCP Server system domain.

This module tests the system management tools including status monitoring,
health metrics, service management, and security auditing.
"""

import json
import sys
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from mcp.server.fastmcp import FastMCP

# Mock the circular import with proper FastMCP instance
mock_mcp = FastMCP("test-server")
mock_server_state = MagicMock()
mock_main = MagicMock()
mock_main.mcp = mock_mcp
mock_main.server_state = mock_server_state
sys.modules["src.opnsense_mcp.main"] = mock_main

from src.opnsense_mcp.core.exceptions import APIError, ConfigurationError
from src.opnsense_mcp.domains.system import (
    _get_all_rules,
    _get_wan_interfaces,
    backup_config,
    get_system_health,
    get_system_status,
    restart_service,
)


@pytest.mark.asyncio
class TestGetSystemStatus:
    """Test get_system_status tool."""

    async def test_successful_status_retrieval(
        self, mock_mcp_context, mock_firmware_status_response
    ):
        """Test successful system status retrieval."""
        with patch(
            "src.opnsense_mcp.domains.system.get_opnsense_client", new_callable=AsyncMock
        ) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(
                side_effect=[
                    mock_firmware_status_response,  # Firmware
                    {"hostname": "opnsense.local"},  # System info
                    {"rows": [{"name": "sshd", "status": "running"}]},  # Services
                ]
            )
            mock_get_client.return_value = mock_client

            result = await get_system_status(ctx=mock_mcp_context)

            # Should return JSON with firmware, system, and services
            result_data = json.loads(result)
            assert "firmware" in result_data
            assert "system" in result_data
            assert "services" in result_data
            assert mock_client.request.call_count == 3

    async def test_configuration_error_handling(self, mock_mcp_context):
        """Test handling of configuration errors."""
        with patch(
            "src.opnsense_mcp.domains.system.get_opnsense_client", new_callable=AsyncMock
        ) as mock_get_client:
            mock_get_client.side_effect = ConfigurationError("Not configured")

            result = await get_system_status(ctx=mock_mcp_context)

            assert "Configuration Error" in result
            mock_mcp_context.error.assert_called_once()

    async def test_api_error_handling(self, mock_mcp_context):
        """Test handling of API errors."""
        with patch(
            "src.opnsense_mcp.domains.system.get_opnsense_client", new_callable=AsyncMock
        ) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(side_effect=APIError("API error"))
            mock_get_client.return_value = mock_client

            result = await get_system_status(ctx=mock_mcp_context)

            assert "Error" in result


@pytest.mark.asyncio
class TestGetSystemHealth:
    """Test get_system_health tool."""

    async def test_successful_health_retrieval(self, mock_mcp_context):
        """Test successful system health metrics retrieval."""
        with patch(
            "src.opnsense_mcp.domains.system.get_opnsense_client", new_callable=AsyncMock
        ) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(
                side_effect=[
                    {"usage": "25.5"},  # CPU
                    {"physical": "16384", "used": "8192"},  # Memory
                    {"/": {"used": "50%"}},  # Storage
                    {"cpu": "45.5"},  # Temperature
                ]
            )
            mock_get_client.return_value = mock_client

            result = await get_system_health(ctx=mock_mcp_context)

            # Should return JSON with health metrics
            result_data = json.loads(result)
            assert "cpu" in result_data
            assert "memory" in result_data
            assert "disk" in result_data

    async def test_partial_health_data(self, mock_mcp_context):
        """Test health retrieval with some API endpoints failing."""
        with patch(
            "src.opnsense_mcp.domains.system.get_opnsense_client", new_callable=AsyncMock
        ) as mock_get_client:
            mock_client = Mock()
            # When any request fails, the whole function returns an error string
            mock_client.request = AsyncMock(side_effect=Exception("Memory API failed"))
            mock_get_client.return_value = mock_client

            result = await get_system_health(ctx=mock_mcp_context)

            # Should return error string
            assert "error" in result.lower()


@pytest.mark.asyncio
class TestRestartService:
    """Test restart_service tool."""

    async def test_successful_service_restart(self, mock_mcp_context):
        """Test successful service restart."""
        with patch(
            "src.opnsense_mcp.domains.system.get_opnsense_client", new_callable=AsyncMock
        ) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={"status": "ok"})
            mock_get_client.return_value = mock_client

            result = await restart_service(ctx=mock_mcp_context, service_name="sshd")

            assert "successfully" in result.lower() or "ok" in result.lower()
            # Verify correct endpoint was called
            call_args = mock_client.request.call_args[0]
            assert "service" in call_args[1]
            assert "restart" in call_args[1]

    async def test_service_restart_error(self, mock_mcp_context):
        """Test service restart error handling."""
        with patch(
            "src.opnsense_mcp.domains.system.get_opnsense_client", new_callable=AsyncMock
        ) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(side_effect=APIError("Service not found"))
            mock_get_client.return_value = mock_client

            result = await restart_service(ctx=mock_mcp_context, service_name="nonexistent")

            assert "Error" in result


@pytest.mark.asyncio
class TestBackupConfig:
    """Test backup_config tool."""

    async def test_successful_backup(self, mock_mcp_context):
        """Test successful configuration backup."""
        with patch(
            "src.opnsense_mcp.domains.system.get_opnsense_client", new_callable=AsyncMock
        ) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value="<?xml version='1.0'?><config></config>")
            mock_get_client.return_value = mock_client

            result = await backup_config(ctx=mock_mcp_context)

            # Should return XML configuration or success message
            assert "xml" in result.lower() or "backup" in result.lower()

    async def test_backup_error_handling(self, mock_mcp_context):
        """Test backup error handling."""
        with patch(
            "src.opnsense_mcp.domains.system.get_opnsense_client", new_callable=AsyncMock
        ) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(side_effect=APIError("Backup failed"))
            mock_get_client.return_value = mock_client

            result = await backup_config(ctx=mock_mcp_context)

            assert "Error" in result


@pytest.mark.asyncio
class TestHelperFunctions:
    """Test helper functions."""

    async def test_get_all_rules_single_page(self):
        """Test fetching firewall rules when all fit in one page."""
        mock_client = Mock()
        mock_rules = [
            {"uuid": "rule1", "description": "Rule 1"},
            {"uuid": "rule2", "description": "Rule 2"},
        ]
        mock_client.request = AsyncMock(return_value={"rows": mock_rules})

        result = await _get_all_rules(mock_client)

        assert len(result) == 2
        assert result[0]["uuid"] == "rule1"
        mock_client.request.assert_called_once()

    async def test_get_all_rules_multiple_pages(self):
        """Test fetching firewall rules with pagination."""
        mock_client = Mock()

        # First call returns 500 rules (full page), second returns 200 (partial page, triggers break)
        mock_client.request = AsyncMock(
            side_effect=[
                {"rows": [{"uuid": f"rule{i}"} for i in range(500)]},
                {"rows": [{"uuid": f"rule{i}"} for i in range(500, 700)]},
            ]
        )

        result = await _get_all_rules(mock_client)

        assert len(result) == 700
        # Function stops when it receives < 500 rules (line 75-76 of system.py)
        assert mock_client.request.call_count == 2

    async def test_get_all_rules_handles_error(self):
        """Test that _get_all_rules handles errors gracefully."""
        mock_client = Mock()
        mock_client.request = AsyncMock(
            side_effect=[{"rows": [{"uuid": "rule1"}]}, Exception("API error on page 2")]
        )

        result = await _get_all_rules(mock_client)

        # Should return partial results
        assert len(result) == 1
        assert result[0]["uuid"] == "rule1"

    async def test_get_wan_interfaces_with_gateway(self):
        """Test identifying WAN interfaces by gateway presence."""
        mock_client = Mock()
        mock_interfaces = {
            "wan": {"gateway": "192.168.1.1", "status": "up"},
            "lan": {"gateway": "none", "status": "up"},
            "opt1": {"gateway": "10.0.0.1", "status": "up"},
        }
        mock_client.request = AsyncMock(return_value=mock_interfaces)

        result = await _get_wan_interfaces(mock_client)

        # Should identify wan and opt1 as WAN interfaces (they have gateways)
        assert "wan" in result
        assert "opt1" in result
        assert "lan" not in result

    async def test_get_wan_interfaces_fallback_to_name(self):
        """Test WAN identification fallback to interface name."""
        mock_client = Mock()
        mock_interfaces = {
            "wan": {"gateway": "none", "status": "up"},  # No gateway but named 'wan'
            "lan": {"gateway": "none", "status": "up"},
        }
        mock_client.request = AsyncMock(return_value=mock_interfaces)

        result = await _get_wan_interfaces(mock_client)

        # Should still identify 'wan' by name
        assert "wan" in result

    async def test_get_wan_interfaces_handles_error(self):
        """Test that _get_wan_interfaces handles errors gracefully."""
        mock_client = Mock()
        mock_client.request = AsyncMock(side_effect=Exception("API error"))

        result = await _get_wan_interfaces(mock_client)

        # Should return empty list on error
        assert result == []

    async def test_get_wan_interfaces_none_identified(self):
        """Test when no WAN interfaces can be identified."""
        mock_client = Mock()
        mock_interfaces = {
            "lan": {"gateway": "none", "status": "up"},
            "opt1": {"gateway": "none", "status": "up"},
        }
        mock_client.request = AsyncMock(return_value=mock_interfaces)

        result = await _get_wan_interfaces(mock_client)

        # Should return empty list
        assert result == []
