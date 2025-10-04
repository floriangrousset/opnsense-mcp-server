"""
Integration tests for OPNsense MCP Server.

This module contains integration tests that verify the interaction between
different components of the system.
"""

import pytest
from unittest.mock import AsyncMock, Mock, patch


@pytest.mark.asyncio
@pytest.mark.integration
class TestEndToEndWorkflows:
    """Test end-to-end workflows."""

    async def test_configure_and_get_status_workflow(self, mock_mcp_context):
        """Test complete workflow: configure connection then get system status."""
        from src.opnsense_mcp.domains.configuration import configure_opnsense_connection
        from src.opnsense_mcp.domains.system import get_system_status

        with patch('src.opnsense_mcp.domains.configuration.server_state') as mock_state, \
             patch('src.opnsense_mcp.domains.system.get_opnsense_client') as mock_get_client:

            # Configure connection
            mock_state.initialize = AsyncMock()
            config_result = await configure_opnsense_connection(
                ctx=mock_mcp_context,
                url="https://192.168.1.1",
                api_key="test_key",
                api_secret="test_secret",
                verify_ssl=False
            )

            assert "configured successfully" in config_result

            # Get system status
            mock_client = Mock()
            mock_client.request = AsyncMock(side_effect=[
                {"product_version": "24.1.1"},  # Firmware
                {"hostname": "opnsense.local"},  # System
                {"rows": [{"name": "sshd"}]}  # Services
            ])
            mock_get_client.return_value = mock_client

            status_result = await get_system_status(ctx=mock_mcp_context)

            assert "firmware" in status_result or "system" in status_result

    async def test_firewall_rule_lifecycle(self, mock_mcp_context):
        """Test firewall rule create, retrieve, delete workflow."""
        from src.opnsense_mcp.domains.firewall import (
            firewall_add_rule,
            firewall_get_rules,
            firewall_delete_rule
        )

        with patch('src.opnsense_mcp.domains.firewall.get_opnsense_client') as mock_get_client:
            mock_client = Mock()

            # Add rule
            mock_client.request = AsyncMock(return_value={
                "result": "saved",
                "uuid": "rule-uuid-123"
            })
            mock_get_client.return_value = mock_client

            add_result = await firewall_add_rule(
                ctx=mock_mcp_context,
                interface="lan",
                direction="in",
                action="pass",
                protocol="tcp",
                source="any",
                destination="any",
                description="Test rule"
            )

            assert "success" in add_result.lower() or "saved" in add_result.lower()

            # Get rules
            mock_client.request = AsyncMock(return_value={
                "rows": [{"uuid": "rule-uuid-123", "description": "Test rule"}]
            })

            get_result = await firewall_get_rules(ctx=mock_mcp_context)
            assert "rule-uuid-123" in get_result

            # Delete rule
            mock_client.request = AsyncMock(return_value={"result": "deleted"})

            delete_result = await firewall_delete_rule(
                ctx=mock_mcp_context,
                rule_uuid="rule-uuid-123"
            )

            assert "success" in delete_result.lower() or "deleted" in delete_result.lower()


@pytest.mark.asyncio
@pytest.mark.integration
class TestComponentIntegration:
    """Test integration between different components."""

    async def test_client_pool_integration(self):
        """Test integration between client and connection pool."""
        from src.opnsense_mcp.core.client import OPNsenseClient
        from src.opnsense_mcp.core.connection import ConnectionPool
        from src.opnsense_mcp.core.models import OPNsenseConfig

        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )

        pool = ConnectionPool()
        client = OPNsenseClient(config, pool)

        assert client.pool == pool
        assert client.base_url == "https://192.168.1.1"

    async def test_server_state_client_integration(self):
        """Test integration between server state and client."""
        from src.opnsense_mcp.core.state import ServerState
        from src.opnsense_mcp.core.models import OPNsenseConfig

        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )

        state = ServerState()

        with patch('src.opnsense_mcp.core.state.ConnectionPool') as MockPool, \
             patch('src.opnsense_mcp.core.state.keyring'), \
             patch('src.opnsense_mcp.core.state.API_CORE_FIRMWARE_STATUS', '/api/test'):

            mock_pool = Mock()
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={"status": "ok"})
            mock_pool.get_client = AsyncMock(return_value=mock_client)
            MockPool.return_value = mock_pool

            await state.initialize(config)

            assert state.config == config
            assert state.pool == mock_pool

    async def test_error_handler_with_tools(self, mock_mcp_context):
        """Test error handling integration with tools."""
        from src.opnsense_mcp.shared.error_handlers import handle_tool_error
        from src.opnsense_mcp.core.exceptions import APIError

        error = APIError("Test error", status_code=500)

        result = await handle_tool_error(
            mock_mcp_context,
            "test_operation",
            error
        )

        assert "Error:" in result
        mock_mcp_context.error.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.integration
class TestDataFlow:
    """Test data flow through the system."""

    async def test_request_response_flow(self):
        """Test complete request/response flow through client."""
        from src.opnsense_mcp.core.client import OPNsenseClient
        from src.opnsense_mcp.core.models import OPNsenseConfig

        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )

        client = OPNsenseClient(config)

        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok", "data": "test"}
        mock_response.content = b'{"status": "ok"}'

        client.client.get = AsyncMock(return_value=mock_response)

        result = await client.request("GET", "/test/endpoint")

        assert result["status"] == "ok"
        assert result["data"] == "test"

    async def test_retry_integration(self):
        """Test retry mechanism integration with client."""
        from src.opnsense_mcp.core.client import OPNsenseClient
        from src.opnsense_mcp.core.models import OPNsenseConfig
        from src.opnsense_mcp.core.retry import RetryConfig
        import httpx

        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )

        client = OPNsenseClient(config)

        # First call fails, second succeeds
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok"}
        mock_response.content = b'{"status": "ok"}'

        client.client.get = AsyncMock(side_effect=[
            httpx.TimeoutException("Timeout"),
            mock_response
        ])

        retry_config = RetryConfig(max_attempts=2, base_delay=0.01)

        result = await client.request("GET", "/test", retry_config=retry_config)

        assert result["status"] == "ok"
        assert client.client.get.call_count == 2
