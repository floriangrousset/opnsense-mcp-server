"""
Tests for OPNsense MCP Server configuration domain.

This module tests the configuration tools including connection setup
and API endpoint discovery.
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

from src.opnsense_mcp.core.exceptions import (
    APIError,
    AuthenticationError,
    ConfigurationError,
    NetworkError,
    ValidationError,
)
from src.opnsense_mcp.core.models import OPNsenseConfig
from src.opnsense_mcp.domains.configuration import (
    configure_opnsense_connection,
    get_api_endpoints,
    get_opnsense_client,
)


@pytest.mark.asyncio
class TestConfigureOPNsenseConnection:
    """Test configure_opnsense_connection tool."""

    async def test_successful_configuration(self, mock_mcp_context):
        """Test successful OPNsense connection configuration."""
        mock_config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False,
        )

        with (
            patch("src.opnsense_mcp.domains.configuration.ConfigLoader") as MockConfigLoader,
            patch("src.opnsense_mcp.domains.configuration.server_state") as mock_state,
        ):
            MockConfigLoader.load.return_value = mock_config
            MockConfigLoader.get_profile_info.return_value = {
                "url": "https://192.168.1.1",
                "api_key_preview": "test...ault",
                "verify_ssl": False,
            }
            mock_state.initialize = AsyncMock()

            result = await configure_opnsense_connection(ctx=mock_mcp_context, profile="default")

            assert "configured successfully" in result
            mock_state.initialize.assert_called_once()
            mock_mcp_context.info.assert_called_once()

    async def test_configuration_with_ssl_verification(self, mock_mcp_context):
        """Test configuration with SSL verification enabled."""
        mock_config = OPNsenseConfig(
            url="https://opnsense.example.com",
            api_key="key",
            api_secret="secret",
            verify_ssl=True,
        )

        with (
            patch("src.opnsense_mcp.domains.configuration.ConfigLoader") as MockConfigLoader,
            patch("src.opnsense_mcp.domains.configuration.server_state") as mock_state,
        ):
            MockConfigLoader.load.return_value = mock_config
            MockConfigLoader.get_profile_info.return_value = {
                "url": "https://opnsense.example.com",
                "api_key_preview": "key...ault",
                "verify_ssl": True,
            }
            mock_state.initialize = AsyncMock()

            result = await configure_opnsense_connection(ctx=mock_mcp_context, profile="default")

            assert "configured successfully" in result

    async def test_authentication_error_handling(self, mock_mcp_context):
        """Test handling of authentication errors."""
        mock_config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="wrong_key",
            api_secret="wrong_secret",
            verify_ssl=False,
        )

        with (
            patch("src.opnsense_mcp.domains.configuration.ConfigLoader") as MockConfigLoader,
            patch("src.opnsense_mcp.domains.configuration.server_state") as mock_state,
        ):
            MockConfigLoader.load.return_value = mock_config
            MockConfigLoader.get_profile_info.return_value = {
                "url": "https://192.168.1.1",
                "api_key_preview": "wrong...ault",
                "verify_ssl": False,
            }
            mock_state.initialize = AsyncMock(
                side_effect=AuthenticationError("Invalid credentials")
            )

            result = await configure_opnsense_connection(ctx=mock_mcp_context, profile="default")

            assert "Authentication Error" in result
            assert "Invalid credentials" in result
            mock_mcp_context.error.assert_called_once()

    async def test_network_error_handling(self, mock_mcp_context):
        """Test handling of network errors."""
        mock_config = OPNsenseConfig(
            url="https://192.168.1.1", api_key="key", api_secret="secret", verify_ssl=True
        )

        with (
            patch("src.opnsense_mcp.domains.configuration.ConfigLoader") as MockConfigLoader,
            patch("src.opnsense_mcp.domains.configuration.server_state") as mock_state,
        ):
            MockConfigLoader.load.return_value = mock_config
            MockConfigLoader.get_profile_info.return_value = {
                "url": "https://192.168.1.1",
                "api_key_preview": "key...ault",
                "verify_ssl": True,
            }
            mock_state.initialize = AsyncMock(side_effect=NetworkError("Cannot connect"))

            result = await configure_opnsense_connection(ctx=mock_mcp_context, profile="default")

            assert "Network Error" in result
            assert "Cannot connect" in result

    async def test_validation_error_handling(self, mock_mcp_context):
        """Test handling of validation errors."""
        with patch("src.opnsense_mcp.domains.configuration.ConfigLoader") as MockConfigLoader:
            MockConfigLoader.load.side_effect = ConfigurationError("Invalid URL format")

            result = await configure_opnsense_connection(ctx=mock_mcp_context, profile="default")

            assert "Configuration Error" in result

    async def test_generic_error_handling(self, mock_mcp_context):
        """Test handling of unexpected errors."""
        mock_config = OPNsenseConfig(
            url="https://192.168.1.1", api_key="key", api_secret="secret", verify_ssl=True
        )

        with (
            patch("src.opnsense_mcp.domains.configuration.ConfigLoader") as MockConfigLoader,
            patch("src.opnsense_mcp.domains.configuration.server_state") as mock_state,
        ):
            MockConfigLoader.load.return_value = mock_config
            MockConfigLoader.get_profile_info.return_value = {
                "url": "https://192.168.1.1",
                "api_key_preview": "key...ault",
                "verify_ssl": True,
            }
            mock_state.initialize = AsyncMock(side_effect=Exception("Unexpected error"))

            result = await configure_opnsense_connection(ctx=mock_mcp_context, profile="default")

            assert "Error:" in result


@pytest.mark.asyncio
class TestGetAPIEndpoints:
    """Test get_api_endpoints tool."""

    async def test_get_all_endpoints(self, mock_mcp_context):
        """Test getting all API endpoints."""
        mock_response = {
            "Firewall": {"routes": ["/firewall/filter/searchRule"]},
            "System": {"routes": ["/core/system/info"]},
        }

        with patch("src.opnsense_mcp.domains.configuration.get_opnsense_client") as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value=mock_response)
            mock_get_client.return_value = mock_client

            result = await get_api_endpoints(ctx=mock_mcp_context)

            # Should return JSON with all modules
            result_data = json.loads(result)
            assert "Firewall" in result_data
            assert "System" in result_data

    async def test_get_filtered_endpoints(self, mock_mcp_context):
        """Test getting filtered API endpoints by module."""
        mock_response = {
            "Firewall": {"routes": ["/firewall/filter/searchRule"]},
            "System": {"routes": ["/core/system/info"]},
        }

        with patch("src.opnsense_mcp.domains.configuration.get_opnsense_client") as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value=mock_response)
            mock_get_client.return_value = mock_client

            result = await get_api_endpoints(ctx=mock_mcp_context, module="Firewall")

            # Should return JSON with only Firewall module
            result_data = json.loads(result)
            assert "routes" in result_data
            assert "/firewall/filter/searchRule" in result_data["routes"]

    async def test_nonexistent_module_returns_available_list(self, mock_mcp_context):
        """Test requesting non-existent module returns available modules."""
        mock_response = {"Firewall": {}, "System": {}}

        with patch("src.opnsense_mcp.domains.configuration.get_opnsense_client") as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value=mock_response)
            mock_get_client.return_value = mock_client

            result = await get_api_endpoints(ctx=mock_mcp_context, module="NonExistent")

            assert "not found" in result
            assert "Available modules" in result
            assert "Firewall" in result

    async def test_configuration_error_handling(self, mock_mcp_context):
        """Test handling of configuration errors."""
        with patch("src.opnsense_mcp.domains.configuration.get_opnsense_client") as mock_get_client:
            mock_get_client.side_effect = ConfigurationError("Not configured")

            result = await get_api_endpoints(ctx=mock_mcp_context)

            assert "Configuration Error" in result
            mock_mcp_context.error.assert_called_once()

    async def test_api_error_handling(self, mock_mcp_context):
        """Test handling of API errors."""
        with patch("src.opnsense_mcp.domains.configuration.get_opnsense_client") as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(side_effect=APIError("API error"))
            mock_get_client.return_value = mock_client

            result = await get_api_endpoints(ctx=mock_mcp_context)

            assert "Error:" in result


@pytest.mark.asyncio
class TestGetOPNsenseClient:
    """Test get_opnsense_client helper function."""

    async def test_get_client_from_server_state(self):
        """Test getting client from server state."""
        with patch("src.opnsense_mcp.domains.configuration.server_state") as mock_state:
            mock_client = Mock()
            mock_state.get_client = AsyncMock(return_value=mock_client)

            result = await get_opnsense_client()

            assert result == mock_client
            mock_state.get_client.assert_called_once()

    async def test_get_client_raises_configuration_error(self):
        """Test that get_client raises ConfigurationError when not configured."""
        with patch("src.opnsense_mcp.domains.configuration.server_state") as mock_state:
            mock_state.get_client = AsyncMock(side_effect=ConfigurationError("Not configured"))

            with pytest.raises(ConfigurationError):
                await get_opnsense_client()
