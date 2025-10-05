"""
Integration Tests for Secure Credential Storage

Tests the complete flow from configuration loading to tool execution
without exposing credentials to the LLM.
"""

import pytest
import json
import os
from pathlib import Path
from unittest.mock import patch, Mock, AsyncMock
from mcp.server.fastmcp import Context

from src.opnsense_mcp.core.config_loader import ConfigLoader
from src.opnsense_mcp.core.models import OPNsenseConfig
from src.opnsense_mcp.domains.configuration import configure_opnsense_connection


@pytest.fixture
def temp_config_setup(tmp_path, monkeypatch):
    """Setup temporary config for testing."""
    config_dir = tmp_path / ".opnsense-mcp"
    config_dir.mkdir()
    config_file = config_dir / "config.json"

    monkeypatch.setattr(ConfigLoader, "DEFAULT_CONFIG_DIR", config_dir)
    monkeypatch.setattr(ConfigLoader, "DEFAULT_CONFIG_FILE", config_file)

    # Create test profile
    config_data = {
        "default": {
            "url": "https://192.168.1.1",
            "api_key": "integration_test_key",
            "api_secret": "integration_test_secret",
            "verify_ssl": True
        }
    }
    with open(config_file, 'w') as f:
        json.dump(config_data, f)
    os.chmod(config_file, 0o600)

    return config_file


@pytest.mark.asyncio
class TestSecureCredentialFlow:
    """Test end-to-end secure credential flow."""

    async def test_complete_flow_from_config_file(self, temp_config_setup):
        """Test complete flow: config file → ConfigLoader → tool execution."""
        # Mock server state and connection
        mock_ctx = Mock(spec=Context)
        mock_ctx.info = AsyncMock()
        mock_ctx.error = AsyncMock()

        with patch('src.opnsense_mcp.domains.configuration.server_state') as mock_state:
            mock_state.initialize = AsyncMock()

            # Execute tool
            result = await configure_opnsense_connection(mock_ctx, profile="default")

            # Verify success
            assert "✅ OPNsense connection configured successfully" in result
            assert "Profile: default" in result
            assert "192.168.1.1" in result

            # Verify server state was initialized
            mock_state.initialize.assert_called_once()
            config = mock_state.initialize.call_args[0][0]
            assert config.url == "https://192.168.1.1"
            assert config.api_key == "integration_test_key"

            # Verify NO credentials in returned message
            assert "integration_test_secret" not in result
            assert "integration_test_key" not in result

    async def test_complete_flow_from_env_vars(self, temp_config_setup, monkeypatch):
        """Test complete flow: env vars → ConfigLoader → tool execution."""
        # Set environment variables (higher priority)
        monkeypatch.setenv("OPNSENSE_URL", "https://env.example.com")
        monkeypatch.setenv("OPNSENSE_API_KEY", "env_key")
        monkeypatch.setenv("OPNSENSE_API_SECRET", "env_secret")

        mock_ctx = Mock(spec=Context)
        mock_ctx.info = AsyncMock()
        mock_ctx.error = AsyncMock()

        with patch('src.opnsense_mcp.domains.configuration.server_state') as mock_state:
            mock_state.initialize = AsyncMock()

            result = await configure_opnsense_connection(mock_ctx, profile="default")

            # Verify environment variables were used (not config file)
            config = mock_state.initialize.call_args[0][0]
            assert config.url == "https://env.example.com"
            assert config.api_key == "env_key"

            # Verify NO credentials in returned message
            assert "env_secret" not in result
            assert "env_key" not in result

    async def test_error_handling_missing_profile(self, temp_config_setup):
        """Test error handling when profile doesn't exist."""
        mock_ctx = Mock(spec=Context)
        mock_ctx.info = AsyncMock()
        mock_ctx.error = AsyncMock()

        result = await configure_opnsense_connection(mock_ctx, profile="nonexistent")

        # Verify helpful error message
        assert "Configuration Error" in result
        assert "Setup Instructions" in result
        assert "opnsense-mcp setup" in result

    async def test_profile_info_never_exposes_secret(self, temp_config_setup):
        """Test that profile info never includes API secret."""
        info = ConfigLoader.get_profile_info("default")

        assert "url" in info
        assert "verify_ssl" in info
        assert "api_key_preview" in info
        assert "api_secret" not in info  # Secret must never be exposed

        # Preview should only show partial key
        assert info["api_key_preview"] == "inte...cret"  # First 4 + last 4
