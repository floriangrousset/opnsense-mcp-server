"""
Security Tests - Credential Leakage Prevention

Tests to verify that credentials are never exposed in:
- Log messages
- Tool responses
- Error messages
- Configuration output
"""

import json
import logging
import os
from unittest.mock import AsyncMock, Mock, patch

import pytest
from mcp.server.fastmcp import Context

from src.opnsense_mcp.core.config_loader import ConfigLoader
from src.opnsense_mcp.core.models import OPNsenseConfig
from src.opnsense_mcp.domains.configuration import configure_opnsense_connection


@pytest.fixture
def secure_config_setup(tmp_path, monkeypatch):
    """Setup config with sensitive credentials for security testing."""
    config_dir = tmp_path / ".opnsense-mcp"
    config_dir.mkdir()
    config_file = config_dir / "config.json"

    monkeypatch.setattr(ConfigLoader, "DEFAULT_CONFIG_DIR", config_dir)
    monkeypatch.setattr(ConfigLoader, "DEFAULT_CONFIG_FILE", config_file)

    # Create test profile with distinctive credentials to detect leaks
    config_data = {
        "default": {
            "url": "https://192.168.1.1",
            "api_key": "SENSITIVE_API_KEY_12345",
            "api_secret": "SENSITIVE_SECRET_67890",
            "verify_ssl": True,
        }
    }
    with open(config_file, "w") as f:
        json.dump(config_data, f)
    os.chmod(config_file, 0o600)

    return config_file


class TestCredentialLeakagePrevention:
    """Test that credentials are never leaked in various contexts."""

    @pytest.mark.asyncio
    async def test_tool_response_no_credentials(self, secure_config_setup):
        """Test that tool response never contains credentials."""
        mock_ctx = Mock(spec=Context)
        mock_ctx.info = AsyncMock()
        mock_ctx.error = AsyncMock()

        with patch("src.opnsense_mcp.domains.configuration.server_state") as mock_state:
            mock_state.initialize = AsyncMock()

            result = await configure_opnsense_connection(mock_ctx, profile="default")

            # Verify NO credentials in response
            assert "SENSITIVE_API_KEY_12345" not in result
            assert "SENSITIVE_SECRET_67890" not in result

    @pytest.mark.asyncio
    async def test_error_messages_no_credentials(self, secure_config_setup):
        """Test that error messages never contain credentials."""
        mock_ctx = Mock(spec=Context)
        mock_ctx.info = AsyncMock()
        mock_ctx.error = AsyncMock()

        with patch("src.opnsense_mcp.domains.configuration.server_state") as mock_state:
            # Simulate authentication error
            mock_state.initialize = AsyncMock(side_effect=Exception("Auth failed"))

            result = await configure_opnsense_connection(mock_ctx, profile="default")

            # Verify NO credentials in error message
            assert "SENSITIVE_API_KEY_12345" not in result
            assert "SENSITIVE_SECRET_67890" not in result

    def test_config_model_repr_hides_secret(self, secure_config_setup):
        """Test that OPNsenseConfig repr() doesn't expose API secret."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="SENSITIVE_API_KEY_12345",
            api_secret="SENSITIVE_SECRET_67890",
            verify_ssl=True,
        )

        repr_output = repr(config)

        # API secret should be hidden (repr=False in model)
        assert "SENSITIVE_SECRET_67890" not in repr_output

    def test_profile_info_partial_key_only(self, secure_config_setup):
        """Test that profile info only shows partial API key."""
        info = ConfigLoader.get_profile_info("default")

        # Should have preview
        assert "api_key_preview" in info

        # Preview should NOT contain full key
        assert "SENSITIVE_API_KEY_12345" not in str(info)

        # Should only show first 4 + last 4 chars
        assert len(info["api_key_preview"].replace("...", "")) == 8

    def test_config_file_permissions(self, secure_config_setup):
        """Test that config file has secure permissions (0600)."""
        stat_info = os.stat(secure_config_setup)
        perms = stat_info.st_mode & 0o777

        # Should be 0600 (owner read/write only)
        assert perms == 0o600

    @pytest.mark.asyncio
    async def test_logging_no_credentials(self, secure_config_setup, caplog):
        """Test that log messages never contain credentials."""
        caplog.set_level(logging.DEBUG)

        mock_ctx = Mock(spec=Context)
        mock_ctx.info = AsyncMock()
        mock_ctx.error = AsyncMock()

        with patch("src.opnsense_mcp.domains.configuration.server_state") as mock_state:
            mock_state.initialize = AsyncMock()

            await configure_opnsense_connection(mock_ctx, profile="default")

            # Check all log messages
            log_output = caplog.text

            # Verify NO credentials in logs
            assert "SENSITIVE_API_KEY_12345" not in log_output
            assert "SENSITIVE_SECRET_67890" not in log_output

    def test_config_file_json_readable_but_protected(self, secure_config_setup):
        """Test that config file is readable JSON but has secure permissions."""
        # Should be able to read as JSON
        with open(secure_config_setup) as f:
            config_data = json.load(f)

        assert "default" in config_data
        assert config_data["default"]["api_key"] == "SENSITIVE_API_KEY_12345"

        # But permissions should be restrictive
        stat_info = os.stat(secure_config_setup)
        perms = stat_info.st_mode & 0o777
        assert perms == 0o600

    @pytest.mark.asyncio
    async def test_tool_signature_no_credential_parameters(self):
        """Test that tool signature doesn't accept credentials as parameters."""
        import inspect

        sig = inspect.signature(configure_opnsense_connection)

        # Should only have ctx and profile parameters
        params = list(sig.parameters.keys())

        assert "ctx" in params
        assert "profile" in params
        assert "url" not in params  # OLD insecure parameter removed
        assert "api_key" not in params  # OLD insecure parameter removed
        assert "api_secret" not in params  # OLD insecure parameter removed
