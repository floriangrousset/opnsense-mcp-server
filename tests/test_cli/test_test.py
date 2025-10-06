"""
Tests for OPNsense MCP Server - Test Connection CLI Command
"""

from unittest.mock import patch

from typer.testing import CliRunner

from src.opnsense_mcp.cli import app
from src.opnsense_mcp.core.config_loader import ConfigLoader
from src.opnsense_mcp.core.models import OPNsenseConfig

runner = CliRunner()


class TestTestCommand:
    """Test test-connection command."""

    def test_connection_success(self):
        """Test successful connection test."""
        mock_config = OPNsenseConfig(
            url="https://192.168.1.1", api_key="test_key", api_secret="test_secret", verify_ssl=True
        )

        with (
            patch.object(ConfigLoader, "load", return_value=mock_config),
            patch.object(
                ConfigLoader,
                "get_profile_info",
                return_value={"url": "https://192.168.1.1", "verify_ssl": True},
            ),
            patch(
                "src.opnsense_mcp.cli.test._test_connection_async",
                return_value={"success": True, "firmware_status": {"product_name": "OPNsense"}},
            ),
        ):
            result = runner.invoke(app, ["test-connection"])

        assert result.exit_code == 0
        assert "Connection successful" in result.stdout

    def test_connection_failure(self):
        """Test failed connection test."""
        mock_config = OPNsenseConfig(
            url="https://192.168.1.1", api_key="test_key", api_secret="test_secret", verify_ssl=True
        )

        with (
            patch.object(ConfigLoader, "load", return_value=mock_config),
            patch.object(
                ConfigLoader,
                "get_profile_info",
                return_value={"url": "https://192.168.1.1", "verify_ssl": True},
            ),
            patch(
                "src.opnsense_mcp.cli.test._test_connection_async",
                return_value={"success": False, "error": "Connection refused"},
            ),
        ):
            result = runner.invoke(app, ["test-connection"])

        assert result.exit_code == 1
        assert "Connection failed" in result.stdout
