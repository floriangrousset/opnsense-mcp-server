"""
Tests for OPNsense MCP Server - List Profiles CLI Command
"""

from unittest.mock import patch

from typer.testing import CliRunner

from src.opnsense_mcp.cli import app
from src.opnsense_mcp.core.config_loader import ConfigLoader

runner = CliRunner()


class TestListCommand:
    """Test list-profiles command."""

    def test_list_empty(self):
        """Test listing when no profiles exist."""
        with patch.object(ConfigLoader, "list_profiles", return_value=[]):
            result = runner.invoke(app, ["list-profiles"])

        assert result.exit_code == 0
        assert "No profiles configured" in result.stdout

    def test_list_profiles(self):
        """Test listing existing profiles."""
        with patch.object(ConfigLoader, "list_profiles", return_value=["default", "production"]):
            result = runner.invoke(app, ["list-profiles"])

        assert result.exit_code == 0
        assert "default" in result.stdout
        assert "production" in result.stdout
        assert "Found 2 profile(s)" in result.stdout

    def test_list_verbose(self):
        """Test listing with verbose output."""
        with (
            patch.object(ConfigLoader, "list_profiles", return_value=["default"]),
            patch.object(
                ConfigLoader,
                "get_profile_info",
                return_value={
                    "url": "https://192.168.1.1",
                    "api_key_preview": "test...ault",
                    "verify_ssl": True,
                },
            ),
        ):
            result = runner.invoke(app, ["list-profiles", "--verbose"])

        assert result.exit_code == 0
        assert "https://192.168.1.1" in result.stdout
        assert "test...ault" in result.stdout
