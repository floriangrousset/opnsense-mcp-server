"""
Tests for OPNsense MCP Server - Setup CLI Command
"""

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from src.opnsense_mcp.cli import app
from src.opnsense_mcp.core.config_loader import ConfigLoader

runner = CliRunner()


@pytest.fixture
def temp_config_dir(tmp_path, monkeypatch):
    """Mock config directory for testing."""
    config_dir = tmp_path / ".opnsense-mcp"
    config_dir.mkdir()
    config_file = config_dir / "config.json"

    monkeypatch.setattr(ConfigLoader, "DEFAULT_CONFIG_DIR", config_dir)
    monkeypatch.setattr(ConfigLoader, "DEFAULT_CONFIG_FILE", config_file)

    return config_dir


class TestSetupCommand:
    """Test setup command."""

    def test_setup_non_interactive_success(self, temp_config_dir):
        """Test non-interactive setup with all parameters."""
        with patch("src.opnsense_mcp.cli.setup._test_connection", return_value=True):
            result = runner.invoke(
                app,
                [
                    "setup",
                    "--non-interactive",
                    "--url",
                    "https://192.168.1.1",
                    "--api-key",
                    "test_key",
                    "--api-secret",
                    "test_secret",
                    "--verify-ssl",
                ],
            )

        assert result.exit_code == 0
        assert "Profile 'default' saved successfully" in result.stdout

        # Verify profile was saved
        profiles = ConfigLoader.list_profiles()
        assert "default" in profiles

    def test_setup_non_interactive_missing_params(self, temp_config_dir):
        """Test non-interactive setup fails without required params."""
        result = runner.invoke(
            app,
            [
                "setup",
                "--non-interactive",
                "--url",
                "https://192.168.1.1"
                # Missing api-key and api-secret
            ],
        )

        assert result.exit_code == 1
        assert "all parameters" in result.stdout.lower()

    def test_setup_custom_profile(self, temp_config_dir):
        """Test setup with custom profile name."""
        with patch("src.opnsense_mcp.cli.setup._test_connection", return_value=True):
            result = runner.invoke(
                app,
                [
                    "setup",
                    "--profile",
                    "production",
                    "--non-interactive",
                    "--url",
                    "https://prod.example.com",
                    "--api-key",
                    "prod_key",
                    "--api-secret",
                    "prod_secret",
                ],
            )

        assert result.exit_code == 0
        assert "Profile 'production' saved successfully" in result.stdout

        profiles = ConfigLoader.list_profiles()
        assert "production" in profiles

    def test_setup_no_verify_ssl(self, temp_config_dir):
        """Test setup with SSL verification disabled."""
        with patch("src.opnsense_mcp.cli.setup._test_connection", return_value=True):
            result = runner.invoke(
                app,
                [
                    "setup",
                    "--non-interactive",
                    "--url",
                    "https://192.168.1.1",
                    "--api-key",
                    "test_key",
                    "--api-secret",
                    "test_secret",
                    "--no-verify-ssl",
                ],
            )

        assert result.exit_code == 0

        # Verify SSL setting
        info = ConfigLoader.get_profile_info("default")
        assert info["verify_ssl"] is False

    def test_setup_interactive_cancelled(self, temp_config_dir):
        """Test interactive setup cancelled by user."""
        # Simulate user cancelling during connection test confirmation
        with patch("src.opnsense_mcp.cli.setup._test_connection", return_value=False), patch(
            "typer.prompt", side_effect=["https://192.168.1.1", "key", "secret"]
        ), patch(
            "typer.confirm", side_effect=[True, False]
        ):  # SSL yes, save no
            result = runner.invoke(app, ["setup"])

        assert result.exit_code == 0
        assert "Setup cancelled" in result.stdout

    def test_setup_connection_test_failure_continue(self, temp_config_dir):
        """Test setup continues after connection test failure if user confirms."""
        with patch("src.opnsense_mcp.cli.setup._test_connection", return_value=False), patch(
            "typer.prompt", side_effect=["https://192.168.1.1", "key", "secret"]
        ), patch(
            "typer.confirm", side_effect=[True, True]
        ):  # SSL yes, save yes
            result = runner.invoke(app, ["setup"])

        assert result.exit_code == 0
        assert "saved successfully" in result.stdout

    def test_setup_invalid_url(self, temp_config_dir):
        """Test setup fails with invalid URL."""
        result = runner.invoke(
            app,
            [
                "setup",
                "--non-interactive",
                "--url",
                "invalid-url",
                "--api-key",
                "test_key",
                "--api-secret",
                "test_secret",
            ],
        )

        assert result.exit_code == 1
        assert "Invalid configuration" in result.stdout
