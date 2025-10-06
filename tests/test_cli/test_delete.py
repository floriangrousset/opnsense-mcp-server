"""
Tests for OPNsense MCP Server delete profile CLI command.

This module tests the delete profile command functionality.
"""

import os
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from src.opnsense_mcp.cli import app
from src.opnsense_mcp.core.exceptions import ConfigurationError

runner = CliRunner()


class TestDeleteCommand:
    """Test delete profile CLI command."""

    @pytest.fixture
    def temp_config_dir(self, tmp_path, monkeypatch):
        """Create temporary config directory."""
        config_dir = tmp_path / ".opnsense-mcp"
        config_dir.mkdir()
        monkeypatch.setenv("HOME", str(tmp_path))
        return config_dir

    def test_delete_command_profile_not_found(self, temp_config_dir):
        """Test delete command when profile doesn't exist."""
        with patch("src.opnsense_mcp.cli.delete.ConfigLoader") as MockConfigLoader:
            MockConfigLoader.list_profiles.return_value = ["default", "production"]

            result = runner.invoke(app, ["delete-profile", "nonexistent"])

            assert result.exit_code == 1
            assert "Profile 'nonexistent' not found" in result.output
            assert "Available profiles: default, production" in result.output

    def test_delete_command_no_profiles_available(self, temp_config_dir):
        """Test delete command when no profiles exist."""
        with patch("src.opnsense_mcp.cli.delete.ConfigLoader") as MockConfigLoader:
            MockConfigLoader.list_profiles.return_value = []

            result = runner.invoke(app, ["delete-profile", "default"])

            assert result.exit_code == 1
            assert "Profile 'default' not found" in result.output
            assert "Available profiles: None" in result.output

    def test_delete_command_cancelled_by_user(self, temp_config_dir):
        """Test delete command cancelled by user confirmation."""
        with (
            patch("src.opnsense_mcp.cli.delete.ConfigLoader") as MockConfigLoader,
            patch("src.opnsense_mcp.cli.delete.typer.confirm", return_value=False),
        ):
            MockConfigLoader.list_profiles.return_value = ["default"]
            MockConfigLoader.get_profile_info.return_value = {
                "url": "https://192.168.1.1",
                "api_key_preview": "test...ault",
                "verify_ssl": True,
            }

            result = runner.invoke(app, ["delete-profile", "default"])

            assert result.exit_code == 0
            assert "Operation cancelled" in result.output
            MockConfigLoader.delete_profile.assert_not_called()

    def test_delete_command_confirmed_by_user(self, temp_config_dir):
        """Test delete command confirmed by user."""
        with (
            patch("src.opnsense_mcp.cli.delete.ConfigLoader") as MockConfigLoader,
            patch("src.opnsense_mcp.cli.delete.typer.confirm", return_value=True),
        ):
            MockConfigLoader.list_profiles.side_effect = [
                ["default", "staging"],  # Before deletion
                ["staging"],  # After deletion
            ]
            MockConfigLoader.get_profile_info.return_value = {
                "url": "https://192.168.1.1",
                "api_key_preview": "test...ault",
                "verify_ssl": True,
            }

            result = runner.invoke(app, ["delete-profile", "default"])

            assert result.exit_code == 0
            assert "Profile 'default' deleted successfully" in result.output
            assert "Remaining profiles: staging" in result.output
            MockConfigLoader.delete_profile.assert_called_once_with("default")

    def test_delete_command_with_force_flag(self, temp_config_dir):
        """Test delete command with --force flag (no confirmation)."""
        with patch("src.opnsense_mcp.cli.delete.ConfigLoader") as MockConfigLoader:
            MockConfigLoader.list_profiles.side_effect = [
                ["default", "production"],  # Before deletion
                ["production"],  # After deletion
            ]
            MockConfigLoader.get_profile_info.return_value = {
                "url": "https://192.168.1.1",
                "api_key_preview": "test...ault",
                "verify_ssl": False,
            }

            result = runner.invoke(app, ["delete-profile", "default", "--force"])

            assert result.exit_code == 0
            assert "Are you sure" not in result.output  # No confirmation prompt
            assert "Profile 'default' deleted successfully" in result.output
            assert "Remaining profiles: production" in result.output
            MockConfigLoader.delete_profile.assert_called_once_with("default")

    def test_delete_command_with_f_flag_shorthand(self, temp_config_dir):
        """Test delete command with -f flag shorthand."""
        with patch("src.opnsense_mcp.cli.delete.ConfigLoader") as MockConfigLoader:
            MockConfigLoader.list_profiles.side_effect = [
                ["staging"],  # Before deletion
                [],  # After deletion - no profiles remain
            ]
            MockConfigLoader.get_profile_info.return_value = {
                "url": "https://192.168.1.1",
                "api_key_preview": "test...ging",
                "verify_ssl": True,
            }

            result = runner.invoke(app, ["delete-profile", "staging", "-f"])

            assert result.exit_code == 0
            assert "Are you sure" not in result.output
            assert "Profile 'staging' deleted successfully" in result.output
            MockConfigLoader.delete_profile.assert_called_once_with("staging")

    def test_delete_command_no_profiles_remaining(self, temp_config_dir):
        """Test delete command when no profiles remain after deletion."""
        with patch("src.opnsense_mcp.cli.delete.ConfigLoader") as MockConfigLoader:
            MockConfigLoader.list_profiles.side_effect = [
                ["default"],  # Before deletion
                [],  # After deletion - empty
            ]
            MockConfigLoader.get_profile_info.return_value = {
                "url": "https://192.168.1.1",
            }

            result = runner.invoke(app, ["delete-profile", "default", "--force"])

            assert result.exit_code == 0
            assert "Profile 'default' deleted successfully" in result.output
            assert "No profiles remaining" in result.output
            assert "Run 'opnsense-mcp setup' to configure a new profile" in result.output

    def test_delete_command_profile_info_error(self, temp_config_dir):
        """Test delete command when profile info cannot be retrieved."""
        with patch("src.opnsense_mcp.cli.delete.ConfigLoader") as MockConfigLoader:
            MockConfigLoader.list_profiles.side_effect = [
                ["default"],  # Before deletion
                [],  # After deletion
            ]
            MockConfigLoader.get_profile_info.side_effect = Exception("Profile info error")

            result = runner.invoke(app, ["delete-profile", "default", "--force"])

            assert result.exit_code == 0
            # Should still show profile name even if info retrieval fails
            assert "Profile: default" in result.output
            assert "Profile 'default' deleted successfully" in result.output

    def test_delete_command_configuration_error(self, temp_config_dir):
        """Test delete command handles ConfigurationError."""
        with patch("src.opnsense_mcp.cli.delete.ConfigLoader") as MockConfigLoader:
            MockConfigLoader.list_profiles.return_value = ["default"]
            MockConfigLoader.get_profile_info.return_value = {"url": "https://192.168.1.1"}
            MockConfigLoader.delete_profile.side_effect = ConfigurationError(
                "Cannot delete profile"
            )

            result = runner.invoke(app, ["delete-profile", "default", "--force"])

            assert result.exit_code == 1
            assert "Error: Cannot delete profile" in result.output

    def test_delete_command_unexpected_error(self, temp_config_dir):
        """Test delete command handles unexpected errors."""
        with patch("src.opnsense_mcp.cli.delete.ConfigLoader") as MockConfigLoader:
            MockConfigLoader.list_profiles.return_value = ["default"]
            MockConfigLoader.get_profile_info.return_value = {"url": "https://192.168.1.1"}
            MockConfigLoader.delete_profile.side_effect = RuntimeError("Unexpected error")

            result = runner.invoke(app, ["delete-profile", "default", "--force"])

            assert result.exit_code == 1
            assert "Unexpected error: Unexpected error" in result.output

    def test_delete_command_displays_profile_info(self, temp_config_dir):
        """Test that delete command displays profile information."""
        with patch("src.opnsense_mcp.cli.delete.ConfigLoader") as MockConfigLoader:
            MockConfigLoader.list_profiles.side_effect = [["default"], []]
            MockConfigLoader.get_profile_info.return_value = {
                "url": "https://firewall.example.com:8443",
                "api_key_preview": "abcd...xyz",
                "verify_ssl": False,
            }

            result = runner.invoke(app, ["delete-profile", "default", "--force"])

            assert result.exit_code == 0
            assert "Profile: default" in result.output
            assert "URL: https://firewall.example.com:8443" in result.output

    def test_delete_command_emoji_output(self, temp_config_dir):
        """Test that delete command uses appropriate emoji indicators."""
        with patch("src.opnsense_mcp.cli.delete.ConfigLoader") as MockConfigLoader:
            MockConfigLoader.list_profiles.side_effect = [["default"], []]
            MockConfigLoader.get_profile_info.return_value = {
                "url": "https://192.168.1.1",
            }

            result = runner.invoke(app, ["delete-profile", "default", "--force"])

            assert result.exit_code == 0
            assert "🗑️" in result.output  # Delete emoji
            assert "✅" in result.output  # Success emoji
            assert "📋" in result.output  # List emoji

    def test_delete_command_lists_remaining_profiles(self, temp_config_dir):
        """Test that delete command lists remaining profiles after deletion."""
        with patch("src.opnsense_mcp.cli.delete.ConfigLoader") as MockConfigLoader:
            MockConfigLoader.list_profiles.side_effect = [
                ["default", "staging", "production"],  # Before
                ["staging", "production"],  # After
            ]
            MockConfigLoader.get_profile_info.return_value = {
                "url": "https://192.168.1.1",
            }

            result = runner.invoke(app, ["delete-profile", "default", "--force"])

            assert result.exit_code == 0
            assert "Remaining profiles: staging, production" in result.output
