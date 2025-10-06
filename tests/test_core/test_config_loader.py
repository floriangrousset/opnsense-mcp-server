"""
Tests for OPNsense MCP Server - ConfigLoader

This module tests the secure configuration loader including:
- Loading from environment variables
- Loading from config file with multiple profiles
- Loading from keyring (backward compatibility)
- Priority resolution
- Profile management operations
- Security controls (file permissions)
"""

import json
import os
from unittest.mock import Mock, patch

import pytest

from src.opnsense_mcp.core.config_loader import ConfigLoader
from src.opnsense_mcp.core.exceptions import ConfigurationError
from src.opnsense_mcp.core.models import OPNsenseConfig


@pytest.fixture
def temp_config_dir(tmp_path):
    """Create temporary config directory for testing."""
    config_dir = tmp_path / ".opnsense-mcp"
    config_dir.mkdir()
    return config_dir


@pytest.fixture
def mock_config_file(temp_config_dir):
    """Create mock config file with test profiles."""
    config_file = temp_config_dir / "config.json"
    config_data = {
        "default": {
            "url": "https://192.168.1.1",
            "api_key": "test_key_default",
            "api_secret": "test_secret_default",
            "verify_ssl": True,
        },
        "production": {
            "url": "https://firewall.example.com",
            "api_key": "test_key_prod",
            "api_secret": "test_secret_prod",
            "verify_ssl": True,
        },
        "staging": {
            "url": "https://staging.example.com",
            "api_key": "test_key_staging",
            "api_secret": "test_secret_staging",
            "verify_ssl": False,
        },
    }
    with open(config_file, "w") as f:
        json.dump(config_data, f)
    os.chmod(config_file, 0o600)
    return config_file


@pytest.mark.asyncio
class TestConfigLoaderEnvironmentVariables:
    """Test loading credentials from environment variables (Priority 1)."""

    def test_load_from_env_success(self, monkeypatch):
        """Test successful loading from environment variables."""
        monkeypatch.setenv("OPNSENSE_URL", "https://192.168.1.1")
        monkeypatch.setenv("OPNSENSE_API_KEY", "env_api_key")
        monkeypatch.setenv("OPNSENSE_API_SECRET", "env_api_secret")
        monkeypatch.setenv("OPNSENSE_VERIFY_SSL", "true")

        config = ConfigLoader._load_from_env()

        assert config is not None
        assert config.url == "https://192.168.1.1"
        assert config.api_key == "env_api_key"
        assert config.api_secret == "env_api_secret"
        assert config.verify_ssl is True

    def test_load_from_env_verify_ssl_false(self, monkeypatch):
        """Test loading with verify_ssl=false from environment."""
        monkeypatch.setenv("OPNSENSE_URL", "https://192.168.1.1")
        monkeypatch.setenv("OPNSENSE_API_KEY", "env_api_key")
        monkeypatch.setenv("OPNSENSE_API_SECRET", "env_api_secret")
        monkeypatch.setenv("OPNSENSE_VERIFY_SSL", "false")

        config = ConfigLoader._load_from_env()

        assert config.verify_ssl is False

    def test_load_from_env_verify_ssl_default(self, monkeypatch):
        """Test loading with default verify_ssl (true) when not set."""
        monkeypatch.setenv("OPNSENSE_URL", "https://192.168.1.1")
        monkeypatch.setenv("OPNSENSE_API_KEY", "env_api_key")
        monkeypatch.setenv("OPNSENSE_API_SECRET", "env_api_secret")
        # Don't set OPNSENSE_VERIFY_SSL

        config = ConfigLoader._load_from_env()

        assert config.verify_ssl is True

    def test_load_from_env_missing_url(self, monkeypatch):
        """Test loading fails gracefully when URL is missing."""
        monkeypatch.setenv("OPNSENSE_API_KEY", "env_api_key")
        monkeypatch.setenv("OPNSENSE_API_SECRET", "env_api_secret")

        config = ConfigLoader._load_from_env()

        assert config is None

    def test_load_from_env_missing_api_key(self, monkeypatch):
        """Test loading fails gracefully when API key is missing."""
        monkeypatch.setenv("OPNSENSE_URL", "https://192.168.1.1")
        monkeypatch.setenv("OPNSENSE_API_SECRET", "env_api_secret")

        config = ConfigLoader._load_from_env()

        assert config is None

    def test_load_from_env_missing_api_secret(self, monkeypatch):
        """Test loading fails gracefully when API secret is missing."""
        monkeypatch.setenv("OPNSENSE_URL", "https://192.168.1.1")
        monkeypatch.setenv("OPNSENSE_API_KEY", "env_api_key")

        config = ConfigLoader._load_from_env()

        assert config is None

    def test_load_from_env_invalid_url(self, monkeypatch):
        """Test loading raises error for invalid URL."""
        monkeypatch.setenv("OPNSENSE_URL", "invalid-url")
        monkeypatch.setenv("OPNSENSE_API_KEY", "env_api_key")
        monkeypatch.setenv("OPNSENSE_API_SECRET", "env_api_secret")

        with pytest.raises(ConfigurationError):
            ConfigLoader._load_from_env()


@pytest.mark.asyncio
class TestConfigLoaderConfigFile:
    """Test loading credentials from config file (Priority 2)."""

    def test_load_from_config_file_default_profile(self, temp_config_dir, mock_config_file):
        """Test loading default profile from config file."""
        with patch.object(ConfigLoader, "DEFAULT_CONFIG_FILE", mock_config_file):
            config = ConfigLoader._load_from_config_file("default")

        assert config is not None
        assert config.url == "https://192.168.1.1"
        assert config.api_key == "test_key_default"
        assert config.api_secret == "test_secret_default"
        assert config.verify_ssl is True

    def test_load_from_config_file_production_profile(self, temp_config_dir, mock_config_file):
        """Test loading production profile from config file."""
        with patch.object(ConfigLoader, "DEFAULT_CONFIG_FILE", mock_config_file):
            config = ConfigLoader._load_from_config_file("production")

        assert config is not None
        assert config.url == "https://firewall.example.com"
        assert config.api_key == "test_key_prod"
        assert config.api_secret == "test_secret_prod"

    def test_load_from_config_file_staging_profile(self, temp_config_dir, mock_config_file):
        """Test loading staging profile with verify_ssl=false."""
        with patch.object(ConfigLoader, "DEFAULT_CONFIG_FILE", mock_config_file):
            config = ConfigLoader._load_from_config_file("staging")

        assert config is not None
        assert config.url == "https://staging.example.com"
        assert config.verify_ssl is False

    def test_load_from_config_file_nonexistent_profile(self, temp_config_dir, mock_config_file):
        """Test loading nonexistent profile returns None."""
        with patch.object(ConfigLoader, "DEFAULT_CONFIG_FILE", mock_config_file):
            config = ConfigLoader._load_from_config_file("nonexistent")

        assert config is None

    def test_load_from_config_file_missing_file(self, temp_config_dir):
        """Test loading when config file doesn't exist."""
        missing_file = temp_config_dir / "nonexistent.json"
        with patch.object(ConfigLoader, "DEFAULT_CONFIG_FILE", missing_file):
            config = ConfigLoader._load_from_config_file("default")

        assert config is None

    def test_load_from_config_file_invalid_json(self, temp_config_dir):
        """Test loading raises error for invalid JSON."""
        invalid_file = temp_config_dir / "invalid.json"
        with open(invalid_file, "w") as f:
            f.write("{invalid json")

        with patch.object(ConfigLoader, "DEFAULT_CONFIG_FILE", invalid_file):
            with pytest.raises(ConfigurationError, match="Invalid JSON"):
                ConfigLoader._load_from_config_file("default")

    def test_load_from_config_file_missing_required_field(self, temp_config_dir):
        """Test loading raises error for missing required field."""
        incomplete_file = temp_config_dir / "incomplete.json"
        config_data = {
            "default": {
                "url": "https://192.168.1.1",
                "api_key": "test_key"
                # Missing api_secret
            }
        }
        with open(incomplete_file, "w") as f:
            json.dump(config_data, f)

        with patch.object(ConfigLoader, "DEFAULT_CONFIG_FILE", incomplete_file):
            with pytest.raises(ConfigurationError, match="Missing required field"):
                ConfigLoader._load_from_config_file("default")


@pytest.mark.asyncio
class TestConfigLoaderKeyring:
    """Test loading credentials from keyring (Priority 3 - backward compatibility)."""

    def test_load_from_keyring_success(self):
        """Test successful loading from keyring."""
        mock_credential = Mock()
        mock_credential.password = json.dumps(
            {
                "url": "https://192.168.1.1",
                "api_key": "keyring_api_key",
                "api_secret": "keyring_api_secret",
                "verify_ssl": True,
            }
        )

        with patch("keyring.get_credential", return_value=mock_credential):
            config = ConfigLoader._load_from_keyring("default")

        assert config is not None
        assert config.url == "https://192.168.1.1"
        assert config.api_key == "keyring_api_key"
        assert config.api_secret == "keyring_api_secret"

    def test_load_from_keyring_no_credential(self):
        """Test loading returns None when keyring has no credential."""
        with patch("keyring.get_credential", return_value=None):
            config = ConfigLoader._load_from_keyring("default")

        assert config is None

    def test_load_from_keyring_exception(self):
        """Test loading returns None on keyring exception."""
        with patch("keyring.get_credential", side_effect=Exception("Keyring error")):
            config = ConfigLoader._load_from_keyring("default")

        assert config is None


@pytest.mark.asyncio
class TestConfigLoaderPriority:
    """Test priority resolution between credential sources."""

    def test_priority_env_over_file(self, monkeypatch, temp_config_dir, mock_config_file):
        """Test environment variables have priority over config file."""
        # Set environment variables
        monkeypatch.setenv("OPNSENSE_URL", "https://env.example.com")
        monkeypatch.setenv("OPNSENSE_API_KEY", "env_key")
        monkeypatch.setenv("OPNSENSE_API_SECRET", "env_secret")

        with patch.object(ConfigLoader, "DEFAULT_CONFIG_FILE", mock_config_file):
            config = ConfigLoader.load("default")

        # Should load from env, not file
        assert config.url == "https://env.example.com"
        assert config.api_key == "env_key"

    def test_priority_file_over_keyring(self, temp_config_dir, mock_config_file):
        """Test config file has priority over keyring."""
        mock_credential = Mock()
        mock_credential.password = json.dumps(
            {
                "url": "https://keyring.example.com",
                "api_key": "keyring_key",
                "api_secret": "keyring_secret",
                "verify_ssl": True,
            }
        )

        with patch.object(ConfigLoader, "DEFAULT_CONFIG_FILE", mock_config_file), patch(
            "keyring.get_credential", return_value=mock_credential
        ):
            config = ConfigLoader.load("default")

        # Should load from file, not keyring
        assert config.url == "https://192.168.1.1"
        assert config.api_key == "test_key_default"

    def test_fallback_to_keyring(self, temp_config_dir):
        """Test fallback to keyring when env and file not available."""
        mock_credential = Mock()
        mock_credential.password = json.dumps(
            {
                "url": "https://keyring.example.com",
                "api_key": "keyring_key",
                "api_secret": "keyring_secret",
                "verify_ssl": True,
            }
        )

        missing_file = temp_config_dir / "nonexistent.json"
        with patch.object(ConfigLoader, "DEFAULT_CONFIG_FILE", missing_file), patch(
            "keyring.get_credential", return_value=mock_credential
        ):
            config = ConfigLoader.load("default")

        # Should load from keyring
        assert config.url == "https://keyring.example.com"
        assert config.api_key == "keyring_key"

    def test_no_credentials_found(self, temp_config_dir):
        """Test error raised when no credentials found in any source."""
        missing_file = temp_config_dir / "nonexistent.json"
        with patch.object(ConfigLoader, "DEFAULT_CONFIG_FILE", missing_file), patch(
            "keyring.get_credential", return_value=None
        ), pytest.raises(ConfigurationError, match="No credentials found"):
            ConfigLoader.load("default")


@pytest.mark.asyncio
class TestConfigLoaderProfileManagement:
    """Test profile management operations."""

    def test_save_profile_new_file(self, temp_config_dir):
        """Test saving profile creates new config file."""
        config_file = temp_config_dir / "config.json"
        config = OPNsenseConfig(
            url="https://192.168.1.1", api_key="test_key", api_secret="test_secret", verify_ssl=True
        )

        with patch.object(ConfigLoader, "DEFAULT_CONFIG_FILE", config_file):
            ConfigLoader.save_profile("default", config)

        assert config_file.exists()
        with open(config_file) as f:
            saved_data = json.load(f)
        assert "default" in saved_data
        assert saved_data["default"]["url"] == "https://192.168.1.1"

    def test_save_profile_existing_file(self, temp_config_dir, mock_config_file):
        """Test saving profile to existing config file."""
        new_config = OPNsenseConfig(
            url="https://new.example.com",
            api_key="new_key",
            api_secret="new_secret",
            verify_ssl=False,
        )

        with patch.object(ConfigLoader, "DEFAULT_CONFIG_FILE", mock_config_file):
            ConfigLoader.save_profile("new_profile", new_config)

        with open(mock_config_file) as f:
            saved_data = json.load(f)
        assert "new_profile" in saved_data
        assert "default" in saved_data  # Existing profile preserved
        assert saved_data["new_profile"]["url"] == "https://new.example.com"

    def test_save_profile_update_existing(self, temp_config_dir, mock_config_file):
        """Test updating existing profile."""
        updated_config = OPNsenseConfig(
            url="https://updated.example.com",
            api_key="updated_key",
            api_secret="updated_secret",
            verify_ssl=False,
        )

        with patch.object(ConfigLoader, "DEFAULT_CONFIG_FILE", mock_config_file):
            ConfigLoader.save_profile("default", updated_config)

        with open(mock_config_file) as f:
            saved_data = json.load(f)
        assert saved_data["default"]["url"] == "https://updated.example.com"

    def test_delete_profile_success(self, temp_config_dir, mock_config_file):
        """Test deleting profile."""
        with patch.object(ConfigLoader, "DEFAULT_CONFIG_FILE", mock_config_file):
            ConfigLoader.delete_profile("staging")

        with open(mock_config_file) as f:
            saved_data = json.load(f)
        assert "staging" not in saved_data
        assert "default" in saved_data  # Other profiles preserved
        assert "production" in saved_data

    def test_delete_profile_nonexistent(self, temp_config_dir, mock_config_file):
        """Test deleting nonexistent profile raises error."""
        with patch.object(ConfigLoader, "DEFAULT_CONFIG_FILE", mock_config_file):
            with pytest.raises(ConfigurationError, match="Profile .* not found"):
                ConfigLoader.delete_profile("nonexistent")

    def test_delete_profile_missing_file(self, temp_config_dir):
        """Test deleting profile when config file doesn't exist."""
        missing_file = temp_config_dir / "nonexistent.json"
        with patch.object(ConfigLoader, "DEFAULT_CONFIG_FILE", missing_file):
            with pytest.raises(ConfigurationError, match="Config file not found"):
                ConfigLoader.delete_profile("default")

    def test_list_profiles(self, temp_config_dir, mock_config_file):
        """Test listing all profiles."""
        with patch.object(ConfigLoader, "DEFAULT_CONFIG_FILE", mock_config_file):
            profiles = ConfigLoader.list_profiles()

        assert len(profiles) == 3
        assert "default" in profiles
        assert "production" in profiles
        assert "staging" in profiles

    def test_list_profiles_empty_file(self, temp_config_dir):
        """Test listing profiles with empty config file."""
        empty_file = temp_config_dir / "empty.json"
        with open(empty_file, "w") as f:
            json.dump({}, f)

        with patch.object(ConfigLoader, "DEFAULT_CONFIG_FILE", empty_file):
            profiles = ConfigLoader.list_profiles()

        assert len(profiles) == 0

    def test_list_profiles_missing_file(self, temp_config_dir):
        """Test listing profiles when config file doesn't exist."""
        missing_file = temp_config_dir / "nonexistent.json"
        with patch.object(ConfigLoader, "DEFAULT_CONFIG_FILE", missing_file):
            profiles = ConfigLoader.list_profiles()

        assert len(profiles) == 0

    def test_get_profile_info(self, temp_config_dir, mock_config_file):
        """Test getting profile info without exposing credentials."""
        with patch.object(ConfigLoader, "DEFAULT_CONFIG_FILE", mock_config_file):
            info = ConfigLoader.get_profile_info("default")

        assert info["url"] == "https://192.168.1.1"
        assert info["verify_ssl"] is True
        assert "api_key_preview" in info
        assert info["api_key_preview"] == "test...ault"  # First 4 and last 4 chars
        assert "api_secret" not in info  # Secret not exposed

    def test_get_profile_info_nonexistent(self, temp_config_dir, mock_config_file):
        """Test getting info for nonexistent profile."""
        with patch.object(ConfigLoader, "DEFAULT_CONFIG_FILE", mock_config_file):
            with pytest.raises(ConfigurationError, match="Profile .* not found"):
                ConfigLoader.get_profile_info("nonexistent")


@pytest.mark.asyncio
class TestConfigLoaderSecurity:
    """Test security controls."""

    def test_file_permissions_set_on_save(self, temp_config_dir):
        """Test that file permissions are set to 0600 on save."""
        config_file = temp_config_dir / "config.json"
        config = OPNsenseConfig(
            url="https://192.168.1.1", api_key="test_key", api_secret="test_secret", verify_ssl=True
        )

        with patch.object(ConfigLoader, "DEFAULT_CONFIG_FILE", config_file):
            ConfigLoader.save_profile("default", config)

        stat_info = os.stat(config_file)
        perms = stat_info.st_mode & 0o777
        assert perms == 0o600

    def test_file_permissions_verified_on_load(self, temp_config_dir, mock_config_file):
        """Test that file permissions are verified on load."""
        # Set insecure permissions
        os.chmod(mock_config_file, 0o644)

        with patch.object(ConfigLoader, "DEFAULT_CONFIG_FILE", mock_config_file), patch.object(
            ConfigLoader, "_set_secure_permissions"
        ) as mock_fix:
            ConfigLoader._load_from_config_file("default")

            # Should attempt to fix permissions
            mock_fix.assert_called_once()

    def test_no_credential_logging(self, temp_config_dir, mock_config_file, caplog):
        """Test that credentials are never logged."""
        with patch.object(ConfigLoader, "DEFAULT_CONFIG_FILE", mock_config_file):
            config = ConfigLoader.load("default")

        # Check that credentials don't appear in logs
        log_output = caplog.text
        assert "test_secret_default" not in log_output
        assert config.api_secret not in log_output
