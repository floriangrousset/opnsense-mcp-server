"""
OPNsense MCP Server - Secure Configuration Loader

This module provides secure credential loading from multiple sources with
cascading priority: environment variables → config file → keyring.
Credentials are never exposed to the LLM or stored in conversation logs.
"""

import json
import logging
import os
from pathlib import Path
from typing import Optional, Dict, Any, List
import keyring

from .models import OPNsenseConfig
from .exceptions import ConfigurationError

logger = logging.getLogger("opnsense-mcp")


class ConfigLoader:
    """
    Secure configuration loader for OPNsense credentials.

    Priority order for credential sources:
    1. Environment variables (highest priority) - for CI/CD and containers
    2. Config file (~/.opnsense-mcp/config.json) - for multiple profiles
    3. Keyring storage (lowest priority) - backward compatibility

    Security features:
    - Automatic file permission enforcement (0600)
    - No credential logging
    - Profile-based multi-firewall support
    """

    DEFAULT_CONFIG_DIR = Path.home() / ".opnsense-mcp"
    DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.json"
    REQUIRED_FILE_PERMISSIONS = 0o600
    KEYRING_SERVICE_NAME = "opnsense-mcp-server"

    @classmethod
    def load(cls, profile: str = "default") -> OPNsenseConfig:
        """
        Load OPNsense configuration for the specified profile.

        Args:
            profile: Profile name to load (default: "default")

        Returns:
            OPNsenseConfig object with credentials

        Raises:
            ConfigurationError: If no credentials found or configuration invalid
        """
        logger.debug(f"Loading configuration for profile: {profile}")

        # Priority 1: Environment variables
        config = cls._load_from_env()
        if config:
            logger.info(f"Loaded configuration from environment variables")
            return config

        # Priority 2: Config file
        config = cls._load_from_config_file(profile)
        if config:
            logger.info(f"Loaded configuration for profile '{profile}' from config file")
            return config

        # Priority 3: Keyring (backward compatibility)
        config = cls._load_from_keyring(profile)
        if config:
            logger.info(f"Loaded configuration for profile '{profile}' from keyring (legacy)")
            logger.warning("Keyring storage is deprecated. Please migrate to config file using 'opnsense-mcp setup'")
            return config

        # No credentials found
        raise ConfigurationError(
            f"No credentials found for profile '{profile}'. "
            f"Please configure credentials using 'opnsense-mcp setup' or set environment variables "
            f"(OPNSENSE_URL, OPNSENSE_API_KEY, OPNSENSE_API_SECRET)"
        )

    @classmethod
    def _load_from_env(cls) -> Optional[OPNsenseConfig]:
        """Load configuration from environment variables."""
        url = os.getenv("OPNSENSE_URL")
        api_key = os.getenv("OPNSENSE_API_KEY")
        api_secret = os.getenv("OPNSENSE_API_SECRET")
        verify_ssl = os.getenv("OPNSENSE_VERIFY_SSL", "true").lower() in ("true", "1", "yes")

        if not (url and api_key and api_secret):
            return None

        try:
            return OPNsenseConfig(
                url=url,
                api_key=api_key,
                api_secret=api_secret,
                verify_ssl=verify_ssl
            )
        except Exception as e:
            logger.error(f"Invalid credentials in environment variables: {e}")
            raise ConfigurationError(f"Invalid credentials in environment variables: {e}")

    @classmethod
    def _load_from_config_file(cls, profile: str) -> Optional[OPNsenseConfig]:
        """Load configuration from config file."""
        config_file = cls.DEFAULT_CONFIG_FILE

        if not config_file.exists():
            logger.debug(f"Config file not found: {config_file}")
            return None

        # Verify file permissions for security
        cls._verify_file_permissions(config_file)

        try:
            with open(config_file, 'r') as f:
                config_data = json.load(f)

            if profile not in config_data:
                logger.debug(f"Profile '{profile}' not found in config file")
                return None

            profile_config = config_data[profile]
            return OPNsenseConfig(
                url=profile_config["url"],
                api_key=profile_config["api_key"],
                api_secret=profile_config["api_secret"],
                verify_ssl=profile_config.get("verify_ssl", True)
            )
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file: {e}")
            raise ConfigurationError(f"Invalid JSON in config file: {e}")
        except KeyError as e:
            logger.error(f"Missing required field in config file: {e}")
            raise ConfigurationError(f"Missing required field in config file: {e}")
        except Exception as e:
            logger.error(f"Error loading config file: {e}")
            raise ConfigurationError(f"Error loading config file: {e}")

    @classmethod
    def _load_from_keyring(cls, profile: str) -> Optional[OPNsenseConfig]:
        """Load configuration from keyring (backward compatibility)."""
        try:
            # Try to find credentials in keyring
            # Legacy format: username = f"{url}-{api_key[:8]}"
            # We need to search through keyring entries
            credentials = keyring.get_credential(cls.KEYRING_SERVICE_NAME, None)
            if not credentials:
                return None

            # Parse stored JSON
            cred_data = json.loads(credentials.password)
            return OPNsenseConfig(
                url=cred_data["url"],
                api_key=cred_data["api_key"],
                api_secret=cred_data["api_secret"],
                verify_ssl=cred_data.get("verify_ssl", True)
            )
        except Exception as e:
            logger.debug(f"Could not load from keyring: {e}")
            return None

    @classmethod
    def save_profile(cls, profile: str, config: OPNsenseConfig) -> None:
        """
        Save configuration profile to config file.

        Args:
            profile: Profile name
            config: OPNsense configuration to save

        Raises:
            ConfigurationError: If save operation fails
        """
        config_file = cls.DEFAULT_CONFIG_FILE

        # Create directory if it doesn't exist
        config_file.parent.mkdir(parents=True, exist_ok=True)

        # Load existing profiles or create new structure
        if config_file.exists():
            cls._verify_file_permissions(config_file)
            with open(config_file, 'r') as f:
                config_data = json.load(f)
        else:
            config_data = {}

        # Add/update profile
        config_data[profile] = {
            "url": config.url,
            "api_key": config.api_key,
            "api_secret": config.api_secret,
            "verify_ssl": config.verify_ssl
        }

        # Write config file
        with open(config_file, 'w') as f:
            json.dump(config_data, f, indent=2)

        # Set secure permissions
        cls._set_secure_permissions(config_file)

        logger.info(f"Saved profile '{profile}' to config file")

    @classmethod
    def delete_profile(cls, profile: str) -> None:
        """
        Delete a profile from config file.

        Args:
            profile: Profile name to delete

        Raises:
            ConfigurationError: If profile doesn't exist or deletion fails
        """
        config_file = cls.DEFAULT_CONFIG_FILE

        if not config_file.exists():
            raise ConfigurationError(f"Config file not found: {config_file}")

        cls._verify_file_permissions(config_file)

        with open(config_file, 'r') as f:
            config_data = json.load(f)

        if profile not in config_data:
            raise ConfigurationError(f"Profile '{profile}' not found")

        del config_data[profile]

        # Write updated config
        with open(config_file, 'w') as f:
            json.dump(config_data, f, indent=2)

        cls._set_secure_permissions(config_file)

        logger.info(f"Deleted profile '{profile}' from config file")

    @classmethod
    def list_profiles(cls) -> List[str]:
        """
        List all configured profiles.

        Returns:
            List of profile names
        """
        config_file = cls.DEFAULT_CONFIG_FILE

        if not config_file.exists():
            return []

        cls._verify_file_permissions(config_file)

        with open(config_file, 'r') as f:
            config_data = json.load(f)

        return list(config_data.keys())

    @classmethod
    def get_profile_info(cls, profile: str) -> Dict[str, Any]:
        """
        Get non-sensitive information about a profile.

        Args:
            profile: Profile name

        Returns:
            Dictionary with URL and verify_ssl (no credentials)

        Raises:
            ConfigurationError: If profile doesn't exist
        """
        config_file = cls.DEFAULT_CONFIG_FILE

        if not config_file.exists():
            raise ConfigurationError(f"Config file not found: {config_file}")

        cls._verify_file_permissions(config_file)

        with open(config_file, 'r') as f:
            config_data = json.load(f)

        if profile not in config_data:
            raise ConfigurationError(f"Profile '{profile}' not found")

        profile_config = config_data[profile]
        return {
            "url": profile_config["url"],
            "verify_ssl": profile_config.get("verify_ssl", True),
            "api_key_preview": f"{profile_config['api_key'][:4]}...{profile_config['api_key'][-4:]}"
        }

    @classmethod
    def _set_secure_permissions(cls, file_path: Path) -> None:
        """Set secure file permissions (0600 - owner read/write only)."""
        try:
            os.chmod(file_path, cls.REQUIRED_FILE_PERMISSIONS)
            logger.debug(f"Set secure permissions on {file_path}")
        except Exception as e:
            logger.warning(f"Could not set secure permissions on {file_path}: {e}")

    @classmethod
    def _verify_file_permissions(cls, file_path: Path) -> None:
        """Verify file has secure permissions and warn if not."""
        try:
            stat_info = os.stat(file_path)
            current_perms = stat_info.st_mode & 0o777

            if current_perms != cls.REQUIRED_FILE_PERMISSIONS:
                logger.warning(
                    f"Config file {file_path} has insecure permissions {oct(current_perms)}. "
                    f"Recommended: {oct(cls.REQUIRED_FILE_PERMISSIONS)}"
                )
                # Attempt to fix
                cls._set_secure_permissions(file_path)
        except Exception as e:
            logger.debug(f"Could not verify file permissions: {e}")
