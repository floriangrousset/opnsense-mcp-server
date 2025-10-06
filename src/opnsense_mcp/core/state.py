"""
OPNsense MCP Server - Server State Management

This module provides server state management with proper lifecycle handling.
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Optional

import keyring

from .exceptions import ConfigurationError
from .models import OPNsenseConfig

if TYPE_CHECKING:
    from .client import OPNsenseClient
    from .connection import ConnectionPool

logger = logging.getLogger("opnsense-mcp")


@dataclass
class ServerState:
    """Managed server state with proper lifecycle."""

    config: OPNsenseConfig | None = None
    pool: Optional["ConnectionPool"] = None
    session_created: datetime | None = None
    session_ttl: timedelta = timedelta(hours=1)  # 1 hour session timeout
    _current_profile: str | None = None  # Track which profile is loaded

    async def initialize(self, config: OPNsenseConfig):
        """Initialize server state with validation.

        Args:
            config: OPNsense connection configuration

        Raises:
            ConfigurationError: If initialization fails
        """
        # Import here to avoid circular dependency
        from ..shared.constants import API_CORE_FIRMWARE_STATUS
        from .connection import ConnectionPool

        await self.cleanup()

        # Store encrypted credentials
        try:
            await self._store_credentials(config)
        except Exception as e:
            logger.warning(f"Could not store credentials securely: {e}. Using in-memory storage.")

        self.config = config
        self.pool = ConnectionPool()
        self.session_created = datetime.now()

        # Validate connection
        client = await self.pool.get_client(config)
        await client.request("GET", API_CORE_FIRMWARE_STATUS)

        logger.info("OPNsense connection initialized successfully")

    async def _store_credentials(self, config: OPNsenseConfig):
        """Store credentials securely using keyring.

        Args:
            config: OPNsense connection configuration
        """
        service_name = "opnsense-mcp-server"
        username = f"{config.url}-{config.api_key[:8]}"  # Partial key for identification

        # Store as JSON for easy retrieval
        credentials = {
            "url": config.url,
            "api_key": config.api_key,
            "api_secret": config.api_secret,
            "verify_ssl": config.verify_ssl,
        }

        keyring.set_password(service_name, username, json.dumps(credentials))
        logger.debug("Credentials stored securely")

    def _config_changed(self, new_config: OPNsenseConfig, old_config: OPNsenseConfig) -> bool:
        """
        Detect if credentials have changed between configs.

        Args:
            new_config: New configuration to compare
            old_config: Current configuration

        Returns:
            True if credentials changed, False otherwise

        Notes:
            Compares URL, API key, and API secret to detect rotation.
            Changes to verify_ssl don't trigger reinitialization.
        """
        return (
            new_config.url != old_config.url
            or new_config.api_key != old_config.api_key
            or new_config.api_secret != old_config.api_secret
        )

    async def get_client(self) -> "OPNsenseClient":
        """Get OPNsense client with session validation and credential rotation detection.

        Returns:
            Configured OPNsense client

        Raises:
            ConfigurationError: If client is not configured or session expired

        Notes:
            Automatically detects and handles:
            - Session expiry (1 hour default)
            - Credential rotation (config file changes)
            - Profile changes
        """
        if not self.config or not self.pool:
            raise ConfigurationError(
                "OPNsense client not configured. Use configure_opnsense_connection first."
            )

        # Check session expiry
        if self.session_created and datetime.now() - self.session_created > self.session_ttl:
            logger.info("Session expired, reinitializing...")
            await self.initialize(self.config)

        # Check for credential rotation (if profile is tracked)
        if self._current_profile:
            try:
                from .config_loader import ConfigLoader

                current_config = ConfigLoader.load(self._current_profile)

                if self._config_changed(current_config, self.config):
                    logger.info(
                        f"Credentials changed for profile '{self._current_profile}', reinitializing..."
                    )
                    await self.initialize(current_config)
            except Exception as e:
                logger.debug(f"Could not check for config changes: {e}")

        return await self.pool.get_client(self.config)

    async def cleanup(self):
        """Cleanup resources."""
        if self.pool:
            await self.pool.close_all()
            self.pool = None
        self.config = None
        self.session_created = None
