"""
OPNsense MCP Server - Server State Management

This module provides server state management with proper lifecycle handling.
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, TYPE_CHECKING
import keyring

from .models import OPNsenseConfig
from .exceptions import ConfigurationError

if TYPE_CHECKING:
    from .connection import ConnectionPool
    from .client import OPNsenseClient

logger = logging.getLogger("opnsense-mcp")


@dataclass
class ServerState:
    """Managed server state with proper lifecycle."""

    config: Optional[OPNsenseConfig] = None
    pool: Optional['ConnectionPool'] = None
    session_created: Optional[datetime] = None
    session_ttl: timedelta = timedelta(hours=1)  # 1 hour session timeout

    async def initialize(self, config: OPNsenseConfig):
        """Initialize server state with validation.

        Args:
            config: OPNsense connection configuration

        Raises:
            ConfigurationError: If initialization fails
        """
        # Import here to avoid circular dependency
        from .connection import ConnectionPool
        from ..shared.constants import API_CORE_FIRMWARE_STATUS

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
            "verify_ssl": config.verify_ssl
        }

        keyring.set_password(service_name, username, json.dumps(credentials))
        logger.debug("Credentials stored securely")

    async def get_client(self) -> 'OPNsenseClient':
        """Get OPNsense client with session validation.

        Returns:
            Configured OPNsense client

        Raises:
            ConfigurationError: If client is not configured or session expired
        """
        if not self.config or not self.pool:
            raise ConfigurationError("OPNsense client not configured. Use configure_opnsense_connection first.")

        # Check session expiry
        if self.session_created and datetime.now() - self.session_created > self.session_ttl:
            logger.info("Session expired, reinitializing...")
            await self.initialize(self.config)

        return await self.pool.get_client(self.config)

    async def cleanup(self):
        """Cleanup resources."""
        if self.pool:
            await self.pool.close_all()
            self.pool = None
        self.config = None
        self.session_created = None
