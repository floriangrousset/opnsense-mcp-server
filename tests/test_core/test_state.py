"""
Tests for OPNsense MCP Server state management.

This module tests the server state lifecycle including initialization,
session management, credential storage, and cleanup.
"""

import pytest
import json
from unittest.mock import AsyncMock, Mock, patch
from datetime import datetime, timedelta

from src.opnsense_mcp.core.state import ServerState
from src.opnsense_mcp.core.models import OPNsenseConfig
from src.opnsense_mcp.core.exceptions import ConfigurationError


@pytest.mark.asyncio
class TestServerState:
    """Test ServerState class."""

    def test_server_state_creation(self):
        """Test creating a ServerState with default values."""
        state = ServerState()

        assert state.config is None
        assert state.pool is None
        assert state.session_created is None
        assert state.session_ttl == timedelta(hours=1)

    def test_server_state_with_custom_session_ttl(self):
        """Test creating a ServerState with custom session TTL."""
        state = ServerState(session_ttl=timedelta(hours=2))

        assert state.session_ttl == timedelta(hours=2)

    async def test_initialize_success(self, mock_opnsense_config):
        """Test successful state initialization."""
        state = ServerState()

        with patch('src.opnsense_mcp.core.connection.ConnectionPool') as MockPool, \
             patch('src.opnsense_mcp.core.state.keyring') as mock_keyring, \
             patch('src.opnsense_mcp.shared.constants.API_CORE_FIRMWARE_STATUS', '/api/core/firmware/status'):

            # Mock connection pool
            mock_pool = Mock()
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={"status": "ok"})
            mock_pool.get_client = AsyncMock(return_value=mock_client)
            MockPool.return_value = mock_pool

            await state.initialize(mock_opnsense_config)

            assert state.config == mock_opnsense_config
            assert state.pool == mock_pool
            assert isinstance(state.session_created, datetime)

            # Verify validation request was made
            mock_client.request.assert_called_once_with("GET", "/api/core/firmware/status")

    async def test_initialize_stores_credentials(self, mock_opnsense_config):
        """Test that initialize stores credentials securely."""
        state = ServerState()

        with patch('src.opnsense_mcp.core.connection.ConnectionPool') as MockPool, \
             patch('src.opnsense_mcp.core.state.keyring') as mock_keyring, \
             patch('src.opnsense_mcp.shared.constants.API_CORE_FIRMWARE_STATUS', '/api/core/firmware/status'):

            mock_pool = Mock()
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={"status": "ok"})
            mock_pool.get_client = AsyncMock(return_value=mock_client)
            MockPool.return_value = mock_pool

            await state.initialize(mock_opnsense_config)

            # Verify credentials were stored
            mock_keyring.set_password.assert_called_once()
            call_args = mock_keyring.set_password.call_args[0]

            assert call_args[0] == "opnsense-mcp-server"  # service_name
            assert "test_api_" in call_args[1]  # username includes partial key

            # Verify credential JSON
            stored_creds = json.loads(call_args[2])
            assert stored_creds["url"] == mock_opnsense_config.url
            assert stored_creds["api_key"] == mock_opnsense_config.api_key
            assert stored_creds["api_secret"] == mock_opnsense_config.api_secret

    async def test_initialize_handles_keyring_failure(self, mock_opnsense_config):
        """Test that initialize handles keyring failure gracefully."""
        state = ServerState()

        with patch('src.opnsense_mcp.core.connection.ConnectionPool') as MockPool, \
             patch('src.opnsense_mcp.core.state.keyring') as mock_keyring, \
             patch('src.opnsense_mcp.shared.constants.API_CORE_FIRMWARE_STATUS', '/api/core/firmware/status'), \
             patch('src.opnsense_mcp.core.state.logging.getLogger') as mock_logger:

            mock_keyring.set_password.side_effect = Exception("Keyring error")

            mock_pool = Mock()
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={"status": "ok"})
            mock_pool.get_client = AsyncMock(return_value=mock_client)
            MockPool.return_value = mock_pool

            # Should not raise, just log warning
            await state.initialize(mock_opnsense_config)

            assert state.config == mock_opnsense_config
            mock_logger.warning.assert_called()

    async def test_initialize_cleans_up_previous_state(self, mock_opnsense_config):
        """Test that initialize cleans up previous state."""
        state = ServerState()

        with patch('src.opnsense_mcp.core.connection.ConnectionPool') as MockPool, \
             patch('src.opnsense_mcp.core.state.keyring'), \
             patch('src.opnsense_mcp.shared.constants.API_CORE_FIRMWARE_STATUS', '/api/core/firmware/status'):

            mock_pool = Mock()
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={"status": "ok"})
            mock_pool.get_client = AsyncMock(return_value=mock_client)
            mock_pool.close_all = AsyncMock()
            MockPool.return_value = mock_pool

            # Initialize twice
            await state.initialize(mock_opnsense_config)
            first_pool = state.pool

            await state.initialize(mock_opnsense_config)

            # Cleanup should have been called on first pool
            first_pool.close_all.assert_called_once()

    async def test_get_client_when_configured(self, mock_opnsense_config):
        """Test get_client returns client when properly configured."""
        state = ServerState()

        with patch('src.opnsense_mcp.core.connection.ConnectionPool') as MockPool, \
             patch('src.opnsense_mcp.core.state.keyring'), \
             patch('src.opnsense_mcp.shared.constants.API_CORE_FIRMWARE_STATUS', '/api/core/firmware/status'):

            mock_pool = Mock()
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={"status": "ok"})
            mock_pool.get_client = AsyncMock(return_value=mock_client)
            MockPool.return_value = mock_pool

            await state.initialize(mock_opnsense_config)

            client = await state.get_client()

            assert client == mock_client
            mock_pool.get_client.assert_called_with(mock_opnsense_config)

    async def test_get_client_raises_when_not_configured(self):
        """Test get_client raises ConfigurationError when not configured."""
        state = ServerState()

        with pytest.raises(ConfigurationError) as exc_info:
            await state.get_client()

        assert "not configured" in str(exc_info.value)
        assert "configure_opnsense_connection" in str(exc_info.value)

    async def test_get_client_with_no_pool(self, mock_opnsense_config):
        """Test get_client raises ConfigurationError when pool is None."""
        state = ServerState()
        state.config = mock_opnsense_config
        state.pool = None

        with pytest.raises(ConfigurationError) as exc_info:
            await state.get_client()

        assert "not configured" in str(exc_info.value)

    async def test_get_client_reinitializes_on_session_expiry(self, mock_opnsense_config):
        """Test get_client reinitializes when session has expired."""
        state = ServerState(session_ttl=timedelta(seconds=1))

        with patch('src.opnsense_mcp.core.connection.ConnectionPool') as MockPool, \
             patch('src.opnsense_mcp.core.state.keyring'), \
             patch('src.opnsense_mcp.shared.constants.API_CORE_FIRMWARE_STATUS', '/api/core/firmware/status'), \
             patch('src.opnsense_mcp.core.state.logging.getLogger') as mock_logger:

            mock_pool = Mock()
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={"status": "ok"})
            mock_pool.get_client = AsyncMock(return_value=mock_client)
            mock_pool.close_all = AsyncMock()
            MockPool.return_value = mock_pool

            await state.initialize(mock_opnsense_config)

            # Manually expire the session
            state.session_created = datetime.now() - timedelta(seconds=2)

            # get_client should reinitialize
            client = await state.get_client()

            assert client == mock_client
            # Check that reinitialization was logged
            mock_logger.info.assert_any_call("Session expired, reinitializing...")

    async def test_cleanup(self, mock_opnsense_config):
        """Test cleanup properly cleans up resources."""
        state = ServerState()

        with patch('src.opnsense_mcp.core.connection.ConnectionPool') as MockPool, \
             patch('src.opnsense_mcp.core.state.keyring'), \
             patch('src.opnsense_mcp.shared.constants.API_CORE_FIRMWARE_STATUS', '/api/core/firmware/status'):

            mock_pool = Mock()
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={"status": "ok"})
            mock_pool.get_client = AsyncMock(return_value=mock_client)
            mock_pool.close_all = AsyncMock()
            MockPool.return_value = mock_pool

            await state.initialize(mock_opnsense_config)

            assert state.config is not None
            assert state.pool is not None
            assert state.session_created is not None

            await state.cleanup()

            # Verify cleanup
            assert state.config is None
            assert state.pool is None
            assert state.session_created is None
            mock_pool.close_all.assert_called_once()

    async def test_cleanup_with_no_pool(self):
        """Test cleanup handles state with no pool gracefully."""
        state = ServerState()

        # Should not raise
        await state.cleanup()

        assert state.config is None
        assert state.pool is None
        assert state.session_created is None

    async def test_store_credentials_format(self, mock_opnsense_config):
        """Test _store_credentials creates correct credential format."""
        state = ServerState()

        with patch('src.opnsense_mcp.core.state.keyring') as mock_keyring:
            await state._store_credentials(mock_opnsense_config)

            # Extract stored credentials
            call_args = mock_keyring.set_password.call_args[0]
            stored_json = call_args[2]
            credentials = json.loads(stored_json)

            assert "url" in credentials
            assert "api_key" in credentials
            assert "api_secret" in credentials
            assert "verify_ssl" in credentials

            assert credentials["url"] == mock_opnsense_config.url
            assert credentials["api_key"] == mock_opnsense_config.api_key
            assert credentials["api_secret"] == mock_opnsense_config.api_secret
            assert credentials["verify_ssl"] == mock_opnsense_config.verify_ssl

    async def test_session_ttl_respected(self, mock_opnsense_config):
        """Test that session TTL is properly respected."""
        state = ServerState(session_ttl=timedelta(minutes=30))

        with patch('src.opnsense_mcp.core.connection.ConnectionPool') as MockPool, \
             patch('src.opnsense_mcp.core.state.keyring'), \
             patch('src.opnsense_mcp.shared.constants.API_CORE_FIRMWARE_STATUS', '/api/core/firmware/status'):

            mock_pool = Mock()
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={"status": "ok"})
            mock_pool.get_client = AsyncMock(return_value=mock_client)
            MockPool.return_value = mock_pool

            await state.initialize(mock_opnsense_config)

            # Session is fresh, should not reinitialize
            client = await state.get_client()
            assert client == mock_client

            # Only one initialization should have occurred
            assert MockPool.call_count == 1

    async def test_session_created_timestamp(self, mock_opnsense_config):
        """Test that session_created timestamp is properly set."""
        state = ServerState()

        with patch('src.opnsense_mcp.core.connection.ConnectionPool') as MockPool, \
             patch('src.opnsense_mcp.core.state.keyring'), \
             patch('src.opnsense_mcp.shared.constants.API_CORE_FIRMWARE_STATUS', '/api/core/firmware/status'):

            mock_pool = Mock()
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={"status": "ok"})
            mock_pool.get_client = AsyncMock(return_value=mock_client)
            MockPool.return_value = mock_pool

            before = datetime.now()
            await state.initialize(mock_opnsense_config)
            after = datetime.now()

            assert state.session_created is not None
            assert before <= state.session_created <= after

    async def test_initialize_logs_success(self, mock_opnsense_config):
        """Test that successful initialization is logged."""
        state = ServerState()

        with patch('src.opnsense_mcp.core.connection.ConnectionPool') as MockPool, \
             patch('src.opnsense_mcp.core.state.keyring'), \
             patch('src.opnsense_mcp.shared.constants.API_CORE_FIRMWARE_STATUS', '/api/core/firmware/status'), \
             patch('src.opnsense_mcp.core.state.logging.getLogger') as mock_logger:

            mock_pool = Mock()
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={"status": "ok"})
            mock_pool.get_client = AsyncMock(return_value=mock_client)
            MockPool.return_value = mock_pool

            await state.initialize(mock_opnsense_config)

            # Verify success was logged
            mock_logger.info.assert_any_call("OPNsense connection initialized successfully")

    async def test_multiple_get_client_calls(self, mock_opnsense_config):
        """Test multiple get_client calls return clients correctly."""
        state = ServerState()

        with patch('src.opnsense_mcp.core.connection.ConnectionPool') as MockPool, \
             patch('src.opnsense_mcp.core.state.keyring'), \
             patch('src.opnsense_mcp.shared.constants.API_CORE_FIRMWARE_STATUS', '/api/core/firmware/status'):

            mock_pool = Mock()
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={"status": "ok"})
            mock_pool.get_client = AsyncMock(return_value=mock_client)
            MockPool.return_value = mock_pool

            await state.initialize(mock_opnsense_config)

            # Multiple get_client calls
            client1 = await state.get_client()
            client2 = await state.get_client()
            client3 = await state.get_client()

            assert client1 == client2 == client3 == mock_client
            assert mock_pool.get_client.call_count == 4  # 1 during init + 3 from get_client calls
