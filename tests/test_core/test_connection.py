"""
Tests for OPNsense MCP Server connection pooling and rate limiting.

This module tests the connection pool that manages OPNsense client connections
with TTL-based expiration, maximum connection limits, and rate limiting.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, Mock, patch
from datetime import datetime, timedelta

from src.opnsense_mcp.core.connection import ConnectionPool
from src.opnsense_mcp.core.models import OPNsenseConfig
from src.opnsense_mcp.core.exceptions import RateLimitError


@pytest.mark.asyncio
class TestConnectionPool:
    """Test ConnectionPool class."""

    def test_connection_pool_creation(self):
        """Test creating a connection pool with default parameters."""
        pool = ConnectionPool()

        assert pool.max_connections == 5
        assert pool.ttl == timedelta(seconds=300)
        assert pool.connections == {}
        assert pool.lock is not None
        assert pool.rate_limiter is not None
        assert pool.burst_limiter is not None

    def test_connection_pool_with_custom_parameters(self):
        """Test creating a connection pool with custom parameters."""
        pool = ConnectionPool(max_connections=10, ttl_seconds=600)

        assert pool.max_connections == 10
        assert pool.ttl == timedelta(seconds=600)

    def test_get_config_hash(self):
        """Test configuration hash generation."""
        pool = ConnectionPool()
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret"
        )

        hash1 = pool._get_config_hash(config)

        assert isinstance(hash1, str)
        assert len(hash1) == 16  # SHA256 truncated to 16 chars

    def test_get_config_hash_consistency(self):
        """Test that same config produces same hash."""
        pool = ConnectionPool()
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret"
        )

        hash1 = pool._get_config_hash(config)
        hash2 = pool._get_config_hash(config)

        assert hash1 == hash2

    def test_get_config_hash_different_for_different_configs(self):
        """Test that different configs produce different hashes."""
        pool = ConnectionPool()

        config1 = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="key1",
            api_secret="secret1"
        )
        config2 = OPNsenseConfig(
            url="https://192.168.1.2",
            api_key="key2",
            api_secret="secret2"
        )

        hash1 = pool._get_config_hash(config1)
        hash2 = pool._get_config_hash(config2)

        assert hash1 != hash2

    async def test_get_client_creates_new_client(self):
        """Test that get_client creates a new client when pool is empty."""
        pool = ConnectionPool()
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )

        with patch('src.opnsense_mcp.core.client.OPNsenseClient') as MockClient:
            mock_client = Mock()
            MockClient.return_value = mock_client

            client = await pool.get_client(config)

            assert client == mock_client
            MockClient.assert_called_once_with(config, pool)
            assert len(pool.connections) == 1

    async def test_get_client_reuses_existing_client(self):
        """Test that get_client reuses existing client from pool."""
        pool = ConnectionPool()
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )

        with patch('src.opnsense_mcp.core.client.OPNsenseClient') as MockClient:
            mock_client = Mock()
            MockClient.return_value = mock_client

            # First call creates client
            client1 = await pool.get_client(config)
            # Second call should reuse client
            client2 = await pool.get_client(config)

            assert client1 == client2
            assert MockClient.call_count == 1  # Only created once
            assert len(pool.connections) == 1

    async def test_get_client_expires_old_client(self):
        """Test that expired clients are removed and new ones created."""
        pool = ConnectionPool(ttl_seconds=1)  # 1 second TTL
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )

        with patch('src.opnsense_mcp.core.client.OPNsenseClient') as MockClient:
            mock_client1 = Mock()
            mock_client1.close = AsyncMock()
            mock_client2 = Mock()
            mock_client2.close = AsyncMock()

            MockClient.side_effect = [mock_client1, mock_client2]

            # First call creates client
            client1 = await pool.get_client(config)
            assert client1 == mock_client1

            # Manually expire the client by backdating the timestamp
            config_hash = pool._get_config_hash(config)
            old_timestamp = datetime.now() - timedelta(seconds=2)
            pool.connections[config_hash] = (mock_client1, old_timestamp)

            # Second call should create new client after closing expired one
            client2 = await pool.get_client(config)
            assert client2 == mock_client2
            assert client1 != client2

            # Old client should have been closed
            mock_client1.close.assert_called_once()

    async def test_get_client_cleanup_oldest_when_pool_full(self):
        """Test that oldest connection is removed when pool is full."""
        pool = ConnectionPool(max_connections=2)

        configs = [
            OPNsenseConfig(url=f"https://192.168.1.{i}", api_key=f"key{i}", api_secret=f"secret{i}", verify_ssl=False)
            for i in range(3)
        ]

        with patch('src.opnsense_mcp.core.client.OPNsenseClient') as MockClient:
            mock_clients = []
            for i in range(3):
                mock_client = Mock()
                mock_client.close = AsyncMock()
                mock_clients.append(mock_client)

            MockClient.side_effect = mock_clients

            # Add first client
            await pool.get_client(configs[0])
            assert len(pool.connections) == 1

            # Add second client
            await pool.get_client(configs[1])
            assert len(pool.connections) == 2

            # Add third client - should trigger cleanup of oldest
            await pool.get_client(configs[2])
            assert len(pool.connections) == 2  # Should still be at max

            # First (oldest) client should have been closed
            mock_clients[0].close.assert_called_once()

    async def test_cleanup_oldest(self):
        """Test _cleanup_oldest removes the oldest connection."""
        pool = ConnectionPool()
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )

        with patch('src.opnsense_mcp.core.client.OPNsenseClient') as MockClient:
            mock_client = Mock()
            mock_client.close = AsyncMock()
            MockClient.return_value = mock_client

            # Add client to pool
            await pool.get_client(config)
            assert len(pool.connections) == 1

            # Cleanup oldest
            await pool._cleanup_oldest()
            assert len(pool.connections) == 0
            mock_client.close.assert_called_once()

    async def test_cleanup_oldest_with_empty_pool(self):
        """Test that _cleanup_oldest handles empty pool gracefully."""
        pool = ConnectionPool()

        # Should not raise any errors
        await pool._cleanup_oldest()
        assert len(pool.connections) == 0

    async def test_check_rate_limit_normal_operation(self):
        """Test rate limiting under normal operation."""
        pool = ConnectionPool()

        # Should succeed without raising
        await pool.check_rate_limit()

    async def test_check_rate_limit_burst_exceeded(self):
        """Test rate limiting when burst limit is exceeded."""
        pool = ConnectionPool()

        # Mock burst limiter to have no capacity
        pool.burst_limiter.has_capacity = Mock(return_value=False)

        with pytest.raises(RateLimitError) as exc_info:
            await pool.check_rate_limit()

        assert "Burst rate limit exceeded" in str(exc_info.value)

    async def test_close_all_connections(self):
        """Test closing all connections in the pool."""
        pool = ConnectionPool()
        configs = [
            OPNsenseConfig(url=f"https://192.168.1.{i}", api_key=f"key{i}", api_secret=f"secret{i}", verify_ssl=False)
            for i in range(3)
        ]

        with patch('src.opnsense_mcp.core.client.OPNsenseClient') as MockClient:
            mock_clients = []
            for _ in range(3):
                mock_client = Mock()
                mock_client.close = AsyncMock()
                mock_clients.append(mock_client)

            MockClient.side_effect = mock_clients

            # Add multiple clients
            for config in configs:
                await pool.get_client(config)

            assert len(pool.connections) == 3

            # Close all
            await pool.close_all()

            # All clients should be closed
            for mock_client in mock_clients:
                mock_client.close.assert_called_once()

            # Pool should be empty
            assert len(pool.connections) == 0

    async def test_close_all_with_empty_pool(self):
        """Test closing all connections when pool is empty."""
        pool = ConnectionPool()

        # Should not raise any errors
        await pool.close_all()
        assert len(pool.connections) == 0

    async def test_concurrent_get_client_requests(self):
        """Test thread safety with concurrent get_client requests."""
        pool = ConnectionPool()
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )

        with patch('src.opnsense_mcp.core.client.OPNsenseClient') as MockClient:
            mock_client = Mock()
            MockClient.return_value = mock_client

            # Simulate concurrent requests
            tasks = [pool.get_client(config) for _ in range(10)]
            results = await asyncio.gather(*tasks)

            # All should return the same client
            assert all(client == mock_client for client in results)
            # Client should only be created once
            assert MockClient.call_count == 1

    async def test_rate_limiter_acquisition(self):
        """Test that rate limiters are properly acquired."""
        pool = ConnectionPool()

        # Mock the rate limiters
        pool.rate_limiter.acquire = AsyncMock()
        pool.burst_limiter.acquire = AsyncMock()
        pool.burst_limiter.has_capacity = Mock(return_value=True)

        await pool.check_rate_limit()

        # Both limiters should be acquired
        pool.rate_limiter.acquire.assert_called_once()
        pool.burst_limiter.acquire.assert_called_once()

    async def test_different_configs_create_different_clients(self):
        """Test that different configs result in different clients in pool."""
        pool = ConnectionPool()

        config1 = OPNsenseConfig(url="https://192.168.1.1", api_key="key1", api_secret="secret1", verify_ssl=False)
        config2 = OPNsenseConfig(url="https://192.168.1.2", api_key="key2", api_secret="secret2", verify_ssl=False)

        with patch('src.opnsense_mcp.core.client.OPNsenseClient') as MockClient:
            mock_client1 = Mock()
            mock_client2 = Mock()
            MockClient.side_effect = [mock_client1, mock_client2]

            client1 = await pool.get_client(config1)
            client2 = await pool.get_client(config2)

            assert client1 != client2
            assert len(pool.connections) == 2
            assert MockClient.call_count == 2

    async def test_ttl_calculation(self):
        """Test TTL calculation for connection expiration."""
        pool = ConnectionPool(ttl_seconds=100)

        assert pool.ttl == timedelta(seconds=100)
        assert pool.ttl.total_seconds() == 100

    async def test_lock_prevents_race_conditions(self):
        """Test that lock prevents race conditions in connection management."""
        pool = ConnectionPool()
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )

        # The lock should be acquired during get_client
        assert pool.lock is not None
        assert isinstance(pool.lock, asyncio.Lock)

        with patch('src.opnsense_mcp.core.client.OPNsenseClient') as MockClient:
            mock_client = Mock()
            MockClient.return_value = mock_client

            await pool.get_client(config)

            # Lock should not be held after operation
            assert not pool.lock.locked()
