"""
OPNsense MCP Server - Connection Management

This module handles connection pooling and rate limiting for OPNsense API connections.
"""

import asyncio
import hashlib
from typing import Dict, Tuple
from datetime import datetime, timedelta
from aiolimiter import AsyncLimiter

from .models import OPNsenseConfig
from .exceptions import RateLimitError


class ConnectionPool:
    """Manages OPNsense client connections with pooling and rate limiting."""

    def __init__(self, max_connections: int = 5, ttl_seconds: int = 300):
        self.max_connections = max_connections
        self.ttl = timedelta(seconds=ttl_seconds)
        self.connections: Dict[str, Tuple['OPNsenseClient', datetime]] = {}
        self.lock = asyncio.Lock()
        # Rate limiting: 10 requests per second with burst of 20
        self.rate_limiter = AsyncLimiter(max_rate=10, time_period=1.0)
        self.burst_limiter = AsyncLimiter(max_rate=20, time_period=1.0)

    def _get_config_hash(self, config: OPNsenseConfig) -> str:
        """Generate hash for config to use as pool key."""
        config_str = f"{config.url}:{config.api_key}"
        return hashlib.sha256(config_str.encode()).hexdigest()[:16]

    async def get_client(self, config: OPNsenseConfig) -> 'OPNsenseClient':
        """Get or create client from pool."""
        # Import here to avoid circular dependency
        from .client import OPNsenseClient

        config_hash = self._get_config_hash(config)

        async with self.lock:
            # Check if we have a valid existing client
            if config_hash in self.connections:
                client, created_at = self.connections[config_hash]
                if datetime.now() - created_at < self.ttl:
                    return client
                else:
                    # Client expired, close and remove
                    await client.close()
                    del self.connections[config_hash]

            # Create new client
            client = OPNsenseClient(config, self)
            self.connections[config_hash] = (client, datetime.now())

            # Cleanup old connections if pool is full
            if len(self.connections) > self.max_connections:
                await self._cleanup_oldest()

            return client

    async def _cleanup_oldest(self):
        """Remove oldest connection from pool."""
        if not self.connections:
            return

        oldest_key = min(
            self.connections.keys(),
            key=lambda k: self.connections[k][1]
        )
        client, _ = self.connections[oldest_key]
        await client.close()
        del self.connections[oldest_key]

    async def check_rate_limit(self):
        """Check and enforce rate limits."""
        # Try burst limit first
        if not self.burst_limiter.has_capacity():
            raise RateLimitError("Burst rate limit exceeded. Please slow down requests.")

        # Apply rate limit
        await self.rate_limiter.acquire()
        await self.burst_limiter.acquire()

    async def close_all(self):
        """Close all connections in pool."""
        async with self.lock:
            for client, _ in self.connections.values():
                await client.close()
            self.connections.clear()
