"""
Shared pytest configuration and fixtures for OPNsense MCP Server tests.

This module provides common fixtures used across all test modules including:
- Mock OPNsense client configurations
- Mock API responses
- Async test setup
- Test data factories
"""

from typing import Any
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
import pytest_asyncio

from src.opnsense_mcp.core import (
    ConnectionPool,
    OPNsenseClient,
    OPNsenseConfig,
    ServerState,
)

# ========== Configuration Fixtures ==========


@pytest.fixture
def mock_opnsense_config() -> OPNsenseConfig:
    """Provide a mock OPNsense configuration for testing."""
    return OPNsenseConfig(
        url="https://192.168.1.1",
        api_key="test_api_key_1234567890",
        api_secret="test_api_secret_abcdefghij",
        verify_ssl=False,  # Disable SSL verification for tests
    )


@pytest.fixture
def mock_opnsense_config_dict() -> dict[str, Any]:
    """Provide a dictionary version of OPNsense configuration."""
    return {
        "url": "https://192.168.1.1",
        "api_key": "test_api_key_1234567890",
        "api_secret": "test_api_secret_abcdefghij",
        "verify_ssl": False,
    }


# ========== Mock HTTP Response Fixtures ==========


@pytest.fixture
def mock_http_success_response() -> dict[str, Any]:
    """Provide a standard successful API response."""
    return {"status": "ok", "result": "success", "message": "Operation completed successfully"}


@pytest.fixture
def mock_http_error_response() -> dict[str, Any]:
    """Provide a standard error API response."""
    return {"status": "error", "message": "Operation failed", "details": "Test error details"}


@pytest.fixture
def mock_firmware_status_response() -> dict[str, Any]:
    """Provide a mock firmware status response."""
    return {
        "product_name": "OPNsense",
        "product_version": "24.1.1",
        "last_check": "2024-10-04 12:00:00",
    }


# ========== Mock Client Fixtures ==========


@pytest_asyncio.fixture
async def mock_opnsense_client(mock_opnsense_config):
    """Provide a mock OPNsense client with standard methods mocked."""
    client = Mock(spec=OPNsenseClient)
    client.config = mock_opnsense_config
    client.request = AsyncMock(return_value={"status": "ok"})
    client.get = AsyncMock(return_value={"status": "ok"})
    client.post = AsyncMock(return_value={"status": "ok"})
    client.close = AsyncMock()
    return client


@pytest_asyncio.fixture
async def mock_server_state(mock_opnsense_config):
    """Provide a mock server state with initialized configuration."""
    state = Mock(spec=ServerState)
    state.config = mock_opnsense_config
    state.pool = Mock(spec=ConnectionPool)
    state.session_created = None

    # Mock get_client to return a mock client
    mock_client = Mock(spec=OPNsenseClient)
    mock_client.request = AsyncMock(return_value={"status": "ok"})
    state.get_client = AsyncMock(return_value=mock_client)
    state.initialize = AsyncMock()
    state.cleanup = AsyncMock()

    return state


# ========== HTTP Mock Transport ==========


class MockTransport(httpx.MockTransport):
    """Custom mock transport for httpx client with configurable responses."""

    def __init__(self, responses: dict[str, Any] = None):
        """Initialize mock transport with optional response mapping.

        Args:
            responses: Dictionary mapping URL patterns to response data
        """
        self.responses = responses or {}
        self.requests_made = []
        super().__init__(self._handle_request)

    def _handle_request(self, request: httpx.Request) -> httpx.Response:
        """Handle mock HTTP requests and return configured responses."""
        self.requests_made.append(
            {
                "method": request.method,
                "url": str(request.url),
                "headers": dict(request.headers),
            }
        )

        # Default successful response
        response_data = {"status": "ok", "result": "success"}
        status_code = 200

        # Check if we have a configured response for this URL
        url_str = str(request.url)
        for pattern, data in self.responses.items():
            if pattern in url_str:
                if isinstance(data, dict) and "status_code" in data:
                    status_code = data["status_code"]
                    response_data = data.get("data", response_data)
                else:
                    response_data = data
                break


        return httpx.Response(
            status_code=status_code,
            json=response_data,
            request=request,
        )


@pytest.fixture
def mock_http_transport():
    """Provide a mock HTTP transport for testing."""
    return MockTransport()


# ========== MCP Context Mocks ==========


@pytest.fixture
def mock_mcp_context():
    """Provide a mock MCP context for tool testing."""
    context = Mock()
    context.info = AsyncMock()
    context.warn = AsyncMock()
    context.error = AsyncMock()
    context.debug = AsyncMock()
    return context


# ========== Pytest Configuration ==========


def pytest_configure(config):
    """Configure pytest with custom markers and settings."""
    config.addinivalue_line("markers", "asyncio: mark test as an asyncio test")
    config.addinivalue_line("markers", "unit: mark test as a unit test")
    config.addinivalue_line("markers", "integration: mark test as an integration test")
    config.addinivalue_line("markers", "slow: mark test as slow running")


@pytest.fixture(autouse=True)
def reset_server_state():
    """Automatically reset server state between tests."""
    return
    # Cleanup code here if needed


# ========== Async Test Configuration ==========


@pytest.fixture(scope="session")
def event_loop_policy():
    """Provide event loop policy for async tests."""
    import asyncio

    return asyncio.get_event_loop_policy()


# ========== Helper Functions for Tests ==========


def create_mock_response(status: str = "ok", **kwargs) -> dict[str, Any]:
    """Create a mock API response with custom fields.

    Args:
        status: Response status ("ok" or "error")
        **kwargs: Additional fields to include in response

    Returns:
        Dictionary representing API response
    """
    response = {"status": status}
    response.update(kwargs)
    return response
