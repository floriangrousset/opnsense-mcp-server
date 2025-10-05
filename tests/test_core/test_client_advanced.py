"""
Tests for OPNsense MCP Server client advanced functionality.

This module tests the advanced request handling including HTTP methods,
error handling, retries, rate limiting, and comprehensive error scenarios.
"""

import json
import pytest
import httpx
from unittest.mock import Mock, AsyncMock, patch
from src.opnsense_mcp.core.client import OPNsenseClient
from src.opnsense_mcp.core.models import OPNsenseConfig
from src.opnsense_mcp.core.retry import RetryConfig
from src.opnsense_mcp.core.exceptions import (
    ValidationError,
    AuthenticationError,
    AuthorizationError,
    ResourceNotFoundError,
    RateLimitError,
    APIError,
    NetworkError,
    TimeoutError as OPNsenseTimeoutError
)


@pytest.mark.asyncio
class TestOPNsenseClientRequest:
    """Test OPNsense client request method."""

    async def test_request_get_success(self):
        """Test successful GET request."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )
        client = OPNsenseClient(config)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok", "data": "test"}
        mock_response.content = b'{"status": "ok"}'

        client.client.get = AsyncMock(return_value=mock_response)

        result = await client.request("GET", "/core/system/status")

        assert result == {"status": "ok", "data": "test"}
        client.client.get.assert_called_once()

    async def test_request_post_success(self):
        """Test successful POST request."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )
        client = OPNsenseClient(config)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": "saved"}
        mock_response.content = b'{"result": "saved"}'

        client.client.post = AsyncMock(return_value=mock_response)

        data = {"enabled": "1", "description": "Test rule"}
        result = await client.request("POST", "/firewall/filter/addRule", data=data)

        assert result == {"result": "saved"}
        client.client.post.assert_called_once()

    async def test_request_put_success(self):
        """Test successful PUT request."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )
        client = OPNsenseClient(config)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": "updated"}
        mock_response.content = b'{"result": "updated"}'

        client.client.put = AsyncMock(return_value=mock_response)

        result = await client.request("PUT", "/resource/123", data={"key": "value"})

        assert result == {"result": "updated"}

    async def test_request_delete_success(self):
        """Test successful DELETE request."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )
        client = OPNsenseClient(config)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": "deleted"}
        mock_response.content = b'{"result": "deleted"}'

        client.client.delete = AsyncMock(return_value=mock_response)

        result = await client.request("DELETE", "/resource/123")

        assert result == {"result": "deleted"}

    async def test_request_patch_success(self):
        """Test successful PATCH request."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )
        client = OPNsenseClient(config)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": "patched"}
        mock_response.content = b'{"result": "patched"}'

        client.client.patch = AsyncMock(return_value=mock_response)

        result = await client.request("PATCH", "/resource/123", data={"field": "new_value"})

        assert result == {"result": "patched"}

    async def test_request_missing_method_raises_error(self):
        """Test that missing method raises ValidationError."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret"
        )
        client = OPNsenseClient(config)

        with pytest.raises(ValidationError) as exc_info:
            await client.request("", "/endpoint")

        assert "Method and endpoint are required" in str(exc_info.value)

    async def test_request_missing_endpoint_raises_error(self):
        """Test that missing endpoint raises ValidationError."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret"
        )
        client = OPNsenseClient(config)

        with pytest.raises(ValidationError) as exc_info:
            await client.request("GET", "")

        assert "Method and endpoint are required" in str(exc_info.value)

    async def test_request_unsupported_method_raises_error(self):
        """Test that unsupported HTTP method raises ValidationError."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret"
        )
        client = OPNsenseClient(config)

        with pytest.raises(ValidationError) as exc_info:
            await client.request("INVALID", "/endpoint")

        assert "Unsupported HTTP method" in str(exc_info.value)

    async def test_request_401_raises_authentication_error(self):
        """Test that 401 status code raises AuthenticationError."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )
        client = OPNsenseClient(config)

        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.content = b'{"error": "Unauthorized"}'

        client.client.get = AsyncMock(return_value=mock_response)

        with pytest.raises(AuthenticationError) as exc_info:
            await client.request("GET", "/endpoint")

        assert "Authentication failed" in str(exc_info.value)
        assert exc_info.value.context["status_code"] == 401

    async def test_request_403_raises_authorization_error(self):
        """Test that 403 status code raises AuthorizationError."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )
        client = OPNsenseClient(config)

        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.content = b'{"error": "Forbidden"}'

        client.client.get = AsyncMock(return_value=mock_response)

        with pytest.raises(AuthorizationError) as exc_info:
            await client.request("GET", "/endpoint")

        assert "Access denied" in str(exc_info.value)
        assert exc_info.value.context["status_code"] == 403

    async def test_request_404_raises_resource_not_found_error(self):
        """Test that 404 status code raises ResourceNotFoundError."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )
        client = OPNsenseClient(config)

        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.content = b'{"error": "Not found"}'

        client.client.get = AsyncMock(return_value=mock_response)

        with pytest.raises(ResourceNotFoundError) as exc_info:
            await client.request("GET", "/endpoint")

        assert "Resource not found" in str(exc_info.value)
        assert exc_info.value.context["status_code"] == 404

    async def test_request_429_raises_rate_limit_error(self):
        """Test that 429 status code raises RateLimitError."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )
        client = OPNsenseClient(config)

        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.content = b'{"error": "Too many requests"}'
        mock_response.headers = {"Retry-After": "60"}

        client.client.get = AsyncMock(return_value=mock_response)

        with pytest.raises(RateLimitError) as exc_info:
            await client.request("GET", "/endpoint")

        assert "rate limit exceeded" in str(exc_info.value)
        assert exc_info.value.context["status_code"] == 429
        assert exc_info.value.context["retry_after"] == "60"

    async def test_request_500_raises_api_error(self):
        """Test that 500 status code raises APIError."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )
        client = OPNsenseClient(config)

        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.content = b'{"error": "Internal server error"}'
        mock_response.text = '{"error": "Internal server error"}'
        mock_response.json.side_effect = Exception("Cannot parse JSON")

        client.client.get = AsyncMock(return_value=mock_response)

        with pytest.raises(APIError) as exc_info:
            await client.request("GET", "/endpoint")

        assert exc_info.value.status_code == 500

    async def test_request_invalid_json_response_raises_api_error(self):
        """Test that invalid JSON response raises APIError."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )
        client = OPNsenseClient(config)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'Not valid JSON'
        mock_response.text = 'Not valid JSON'
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)

        client.client.get = AsyncMock(return_value=mock_response)

        with pytest.raises(APIError) as exc_info:
            await client.request("GET", "/endpoint")

        assert "Invalid JSON response" in str(exc_info.value)

    async def test_request_timeout_raises_timeout_error(self):
        """Test that request timeout raises OPNsenseTimeoutError."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )
        client = OPNsenseClient(config)

        client.client.get = AsyncMock(side_effect=httpx.TimeoutException("Request timed out"))

        with pytest.raises(OPNsenseTimeoutError) as exc_info:
            await client.request("GET", "/endpoint", timeout=5.0)

        assert "timed out" in str(exc_info.value)
        assert exc_info.value.context["timeout"] == 5.0

    async def test_request_connection_error_raises_network_error(self):
        """Test that connection error raises NetworkError."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )
        client = OPNsenseClient(config)

        client.client.get = AsyncMock(side_effect=httpx.ConnectError("Cannot connect"))

        with pytest.raises(NetworkError) as exc_info:
            await client.request("GET", "/endpoint")

        assert "Cannot connect" in str(exc_info.value)

    async def test_request_generic_request_error_raises_network_error(self):
        """Test that generic request error raises NetworkError."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )
        client = OPNsenseClient(config)

        client.client.get = AsyncMock(side_effect=httpx.RequestError("Network error"))

        with pytest.raises(NetworkError) as exc_info:
            await client.request("GET", "/endpoint")

        assert "Network error" in str(exc_info.value)

    async def test_request_with_params(self):
        """Test request with query parameters."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )
        client = OPNsenseClient(config)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok"}
        mock_response.content = b'{"status": "ok"}'

        client.client.get = AsyncMock(return_value=mock_response)

        params = {"filter": "active", "limit": "10"}
        result = await client.request("GET", "/endpoint", params=params)

        assert result == {"status": "ok"}
        call_kwargs = client.client.get.call_args[1]
        assert call_kwargs["params"] == params

    async def test_request_with_rate_limiting(self):
        """Test request with rate limiting from connection pool."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )

        mock_pool = Mock()
        mock_pool.check_rate_limit = AsyncMock()

        client = OPNsenseClient(config, pool=mock_pool)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok"}
        mock_response.content = b'{"status": "ok"}'

        client.client.get = AsyncMock(return_value=mock_response)

        await client.request("GET", "/endpoint")

        # Verify rate limit was checked
        mock_pool.check_rate_limit.assert_called_once()

    async def test_request_with_retry_config(self):
        """Test request with retry configuration."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )
        client = OPNsenseClient(config)

        # First call fails, second succeeds
        mock_response_fail = Mock()
        mock_response_fail.status_code = 500
        mock_response_fail.content = b'{"error": "Server error"}'
        mock_response_fail.text = '{"error": "Server error"}'
        mock_response_fail.json.side_effect = Exception()

        mock_response_success = Mock()
        mock_response_success.status_code = 200
        mock_response_success.json.return_value = {"status": "ok"}
        mock_response_success.content = b'{"status": "ok"}'

        client.client.get = AsyncMock(side_effect=[
            httpx.TimeoutException("Timeout"),
            mock_response_success
        ])

        retry_config = RetryConfig(max_attempts=2, base_delay=0.01)
        result = await client.request("GET", "/endpoint", retry_config=retry_config)

        assert result == {"status": "ok"}
        assert client.client.get.call_count == 2

    async def test_request_headers_include_authorization(self):
        """Test that request includes authorization header."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )
        client = OPNsenseClient(config)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok"}
        mock_response.content = b'{"status": "ok"}'

        client.client.get = AsyncMock(return_value=mock_response)

        await client.request("GET", "/endpoint")

        call_kwargs = client.client.get.call_args[1]
        headers = call_kwargs["headers"]

        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Basic ")

    async def test_request_headers_include_user_agent(self):
        """Test that request includes custom user agent."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )
        client = OPNsenseClient(config)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok"}
        mock_response.content = b'{"status": "ok"}'

        client.client.get = AsyncMock(return_value=mock_response)

        await client.request("GET", "/endpoint")

        call_kwargs = client.client.get.call_args[1]
        headers = call_kwargs["headers"]

        assert "User-Agent" in headers
        assert "OPNsense-MCP-Server" in headers["User-Agent"]

    async def test_request_custom_timeout(self):
        """Test request with custom timeout."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )
        client = OPNsenseClient(config)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok"}
        mock_response.content = b'{"status": "ok"}'

        client.client.get = AsyncMock(return_value=mock_response)

        await client.request("GET", "/endpoint", timeout=60.0)

        call_kwargs = client.client.get.call_args[1]
        assert call_kwargs["timeout"] == 60.0

    async def test_request_url_construction(self):
        """Test that request URL is properly constructed."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False
        )
        client = OPNsenseClient(config)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok"}
        mock_response.content = b'{"status": "ok"}'

        client.client.get = AsyncMock(return_value=mock_response)

        await client.request("GET", "/core/system/status")

        # Check that URL was constructed correctly
        call_args = client.client.get.call_args[0]
        assert call_args[0] == "https://192.168.1.1/api/core/system/status"
