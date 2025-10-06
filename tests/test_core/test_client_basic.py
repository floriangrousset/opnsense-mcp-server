"""
Tests for OPNsense MCP Server client basic functionality.

This module tests the basic OPNsense client functionality including initialization,
request/response logging, and client lifecycle management.
"""

import json
import logging
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.opnsense_mcp.core.client import OPNsenseClient, RequestResponseLogger
from src.opnsense_mcp.core.models import OPNsenseConfig


class TestRequestResponseLogger:
    """Test RequestResponseLogger class."""

    def test_logger_creation(self):
        """Test creating a RequestResponseLogger."""
        mock_logger = Mock(spec=logging.Logger)
        req_logger = RequestResponseLogger(mock_logger)

        assert req_logger.logger == mock_logger

    def test_log_request_with_basic_info(self):
        """Test logging a basic API request."""
        mock_logger = Mock(spec=logging.Logger)
        req_logger = RequestResponseLogger(mock_logger)

        req_logger.log_request(
            method="GET", url="https://192.168.1.1/api/core/system", operation="get_system_status"
        )

        mock_logger.info.assert_called_once()
        log_message = mock_logger.info.call_args[0][0]

        assert "API Request" in log_message
        assert "GET" in log_message
        assert "get_system_status" in log_message

    def test_log_request_sanitizes_authorization_header(self):
        """Test that authorization headers are redacted in logs."""
        mock_logger = Mock(spec=logging.Logger)
        req_logger = RequestResponseLogger(mock_logger)

        headers = {"Authorization": "Basic dGVzdDp0ZXN0", "Content-Type": "application/json"}

        req_logger.log_request(
            method="POST",
            url="https://192.168.1.1/api/core/system",
            headers=headers,
            operation="test_operation",
        )

        log_message = mock_logger.info.call_args[0][0]
        log_data = json.loads(log_message.replace("API Request: ", ""))

        assert log_data["request"]["headers"]["Authorization"] == "[REDACTED]"
        assert log_data["request"]["headers"]["Content-Type"] == "application/json"

    def test_log_request_sanitizes_api_key_header(self):
        """Test that API key headers are redacted in logs."""
        mock_logger = Mock(spec=logging.Logger)
        req_logger = RequestResponseLogger(mock_logger)

        headers = {"X-Api-Key": "secret_api_key_12345", "Accept": "application/json"}

        req_logger.log_request(method="GET", url="https://192.168.1.1/api/test", headers=headers)

        log_message = mock_logger.info.call_args[0][0]
        log_data = json.loads(log_message.replace("API Request: ", ""))

        assert log_data["request"]["headers"]["X-Api-Key"] == "[REDACTED]"
        assert log_data["request"]["headers"]["Accept"] == "application/json"

    def test_log_request_with_data(self):
        """Test logging request with data payload."""
        mock_logger = Mock(spec=logging.Logger)
        req_logger = RequestResponseLogger(mock_logger)

        data = {"key": "value", "number": 123}

        req_logger.log_request(method="POST", url="https://192.168.1.1/api/test", data=data)

        log_message = mock_logger.info.call_args[0][0]
        log_data = json.loads(log_message.replace("API Request: ", ""))

        assert log_data["request"]["has_data"] is True

    def test_log_request_without_data(self):
        """Test logging request without data payload."""
        mock_logger = Mock(spec=logging.Logger)
        req_logger = RequestResponseLogger(mock_logger)

        req_logger.log_request(method="GET", url="https://192.168.1.1/api/test")

        log_message = mock_logger.info.call_args[0][0]
        log_data = json.loads(log_message.replace("API Request: ", ""))

        assert log_data["request"]["has_data"] is False

    def test_log_response_success(self):
        """Test logging successful API response."""
        mock_logger = Mock(spec=logging.Logger)
        req_logger = RequestResponseLogger(mock_logger)

        req_logger.log_response(
            status_code=200, response_size=1024, duration_ms=250.5, operation="test_operation"
        )

        mock_logger.log.assert_called_once()
        level, message = mock_logger.log.call_args[0]

        assert level == logging.INFO
        assert "API Response" in message

        log_data = json.loads(message.replace("API Response: ", ""))
        assert log_data["response"]["status_code"] == 200
        assert log_data["response"]["response_size"] == 1024
        assert log_data["response"]["duration_ms"] == 250.5
        assert log_data["response"]["success"] is True
        assert log_data["response"]["has_error"] is False

    def test_log_response_error(self):
        """Test logging error API response."""
        mock_logger = Mock(spec=logging.Logger)
        req_logger = RequestResponseLogger(mock_logger)

        error = Exception("Test error")

        req_logger.log_response(
            status_code=500,
            response_size=512,
            duration_ms=100.0,
            operation="test_operation",
            error=error,
        )

        mock_logger.log.assert_called_once()
        level, message = mock_logger.log.call_args[0]

        assert level == logging.WARNING
        assert "API Response" in message

        log_data = json.loads(message.replace("API Response: ", ""))
        assert log_data["response"]["status_code"] == 500
        assert log_data["response"]["success"] is False
        assert log_data["response"]["has_error"] is True
        assert log_data["error"] == "Test error"

    def test_log_response_with_none_values(self):
        """Test logging response with None values."""
        mock_logger = Mock(spec=logging.Logger)
        req_logger = RequestResponseLogger(mock_logger)

        req_logger.log_response(
            status_code=204, response_size=None, duration_ms=None, operation="test_operation"
        )

        mock_logger.log.assert_called_once()
        message = mock_logger.log.call_args[0][1]
        log_data = json.loads(message.replace("API Response: ", ""))

        assert log_data["response"]["response_size"] is None
        assert log_data["response"]["duration_ms"] is None


class TestOPNsenseClientBasic:
    """Test basic OPNsense client functionality."""

    def test_client_initialization(self):
        """Test initializing OPNsense client."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False,
        )

        with patch("src.opnsense_mcp.core.client.logger") as mock_logger:
            client = OPNsenseClient(config)

            assert client.base_url == "https://192.168.1.1"
            assert client.api_key == "test_key"
            assert client.api_secret == "test_secret"
            assert client.verify_ssl is False
            assert client.pool is None
            assert client.client is not None

            # Verify initialization was logged
            mock_logger.info.assert_called()

    def test_client_initialization_with_trailing_slash(self):
        """Test that trailing slash is removed from base URL."""
        config = OPNsenseConfig(
            url="https://192.168.1.1/", api_key="test_key", api_secret="test_secret"
        )

        client = OPNsenseClient(config)

        assert client.base_url == "https://192.168.1.1"
        assert not client.base_url.endswith("/")

    def test_client_initialization_with_pool(self):
        """Test initializing client with connection pool."""
        config = OPNsenseConfig(
            url="https://192.168.1.1", api_key="test_key", api_secret="test_secret"
        )
        mock_pool = Mock()

        client = OPNsenseClient(config, pool=mock_pool)

        assert client.pool == mock_pool

    def test_client_auth_header_generation(self):
        """Test that authentication header is properly generated."""
        config = OPNsenseConfig(
            url="https://192.168.1.1", api_key="test_key", api_secret="test_secret"
        )

        client = OPNsenseClient(config)

        assert client.auth_header is not None
        assert isinstance(client.auth_header, str)

        # Verify it's base64 encoded
        import base64

        decoded = base64.b64decode(client.auth_header).decode()
        assert decoded == "test_key:test_secret"

    def test_client_httpx_configuration(self):
        """Test that httpx client is properly configured."""
        config = OPNsenseConfig(
            url="https://192.168.1.1", api_key="test_key", api_secret="test_secret", verify_ssl=True
        )

        client = OPNsenseClient(config)

        # Verify httpx client settings
        assert client.client is not None
        # Check that verify SSL matches config
        # Note: httpx.AsyncClient doesn't expose verify directly, but we can check it was set

    async def test_client_close(self):
        """Test closing the client."""
        config = OPNsenseConfig(
            url="https://192.168.1.1", api_key="test_key", api_secret="test_secret"
        )

        client = OPNsenseClient(config)

        # Mock the aclose method
        client.client.aclose = AsyncMock()

        await client.close()

        client.client.aclose.assert_called_once()

    def test_client_with_different_ssl_settings(self):
        """Test client with SSL verification enabled."""
        config = OPNsenseConfig(
            url="https://192.168.1.1", api_key="test_key", api_secret="test_secret", verify_ssl=True
        )

        client = OPNsenseClient(config)

        assert client.verify_ssl is True

    def test_client_with_http_url(self):
        """Test client with HTTP (non-SSL) URL."""
        config = OPNsenseConfig(
            url="http://192.168.1.1", api_key="test_key", api_secret="test_secret"
        )

        client = OPNsenseClient(config)

        assert client.base_url == "http://192.168.1.1"

    def test_client_with_port_number(self):
        """Test client with custom port number in URL."""
        config = OPNsenseConfig(
            url="https://192.168.1.1:8443", api_key="test_key", api_secret="test_secret"
        )

        client = OPNsenseClient(config)

        assert client.base_url == "https://192.168.1.1:8443"

    def test_client_with_domain_name(self):
        """Test client with domain name instead of IP."""
        config = OPNsenseConfig(
            url="https://opnsense.example.com", api_key="test_key", api_secret="test_secret"
        )

        client = OPNsenseClient(config)

        assert client.base_url == "https://opnsense.example.com"

    def test_multiple_clients_with_different_configs(self):
        """Test creating multiple clients with different configurations."""
        config1 = OPNsenseConfig(url="https://192.168.1.1", api_key="key1", api_secret="secret1")
        config2 = OPNsenseConfig(url="https://192.168.1.2", api_key="key2", api_secret="secret2")

        client1 = OPNsenseClient(config1)
        client2 = OPNsenseClient(config2)

        assert client1.base_url != client2.base_url
        assert client1.api_key != client2.api_key
        assert client1.auth_header != client2.auth_header

    async def test_client_lifecycle(self):
        """Test complete client lifecycle (create, use, close)."""
        config = OPNsenseConfig(
            url="https://192.168.1.1", api_key="test_key", api_secret="test_secret"
        )

        client = OPNsenseClient(config)
        assert client.client is not None

        # Mock close
        client.client.aclose = AsyncMock()

        await client.close()
        client.client.aclose.assert_called_once()
