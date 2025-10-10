"""
Tests for OPNsense MCP Server error sanitization module.

This module tests error message sanitization for preventing information
disclosure while maintaining helpful user feedback.
"""

import json
import logging
from unittest.mock import Mock

import httpx

from src.opnsense_mcp.core.exceptions import (
    APIError,
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    NetworkError,
    OPNsenseError,
    RateLimitError,
    ResourceNotFoundError,
    TimeoutError,
    ValidationError,
)
from src.opnsense_mcp.shared.error_sanitizer import (
    ErrorMessageSanitizer,
    log_error_safely,
)


class TestErrorMessageSanitizer:
    """Test ErrorMessageSanitizer class."""

    def test_sanitize_for_user_authentication_error(self):
        """Test sanitization of AuthenticationError."""
        error = AuthenticationError("Invalid API credentials")
        message = ErrorMessageSanitizer.sanitize_for_user(error)

        assert "Authentication failed" in message
        assert "check your OPNsense credentials" in message
        assert "Invalid API credentials" not in message

    def test_sanitize_for_user_authorization_error(self):
        """Test sanitization of AuthorizationError."""
        error = AuthorizationError("User lacks permission")
        message = ErrorMessageSanitizer.sanitize_for_user(error)

        assert "Authorization failed" in message
        assert "lack necessary permissions" in message
        assert "User lacks permission" not in message

    def test_sanitize_for_user_configuration_error(self):
        """Test sanitization of ConfigurationError."""
        error = ConfigurationError("Missing API key")
        message = ErrorMessageSanitizer.sanitize_for_user(error)

        assert "Configuration error" in message
        assert "Missing API key" in message

    def test_sanitize_for_user_validation_error(self):
        """Test sanitization of ValidationError."""
        error = ValidationError("Port must be between 1-65535")
        message = ErrorMessageSanitizer.sanitize_for_user(error)

        assert "Invalid input" in message
        assert "Port must be between 1-65535" in message

    def test_sanitize_for_user_resource_not_found_error(self):
        """Test sanitization of ResourceNotFoundError."""
        error = ResourceNotFoundError("Firewall rule not found")
        message = ErrorMessageSanitizer.sanitize_for_user(error)

        assert "Resource not found" in message
        assert "Firewall rule not found" in message

    def test_sanitize_for_user_rate_limit_error(self):
        """Test sanitization of RateLimitError."""
        error = RateLimitError("Too many requests")
        message = ErrorMessageSanitizer.sanitize_for_user(error)

        assert "Rate limit exceeded" in message
        assert "wait before retrying" in message
        assert "Too many requests" not in message

    def test_sanitize_for_user_timeout_error(self):
        """Test sanitization of TimeoutError."""
        error = TimeoutError("Request timed out after 30s")
        message = ErrorMessageSanitizer.sanitize_for_user(error)

        assert "Request timed out" in message
        assert "overloaded or unreachable" in message

    def test_sanitize_for_user_network_error(self):
        """Test sanitization of NetworkError."""
        error = NetworkError("Connection refused")
        message = ErrorMessageSanitizer.sanitize_for_user(error)

        assert "Network error" in message
        assert "Cannot connect" in message
        assert "Check URL and network connectivity" in message

    def test_sanitize_for_user_httpx_connect_error(self):
        """Test sanitization of httpx.ConnectError."""
        error = httpx.ConnectError("Connection failed")
        message = ErrorMessageSanitizer.sanitize_for_user(error)

        assert "Cannot connect to OPNsense" in message
        assert "check the URL and network" in message

    def test_sanitize_for_user_httpx_timeout(self):
        """Test sanitization of httpx.TimeoutException."""
        error = httpx.TimeoutException("Request timeout")
        message = ErrorMessageSanitizer.sanitize_for_user(error)

        assert "Request timed out" in message
        assert "overloaded" in message

    def test_sanitize_for_user_json_decode_error(self):
        """Test sanitization of JSONDecodeError."""
        error = json.JSONDecodeError("Expecting value", "", 0)
        message = ErrorMessageSanitizer.sanitize_for_user(error)

        assert "invalid response" in message
        assert "OPNsense API" in message

    def test_sanitize_for_user_api_error(self):
        """Test sanitization of APIError."""
        error = APIError("API error with password=secret123")
        message = ErrorMessageSanitizer.sanitize_for_user(error)

        assert "OPNsense API error" in message
        assert "password=[REDACTED]" in message
        assert "secret123" not in message

    def test_sanitize_for_user_generic_error(self):
        """Test sanitization of generic exceptions."""
        error = Exception("Unexpected error")
        message = ErrorMessageSanitizer.sanitize_for_user(error, operation="backup")

        assert "error occurred during backup" in message
        assert "check the logs" in message

    def test_sanitize_text_removes_password(self):
        """Test _sanitize_text removes password values."""
        text = "Error: password=secret123 in request"
        sanitized = ErrorMessageSanitizer._sanitize_text(text)

        assert "password=[REDACTED]" in sanitized
        assert "secret123" not in sanitized

    def test_sanitize_text_removes_api_key(self):
        """Test _sanitize_text removes API key values."""
        text = "Failed with api_key=ABC123DEF456"
        sanitized = ErrorMessageSanitizer._sanitize_text(text)

        assert "api_key=[REDACTED]" in sanitized
        assert "ABC123DEF456" not in sanitized

    def test_sanitize_text_removes_token(self):
        """Test _sanitize_text removes token values."""
        text = "Auth failed: token:bearer_token_value"
        sanitized = ErrorMessageSanitizer._sanitize_text(text)

        assert "token=[REDACTED]" in sanitized
        assert "bearer_token_value" not in sanitized

    def test_sanitize_text_case_insensitive(self):
        """Test _sanitize_text is case-insensitive."""
        text = "ERROR: PASSWORD=Secret123 TOKEN=ABC"
        sanitized = ErrorMessageSanitizer._sanitize_text(text)

        # Regex replaces pattern names (becomes lowercase) with [REDACTED]
        assert "password=[REDACTED]" in sanitized
        assert "token=[REDACTED]" in sanitized
        assert "Secret123" not in sanitized
        assert "ABC" not in sanitized

    def test_sanitize_text_multiple_patterns(self):
        """Test _sanitize_text removes multiple sensitive patterns."""
        text = "password=pass123 api_secret=secret456 token=tok789"
        sanitized = ErrorMessageSanitizer._sanitize_text(text)

        assert "password=[REDACTED]" in sanitized
        assert "api_secret=[REDACTED]" in sanitized
        assert "token=[REDACTED]" in sanitized
        assert "pass123" not in sanitized
        assert "secret456" not in sanitized
        assert "tok789" not in sanitized

    def test_sanitize_context_empty_dict(self):
        """Test _sanitize_context handles empty dictionary."""
        context = {}
        sanitized = ErrorMessageSanitizer._sanitize_context(context)

        assert sanitized == {}

    def test_sanitize_context_none(self):
        """Test _sanitize_context handles None."""
        sanitized = ErrorMessageSanitizer._sanitize_context(None)

        assert sanitized == {}

    def test_sanitize_context_redacts_sensitive_keys(self):
        """Test _sanitize_context redacts sensitive keys."""
        context = {
            "url": "https://192.168.1.1",
            "api_key": "secret_key_123",
            "password": "super_secret",
            "username": "admin",
        }
        sanitized = ErrorMessageSanitizer._sanitize_context(context)

        assert sanitized["url"] == "https://192.168.1.1"
        assert sanitized["username"] == "admin"
        assert sanitized["api_key"] == "[REDACTED]"
        assert sanitized["password"] == "[REDACTED]"

    def test_sanitize_context_nested_dict(self):
        """Test _sanitize_context handles nested dictionaries."""
        context = {
            "config": {
                "url": "https://192.168.1.1",
                "settings": {
                    "timeout": 30,
                    "verify_ssl": True,
                },
            }
        }
        sanitized = ErrorMessageSanitizer._sanitize_context(context)

        assert sanitized["config"]["url"] == "https://192.168.1.1"
        assert sanitized["config"]["settings"]["timeout"] == 30
        assert sanitized["config"]["settings"]["verify_ssl"] is True

    def test_sanitize_context_sanitizes_string_values(self):
        """Test _sanitize_context sanitizes sensitive patterns in string values."""
        context = {
            "error_message": "Authentication failed with password=secret123",
            "status": "failed",
        }
        sanitized = ErrorMessageSanitizer._sanitize_context(context)

        assert "password=[REDACTED]" in sanitized["error_message"]
        assert "secret123" not in sanitized["error_message"]
        assert sanitized["status"] == "failed"

    def test_sanitize_context_preserves_non_sensitive_data(self):
        """Test _sanitize_context preserves non-sensitive data."""
        context = {
            "request_id": "req-123",
            "endpoint": "/api/firewall/rules",
            "method": "POST",
            "status_code": 500,
            "duration_ms": 123.45,
            "success": False,
        }
        sanitized = ErrorMessageSanitizer._sanitize_context(context)

        assert sanitized == context

    def test_sanitize_for_logs_opnsense_error(self):
        """Test sanitize_for_logs with OPNsenseError."""
        context = {
            "api_key": "secret123",
            "url": "https://192.168.1.1",
        }
        error = OPNsenseError("Test error", error_code="TEST_ERROR", context=context)

        log_info = ErrorMessageSanitizer.sanitize_for_logs(error)

        assert log_info["error_type"] == "OPNsenseError"
        assert log_info["error_code"] == "TEST_ERROR"
        assert log_info["context"]["api_key"] == "[REDACTED]"
        assert log_info["context"]["url"] == "https://192.168.1.1"

    def test_sanitize_for_logs_httpx_error_with_response(self):
        """Test sanitize_for_logs with httpx error containing response."""
        # Create mock response
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.reason_phrase = "Unauthorized"

        # Create httpx error with response
        error = httpx.HTTPStatusError(
            "Unauthorized",
            request=Mock(),
            response=mock_response,
        )
        error.response = mock_response

        log_info = ErrorMessageSanitizer.sanitize_for_logs(error)

        assert log_info["error_type"] == "HTTPStatusError"
        assert log_info["status_code"] == 401
        assert log_info["reason"] == "Unauthorized"

    def test_sanitize_for_logs_generic_exception(self):
        """Test sanitize_for_logs with generic exception."""
        error = ValueError("Invalid value")

        log_info = ErrorMessageSanitizer.sanitize_for_logs(error)

        assert log_info["error_type"] == "ValueError"
        assert log_info["error_module"] == "builtins"
        assert log_info["error_message"] == "Invalid value"


class TestLogErrorSafely:
    """Test log_error_safely convenience function."""

    def test_log_error_safely_logs_details(self):
        """Test that log_error_safely logs full error details."""
        mock_logger = Mock(spec=logging.Logger)
        error = ConfigurationError("Test error")

        message = log_error_safely(mock_logger, error, operation="test_op")

        # Verify logging was called
        mock_logger.error.assert_called_once()
        call_args = mock_logger.error.call_args

        # Check that error details were logged
        assert "Error in test_op" in call_args[0][0]
        assert call_args[1]["exc_info"] is True

        # Verify sanitized message returned
        assert "Configuration error" in message
        assert "Test error" in message

    def test_log_error_safely_with_custom_user_message(self):
        """Test log_error_safely with custom user message."""
        mock_logger = Mock(spec=logging.Logger)
        error = Exception("Internal error")
        custom_message = "Something went wrong. Please contact support."

        message = log_error_safely(
            mock_logger, error, operation="test_op", user_message=custom_message
        )

        # Verify custom message is returned
        assert message == custom_message

        # Verify error was still logged
        mock_logger.error.assert_called_once()

    def test_log_error_safely_sanitizes_sensitive_data(self):
        """Test log_error_safely sanitizes sensitive data in logs."""
        mock_logger = Mock(spec=logging.Logger)
        context = {"api_key": "secret123", "password": "pass456"}
        error = OPNsenseError("Test error", context=context)

        log_error_safely(mock_logger, error, operation="test_op")

        # Verify logging was called
        mock_logger.error.assert_called_once()
        call_args = mock_logger.error.call_args[0][0]

        # Check that sensitive data was redacted in logs
        assert "secret123" not in call_args
        assert "pass456" not in call_args
        assert "[REDACTED]" in call_args
