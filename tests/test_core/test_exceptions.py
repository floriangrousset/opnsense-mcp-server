"""
Tests for OPNsense MCP Server exception classes.

This module tests the custom exception hierarchy including error context,
error codes, and structured exception serialization.
"""

from datetime import datetime

import pytest

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


class TestOPNsenseError:
    """Test the base OPNsenseError exception class."""

    def test_basic_exception_creation(self):
        """Test creating a basic exception with just a message."""
        error = OPNsenseError("Test error message")
        assert str(error) == "Test error message"
        assert error.message == "Test error message"
        assert error.error_code == "OPNsenseError"
        assert error.context == {}
        assert isinstance(error.timestamp, datetime)

    def test_exception_with_error_code(self):
        """Test creating an exception with a custom error code."""
        error = OPNsenseError("Test error", error_code="CUSTOM_ERROR")
        assert error.error_code == "CUSTOM_ERROR"
        assert error.message == "Test error"

    def test_exception_with_context(self):
        """Test creating an exception with context data."""
        context = {"api_endpoint": "/api/core/system", "status_code": 500}
        error = OPNsenseError("API failed", context=context)
        assert error.context == context
        assert error.context["api_endpoint"] == "/api/core/system"
        assert error.context["status_code"] == 500

    def test_exception_with_all_parameters(self):
        """Test creating an exception with all parameters."""
        context = {"user": "admin", "action": "delete"}
        error = OPNsenseError("Operation failed", error_code="DELETE_FAILED", context=context)
        assert error.message == "Operation failed"
        assert error.error_code == "DELETE_FAILED"
        assert error.context == context

    def test_backward_compatibility_details(self):
        """Test that 'details' attribute is maintained for backward compatibility."""
        context = {"key": "value"}
        error = OPNsenseError("Test", context=context)
        assert error.details == context
        assert error.details == error.context

    def test_to_dict_method(self):
        """Test converting exception to dictionary for structured logging."""
        context = {"endpoint": "/api/test", "method": "POST"}
        error = OPNsenseError("Test error", error_code="TEST_ERR", context=context)

        error_dict = error.to_dict()

        assert error_dict["error_type"] == "OPNsenseError"
        assert error_dict["error_code"] == "TEST_ERR"
        assert error_dict["message"] == "Test error"
        assert error_dict["context"] == context
        assert "timestamp" in error_dict
        assert isinstance(error_dict["timestamp"], str)

    def test_exception_is_raiseable(self):
        """Test that exception can be raised and caught."""
        with pytest.raises(OPNsenseError) as exc_info:
            raise OPNsenseError("Test exception")

        assert str(exc_info.value) == "Test exception"
        assert isinstance(exc_info.value, OPNsenseError)


class TestConfigurationError:
    """Test ConfigurationError exception."""

    def test_configuration_error_creation(self):
        """Test creating a ConfigurationError."""
        error = ConfigurationError("Client not configured")
        assert isinstance(error, OPNsenseError)
        assert str(error) == "Client not configured"
        assert error.error_code == "ConfigurationError"

    def test_configuration_error_with_context(self):
        """Test ConfigurationError with context."""
        context = {"missing_field": "api_key"}
        error = ConfigurationError("Missing API key", context=context)
        assert error.context["missing_field"] == "api_key"


class TestAuthenticationError:
    """Test AuthenticationError exception."""

    def test_authentication_error_creation(self):
        """Test creating an AuthenticationError."""
        error = AuthenticationError("Invalid credentials")
        assert isinstance(error, OPNsenseError)
        assert str(error) == "Invalid credentials"
        assert error.error_code == "AuthenticationError"

    def test_authentication_error_with_context(self):
        """Test AuthenticationError with context."""
        context = {"username": "admin", "attempts": 3}
        error = AuthenticationError("Auth failed", context=context)
        assert error.context["username"] == "admin"
        assert error.context["attempts"] == 3


class TestAPIError:
    """Test APIError exception with HTTP status codes."""

    def test_api_error_basic(self):
        """Test creating a basic APIError."""
        error = APIError("API request failed")
        assert isinstance(error, OPNsenseError)
        assert str(error) == "API request failed"
        assert error.status_code is None
        assert error.response_text is None

    def test_api_error_with_status_code(self):
        """Test APIError with HTTP status code."""
        error = APIError("Server error", status_code=500)
        assert error.status_code == 500
        assert error.message == "Server error"

    def test_api_error_with_response_text(self):
        """Test APIError with response text."""
        response = '{"error": "Internal server error"}'
        error = APIError("API failed", response_text=response)
        assert error.response_text == response

    def test_api_error_with_all_parameters(self):
        """Test APIError with all parameters."""
        response = '{"error": "Not found"}'
        error = APIError("Resource not found", status_code=404, response_text=response)
        assert error.message == "Resource not found"
        assert error.status_code == 404
        assert error.response_text == response


class TestNetworkError:
    """Test NetworkError exception."""

    def test_network_error_creation(self):
        """Test creating a NetworkError."""
        error = NetworkError("Connection refused")
        assert isinstance(error, OPNsenseError)
        assert str(error) == "Connection refused"

    def test_network_error_with_context(self):
        """Test NetworkError with connection context."""
        context = {"host": "192.168.1.1", "port": 443}
        error = NetworkError("Cannot connect", context=context)
        assert error.context["host"] == "192.168.1.1"
        assert error.context["port"] == 443


class TestRateLimitError:
    """Test RateLimitError exception."""

    def test_rate_limit_error_creation(self):
        """Test creating a RateLimitError."""
        error = RateLimitError("Rate limit exceeded")
        assert isinstance(error, OPNsenseError)
        assert str(error) == "Rate limit exceeded"

    def test_rate_limit_error_with_context(self):
        """Test RateLimitError with rate limit details."""
        context = {"limit": 100, "window": "1m", "retry_after": 60}
        error = RateLimitError("Too many requests", context=context)
        assert error.context["limit"] == 100
        assert error.context["retry_after"] == 60


class TestValidationError:
    """Test ValidationError exception."""

    def test_validation_error_creation(self):
        """Test creating a ValidationError."""
        error = ValidationError("Invalid parameter")
        assert isinstance(error, OPNsenseError)
        assert str(error) == "Invalid parameter"

    def test_validation_error_with_field_details(self):
        """Test ValidationError with field validation details."""
        context = {
            "field": "email",
            "value": "invalid-email",
            "constraint": "must be valid email format",
        }
        error = ValidationError("Validation failed", context=context)
        assert error.context["field"] == "email"
        assert error.context["constraint"] == "must be valid email format"


class TestTimeoutError:
    """Test TimeoutError exception."""

    def test_timeout_error_creation(self):
        """Test creating a TimeoutError."""
        error = TimeoutError("Request timed out")
        assert isinstance(error, OPNsenseError)
        assert str(error) == "Request timed out"

    def test_timeout_error_with_duration(self):
        """Test TimeoutError with timeout duration."""
        context = {"timeout_seconds": 30, "operation": "backup_config"}
        error = TimeoutError("Operation timed out", context=context)
        assert error.context["timeout_seconds"] == 30
        assert error.context["operation"] == "backup_config"


class TestResourceNotFoundError:
    """Test ResourceNotFoundError exception."""

    def test_resource_not_found_error_creation(self):
        """Test creating a ResourceNotFoundError."""
        error = ResourceNotFoundError("Firewall rule not found")
        assert isinstance(error, OPNsenseError)
        assert str(error) == "Firewall rule not found"

    def test_resource_not_found_with_identifier(self):
        """Test ResourceNotFoundError with resource identifier."""
        context = {"resource_type": "firewall_rule", "uuid": "rule-uuid-123"}
        error = ResourceNotFoundError("Rule not found", context=context)
        assert error.context["resource_type"] == "firewall_rule"
        assert error.context["uuid"] == "rule-uuid-123"


class TestAuthorizationError:
    """Test AuthorizationError exception."""

    def test_authorization_error_creation(self):
        """Test creating an AuthorizationError."""
        error = AuthorizationError("Permission denied")
        assert isinstance(error, OPNsenseError)
        assert str(error) == "Permission denied"

    def test_authorization_error_with_permission_details(self):
        """Test AuthorizationError with permission context."""
        context = {
            "user": "readonly",
            "required_privilege": "page-firewall-rules-edit",
            "operation": "modify_rule",
        }
        error = AuthorizationError("Insufficient privileges", context=context)
        assert error.context["user"] == "readonly"
        assert error.context["required_privilege"] == "page-firewall-rules-edit"


class TestExceptionInheritance:
    """Test exception inheritance hierarchy."""

    def test_all_exceptions_inherit_from_opnsense_error(self):
        """Test that all custom exceptions inherit from OPNsenseError."""
        exceptions = [
            ConfigurationError,
            AuthenticationError,
            APIError,
            NetworkError,
            RateLimitError,
            ValidationError,
            TimeoutError,
            ResourceNotFoundError,
            AuthorizationError,
        ]

        for exc_class in exceptions:
            error = exc_class("Test")
            assert isinstance(error, OPNsenseError)
            assert isinstance(error, Exception)

    def test_exception_can_be_caught_as_base_exception(self):
        """Test that specific exceptions can be caught as OPNsenseError."""
        with pytest.raises(OPNsenseError):
            raise ConfigurationError("Config error")

        with pytest.raises(OPNsenseError):
            raise AuthenticationError("Auth error")

        with pytest.raises(OPNsenseError):
            raise APIError("API error")
