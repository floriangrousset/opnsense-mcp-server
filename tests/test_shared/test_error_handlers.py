"""
Tests for OPNsense MCP Server error handling utilities.

This module tests the error handling helpers including error severity,
error response formatting, and validation utilities.
"""

import pytest
from unittest.mock import AsyncMock, Mock
from datetime import datetime

from src.opnsense_mcp.shared.error_handlers import (
    ErrorSeverity,
    ErrorResponse,
    handle_tool_error,
    validate_uuid,
    validate_firewall_parameters
)
from src.opnsense_mcp.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    NetworkError,
    ConfigurationError,
    ValidationError,
    APIError,
    TimeoutError,
    ResourceNotFoundError,
    RateLimitError
)


class TestErrorSeverity:
    """Test ErrorSeverity enumeration."""

    def test_severity_levels_defined(self):
        """Test that all severity levels are defined."""
        assert hasattr(ErrorSeverity, 'LOW')
        assert hasattr(ErrorSeverity, 'MEDIUM')
        assert hasattr(ErrorSeverity, 'HIGH')
        assert hasattr(ErrorSeverity, 'CRITICAL')

    def test_severity_values(self):
        """Test that severity levels have correct string values."""
        assert ErrorSeverity.LOW == "low"
        assert ErrorSeverity.MEDIUM == "medium"
        assert ErrorSeverity.HIGH == "high"
        assert ErrorSeverity.CRITICAL == "critical"

    def test_severity_is_enum(self):
        """Test that ErrorSeverity is an enum."""
        assert isinstance(ErrorSeverity.LOW, ErrorSeverity)
        assert isinstance(ErrorSeverity.MEDIUM, ErrorSeverity)


class TestErrorResponse:
    """Test ErrorResponse class."""

    def test_error_response_creation(self):
        """Test creating an ErrorResponse."""
        error = ValidationError("Invalid input")
        response = ErrorResponse(error, "test_operation")

        assert response.error == error
        assert response.operation == "test_operation"
        assert response.severity == ErrorSeverity.MEDIUM  # default
        assert isinstance(response.timestamp, datetime)
        assert response.error_id.startswith("test_operation_")

    def test_error_response_with_custom_severity(self):
        """Test ErrorResponse with custom severity level."""
        error = AuthenticationError("Auth failed")
        response = ErrorResponse(error, "login", ErrorSeverity.CRITICAL)

        assert response.severity == ErrorSeverity.CRITICAL

    def test_authentication_error_message(self):
        """Test user message for AuthenticationError."""
        error = AuthenticationError("Invalid credentials")
        response = ErrorResponse(error, "test_op")

        message = response.get_user_message()

        assert "Authentication failed" in message
        assert "API credentials" in message

    def test_authorization_error_message(self):
        """Test user message for AuthorizationError."""
        error = AuthorizationError("Access denied")
        response = ErrorResponse(error, "test_op")

        message = response.get_user_message()

        assert "Access denied" in message
        assert "permission" in message

    def test_network_error_message(self):
        """Test user message for NetworkError."""
        error = NetworkError("Connection failed")
        response = ErrorResponse(error, "test_op")

        message = response.get_user_message()

        assert "Cannot connect" in message
        assert "OPNsense" in message

    def test_configuration_error_message(self):
        """Test user message for ConfigurationError."""
        error = ConfigurationError("Not configured")
        response = ErrorResponse(error, "test_op")

        message = response.get_user_message()

        assert "not configured" in message
        assert "configure the connection" in message

    def test_validation_error_message(self):
        """Test user message for ValidationError."""
        error = ValidationError("Invalid parameter")
        response = ErrorResponse(error, "test_op")

        message = response.get_user_message()

        assert "Invalid input" in message
        assert "Invalid parameter" in message

    def test_api_error_404_message(self):
        """Test user message for APIError with 404 status."""
        error = APIError("Not found", status_code=404)
        response = ErrorResponse(error, "test_op")

        message = response.get_user_message()

        assert "not found" in message.lower()

    def test_api_error_429_message(self):
        """Test user message for APIError with 429 status."""
        error = APIError("Rate limit", status_code=429)
        response = ErrorResponse(error, "test_op")

        message = response.get_user_message()

        assert "rate limit" in message.lower()

    def test_api_error_generic_message(self):
        """Test user message for generic APIError."""
        error = APIError("Server error", status_code=500)
        response = ErrorResponse(error, "test_op")

        message = response.get_user_message()

        assert "API error" in message

    def test_timeout_error_message(self):
        """Test user message for TimeoutError."""
        error = TimeoutError("Timeout")
        response = ErrorResponse(error, "test_op")

        message = response.get_user_message()

        assert "timed out" in message.lower()
        assert "overloaded" in message.lower()

    def test_resource_not_found_error_message(self):
        """Test user message for ResourceNotFoundError."""
        error = ResourceNotFoundError("Resource not found")
        response = ErrorResponse(error, "test_op")

        message = response.get_user_message()

        assert "Resource not found" in message

    def test_rate_limit_error_message(self):
        """Test user message for RateLimitError."""
        error = RateLimitError("Rate limit exceeded")
        response = ErrorResponse(error, "test_op")

        message = response.get_user_message()

        assert "Rate limit exceeded" in message
        assert "slow down" in message

    def test_generic_error_message(self):
        """Test user message for unknown error type."""
        error = Exception("Unknown error")
        response = ErrorResponse(error, "test_operation")

        message = response.get_user_message()

        assert "unexpected error" in message
        assert "test_operation" in message

    def test_get_technical_details(self):
        """Test getting technical error details."""
        error = ValidationError("Invalid input", context={"field": "email"})
        response = ErrorResponse(error, "validate_user", ErrorSeverity.HIGH)

        details = response.get_technical_details()

        assert "error_id" in details
        assert details["operation"] == "validate_user"
        assert details["severity"] == "high"
        assert "timestamp" in details
        assert details["error_type"] == "ValidationError"
        assert "Invalid input" in details["message"]

    def test_technical_details_includes_api_error_info(self):
        """Test that technical details include APIError-specific info."""
        error = APIError("Server error", status_code=500, response_text="Internal error")
        response = ErrorResponse(error, "test_op")

        details = response.get_technical_details()

        assert details["status_code"] == 500
        assert details["response_text"] == "Internal error"

    def test_technical_details_includes_opnsense_error_dict(self):
        """Test that technical details include OPNsenseError.to_dict()."""
        error = AuthenticationError("Auth failed", context={"attempts": 3})
        response = ErrorResponse(error, "login")

        details = response.get_technical_details()

        # Should include data from error.to_dict()
        assert "error_type" in details
        assert "context" in details or "attempts" in str(details)

    def test_error_id_format(self):
        """Test that error_id has expected format."""
        error = ValidationError("Test")
        response = ErrorResponse(error, "test_operation")

        assert response.error_id.startswith("test_operation_")
        # Should have a timestamp part
        parts = response.error_id.split("_")
        assert len(parts) >= 3  # operation name (may have underscores) + timestamp

    def test_timestamp_is_utc(self):
        """Test that timestamp is in UTC."""
        error = ValidationError("Test")
        response = ErrorResponse(error, "test_op")

        # Timestamp should be close to now (within a few seconds)
        now = datetime.utcnow()
        time_diff = abs((now - response.timestamp).total_seconds())
        assert time_diff < 5  # Should be created within 5 seconds


@pytest.mark.asyncio
class TestHandleToolError:
    """Test handle_tool_error async function."""

    async def test_handle_tool_error_logs_and_reports(self):
        """Test that handle_tool_error logs and reports errors."""
        mock_ctx = Mock()
        mock_ctx.error = AsyncMock()

        error = ValidationError("Invalid input")

        result = await handle_tool_error(mock_ctx, "test_operation", error)

        # Should call ctx.error
        mock_ctx.error.assert_called_once()
        # Should return error message
        assert result.startswith("Error:")
        assert "Invalid input" in result

    async def test_handle_tool_error_with_custom_severity(self):
        """Test handle_tool_error with custom severity."""
        mock_ctx = Mock()
        mock_ctx.error = AsyncMock()

        error = AuthenticationError("Auth failed")

        result = await handle_tool_error(mock_ctx, "login", error, ErrorSeverity.CRITICAL)

        assert result.startswith("Error:")
        mock_ctx.error.assert_called_once()

    async def test_handle_tool_error_returns_user_friendly_message(self):
        """Test that handle_tool_error returns user-friendly message."""
        mock_ctx = Mock()
        mock_ctx.error = AsyncMock()

        error = NetworkError("Connection refused")

        result = await handle_tool_error(mock_ctx, "connect", error)

        # Should be user-friendly, not technical
        assert "Cannot connect" in result
        assert "OPNsense" in result


class TestValidateUUID:
    """Test validate_uuid function."""

    def test_valid_uuid(self):
        """Test that valid UUID passes validation."""
        valid_uuid = "550e8400-e29b-41d4-a716-446655440000"

        # Should not raise any exception
        validate_uuid(valid_uuid, "test_operation")

    def test_valid_uuid_with_uppercase(self):
        """Test that valid UUID with uppercase letters passes."""
        valid_uuid = "550E8400-E29B-41D4-A716-446655440000"

        validate_uuid(valid_uuid, "test_operation")

    def test_valid_uuid_mixed_case(self):
        """Test that valid UUID with mixed case passes."""
        valid_uuid = "550e8400-E29b-41D4-a716-446655440000"

        validate_uuid(valid_uuid, "test_operation")

    def test_invalid_uuid_format_raises_error(self):
        """Test that invalid UUID format raises ValidationError."""
        invalid_uuid = "not-a-valid-uuid"

        with pytest.raises(ValidationError) as exc_info:
            validate_uuid(invalid_uuid, "test_operation")

        assert "Invalid UUID format" in str(exc_info.value)
        assert invalid_uuid in str(exc_info.value)

    def test_invalid_uuid_wrong_sections_raises_error(self):
        """Test that UUID with wrong number of sections raises error."""
        invalid_uuid = "550e8400-e29b-41d4-a716"  # Missing last section

        with pytest.raises(ValidationError) as exc_info:
            validate_uuid(invalid_uuid, "test_operation")

        assert "Invalid UUID format" in str(exc_info.value)

    def test_invalid_uuid_wrong_characters_raises_error(self):
        """Test that UUID with invalid characters raises error."""
        invalid_uuid = "550e8400-e29b-41d4-a716-44665544000g"  # 'g' is invalid

        with pytest.raises(ValidationError) as exc_info:
            validate_uuid(invalid_uuid, "test_operation")

        assert "Invalid UUID format" in str(exc_info.value)

    def test_empty_uuid_raises_error(self):
        """Test that empty string raises ValidationError."""
        with pytest.raises(ValidationError):
            validate_uuid("", "test_operation")

    def test_validation_error_includes_context(self):
        """Test that validation error includes helpful context."""
        invalid_uuid = "invalid"

        with pytest.raises(ValidationError) as exc_info:
            validate_uuid(invalid_uuid, "delete_rule")

        assert exc_info.value.context["uuid"] == "invalid"
        assert exc_info.value.context["operation"] == "delete_rule"
        assert "expected_format" in exc_info.value.context


class TestValidateFirewallParameters:
    """Test validate_firewall_parameters function."""

    def test_valid_firewall_parameters(self):
        """Test that valid firewall parameters pass validation."""
        # Should not raise any exception
        validate_firewall_parameters(
            action="pass",
            direction="in",
            ipprotocol="inet",
            protocol="tcp",
            operation="test_op"
        )

    def test_all_valid_actions(self):
        """Test all valid action values."""
        valid_actions = ["pass", "block", "reject"]

        for action in valid_actions:
            validate_firewall_parameters(
                action=action,
                direction="in",
                ipprotocol="inet",
                protocol="tcp",
                operation="test"
            )

    def test_all_valid_directions(self):
        """Test all valid direction values."""
        valid_directions = ["in", "out"]

        for direction in valid_directions:
            validate_firewall_parameters(
                action="pass",
                direction=direction,
                ipprotocol="inet",
                protocol="tcp",
                operation="test"
            )

    def test_all_valid_ipprotocols(self):
        """Test all valid IP protocol values."""
        valid_ipprotocols = ["inet", "inet6"]

        for ipprotocol in valid_ipprotocols:
            validate_firewall_parameters(
                action="pass",
                direction="in",
                ipprotocol=ipprotocol,
                protocol="tcp",
                operation="test"
            )

    def test_all_valid_protocols(self):
        """Test all valid protocol values."""
        valid_protocols = ["tcp", "udp", "icmp", "any"]

        for protocol in valid_protocols:
            validate_firewall_parameters(
                action="pass",
                direction="in",
                ipprotocol="inet",
                protocol=protocol,
                operation="test"
            )

    def test_invalid_action_raises_error(self):
        """Test that invalid action raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            validate_firewall_parameters(
                action="invalid",
                direction="in",
                ipprotocol="inet",
                protocol="tcp",
                operation="test_op"
            )

        assert "Invalid action" in str(exc_info.value)
        assert "pass" in str(exc_info.value)
        assert "block" in str(exc_info.value)

    def test_invalid_direction_raises_error(self):
        """Test that invalid direction raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            validate_firewall_parameters(
                action="pass",
                direction="sideways",
                ipprotocol="inet",
                protocol="tcp",
                operation="test_op"
            )

        assert "Invalid direction" in str(exc_info.value)

    def test_invalid_ipprotocol_raises_error(self):
        """Test that invalid IP protocol raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            validate_firewall_parameters(
                action="pass",
                direction="in",
                ipprotocol="ipv4",
                protocol="tcp",
                operation="test_op"
            )

        assert "Invalid IP protocol" in str(exc_info.value)

    def test_invalid_protocol_raises_error(self):
        """Test that invalid protocol raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            validate_firewall_parameters(
                action="pass",
                direction="in",
                ipprotocol="inet",
                protocol="http",
                operation="test_op"
            )

        assert "Invalid protocol" in str(exc_info.value)

    def test_validation_error_includes_context(self):
        """Test that validation errors include parameter context."""
        with pytest.raises(ValidationError) as exc_info:
            validate_firewall_parameters(
                action="invalid_action",
                direction="in",
                ipprotocol="inet",
                protocol="tcp",
                operation="add_rule"
            )

        assert exc_info.value.context["operation"] == "add_rule"
        assert exc_info.value.context["parameter"] == "action"
        assert exc_info.value.context["value"] == "invalid_action"
