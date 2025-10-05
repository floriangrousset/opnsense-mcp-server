"""
Tests for OPNsense MCP Server retry mechanism.

This module tests the retry logic with exponential backoff for handling
transient failures in API operations.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, patch, Mock
from src.opnsense_mcp.core.retry import RetryConfig, retry_with_backoff
from src.opnsense_mcp.core.exceptions import (
    NetworkError,
    TimeoutError,
    APIError,
    RateLimitError,
    ValidationError,
    ConfigurationError,
)


class TestRetryConfig:
    """Test RetryConfig class."""

    def test_default_config(self):
        """Test RetryConfig with default values."""
        config = RetryConfig()

        assert config.max_attempts == 3
        assert config.base_delay == 1.0
        assert config.max_delay == 60.0
        assert config.exponential_backoff is True
        assert config.retryable_errors == [NetworkError, TimeoutError, APIError, RateLimitError]

    def test_custom_config(self):
        """Test RetryConfig with custom values."""
        config = RetryConfig(
            max_attempts=5,
            base_delay=2.0,
            max_delay=120.0,
            exponential_backoff=False,
            retryable_errors=[NetworkError]
        )

        assert config.max_attempts == 5
        assert config.base_delay == 2.0
        assert config.max_delay == 120.0
        assert config.exponential_backoff is False
        assert config.retryable_errors == [NetworkError]

    def test_config_with_single_retry(self):
        """Test RetryConfig with just one attempt (no retries)."""
        config = RetryConfig(max_attempts=1)

        assert config.max_attempts == 1

    def test_config_with_zero_base_delay(self):
        """Test RetryConfig with zero base delay (immediate retry)."""
        config = RetryConfig(base_delay=0.0)

        assert config.base_delay == 0.0


@pytest.mark.asyncio
class TestRetryWithBackoff:
    """Test retry_with_backoff async function."""

    async def test_successful_first_attempt(self):
        """Test successful operation on first attempt (no retries needed)."""
        mock_func = AsyncMock(return_value="success")

        result = await retry_with_backoff(mock_func)

        assert result == "success"
        assert mock_func.call_count == 1

    async def test_successful_with_arguments(self):
        """Test successful operation with positional and keyword arguments."""
        mock_func = AsyncMock(return_value="result")

        result = await retry_with_backoff(
            mock_func,
            "arg1", "arg2",
            kwarg1="value1",
            kwarg2="value2"
        )

        assert result == "result"
        mock_func.assert_called_once_with("arg1", "arg2", kwarg1="value1", kwarg2="value2")

    async def test_retry_on_network_error(self):
        """Test retry behavior on NetworkError."""
        mock_func = AsyncMock(side_effect=[
            NetworkError("Connection failed"),
            NetworkError("Connection failed again"),
            "success"
        ])

        config = RetryConfig(max_attempts=3, base_delay=0.01)

        with patch('src.opnsense_mcp.core.retry.logger') as mock_logger:
            result = await retry_with_backoff(mock_func, retry_config=config)

        assert result == "success"
        assert mock_func.call_count == 3
        assert mock_logger.info.call_count == 2  # Log retry attempts

    async def test_retry_on_timeout_error(self):
        """Test retry behavior on TimeoutError."""
        mock_func = AsyncMock(side_effect=[
            TimeoutError("Request timed out"),
            "success"
        ])

        config = RetryConfig(max_attempts=3, base_delay=0.01)
        result = await retry_with_backoff(mock_func, retry_config=config)

        assert result == "success"
        assert mock_func.call_count == 2

    async def test_retry_on_api_error(self):
        """Test retry behavior on APIError."""
        mock_func = AsyncMock(side_effect=[
            APIError("API error", status_code=500),
            "success"
        ])

        config = RetryConfig(max_attempts=3, base_delay=0.01)
        result = await retry_with_backoff(mock_func, retry_config=config)

        assert result == "success"
        assert mock_func.call_count == 2

    async def test_retry_on_rate_limit_error(self):
        """Test retry behavior on RateLimitError."""
        mock_func = AsyncMock(side_effect=[
            RateLimitError("Rate limit exceeded"),
            "success"
        ])

        config = RetryConfig(max_attempts=3, base_delay=0.01)
        result = await retry_with_backoff(mock_func, retry_config=config)

        assert result == "success"
        assert mock_func.call_count == 2

    async def test_non_retryable_error_raised_immediately(self):
        """Test that non-retryable errors are raised immediately without retry."""
        mock_func = AsyncMock(side_effect=ValidationError("Invalid input"))

        config = RetryConfig(max_attempts=3, base_delay=0.01)

        with pytest.raises(ValidationError) as exc_info:
            await retry_with_backoff(mock_func, retry_config=config)

        assert str(exc_info.value) == "Invalid input"
        assert mock_func.call_count == 1  # No retries

    async def test_all_attempts_fail(self):
        """Test that exception is raised after all retry attempts fail."""
        mock_func = AsyncMock(side_effect=NetworkError("Persistent failure"))

        config = RetryConfig(max_attempts=3, base_delay=0.01)

        with pytest.raises(NetworkError) as exc_info:
            await retry_with_backoff(mock_func, retry_config=config)

        assert str(exc_info.value) == "Persistent failure"
        assert mock_func.call_count == 3

    async def test_exponential_backoff_delays(self):
        """Test that exponential backoff calculates correct delays."""
        mock_func = AsyncMock(side_effect=[
            NetworkError("Fail 1"),
            NetworkError("Fail 2"),
            "success"
        ])

        config = RetryConfig(
            max_attempts=3,
            base_delay=1.0,
            max_delay=10.0,
            exponential_backoff=True
        )

        with patch('asyncio.sleep', new_callable=AsyncMock) as mock_sleep:
            result = await retry_with_backoff(mock_func, retry_config=config)

        assert result == "success"

        # Check exponential backoff delays: 1.0 * 2^0 = 1.0, 1.0 * 2^1 = 2.0
        assert mock_sleep.call_count == 2
        assert mock_sleep.call_args_list[0][0][0] == 1.0  # First retry delay
        assert mock_sleep.call_args_list[1][0][0] == 2.0  # Second retry delay

    async def test_max_delay_cap(self):
        """Test that delays are capped at max_delay."""
        mock_func = AsyncMock(side_effect=[
            NetworkError("Fail 1"),
            NetworkError("Fail 2"),
            NetworkError("Fail 3"),
            "success"
        ])

        config = RetryConfig(
            max_attempts=4,
            base_delay=10.0,
            max_delay=15.0,  # Cap at 15 seconds
            exponential_backoff=True
        )

        with patch('asyncio.sleep', new_callable=AsyncMock) as mock_sleep:
            result = await retry_with_backoff(mock_func, retry_config=config)

        assert result == "success"

        # Delays: 10.0 * 2^0 = 10.0, 10.0 * 2^1 = 20.0 (capped to 15.0), 10.0 * 2^2 = 40.0 (capped to 15.0)
        assert mock_sleep.call_count == 3
        assert mock_sleep.call_args_list[0][0][0] == 10.0
        assert mock_sleep.call_args_list[1][0][0] == 15.0  # Capped
        assert mock_sleep.call_args_list[2][0][0] == 15.0  # Capped

    async def test_linear_backoff(self):
        """Test linear backoff (exponential_backoff=False)."""
        mock_func = AsyncMock(side_effect=[
            NetworkError("Fail 1"),
            NetworkError("Fail 2"),
            "success"
        ])

        config = RetryConfig(
            max_attempts=3,
            base_delay=2.0,
            exponential_backoff=False
        )

        with patch('asyncio.sleep', new_callable=AsyncMock) as mock_sleep:
            result = await retry_with_backoff(mock_func, retry_config=config)

        assert result == "success"

        # All delays should be base_delay (no exponential growth)
        assert mock_sleep.call_count == 2
        assert mock_sleep.call_args_list[0][0][0] == 2.0
        assert mock_sleep.call_args_list[1][0][0] == 2.0

    async def test_custom_retryable_errors(self):
        """Test retry with custom retryable error list."""
        mock_func = AsyncMock(side_effect=[
            NetworkError("Network error"),
            "success"
        ])

        # Only retry on NetworkError, not other errors
        config = RetryConfig(
            max_attempts=3,
            base_delay=0.01,
            retryable_errors=[NetworkError]
        )

        result = await retry_with_backoff(mock_func, retry_config=config)

        assert result == "success"
        assert mock_func.call_count == 2

    async def test_custom_retryable_errors_non_retryable_raised(self):
        """Test that errors not in custom retryable list are raised immediately."""
        mock_func = AsyncMock(side_effect=APIError("API error"))

        # Only NetworkError is retryable
        config = RetryConfig(
            max_attempts=3,
            base_delay=0.01,
            retryable_errors=[NetworkError]
        )

        with pytest.raises(APIError):
            await retry_with_backoff(mock_func, retry_config=config)

        assert mock_func.call_count == 1  # No retries

    async def test_default_config_when_none_provided(self):
        """Test that default RetryConfig is used when none provided."""
        mock_func = AsyncMock(side_effect=[
            NetworkError("Fail"),
            "success"
        ])

        # Don't provide retry_config - should use defaults
        result = await retry_with_backoff(mock_func)

        assert result == "success"
        assert mock_func.call_count == 2

    async def test_zero_delay_immediate_retry(self):
        """Test immediate retry with zero delay."""
        mock_func = AsyncMock(side_effect=[
            NetworkError("Fail"),
            "success"
        ])

        config = RetryConfig(max_attempts=2, base_delay=0.0)

        with patch('asyncio.sleep', new_callable=AsyncMock) as mock_sleep:
            result = await retry_with_backoff(mock_func, retry_config=config)

        assert result == "success"
        mock_sleep.assert_called_once_with(0.0)

    async def test_single_attempt_no_retry(self):
        """Test that max_attempts=1 means no retries."""
        mock_func = AsyncMock(side_effect=NetworkError("Fail"))

        config = RetryConfig(max_attempts=1, base_delay=0.01)

        with pytest.raises(NetworkError):
            await retry_with_backoff(mock_func, retry_config=config)

        assert mock_func.call_count == 1  # Only one attempt, no retries

    async def test_logging_on_retry(self):
        """Test that retry attempts are logged."""
        mock_func = AsyncMock(side_effect=[
            NetworkError("Connection failed"),
            "success"
        ])

        config = RetryConfig(max_attempts=2, base_delay=0.01)

        with patch('src.opnsense_mcp.core.retry.logger') as mock_logger:
            await retry_with_backoff(mock_func, retry_config=config)

        # Should log the retry attempt
        assert mock_logger.info.call_count == 1
        log_call = mock_logger.info.call_args[0][0]
        assert "Attempt 1 failed" in log_call
        assert "retrying in" in log_call

    async def test_complex_return_types(self):
        """Test retry with complex return types (dict, list, object)."""
        expected_result = {"status": "ok", "data": [1, 2, 3]}
        mock_func = AsyncMock(return_value=expected_result)

        result = await retry_with_backoff(mock_func)

        assert result == expected_result
        assert isinstance(result, dict)

    async def test_none_return_value(self):
        """Test retry with None return value."""
        mock_func = AsyncMock(return_value=None)

        result = await retry_with_backoff(mock_func)

        assert result is None

    async def test_exception_details_preserved(self):
        """Test that exception details are preserved through retries."""
        original_error = APIError("Server error", status_code=503, response_text="Service unavailable")
        mock_func = AsyncMock(side_effect=original_error)

        config = RetryConfig(max_attempts=2, base_delay=0.01)

        with pytest.raises(APIError) as exc_info:
            await retry_with_backoff(mock_func, retry_config=config)

        # Verify exception details are preserved
        assert exc_info.value.message == "Server error"
        assert exc_info.value.status_code == 503
        assert exc_info.value.response_text == "Service unavailable"
