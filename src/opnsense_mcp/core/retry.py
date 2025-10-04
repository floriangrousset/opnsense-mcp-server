"""
OPNsense MCP Server - Retry Mechanism

This module provides retry functionality with exponential backoff for transient failures.
"""

import asyncio
import logging
from typing import List, Optional, Callable, Any
from .exceptions import NetworkError, TimeoutError, APIError, RateLimitError

logger = logging.getLogger("opnsense-mcp")


class RetryConfig:
    """Configuration for retry mechanism with exponential backoff."""

    def __init__(
        self,
        max_attempts: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_backoff: bool = True,
        retryable_errors: Optional[List[type]] = None
    ):
        """Initialize retry configuration.

        Args:
            max_attempts: Maximum number of retry attempts
            base_delay: Base delay in seconds between retries
            max_delay: Maximum delay in seconds between retries
            exponential_backoff: Whether to use exponential backoff
            retryable_errors: List of error types that should trigger a retry
        """
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_backoff = exponential_backoff
        self.retryable_errors = retryable_errors or [NetworkError, TimeoutError, APIError, RateLimitError]


async def retry_with_backoff(
    func: Callable,
    *args,
    retry_config: Optional[RetryConfig] = None,
    **kwargs
) -> Any:
    """Retry function with exponential backoff for transient failures.

    Args:
        func: Async function to retry
        *args: Positional arguments to pass to the function
        retry_config: Configuration for retry mechanism
        **kwargs: Keyword arguments to pass to the function

    Returns:
        Result from the function call

    Raises:
        Exception: Re-raises the last exception if all retry attempts fail
    """
    if retry_config is None:
        retry_config = RetryConfig()

    last_exception = None

    for attempt in range(retry_config.max_attempts):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            last_exception = e

            # Check if error is retryable
            if not any(isinstance(e, err_type) for err_type in retry_config.retryable_errors):
                raise e

            # Don't retry on last attempt
            if attempt == retry_config.max_attempts - 1:
                break

            # Calculate delay with exponential backoff
            if retry_config.exponential_backoff:
                delay = min(retry_config.base_delay * (2 ** attempt), retry_config.max_delay)
            else:
                delay = retry_config.base_delay

            logger.info(f"Attempt {attempt + 1} failed, retrying in {delay}s: {str(e)}")
            await asyncio.sleep(delay)

    # All attempts failed
    raise last_exception
