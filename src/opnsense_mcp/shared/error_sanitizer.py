"""
OPNsense MCP Server - Error Message Sanitization

This module provides utilities for sanitizing error messages to prevent
information disclosure while maintaining helpful user feedback.
"""

import json
import logging
from typing import Any

import httpx

from ..core.exceptions import (
    APIError,
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    NetworkError,
    OPNsenseError,
    RateLimitError,
    ResourceNotFoundError,
    ValidationError,
)
from ..core.exceptions import (
    TimeoutError as OPNsenseTimeoutError,
)

logger = logging.getLogger("opnsense-mcp")


class ErrorMessageSanitizer:
    """Sanitize error messages for safe user display."""

    # Sensitive patterns that should never appear in user-facing messages
    SENSITIVE_PATTERNS = [
        "password",
        "api_key",
        "api_secret",
        "token",
        "credential",
        "authorization",
        "bearer",
        "secret",
    ]

    @staticmethod
    def sanitize_for_user(error: Exception, operation: str = "operation") -> str:
        """
        Return user-safe error message without sensitive details.

        Args:
            error: The exception to sanitize
            operation: Description of the operation that failed

        Returns:
            User-safe error message
        """
        # Handle known exception types with specific messages
        if isinstance(error, AuthenticationError):
            return "Authentication failed. Please check your OPNsense credentials."

        if isinstance(error, AuthorizationError):
            return "Authorization failed. The API user may lack necessary permissions."

        if isinstance(error, ConfigurationError):
            return f"Configuration error: {error.message}"

        if isinstance(error, ValidationError):
            # Validation errors usually safe to show
            return f"Invalid input: {error.message}"

        if isinstance(error, ResourceNotFoundError):
            return f"Resource not found: {error.message}"

        if isinstance(error, RateLimitError):
            return "Rate limit exceeded. Please wait before retrying."

        if isinstance(error, OPNsenseTimeoutError):
            return "Request timed out. OPNsense may be overloaded or unreachable."

        if isinstance(error, NetworkError):
            return "Network error. Cannot connect to OPNsense. Check URL and network connectivity."

        if isinstance(error, httpx.ConnectError):
            return "Cannot connect to OPNsense. Please check the URL and network."

        if isinstance(error, httpx.TimeoutException):
            return "Request timed out. OPNsense may be overloaded."

        if isinstance(error, json.JSONDecodeError):
            return "Received invalid response from OPNsense API."

        if isinstance(error, APIError):
            # API errors may contain details, sanitize them
            return f"OPNsense API error: {ErrorMessageSanitizer._sanitize_text(str(error))}"

        # Generic message for unexpected errors
        return f"An error occurred during {operation}. Please check the logs for details."

    @staticmethod
    def sanitize_for_logs(error: Exception, include_traceback: bool = False) -> dict[str, Any]:
        """
        Return detailed error info for logging (never shown to users).

        Args:
            error: The exception to log
            include_traceback: Whether to include traceback info

        Returns:
            Dictionary with error details for logging
        """
        error_info = {
            "error_type": type(error).__name__,
            "error_module": error.__class__.__module__,
            "error_message": str(error),
        }

        # Add context if it's an OPNsenseError
        if isinstance(error, OPNsenseError):
            error_info["error_code"] = error.error_code
            error_info["context"] = ErrorMessageSanitizer._sanitize_context(error.context)

        # Add HTTP details if it's an httpx error
        if isinstance(error, (httpx.HTTPError, httpx.RequestError)):
            if hasattr(error, "response") and error.response is not None:
                error_info["status_code"] = error.response.status_code
                error_info["reason"] = error.response.reason_phrase

        return error_info

    @staticmethod
    def _sanitize_text(text: str) -> str:
        """
        Remove sensitive patterns from text.

        Args:
            text: Text to sanitize

        Returns:
            Sanitized text
        """
        sanitized = text
        for pattern in ErrorMessageSanitizer.SENSITIVE_PATTERNS:
            if pattern in sanitized.lower():
                # Replace entire value after the pattern
                # e.g., "password=secret123" becomes "password=[REDACTED]"
                import re

                sanitized = re.sub(
                    f"{pattern}[=:]\\S+",
                    f"{pattern}=[REDACTED]",
                    sanitized,
                    flags=re.IGNORECASE,
                )
        return sanitized

    @staticmethod
    def _sanitize_context(context: dict[str, Any] | None) -> dict[str, Any]:
        """
        Remove sensitive data from context dictionary.

        Args:
            context: Context dictionary to sanitize

        Returns:
            Sanitized context dictionary
        """
        if not context:
            return {}

        sanitized = {}
        for key, value in context.items():
            # Check if key contains sensitive pattern
            key_lower = key.lower()
            is_sensitive = any(
                pattern in key_lower for pattern in ErrorMessageSanitizer.SENSITIVE_PATTERNS
            )

            if is_sensitive:
                sanitized[key] = "[REDACTED]"
            elif isinstance(value, dict):
                sanitized[key] = ErrorMessageSanitizer._sanitize_context(value)
            elif isinstance(value, str):
                sanitized[key] = ErrorMessageSanitizer._sanitize_text(value)
            else:
                sanitized[key] = value

        return sanitized


def log_error_safely(
    logger: logging.Logger,
    error: Exception,
    operation: str = "operation",
    user_message: str | None = None,
) -> str:
    """
    Log error with full details and return sanitized user message.

    Args:
        logger: Logger instance
        error: Exception that occurred
        operation: Description of the operation
        user_message: Optional custom user message

    Returns:
        Sanitized user-facing error message
    """
    # Log full details (secure logs)
    error_details = ErrorMessageSanitizer.sanitize_for_logs(error)
    logger.error(
        f"Error in {operation}: {json.dumps(error_details)}",
        exc_info=True,
    )

    # Return safe message for user
    if user_message:
        return user_message
    return ErrorMessageSanitizer.sanitize_for_user(error, operation)
