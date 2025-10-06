"""
Tests for OPNsense MCP Server Pydantic models.

This module tests the data models used for configuration validation
including field validation, defaults, and security features.
"""

import pytest
from pydantic import ValidationError

from src.opnsense_mcp.core.models import OPNsenseConfig


class TestOPNsenseConfig:
    """Test OPNsenseConfig Pydantic model."""

    def test_valid_config_creation(self):
        """Test creating a valid configuration."""
        config = OPNsenseConfig(
            url="https://192.168.1.1", api_key="test_key_123", api_secret="test_secret_456"
        )

        assert config.url == "https://192.168.1.1"
        assert config.api_key == "test_key_123"
        assert config.api_secret == "test_secret_456"
        assert config.verify_ssl is True  # default value

    def test_config_with_http_url(self):
        """Test configuration with HTTP URL (non-SSL)."""
        config = OPNsenseConfig(
            url="http://192.168.1.1", api_key="test_key", api_secret="test_secret"
        )

        assert config.url == "http://192.168.1.1"

    def test_config_with_verify_ssl_false(self):
        """Test configuration with SSL verification disabled."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False,
        )

        assert config.verify_ssl is False

    def test_url_trailing_slash_removed(self):
        """Test that trailing slashes are removed from URLs."""
        config = OPNsenseConfig(
            url="https://192.168.1.1/", api_key="test_key", api_secret="test_secret"
        )

        assert config.url == "https://192.168.1.1"
        assert not config.url.endswith("/")

    def test_url_multiple_trailing_slashes_removed(self):
        """Test that multiple trailing slashes are removed."""
        config = OPNsenseConfig(
            url="https://192.168.1.1///", api_key="test_key", api_secret="test_secret"
        )

        # rstrip('/') removes all trailing slashes
        assert config.url == "https://192.168.1.1"

    def test_url_without_protocol_raises_error(self):
        """Test that URLs without http:// or https:// are rejected."""
        with pytest.raises(ValidationError) as exc_info:
            OPNsenseConfig(url="192.168.1.1", api_key="test_key", api_secret="test_secret")

        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert errors[0]["loc"] == ("url",)
        assert "must start with http:// or https://" in errors[0]["msg"]

    def test_url_with_invalid_protocol_raises_error(self):
        """Test that URLs with invalid protocols are rejected."""
        with pytest.raises(ValidationError) as exc_info:
            OPNsenseConfig(url="ftp://192.168.1.1", api_key="test_key", api_secret="test_secret")

        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "must start with http:// or https://" in errors[0]["msg"]

    def test_missing_url_raises_error(self):
        """Test that missing URL field raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            OPNsenseConfig(api_key="test_key", api_secret="test_secret")

        errors = exc_info.value.errors()
        assert any(error["loc"] == ("url",) for error in errors)

    def test_missing_api_key_raises_error(self):
        """Test that missing api_key raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            OPNsenseConfig(url="https://192.168.1.1", api_secret="test_secret")

        errors = exc_info.value.errors()
        assert any(error["loc"] == ("api_key",) for error in errors)

    def test_missing_api_secret_raises_error(self):
        """Test that missing api_secret raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            OPNsenseConfig(url="https://192.168.1.1", api_key="test_key")

        errors = exc_info.value.errors()
        assert any(error["loc"] == ("api_secret",) for error in errors)

    def test_api_secret_hidden_in_repr(self):
        """Test that api_secret is hidden in string representation."""
        config = OPNsenseConfig(
            url="https://192.168.1.1", api_key="test_key", api_secret="super_secret_value"
        )

        repr_str = repr(config)

        # api_secret should be hidden (repr=False in Field)
        assert "super_secret_value" not in repr_str
        # Other fields should be visible
        assert "test_key" in repr_str
        assert "192.168.1.1" in repr_str

    def test_verify_ssl_default_value(self):
        """Test that verify_ssl defaults to True when not provided."""
        config = OPNsenseConfig(
            url="https://192.168.1.1", api_key="test_key", api_secret="test_secret"
        )

        assert config.verify_ssl is True

    def test_config_with_domain_name(self):
        """Test configuration with domain name instead of IP."""
        config = OPNsenseConfig(
            url="https://opnsense.example.com", api_key="test_key", api_secret="test_secret"
        )

        assert config.url == "https://opnsense.example.com"

    def test_config_with_port_number(self):
        """Test configuration with custom port number."""
        config = OPNsenseConfig(
            url="https://192.168.1.1:8443", api_key="test_key", api_secret="test_secret"
        )

        assert config.url == "https://192.168.1.1:8443"

    def test_config_with_url_path(self):
        """Test configuration with URL path (should preserve path)."""
        config = OPNsenseConfig(
            url="https://192.168.1.1/opnsense", api_key="test_key", api_secret="test_secret"
        )

        assert config.url == "https://192.168.1.1/opnsense"

    def test_validate_assignment_enabled(self):
        """Test that validate_assignment is enabled for field updates."""
        config = OPNsenseConfig(
            url="https://192.168.1.1", api_key="test_key", api_secret="test_secret"
        )

        # Valid assignment should work
        config.url = "https://192.168.1.2"
        assert config.url == "https://192.168.1.2"

        # Invalid assignment should raise error
        with pytest.raises(ValidationError):
            config.url = "invalid-url-without-protocol"

    def test_config_serialization(self):
        """Test that config can be serialized to dict."""
        config = OPNsenseConfig(
            url="https://192.168.1.1",
            api_key="test_key",
            api_secret="test_secret",
            verify_ssl=False,
        )

        config_dict = config.model_dump()

        assert config_dict["url"] == "https://192.168.1.1"
        assert config_dict["api_key"] == "test_key"
        assert config_dict["api_secret"] == "test_secret"
        assert config_dict["verify_ssl"] is False

    def test_config_from_dict(self):
        """Test creating config from dictionary."""
        config_data = {
            "url": "https://192.168.1.1",
            "api_key": "test_key",
            "api_secret": "test_secret",
            "verify_ssl": True,
        }

        config = OPNsenseConfig(**config_data)

        assert config.url == config_data["url"]
        assert config.api_key == config_data["api_key"]
        assert config.api_secret == config_data["api_secret"]
        assert config.verify_ssl == config_data["verify_ssl"]

    def test_config_field_descriptions(self):
        """Test that field descriptions are properly defined."""
        schema = OPNsenseConfig.model_json_schema()

        assert "url" in schema["properties"]
        assert "description" in schema["properties"]["url"]
        assert "api_key" in schema["properties"]
        assert "description" in schema["properties"]["api_key"]
        assert "api_secret" in schema["properties"]
        assert "description" in schema["properties"]["api_secret"]
        assert "verify_ssl" in schema["properties"]
        assert "description" in schema["properties"]["verify_ssl"]

    def test_config_immutability_of_field_types(self):
        """Test that field types are enforced."""
        config = OPNsenseConfig(
            url="https://192.168.1.1", api_key="test_key", api_secret="test_secret"
        )

        # verify_ssl should be boolean
        with pytest.raises(ValidationError):
            config.verify_ssl = "not a boolean"

    def test_empty_string_url_raises_error(self):
        """Test that empty string URL is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            OPNsenseConfig(url="", api_key="test_key", api_secret="test_secret")

        # Should fail because empty string doesn't start with http:// or https://
        errors = exc_info.value.errors()
        assert len(errors) > 0

    def test_url_with_path_and_trailing_slash(self):
        """Test URL with path and trailing slash is properly handled."""
        config = OPNsenseConfig(
            url="https://192.168.1.1/api/", api_key="test_key", api_secret="test_secret"
        )

        # Trailing slash should be removed
        assert config.url == "https://192.168.1.1/api"
