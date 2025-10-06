"""
OPNsense MCP Server - Data Models

This module contains Pydantic models for configuration and validation.
"""

from pydantic import BaseModel, Field, field_validator


class OPNsenseConfig(BaseModel):
    """Configuration for OPNsense connection."""

    url: str = Field(..., description="OPNsense base URL")
    api_key: str = Field(..., description="API key")
    api_secret: str = Field(..., description="API secret", repr=False)  # Hide in logs
    verify_ssl: bool = Field(default=True, description="Whether to verify SSL certificates")

    @field_validator("url")
    @classmethod
    def validate_url(cls, v):
        """Validate URL format."""
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v.rstrip("/")

    class Config:
        """Pydantic configuration."""

        validate_assignment = True
