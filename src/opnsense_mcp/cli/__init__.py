"""
OPNsense MCP Server - CLI Interface

This module provides command-line interface for managing OPNsense credentials
and profiles securely without exposing them to the LLM.
"""

import typer
from typing import Optional
import sys

from .setup import setup_command
from .list import list_command
from .test import test_command
from .delete import delete_command

# Create main CLI app
app = typer.Typer(
    name="opnsense-mcp",
    help="OPNsense MCP Server - Secure credential management",
    add_completion=False
)

# Register commands
app.command(name="setup", help="Configure OPNsense connection credentials")(setup_command)
app.command(name="list-profiles", help="List all configured profiles")(list_command)
app.command(name="test-connection", help="Test connection to OPNsense")(test_command)
app.command(name="delete-profile", help="Delete a credential profile")(delete_command)


def main():
    """CLI entry point."""
    try:
        app()
    except KeyboardInterrupt:
        typer.echo("\n\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
