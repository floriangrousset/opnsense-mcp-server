"""
OPNsense MCP Server - Setup Command

Interactive setup for configuring OPNsense credentials.
"""

import getpass

import typer

from ..core.config_loader import ConfigLoader
from ..core.models import OPNsenseConfig


def setup_command(
    profile: str | None = typer.Option(
        "default", "--profile", "-p", help="Profile name (default, production, staging, etc.)"
    ),
    url: str | None = typer.Option(None, "--url", help="OPNsense URL (e.g., https://192.168.1.1)"),
    api_key: str | None = typer.Option(None, "--api-key", help="OPNsense API key"),
    api_secret: str | None = typer.Option(None, "--api-secret", help="OPNsense API secret"),
    verify_ssl: bool = typer.Option(
        True, "--verify-ssl/--no-verify-ssl", help="Verify SSL certificates"
    ),
    interactive: bool = typer.Option(
        True, "--interactive/--non-interactive", help="Interactive mode with prompts"
    ),
):
    """
    Configure OPNsense connection credentials.

    Examples:
        # Interactive setup
        opnsense-mcp setup

        # Non-interactive setup
        opnsense-mcp setup --url https://192.168.1.1 --api-key KEY --api-secret SECRET

        # Setup production profile
        opnsense-mcp setup --profile production
    """
    typer.echo("\n🔧 OPNsense MCP Server - Credential Setup\n")
    typer.echo(f"Profile: {typer.style(profile, fg=typer.colors.CYAN, bold=True)}\n")

    # Interactive mode - prompt for missing values
    if interactive:
        if not url:
            url = typer.prompt("OPNsense URL (e.g., https://192.168.1.1)")

        if not api_key:
            api_key = typer.prompt("API Key")

        if not api_secret:
            # Use getpass for secure password input
            api_secret = getpass.getpass("API Secret (hidden): ")

        # Confirm SSL verification
        if not typer.confirm("Verify SSL certificates?", default=True):
            verify_ssl = False

    # Non-interactive mode - require all parameters
    elif not all([url, api_key, api_secret]):
        typer.echo(
            "❌ Error: In non-interactive mode, all parameters (--url, --api-key, --api-secret) are required",
            err=True,
        )
        raise typer.Exit(1)

    # Validate and create config
    try:
        config = OPNsenseConfig(
            url=url, api_key=api_key, api_secret=api_secret, verify_ssl=verify_ssl
        )
    except Exception as e:
        typer.echo(f"❌ Invalid configuration: {e}", err=True)
        raise typer.Exit(1)

    # Test connection before saving
    typer.echo("\n🔍 Testing connection...")
    if not _test_connection(config):
        typer.echo("\n⚠️  Connection test failed. Save anyway?", err=True)
        if not typer.confirm("Continue with save?", default=False):
            typer.echo("Setup cancelled")
            raise typer.Exit(0)

    # Save profile
    try:
        ConfigLoader.save_profile(profile, config)
        typer.echo(f"\n✅ Profile '{profile}' saved successfully!")
        typer.echo(f"\n📍 Config location: {ConfigLoader.DEFAULT_CONFIG_FILE}")
        typer.echo("🔒 File permissions: 0600 (owner read/write only)")

        # Show usage instructions
        typer.echo("\n📖 Usage:")
        typer.echo(
            f'   • In Claude Desktop, say: "Configure OPNsense connection using profile {profile}"'
        )
        typer.echo(f"   • Test connection: opnsense-mcp test-connection --profile {profile}")
        typer.echo("   • List profiles: opnsense-mcp list-profiles")

    except Exception as e:
        typer.echo(f"\n❌ Error saving profile: {e}", err=True)
        raise typer.Exit(1)


def _test_connection(config: OPNsenseConfig) -> bool:
    """
    Test connection to OPNsense.

    Args:
        config: OPNsense configuration

    Returns:
        True if connection successful, False otherwise
    """
    try:
        import asyncio

        from ..core.client import OPNsenseClient
        from ..shared.constants import API_CORE_FIRMWARE_STATUS

        async def test():
            client = OPNsenseClient(config)
            await client.request("GET", API_CORE_FIRMWARE_STATUS)
            await client.close()

        asyncio.run(test())
        typer.echo("✅ Connection successful!")
        return True

    except Exception as e:
        typer.echo(f"⚠️  Connection failed: {e}")
        return False
