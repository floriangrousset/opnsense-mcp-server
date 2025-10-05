"""
OPNsense MCP Server - Test Connection Command

Test connection to OPNsense firewall.
"""

import typer
from typing import Optional
import asyncio

from ..core.config_loader import ConfigLoader
from ..core.client import OPNsenseClient
from ..core.exceptions import ConfigurationError, AuthenticationError, NetworkError
from ..shared.constants import API_CORE_FIRMWARE_STATUS


def test_command(
    profile: str = typer.Option(
        "default",
        "--profile", "-p",
        help="Profile name to test"
    )
):
    """
    Test connection to OPNsense firewall.

    Examples:
        # Test default profile
        opnsense-mcp test-connection

        # Test specific profile
        opnsense-mcp test-connection --profile production
    """
    typer.echo(f"\n🔍 Testing OPNsense Connection\n")
    typer.echo(f"Profile: {typer.style(profile, fg=typer.colors.CYAN, bold=True)}\n")

    try:
        # Load configuration
        typer.echo("📡 Loading credentials...")
        config = ConfigLoader.load(profile)

        # Show connection details (no credentials)
        info = ConfigLoader.get_profile_info(profile)
        typer.echo(f"URL: {info['url']}")
        typer.echo(f"SSL Verification: {'Enabled' if info['verify_ssl'] else 'Disabled'}\n")

        # Test connection
        typer.echo("🔌 Connecting to OPNsense...")
        result = asyncio.run(_test_connection_async(config))

        if result["success"]:
            typer.echo(f"\n✅ {typer.style('Connection successful!', fg=typer.colors.GREEN, bold=True)}")

            if result.get("firmware_status"):
                typer.echo("\n📊 System Information:")
                status = result["firmware_status"]
                if "product_name" in status:
                    typer.echo(f"   Product: {status['product_name']}")
                if "product_version" in status:
                    typer.echo(f"   Version: {status['product_version']}")

            typer.echo(f"\n✓ Your OPNsense connection is properly configured")
            typer.echo(f"✓ You can now use this profile in Claude Desktop")

        else:
            typer.echo(f"\n❌ {typer.style('Connection failed', fg=typer.colors.RED, bold=True)}")
            typer.echo(f"\nError: {result.get('error', 'Unknown error')}")
            typer.echo("\n💡 Troubleshooting tips:")
            typer.echo("   • Verify the URL is correct and accessible")
            typer.echo("   • Check API key and secret are valid")
            typer.echo("   • Ensure firewall allows API access from your IP")
            typer.echo("   • Try with --no-verify-ssl if using self-signed certificate")
            raise typer.Exit(1)

    except ConfigurationError as e:
        typer.echo(f"❌ Configuration error: {e}", err=True)
        typer.echo("\n💡 Run 'opnsense-mcp setup' to configure credentials")
        raise typer.Exit(1)

    except Exception as e:
        typer.echo(f"❌ Unexpected error: {e}", err=True)
        raise typer.Exit(1)


async def _test_connection_async(config):
    """
    Async helper to test connection.

    Args:
        config: OPNsense configuration

    Returns:
        Dictionary with test results
    """
    client = None
    try:
        client = OPNsenseClient(config)

        # Try to fetch firmware status (basic API call)
        response = await client.request("GET", API_CORE_FIRMWARE_STATUS)

        return {
            "success": True,
            "firmware_status": response
        }

    except AuthenticationError as e:
        return {
            "success": False,
            "error": f"Authentication failed: {str(e)}"
        }

    except NetworkError as e:
        return {
            "success": False,
            "error": f"Network error: {str(e)}"
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

    finally:
        if client:
            await client.close()
