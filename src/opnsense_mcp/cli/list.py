"""
OPNsense MCP Server - List Profiles Command

List all configured credential profiles.
"""


import typer

from ..core.config_loader import ConfigLoader


def list_command(
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show detailed information for each profile"
    )
):
    """
    List all configured OPNsense profiles.

    Examples:
        # List all profiles
        opnsense-mcp list-profiles

        # List with details
        opnsense-mcp list-profiles --verbose
    """
    typer.echo("\n📋 Configured OPNsense Profiles\n")

    try:
        profiles = ConfigLoader.list_profiles()

        if not profiles:
            typer.echo("❌ No profiles configured yet")
            typer.echo("\n💡 Tip: Run 'opnsense-mcp setup' to configure your first profile")
            return

        typer.echo(f"Found {len(profiles)} profile(s):\n")

        for profile in profiles:
            if verbose:
                # Show detailed information
                try:
                    info = ConfigLoader.get_profile_info(profile)
                    typer.echo(f"📦 {typer.style(profile, fg=typer.colors.CYAN, bold=True)}")
                    typer.echo(f"   URL: {info['url']}")
                    typer.echo(f"   API Key: {info['api_key_preview']}")
                    typer.echo(f"   SSL Verification: {'✓' if info['verify_ssl'] else '✗'}")
                    typer.echo()
                except Exception as e:
                    typer.echo(f"📦 {profile} - Error loading details: {e}")
                    typer.echo()
            else:
                # Simple list
                typer.echo(f"  • {profile}")

        if not verbose:
            typer.echo("\n💡 Tip: Use --verbose to see profile details")

        typer.echo(f"\n📍 Config file: {ConfigLoader.DEFAULT_CONFIG_FILE}")

    except Exception as e:
        typer.echo(f"❌ Error listing profiles: {e}", err=True)
        raise typer.Exit(1)
