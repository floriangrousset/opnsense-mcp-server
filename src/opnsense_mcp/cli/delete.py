"""
OPNsense MCP Server - Delete Profile Command

Delete a credential profile.
"""

import typer

from ..core.config_loader import ConfigLoader
from ..core.exceptions import ConfigurationError


def delete_command(
    profile: str = typer.Argument(..., help="Profile name to delete"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation prompt"),
):
    """
    Delete a credential profile.

    Examples:
        # Delete with confirmation
        opnsense-mcp delete-profile staging

        # Force delete without confirmation
        opnsense-mcp delete-profile staging --force
    """
    typer.echo("\n🗑️  Delete OPNsense Profile\n")

    try:
        # Check if profile exists
        profiles = ConfigLoader.list_profiles()
        if profile not in profiles:
            typer.echo(f"❌ Profile '{profile}' not found", err=True)
            typer.echo(f"\n📋 Available profiles: {', '.join(profiles) if profiles else 'None'}")
            raise typer.Exit(1)

        # Show profile info
        try:
            info = ConfigLoader.get_profile_info(profile)
            typer.echo(f"Profile: {typer.style(profile, fg=typer.colors.YELLOW, bold=True)}")
            typer.echo(f"URL: {info['url']}\n")
        except Exception:
            typer.echo(f"Profile: {typer.style(profile, fg=typer.colors.YELLOW, bold=True)}\n")

        # Confirm deletion (unless force flag)
        if not force:
            if not typer.confirm(
                f"⚠️  Are you sure you want to delete profile '{profile}'?", default=False
            ):
                typer.echo("Operation cancelled")
                raise typer.Exit(0)

        # Delete profile
        ConfigLoader.delete_profile(profile)
        typer.echo(f"\n✅ Profile '{profile}' deleted successfully")

        # Show remaining profiles
        remaining = ConfigLoader.list_profiles()
        if remaining:
            typer.echo(f"\n📋 Remaining profiles: {', '.join(remaining)}")
        else:
            typer.echo("\n📋 No profiles remaining")
            typer.echo("💡 Run 'opnsense-mcp setup' to configure a new profile")

    except typer.Exit:
        # Re-raise typer.Exit to preserve exit code
        raise

    except ConfigurationError as e:
        typer.echo(f"❌ Error: {e}", err=True)
        raise typer.Exit(1)

    except Exception as e:
        typer.echo(f"❌ Unexpected error: {e}", err=True)
        raise typer.Exit(1)
