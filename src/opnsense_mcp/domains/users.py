"""
OPNsense MCP Server - Users Domain

This module provides comprehensive user and group management capabilities including:
- User CRUD operations (create, read, update, delete, toggle)
- Group management with privilege assignment
- Group membership management
- Authentication and privilege system
- External authentication server support
- Helper tools for common scenarios (admin users, read-only users, password resets)
- Bulk user creation and group templates

The module implements full RBAC (Role-Based Access Control) support with:
- Direct user privilege assignment
- Group-based privilege inheritance
- Effective privilege calculation (combines user + group privileges)
- Authentication testing against local and external auth servers
"""

import json
import logging
from typing import Optional

from mcp.server.fastmcp import Context

from ..main import mcp
from ..core import (
    ValidationError,
    ResourceNotFoundError,
)
from ..shared.constants import (
    API_CORE_USER_SEARCH,
    API_CORE_USER_GET,
    API_CORE_USER_ADD,
    API_CORE_USER_SET,
    API_CORE_USER_DEL,
    API_CORE_USER_TOGGLE,
    API_CORE_GROUP_SEARCH,
    API_CORE_GROUP_GET,
    API_CORE_GROUP_ADD,
    API_CORE_GROUP_SET,
    API_CORE_GROUP_DEL,
    API_CORE_AUTH_PRIVILEGES,
    API_CORE_AUTH_SERVERS,
    API_CORE_AUTH_TEST,
    API_CORE_CONFIG_RELOAD,
)
from ..shared.error_handlers import handle_tool_error, validate_uuid

logger = logging.getLogger("opnsense-mcp")


# ========== HELPER FUNCTIONS ==========

async def get_opnsense_client():
    """Get configured OPNsense client from server state."""
    from ..domains.configuration import get_opnsense_client as get_client
    return await get_client()


# ========== USER MANAGEMENT ==========

@mcp.tool(name="list_users", description="List all users in OPNsense")
async def list_users(ctx: Context) -> str:
    """List all users configured in OPNsense.

    Args:
        ctx: MCP context

    Returns:
        JSON string with list of all users
    """
    try:
        client = await get_opnsense_client()

        response = await client.request("POST", API_CORE_USER_SEARCH, operation="list_users")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "list_users", e)


@mcp.tool(name="get_user", description="Get details of a specific user")
async def get_user(ctx: Context, user_uuid: Optional[str] = None) -> str:
    """Get details of a specific user or all users.

    Args:
        ctx: MCP context
        user_uuid: UUID of specific user to retrieve (optional - if not provided, returns all users)

    Returns:
        JSON string with user details
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID if provided
        if user_uuid:
            validate_uuid(user_uuid, "user_uuid")
            endpoint = f"{API_CORE_USER_GET}/{user_uuid}"
        else:
            endpoint = API_CORE_USER_GET

        response = await client.request("GET", endpoint, operation="get_user")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_user", e)


@mcp.tool(name="create_user", description="Create a new user account")
async def create_user(
    ctx: Context,
    username: str,
    password: str,
    full_name: str = "",
    email: str = "",
    groups: Optional[str] = None,
    privileges: Optional[str] = None,
    enabled: bool = True,
    expires: Optional[str] = None,
    comment: str = ""
) -> str:
    """Create a new user account in OPNsense.

    Args:
        ctx: MCP context
        username: Unique username for the account
        password: Password for the user (will be hashed)
        full_name: Full name of the user (optional)
        email: Email address of the user (optional)
        groups: Comma-separated list of group names (optional)
        privileges: Comma-separated list of privilege names (optional)
        enabled: Whether the account should be enabled (default: True)
        expires: Expiration date in YYYY-MM-DD format (optional)
        comment: Additional comments about the user (optional)

    Returns:
        JSON string with creation result and new user UUID
    """
    try:
        client = await get_opnsense_client()

        # Validate required parameters
        if not username or not password:
            raise ValidationError("Username and password are required",
                                context={"username": username, "has_password": bool(password)})

        if len(username) < 3:
            raise ValidationError("Username must be at least 3 characters long",
                                context={"username": username})

        if len(password) < 6:
            raise ValidationError("Password must be at least 6 characters long")

        # Prepare user data
        user_data = {
            "user": {
                "enabled": "1" if enabled else "0",
                "name": username,
                "password": password,
                "full_name": full_name,
                "email": email,
                "comment": comment
            }
        }

        # Add groups if specified
        if groups:
            # Convert comma-separated string to list and validate group names
            group_list = [g.strip() for g in groups.split(",") if g.strip()]
            user_data["user"]["groups"] = ",".join(group_list)

        # Add privileges if specified
        if privileges:
            # Convert comma-separated string to list
            priv_list = [p.strip() for p in privileges.split(",") if p.strip()]
            user_data["user"]["priv"] = ",".join(priv_list)

        # Add expiration if specified
        if expires:
            # Basic date format validation
            import re
            if not re.match(r'^\d{4}-\d{2}-\d{2}$', expires):
                raise ValidationError("Expires must be in YYYY-MM-DD format",
                                    context={"expires": expires})
            user_data["user"]["expires"] = expires

        # Create the user
        response = await client.request("POST", API_CORE_USER_ADD,
                                      data=user_data, operation="create_user")

        # Reload configuration if creation was successful
        if response.get("result") == "saved":
            await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_user_create")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "create_user", e)


@mcp.tool(name="update_user", description="Update an existing user account")
async def update_user(
    ctx: Context,
    user_uuid: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    full_name: Optional[str] = None,
    email: Optional[str] = None,
    groups: Optional[str] = None,
    privileges: Optional[str] = None,
    enabled: Optional[bool] = None,
    expires: Optional[str] = None,
    comment: Optional[str] = None
) -> str:
    """Update an existing user account in OPNsense.

    Args:
        ctx: MCP context
        user_uuid: UUID of the user to update
        username: New username (optional)
        password: New password (optional)
        full_name: New full name (optional)
        email: New email address (optional)
        groups: Comma-separated list of group names (optional)
        privileges: Comma-separated list of privilege names (optional)
        enabled: Whether the account should be enabled (optional)
        expires: Expiration date in YYYY-MM-DD format (optional)
        comment: Additional comments about the user (optional)

    Returns:
        JSON string with update result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID
        validate_uuid(user_uuid, "user_uuid")

        # Get current user configuration
        current_user_response = await client.request("GET", f"{API_CORE_USER_GET}/{user_uuid}",
                                                   operation="get_user_for_update")

        if "user" not in current_user_response:
            raise ResourceNotFoundError(f"User with UUID {user_uuid} not found")

        current_user = current_user_response["user"]

        # Update only provided fields
        if username is not None:
            if len(username) < 3:
                raise ValidationError("Username must be at least 3 characters long",
                                    context={"username": username})
            current_user["name"] = username

        if password is not None:
            if len(password) < 6:
                raise ValidationError("Password must be at least 6 characters long")
            current_user["password"] = password

        if full_name is not None:
            current_user["full_name"] = full_name

        if email is not None:
            current_user["email"] = email

        if groups is not None:
            # Convert comma-separated string to list and validate group names
            group_list = [g.strip() for g in groups.split(",") if g.strip()]
            current_user["groups"] = ",".join(group_list)

        if privileges is not None:
            # Convert comma-separated string to list
            priv_list = [p.strip() for p in privileges.split(",") if p.strip()]
            current_user["priv"] = ",".join(priv_list)

        if enabled is not None:
            current_user["enabled"] = "1" if enabled else "0"

        if expires is not None:
            if expires:  # Only validate if not empty
                import re
                if not re.match(r'^\d{4}-\d{2}-\d{2}$', expires):
                    raise ValidationError("Expires must be in YYYY-MM-DD format or empty",
                                        context={"expires": expires})
            current_user["expires"] = expires

        if comment is not None:
            current_user["comment"] = comment

        # Prepare update data
        user_data = {"user": current_user}

        # Update the user
        response = await client.request("POST", f"{API_CORE_USER_SET}/{user_uuid}",
                                      data=user_data, operation="update_user")

        # Reload configuration if update was successful
        if response.get("result") == "saved":
            await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_user_update")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "update_user", e)


@mcp.tool(name="delete_user", description="Delete a user account")
async def delete_user(ctx: Context, user_uuid: str) -> str:
    """Delete a user account from OPNsense.

    This will remove the user account and all associated data including API keys.

    Args:
        ctx: MCP context
        user_uuid: UUID of the user to delete

    Returns:
        JSON string with deletion result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID
        validate_uuid(user_uuid, "user_uuid")

        # Delete the user
        response = await client.request("POST", f"{API_CORE_USER_DEL}/{user_uuid}",
                                      operation="delete_user")

        # Reload configuration if deletion was successful
        if response.get("result") == "deleted":
            await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_user_delete")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "delete_user", e)


@mcp.tool(name="toggle_user", description="Enable or disable a user account")
async def toggle_user(ctx: Context, user_uuid: str, enabled: bool) -> str:
    """Enable or disable a user account.

    Args:
        ctx: MCP context
        user_uuid: UUID of the user to toggle
        enabled: True to enable, False to disable

    Returns:
        JSON string with toggle result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID
        validate_uuid(user_uuid, "user_uuid")

        # Toggle the user
        enabled_int = 1 if enabled else 0
        response = await client.request("POST", f"{API_CORE_USER_TOGGLE}/{user_uuid}/{enabled_int}",
                                      operation="toggle_user")

        # Reload configuration if toggle was successful
        if response.get("result") == "saved":
            await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_user_toggle")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "toggle_user", e)


# ========== GROUP MANAGEMENT ==========

@mcp.tool(name="list_groups", description="List all groups in OPNsense")
async def list_groups(ctx: Context) -> str:
    """List all groups configured in OPNsense.

    Args:
        ctx: MCP context

    Returns:
        JSON string with list of all groups
    """
    try:
        client = await get_opnsense_client()

        response = await client.request("POST", API_CORE_GROUP_SEARCH, operation="list_groups")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "list_groups", e)


@mcp.tool(name="get_group", description="Get details of a specific group")
async def get_group(ctx: Context, group_uuid: Optional[str] = None) -> str:
    """Get details of a specific group or all groups.

    Args:
        ctx: MCP context
        group_uuid: UUID of specific group to retrieve (optional - if not provided, returns all groups)

    Returns:
        JSON string with group details
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID if provided
        if group_uuid:
            validate_uuid(group_uuid, "group_uuid")
            endpoint = f"{API_CORE_GROUP_GET}/{group_uuid}"
        else:
            endpoint = API_CORE_GROUP_GET

        response = await client.request("GET", endpoint, operation="get_group")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_group", e)


@mcp.tool(name="create_group", description="Create a new group")
async def create_group(
    ctx: Context,
    name: str,
    description: str = "",
    privileges: Optional[str] = None,
    members: Optional[str] = None
) -> str:
    """Create a new group in OPNsense.

    Args:
        ctx: MCP context
        name: Name of the group (must be unique)
        description: Description of the group (optional)
        privileges: Comma-separated list of privilege names (optional)
        members: Comma-separated list of usernames to add to group (optional)

    Returns:
        JSON string with creation result and new group UUID
    """
    try:
        client = await get_opnsense_client()

        # Validate required parameters
        if not name:
            raise ValidationError("Group name is required", context={"name": name})

        if len(name) < 2:
            raise ValidationError("Group name must be at least 2 characters long",
                                context={"name": name})

        # Prepare group data
        group_data = {
            "group": {
                "name": name,
                "description": description
            }
        }

        # Add privileges if specified
        if privileges:
            # Convert comma-separated string to list
            priv_list = [p.strip() for p in privileges.split(",") if p.strip()]
            group_data["group"]["priv"] = ",".join(priv_list)

        # Add members if specified
        if members:
            # Convert comma-separated string to list and validate usernames
            member_list = [m.strip() for m in members.split(",") if m.strip()]
            group_data["group"]["member"] = ",".join(member_list)

        # Create the group
        response = await client.request("POST", API_CORE_GROUP_ADD,
                                      data=group_data, operation="create_group")

        # Reload configuration if creation was successful
        if response.get("result") == "saved":
            await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_group_create")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "create_group", e)


@mcp.tool(name="update_group", description="Update an existing group")
async def update_group(
    ctx: Context,
    group_uuid: str,
    name: Optional[str] = None,
    description: Optional[str] = None,
    privileges: Optional[str] = None,
    members: Optional[str] = None
) -> str:
    """Update an existing group in OPNsense.

    Args:
        ctx: MCP context
        group_uuid: UUID of the group to update
        name: New name for the group (optional)
        description: New description for the group (optional)
        privileges: Comma-separated list of privilege names (optional)
        members: Comma-separated list of usernames in group (optional)

    Returns:
        JSON string with update result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID
        validate_uuid(group_uuid, "group_uuid")

        # Get current group configuration
        current_group_response = await client.request("GET", f"{API_CORE_GROUP_GET}/{group_uuid}",
                                                    operation="get_group_for_update")

        if "group" not in current_group_response:
            raise ResourceNotFoundError(f"Group with UUID {group_uuid} not found")

        current_group = current_group_response["group"]

        # Update only provided fields
        if name is not None:
            if len(name) < 2:
                raise ValidationError("Group name must be at least 2 characters long",
                                    context={"name": name})
            current_group["name"] = name

        if description is not None:
            current_group["description"] = description

        if privileges is not None:
            # Convert comma-separated string to list
            priv_list = [p.strip() for p in privileges.split(",") if p.strip()]
            current_group["priv"] = ",".join(priv_list)

        if members is not None:
            # Convert comma-separated string to list and validate usernames
            member_list = [m.strip() for m in members.split(",") if m.strip()]
            current_group["member"] = ",".join(member_list)

        # Prepare update data
        group_data = {"group": current_group}

        # Update the group
        response = await client.request("POST", f"{API_CORE_GROUP_SET}/{group_uuid}",
                                      data=group_data, operation="update_group")

        # Reload configuration if update was successful
        if response.get("result") == "saved":
            await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_group_update")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "update_group", e)


@mcp.tool(name="delete_group", description="Delete a group")
async def delete_group(ctx: Context, group_uuid: str) -> str:
    """Delete a group from OPNsense.

    This will remove the group and update all users who were members of this group.

    Args:
        ctx: MCP context
        group_uuid: UUID of the group to delete

    Returns:
        JSON string with deletion result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID
        validate_uuid(group_uuid, "group_uuid")

        # Delete the group
        response = await client.request("POST", f"{API_CORE_GROUP_DEL}/{group_uuid}",
                                      operation="delete_group")

        # Reload configuration if deletion was successful
        if response.get("result") == "deleted":
            await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_group_delete")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "delete_group", e)


@mcp.tool(name="add_user_to_group", description="Add a user to a group")
async def add_user_to_group(ctx: Context, group_uuid: str, username: str) -> str:
    """Add a user to an existing group.

    Args:
        ctx: MCP context
        group_uuid: UUID of the group to modify
        username: Username to add to the group

    Returns:
        JSON string with update result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID
        validate_uuid(group_uuid, "group_uuid")

        if not username:
            raise ValidationError("Username is required", context={"username": username})

        # Get current group configuration
        current_group_response = await client.request("GET", f"{API_CORE_GROUP_GET}/{group_uuid}",
                                                    operation="get_group_for_member_add")

        if "group" not in current_group_response:
            raise ResourceNotFoundError(f"Group with UUID {group_uuid} not found")

        current_group = current_group_response["group"]

        # Get current members
        current_members = []
        if "member" in current_group and current_group["member"]:
            current_members = [m.strip() for m in current_group["member"].split(",") if m.strip()]

        # Check if user is already a member
        if username in current_members:
            return json.dumps({"result": "no_change", "message": f"User '{username}' is already a member of the group"}, indent=2)

        # Add the new member
        current_members.append(username)
        current_group["member"] = ",".join(current_members)

        # Prepare update data
        group_data = {"group": current_group}

        # Update the group
        response = await client.request("POST", f"{API_CORE_GROUP_SET}/{group_uuid}",
                                      data=group_data, operation="add_user_to_group")

        # Reload configuration if update was successful
        if response.get("result") == "saved":
            await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_group_member_add")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "add_user_to_group", e)


@mcp.tool(name="remove_user_from_group", description="Remove a user from a group")
async def remove_user_from_group(ctx: Context, group_uuid: str, username: str) -> str:
    """Remove a user from an existing group.

    Args:
        ctx: MCP context
        group_uuid: UUID of the group to modify
        username: Username to remove from the group

    Returns:
        JSON string with update result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID
        validate_uuid(group_uuid, "group_uuid")

        if not username:
            raise ValidationError("Username is required", context={"username": username})

        # Get current group configuration
        current_group_response = await client.request("GET", f"{API_CORE_GROUP_GET}/{group_uuid}",
                                                    operation="get_group_for_member_remove")

        if "group" not in current_group_response:
            raise ResourceNotFoundError(f"Group with UUID {group_uuid} not found")

        current_group = current_group_response["group"]

        # Get current members
        current_members = []
        if "member" in current_group and current_group["member"]:
            current_members = [m.strip() for m in current_group["member"].split(",") if m.strip()]

        # Check if user is actually a member
        if username not in current_members:
            return json.dumps({"result": "no_change", "message": f"User '{username}' is not a member of the group"}, indent=2)

        # Remove the member
        current_members.remove(username)
        current_group["member"] = ",".join(current_members)

        # Prepare update data
        group_data = {"group": current_group}

        # Update the group
        response = await client.request("POST", f"{API_CORE_GROUP_SET}/{group_uuid}",
                                      data=group_data, operation="remove_user_from_group")

        # Reload configuration if update was successful
        if response.get("result") == "saved":
            await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_group_member_remove")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "remove_user_from_group", e)


# ========== AUTHENTICATION & PRIVILEGE MANAGEMENT ==========

@mcp.tool(name="list_privileges", description="List all available privileges in OPNsense")
async def list_privileges(ctx: Context) -> str:
    """List all available privileges and their descriptions in OPNsense.

    Args:
        ctx: MCP context

    Returns:
        JSON string with list of all available privileges
    """
    try:
        client = await get_opnsense_client()

        response = await client.request("GET", API_CORE_AUTH_PRIVILEGES, operation="list_privileges")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "list_privileges", e)


@mcp.tool(name="get_user_effective_privileges", description="Get effective privileges for a user")
async def get_user_effective_privileges(ctx: Context, username: str) -> str:
    """Get the effective privileges for a specific user (combines user and group privileges).

    Args:
        ctx: MCP context
        username: Username to get privileges for

    Returns:
        JSON string with user's effective privileges
    """
    try:
        client = await get_opnsense_client()

        if not username:
            raise ValidationError("Username is required", context={"username": username})

        # First get the user details to find their UUID
        users_response = await client.request("POST", API_CORE_USER_SEARCH, operation="search_user_for_privileges")

        user_uuid = None
        if "rows" in users_response:
            for user in users_response["rows"]:
                if user.get("name") == username:
                    user_uuid = user.get("uuid")
                    break

        if not user_uuid:
            raise ResourceNotFoundError(f"User '{username}' not found")

        # Get detailed user information including groups and privileges
        user_details_response = await client.request("GET", f"{API_CORE_USER_GET}/{user_uuid}",
                                                   operation="get_user_privileges")

        if "user" not in user_details_response:
            raise ResourceNotFoundError(f"User details for '{username}' not found")

        user_details = user_details_response["user"]

        # Collect all privileges
        effective_privileges = set()

        # Add direct user privileges
        if "priv" in user_details and user_details["priv"]:
            user_privs = [p.strip() for p in user_details["priv"].split(",") if p.strip()]
            effective_privileges.update(user_privs)

        # Add group privileges
        if "groups" in user_details and user_details["groups"]:
            group_names = [g.strip() for g in user_details["groups"].split(",") if g.strip()]

            # Get all groups to find UUIDs and privileges
            groups_response = await client.request("POST", API_CORE_GROUP_SEARCH, operation="search_groups_for_user_privileges")

            if "rows" in groups_response:
                for group in groups_response["rows"]:
                    if group.get("name") in group_names:
                        # Get detailed group information
                        group_uuid = group.get("uuid")
                        if group_uuid:
                            group_details_response = await client.request("GET", f"{API_CORE_GROUP_GET}/{group_uuid}",
                                                                        operation="get_group_privileges")
                            if "group" in group_details_response:
                                group_details = group_details_response["group"]
                                if "priv" in group_details and group_details["priv"]:
                                    group_privs = [p.strip() for p in group_details["priv"].split(",") if p.strip()]
                                    effective_privileges.update(group_privs)

        # Format result
        result = {
            "username": username,
            "user_uuid": user_uuid,
            "direct_privileges": [p.strip() for p in user_details.get("priv", "").split(",") if p.strip()],
            "group_memberships": [g.strip() for g in user_details.get("groups", "").split(",") if g.strip()],
            "effective_privileges": sorted(list(effective_privileges)),
            "privilege_count": len(effective_privileges)
        }

        return json.dumps(result, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "get_user_effective_privileges", e)


@mcp.tool(name="assign_privilege_to_user", description="Assign a privilege directly to a user")
async def assign_privilege_to_user(ctx: Context, username: str, privilege: str) -> str:
    """Assign a specific privilege directly to a user.

    Args:
        ctx: MCP context
        username: Username to assign privilege to
        privilege: Privilege name to assign

    Returns:
        JSON string with assignment result
    """
    try:
        client = await get_opnsense_client()

        if not username or not privilege:
            raise ValidationError("Username and privilege are required",
                                context={"username": username, "privilege": privilege})

        # Find the user
        users_response = await client.request("POST", API_CORE_USER_SEARCH, operation="search_user_for_privilege_assignment")

        user_uuid = None
        if "rows" in users_response:
            for user in users_response["rows"]:
                if user.get("name") == username:
                    user_uuid = user.get("uuid")
                    break

        if not user_uuid:
            raise ResourceNotFoundError(f"User '{username}' not found")

        # Get current user details
        user_details_response = await client.request("GET", f"{API_CORE_USER_GET}/{user_uuid}",
                                                   operation="get_user_for_privilege_assignment")

        if "user" not in user_details_response:
            raise ResourceNotFoundError(f"User details for '{username}' not found")

        current_user = user_details_response["user"]

        # Get current privileges
        current_privileges = []
        if "priv" in current_user and current_user["priv"]:
            current_privileges = [p.strip() for p in current_user["priv"].split(",") if p.strip()]

        # Check if privilege is already assigned
        if privilege in current_privileges:
            return json.dumps({"result": "no_change", "message": f"Privilege '{privilege}' is already assigned to user '{username}'"}, indent=2)

        # Add the new privilege
        current_privileges.append(privilege)
        current_user["priv"] = ",".join(current_privileges)

        # Update the user
        user_data = {"user": current_user}
        response = await client.request("POST", f"{API_CORE_USER_SET}/{user_uuid}",
                                      data=user_data, operation="assign_privilege_to_user")

        # Reload configuration if update was successful
        if response.get("result") == "saved":
            await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_privilege_assignment")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "assign_privilege_to_user", e)


@mcp.tool(name="revoke_privilege_from_user", description="Revoke a privilege directly from a user")
async def revoke_privilege_from_user(ctx: Context, username: str, privilege: str) -> str:
    """Revoke a specific privilege directly from a user.

    Args:
        ctx: MCP context
        username: Username to revoke privilege from
        privilege: Privilege name to revoke

    Returns:
        JSON string with revocation result
    """
    try:
        client = await get_opnsense_client()

        if not username or not privilege:
            raise ValidationError("Username and privilege are required",
                                context={"username": username, "privilege": privilege})

        # Find the user
        users_response = await client.request("POST", API_CORE_USER_SEARCH, operation="search_user_for_privilege_revocation")

        user_uuid = None
        if "rows" in users_response:
            for user in users_response["rows"]:
                if user.get("name") == username:
                    user_uuid = user.get("uuid")
                    break

        if not user_uuid:
            raise ResourceNotFoundError(f"User '{username}' not found")

        # Get current user details
        user_details_response = await client.request("GET", f"{API_CORE_USER_GET}/{user_uuid}",
                                                   operation="get_user_for_privilege_revocation")

        if "user" not in user_details_response:
            raise ResourceNotFoundError(f"User details for '{username}' not found")

        current_user = user_details_response["user"]

        # Get current privileges
        current_privileges = []
        if "priv" in current_user and current_user["priv"]:
            current_privileges = [p.strip() for p in current_user["priv"].split(",") if p.strip()]

        # Check if privilege is actually assigned
        if privilege not in current_privileges:
            return json.dumps({"result": "no_change", "message": f"Privilege '{privilege}' is not assigned to user '{username}'"}, indent=2)

        # Remove the privilege
        current_privileges.remove(privilege)
        current_user["priv"] = ",".join(current_privileges)

        # Update the user
        user_data = {"user": current_user}
        response = await client.request("POST", f"{API_CORE_USER_SET}/{user_uuid}",
                                      data=user_data, operation="revoke_privilege_from_user")

        # Reload configuration if update was successful
        if response.get("result") == "saved":
            await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_privilege_revocation")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "revoke_privilege_from_user", e)


@mcp.tool(name="list_auth_servers", description="List configured authentication servers")
async def list_auth_servers(ctx: Context) -> str:
    """List all configured authentication servers (LDAP, RADIUS, etc.).

    Args:
        ctx: MCP context

    Returns:
        JSON string with list of authentication servers
    """
    try:
        client = await get_opnsense_client()

        response = await client.request("GET", API_CORE_AUTH_SERVERS, operation="list_auth_servers")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "list_auth_servers", e)


@mcp.tool(name="test_user_authentication", description="Test user authentication against configured servers")
async def test_user_authentication(ctx: Context, username: str, auth_server: Optional[str] = None) -> str:
    """Test user authentication against a specific authentication server or all servers.

    Args:
        ctx: MCP context
        username: Username to test authentication for
        auth_server: Specific authentication server to test against (optional)

    Returns:
        JSON string with authentication test results
    """
    try:
        client = await get_opnsense_client()

        if not username:
            raise ValidationError("Username is required", context={"username": username})

        # Prepare test data
        test_data = {
            "username": username
        }

        if auth_server:
            test_data["auth_server"] = auth_server

        response = await client.request("POST", API_CORE_AUTH_TEST,
                                      data=test_data, operation="test_user_authentication")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "test_user_authentication", e)


# ========== USER MANAGEMENT HELPER TOOLS ==========

@mcp.tool(name="create_admin_user", description="Create a new administrative user with full system privileges")
async def create_admin_user(ctx: Context, username: str, password: str,
                           full_name: str = "", email: str = "") -> str:
    """Create a new administrative user with full system privileges.

    Args:
        ctx: MCP context
        username: Username for the new admin user
        password: Password for the user
        full_name: Full name of the user (optional)
        email: Email address of the user (optional)

    Returns:
        JSON response with creation status and user details
    """
    try:
        client = await get_opnsense_client()

        # Create the user first
        user_data = {
            "user": {
                "name": username,
                "password": password,
                "full_name": full_name or username,
                "email": email,
                "disabled": "0",
                "expires": "",
                "comment": "Administrative user created via MCP"
            }
        }

        response = await client.request("POST", API_CORE_USER_ADD,
                                      data=user_data, operation="create_admin_user")

        if response.get("result") != "saved":
            return json.dumps({"error": "Failed to create user", "response": response}, indent=2)

        user_uuid = response.get("uuid")
        if not user_uuid:
            return json.dumps({"error": "User created but UUID not returned", "response": response}, indent=2)

        # Get all available privileges
        privileges_response = await client.request("GET", API_CORE_AUTH_PRIVILEGES,
                                                 operation="get_privileges_for_admin")

        if "privileges" not in privileges_response:
            return json.dumps({
                "user_created": True,
                "uuid": user_uuid,
                "warning": "User created but could not retrieve privileges for assignment"
            }, indent=2)

        # Assign all privileges to make this a full admin
        all_privileges = list(privileges_response["privileges"].keys())
        privilege_string = ",".join(all_privileges)

        # Update user with all privileges
        update_data = {
            "user": {
                "name": username,
                "password": password,
                "full_name": full_name or username,
                "email": email,
                "disabled": "0",
                "expires": "",
                "comment": "Administrative user created via MCP",
                "priv": privilege_string
            }
        }

        await client.request("POST", f"{API_CORE_USER_SET}/{user_uuid}",
                           data=update_data, operation="assign_admin_privileges")

        # Reload configuration
        await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_admin_creation")

        return json.dumps({
            "result": "success",
            "message": f"Administrative user '{username}' created successfully",
            "uuid": user_uuid,
            "privileges_assigned": len(all_privileges),
            "full_admin": True
        }, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "create_admin_user", e)


@mcp.tool(name="create_readonly_user", description="Create a new read-only user with limited system access")
async def create_readonly_user(ctx: Context, username: str, password: str,
                              full_name: str = "", email: str = "") -> str:
    """Create a new read-only user with limited system access.

    Args:
        ctx: MCP context
        username: Username for the new read-only user
        password: Password for the user
        full_name: Full name of the user (optional)
        email: Email address of the user (optional)

    Returns:
        JSON response with creation status and user details
    """
    try:
        client = await get_opnsense_client()

        # Define read-only privileges (common monitoring/viewing privileges)
        readonly_privileges = [
            "page-all",                    # Basic page access
            "page-status-system",          # System status
            "page-status-interfaces",      # Interface status
            "page-status-logs",           # Log viewing
            "page-diagnostics-all",       # Diagnostic tools
            "page-status-dashboard",      # Dashboard access
            "page-firewall-rules",        # Firewall rule viewing (read-only)
            "page-interfaces-overview"    # Interface overview
        ]

        # Create user with read-only privileges
        user_data = {
            "user": {
                "name": username,
                "password": password,
                "full_name": full_name or username,
                "email": email,
                "disabled": "0",
                "expires": "",
                "comment": "Read-only user created via MCP",
                "priv": ",".join(readonly_privileges)
            }
        }

        response = await client.request("POST", API_CORE_USER_ADD,
                                      data=user_data, operation="create_readonly_user")

        if response.get("result") != "saved":
            return json.dumps({"error": "Failed to create read-only user", "response": response}, indent=2)

        # Reload configuration
        await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_readonly_creation")

        return json.dumps({
            "result": "success",
            "message": f"Read-only user '{username}' created successfully",
            "uuid": response.get("uuid"),
            "privileges_assigned": readonly_privileges,
            "access_level": "read-only"
        }, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "create_readonly_user", e)


@mcp.tool(name="reset_user_password", description="Reset a user's password by username")
async def reset_user_password(ctx: Context, username: str, new_password: str) -> str:
    """Reset a user's password by username.

    Args:
        ctx: MCP context
        username: Username of the user whose password to reset
        new_password: New password to set

    Returns:
        JSON response with password reset status
    """
    try:
        client = await get_opnsense_client()

        # First, find the user by username
        search_response = await client.request("POST", API_CORE_USER_SEARCH,
                                             operation="search_user_for_password_reset")

        if "rows" not in search_response:
            return json.dumps({"error": "Failed to retrieve user list"}, indent=2)

        user_uuid = None
        user_data = None
        for user in search_response["rows"]:
            if user.get("name") == username:
                user_uuid = user.get("uuid")
                user_data = user
                break

        if not user_uuid:
            return json.dumps({"error": f"User '{username}' not found"}, indent=2)

        # Get full user details
        user_detail_response = await client.request("GET", f"{API_CORE_USER_GET}/{user_uuid}",
                                                   operation="get_user_details_for_password_reset")

        if "user" not in user_detail_response:
            return json.dumps({"error": "Failed to retrieve user details"}, indent=2)

        current_user = user_detail_response["user"]

        # Update user with new password (preserve all other settings)
        update_data = {
            "user": {
                "name": current_user.get("name", username),
                "password": new_password,
                "full_name": current_user.get("full_name", ""),
                "email": current_user.get("email", ""),
                "disabled": current_user.get("disabled", "0"),
                "expires": current_user.get("expires", ""),
                "comment": current_user.get("comment", ""),
                "priv": current_user.get("priv", ""),
                "groups": current_user.get("groups", "")
            }
        }

        response = await client.request("POST", f"{API_CORE_USER_SET}/{user_uuid}",
                                      data=update_data, operation="reset_user_password")

        if response.get("result") != "saved":
            return json.dumps({"error": "Failed to reset password", "response": response}, indent=2)

        # Reload configuration
        await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_password_reset")

        return json.dumps({
            "result": "success",
            "message": f"Password successfully reset for user '{username}'",
            "uuid": user_uuid
        }, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "reset_user_password", e)


@mcp.tool(name="bulk_user_creation", description="Create multiple users from a template specification")
async def bulk_user_creation(ctx: Context, user_template: str) -> str:
    """Create multiple users from a template specification.

    Args:
        ctx: MCP context
        user_template: JSON string containing user template and list of users to create.
                      Format: {
                        "template": {
                          "password": "default_password",
                          "privileges": ["priv1", "priv2"],
                          "groups": ["group1"],
                          "expires": "",
                          "disabled": "0"
                        },
                        "users": [
                          {"username": "user1", "full_name": "User One", "email": "user1@example.com"},
                          {"username": "user2", "full_name": "User Two", "email": "user2@example.com"}
                        ]
                      }

    Returns:
        JSON response with bulk creation results
    """
    try:
        client = await get_opnsense_client()

        # Parse the template
        try:
            template_data = json.loads(user_template)
        except json.JSONDecodeError as e:
            return json.dumps({"error": f"Invalid JSON template: {str(e)}"}, indent=2)

        if "template" not in template_data or "users" not in template_data:
            return json.dumps({"error": "Template must contain 'template' and 'users' sections"}, indent=2)

        template = template_data["template"]
        users_to_create = template_data["users"]

        results = []
        successful_creations = 0

        for user_spec in users_to_create:
            try:
                username = user_spec.get("username")
                if not username:
                    results.append({"error": "Username required for each user", "user_spec": user_spec})
                    continue

                # Build user data from template and user-specific overrides
                user_data = {
                    "user": {
                        "name": username,
                        "password": user_spec.get("password", template.get("password", "")),
                        "full_name": user_spec.get("full_name", template.get("full_name", username)),
                        "email": user_spec.get("email", template.get("email", "")),
                        "disabled": user_spec.get("disabled", template.get("disabled", "0")),
                        "expires": user_spec.get("expires", template.get("expires", "")),
                        "comment": user_spec.get("comment", template.get("comment", "Bulk created via MCP")),
                        "priv": ",".join(user_spec.get("privileges", template.get("privileges", []))),
                        "groups": ",".join(user_spec.get("groups", template.get("groups", [])))
                    }
                }

                response = await client.request("POST", API_CORE_USER_ADD,
                                              data=user_data, operation=f"bulk_create_user_{username}")

                if response.get("result") == "saved":
                    results.append({
                        "username": username,
                        "status": "success",
                        "uuid": response.get("uuid")
                    })
                    successful_creations += 1
                else:
                    results.append({
                        "username": username,
                        "status": "failed",
                        "error": response.get("validations", "Unknown error")
                    })

            except Exception as user_error:
                results.append({
                    "username": user_spec.get("username", "unknown"),
                    "status": "failed",
                    "error": str(user_error)
                })

        # Reload configuration if any users were created
        if successful_creations > 0:
            await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_bulk_creation")

        return json.dumps({
            "result": "completed",
            "total_users": len(users_to_create),
            "successful_creations": successful_creations,
            "failed_creations": len(users_to_create) - successful_creations,
            "details": results
        }, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "bulk_user_creation", e)


@mcp.tool(name="setup_user_group_template", description="Create a user group template with predefined privileges")
async def setup_user_group_template(ctx: Context, template_name: str,
                                   privileges: str, description: str = "") -> str:
    """Create a user group template with predefined privileges for common roles.

    Args:
        ctx: MCP context
        template_name: Name for the group template
        privileges: Comma-separated list of privilege names to assign to the group
        description: Description of the group's purpose

    Returns:
        JSON response with group creation status
    """
    try:
        client = await get_opnsense_client()

        # Convert privileges string to list
        privilege_list = [p.strip() for p in privileges.split(",") if p.strip()]

        # Validate privileges exist
        privileges_response = await client.request("GET", API_CORE_AUTH_PRIVILEGES,
                                                 operation="validate_privileges_for_template")

        if "privileges" not in privileges_response:
            return json.dumps({"error": "Could not retrieve available privileges"}, indent=2)

        available_privileges = set(privileges_response["privileges"].keys())
        invalid_privileges = [p for p in privilege_list if p not in available_privileges]

        if invalid_privileges:
            return json.dumps({
                "error": "Invalid privileges specified",
                "invalid_privileges": invalid_privileges,
                "available_privileges": list(available_privileges)
            }, indent=2)

        # Create the group
        group_data = {
            "group": {
                "name": template_name,
                "description": description or f"Template group: {template_name}",
                "priv": ",".join(privilege_list)
            }
        }

        response = await client.request("POST", API_CORE_GROUP_ADD,
                                      data=group_data, operation="create_group_template")

        if response.get("result") != "saved":
            return json.dumps({"error": "Failed to create group template", "response": response}, indent=2)

        # Reload configuration
        await client.request("POST", API_CORE_CONFIG_RELOAD, operation="reload_config_after_template_creation")

        return json.dumps({
            "result": "success",
            "message": f"Group template '{template_name}' created successfully",
            "uuid": response.get("uuid"),
            "privileges_assigned": privilege_list,
            "privilege_count": len(privilege_list)
        }, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "setup_user_group_template", e)
