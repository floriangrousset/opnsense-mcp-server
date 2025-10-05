"""
Traffic Shaping and QoS Management Domain

This module provides comprehensive traffic shaping and Quality of Service (QoS) management
capabilities for OPNsense, including pipes, queues, rules, and common use case helpers.

Architecture:
- Pipes: Define hard bandwidth limits with configurable schedulers
- Queues: Provide weighted bandwidth sharing within pipes
- Rules: Apply shaping policies to specific traffic flows

Supported Features:
- Bandwidth limitation with multiple metrics (bit/s, Kbit/s, Mbit/s, Gbit/s)
- Multiple scheduler algorithms (FIFO, DRR, QFQ, FQ-CoDel, FQ-PIE)
- Weighted queue management for bandwidth sharing
- Comprehensive rule matching (interface, protocol, source, destination)
- Common use case helpers (user limits, VoIP priority, gaming, guest networks)
"""

import json
from typing import Optional
from mcp.server.fastmcp import Context

from ..main import mcp
from .configuration import get_opnsense_client
from ..core.exceptions import ValidationError, ResourceNotFoundError
from ..shared.error_handlers import handle_tool_error, validate_uuid
from ..shared.constants import (
    # Service endpoints
    API_TRAFFICSHAPER_SERVICE_RECONFIGURE,
    API_TRAFFICSHAPER_SERVICE_STATISTICS,

    # Pipe endpoints
    API_TRAFFICSHAPER_SETTINGS_ADD_PIPE,
    API_TRAFFICSHAPER_SETTINGS_DEL_PIPE,
    API_TRAFFICSHAPER_SETTINGS_GET_PIPE,
    API_TRAFFICSHAPER_SETTINGS_SET_PIPE,
    API_TRAFFICSHAPER_SETTINGS_TOGGLE_PIPE,
    API_TRAFFICSHAPER_SETTINGS_SEARCH_PIPES,

    # Queue endpoints
    API_TRAFFICSHAPER_SETTINGS_ADD_QUEUE,
    API_TRAFFICSHAPER_SETTINGS_DEL_QUEUE,
    API_TRAFFICSHAPER_SETTINGS_GET_QUEUE,
    API_TRAFFICSHAPER_SETTINGS_SET_QUEUE,
    API_TRAFFICSHAPER_SETTINGS_TOGGLE_QUEUE,
    API_TRAFFICSHAPER_SETTINGS_SEARCH_QUEUES,

    # Rule endpoints
    API_TRAFFICSHAPER_SETTINGS_ADD_RULE,
    API_TRAFFICSHAPER_SETTINGS_DEL_RULE,
    API_TRAFFICSHAPER_SETTINGS_GET_RULE,
    API_TRAFFICSHAPER_SETTINGS_SET_RULE,
    API_TRAFFICSHAPER_SETTINGS_TOGGLE_RULE,
    API_TRAFFICSHAPER_SETTINGS_SEARCH_RULES,

    # General settings
    API_TRAFFICSHAPER_SETTINGS_GET,
)


# ========== CORE TRAFFIC SHAPER MANAGEMENT ==========

@mcp.tool(name="traffic_shaper_get_status", description="Get traffic shaper service status and statistics")
async def traffic_shaper_get_status(ctx: Context) -> str:
    """Get traffic shaper service status and detailed statistics.

    Args:
        ctx: MCP context

    Returns:
        JSON string containing traffic shaper status and statistics
    """
    try:
        client = await get_opnsense_client()

        # Get service status and statistics
        statistics_response = await client.request("GET", API_TRAFFICSHAPER_SERVICE_STATISTICS, operation="get_traffic_shaper_statistics")

        return json.dumps(statistics_response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_get_status", e)


@mcp.tool(name="traffic_shaper_reconfigure", description="Apply traffic shaper configuration changes")
async def traffic_shaper_reconfigure(ctx: Context) -> str:
    """Reconfigure and apply all traffic shaper changes.

    This should be called after making configuration changes to pipes, queues, or rules
    to ensure the changes take effect.

    Args:
        ctx: MCP context

    Returns:
        JSON string with reconfiguration status
    """
    try:
        client = await get_opnsense_client()

        # Reconfigure the traffic shaper service
        response = await client.request("POST", API_TRAFFICSHAPER_SERVICE_RECONFIGURE, operation="reconfigure_traffic_shaper")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_reconfigure", e)


@mcp.tool(name="traffic_shaper_get_settings", description="Get general traffic shaper settings and configuration")
async def traffic_shaper_get_settings(ctx: Context) -> str:
    """Get general traffic shaper settings and configuration.

    Args:
        ctx: MCP context

    Returns:
        JSON string with general traffic shaper settings
    """
    try:
        client = await get_opnsense_client()

        response = await client.request("GET", API_TRAFFICSHAPER_SETTINGS_GET, operation="get_traffic_shaper_settings")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_get_settings", e)


# ========== PIPE MANAGEMENT ==========

@mcp.tool(name="traffic_shaper_list_pipes", description="List all traffic shaper pipes with optional filtering")
async def traffic_shaper_list_pipes(ctx: Context) -> str:
    """List all traffic shaper pipes with their configurations.

    Args:
        ctx: MCP context

    Returns:
        JSON string with list of all pipes
    """
    try:
        client = await get_opnsense_client()

        response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_SEARCH_PIPES, operation="search_traffic_shaper_pipes")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_list_pipes", e)


@mcp.tool(name="traffic_shaper_get_pipe", description="Get details of a specific traffic shaper pipe")
async def traffic_shaper_get_pipe(ctx: Context, pipe_uuid: Optional[str] = None) -> str:
    """Get details of a specific traffic shaper pipe or all pipes.

    Args:
        ctx: MCP context
        pipe_uuid: UUID of specific pipe to retrieve (optional - if not provided, returns all pipes)

    Returns:
        JSON string with pipe details
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID if provided
        if pipe_uuid:
            validate_uuid(pipe_uuid, "pipe_uuid")
            endpoint = f"{API_TRAFFICSHAPER_SETTINGS_GET_PIPE}/{pipe_uuid}"
        else:
            endpoint = API_TRAFFICSHAPER_SETTINGS_GET_PIPE

        response = await client.request("GET", endpoint, operation="get_traffic_shaper_pipe")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_get_pipe", e)


@mcp.tool(name="traffic_shaper_create_pipe", description="Create a new traffic shaper pipe for bandwidth limiting")
async def traffic_shaper_create_pipe(
    ctx: Context,
    bandwidth: int,
    bandwidth_metric: str = "Mbit/s",
    queue_size: int = 50,
    scheduler: str = "FIFO",
    description: str = "",
    enabled: bool = True
) -> str:
    """Create a new traffic shaper pipe with specified bandwidth limits.

    Args:
        ctx: MCP context
        bandwidth: Bandwidth limit (positive integer)
        bandwidth_metric: Bandwidth unit (bit/s, Kbit/s, Mbit/s, Gbit/s)
        queue_size: Queue size in slots (2-100)
        scheduler: Scheduler algorithm (FIFO, DRR, QFQ, FQ-CoDel, FQ-PIE)
        description: Description for the pipe
        enabled: Whether the pipe should be enabled

    Returns:
        JSON string with creation result and new pipe UUID
    """
    try:
        client = await get_opnsense_client()

        # Validate parameters
        if bandwidth <= 0:
            raise ValidationError("Bandwidth must be a positive integer",
                                context={"bandwidth": bandwidth})

        if bandwidth_metric not in ["bit/s", "Kbit/s", "Mbit/s", "Gbit/s"]:
            raise ValidationError("Invalid bandwidth metric",
                                context={"bandwidth_metric": bandwidth_metric,
                                       "valid_options": ["bit/s", "Kbit/s", "Mbit/s", "Gbit/s"]})

        if not (2 <= queue_size <= 100):
            raise ValidationError("Queue size must be between 2 and 100",
                                context={"queue_size": queue_size})

        if scheduler not in ["FIFO", "DRR", "QFQ", "FQ-CoDel", "FQ-PIE"]:
            raise ValidationError("Invalid scheduler",
                                context={"scheduler": scheduler,
                                       "valid_options": ["FIFO", "DRR", "QFQ", "FQ-CoDel", "FQ-PIE"]})

        # Prepare pipe data
        pipe_data = {
            "pipe": {
                "enabled": "1" if enabled else "0",
                "bandwidth": str(bandwidth),
                "bandwidthMetric": bandwidth_metric,
                "queue": str(queue_size),
                "scheduler": scheduler,
                "description": description
            }
        }

        # Create the pipe
        response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_ADD_PIPE,
                                      data=pipe_data, operation="create_traffic_shaper_pipe")

        # Apply configuration if creation was successful
        if response.get("result") == "saved":
            await client.request("POST", API_TRAFFICSHAPER_SERVICE_RECONFIGURE, operation="reconfigure_after_pipe_create")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_create_pipe", e)


@mcp.tool(name="traffic_shaper_update_pipe", description="Update an existing traffic shaper pipe configuration")
async def traffic_shaper_update_pipe(
    ctx: Context,
    pipe_uuid: str,
    bandwidth: Optional[int] = None,
    bandwidth_metric: Optional[str] = None,
    queue_size: Optional[int] = None,
    scheduler: Optional[str] = None,
    description: Optional[str] = None,
    enabled: Optional[bool] = None
) -> str:
    """Update an existing traffic shaper pipe configuration.

    Args:
        ctx: MCP context
        pipe_uuid: UUID of the pipe to update
        bandwidth: Bandwidth limit (positive integer, optional)
        bandwidth_metric: Bandwidth unit (bit/s, Kbit/s, Mbit/s, Gbit/s, optional)
        queue_size: Queue size in slots (2-100, optional)
        scheduler: Scheduler algorithm (FIFO, DRR, QFQ, FQ-CoDel, FQ-PIE, optional)
        description: Description for the pipe (optional)
        enabled: Whether the pipe should be enabled (optional)

    Returns:
        JSON string with update result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID
        validate_uuid(pipe_uuid, "pipe_uuid")

        # Get current pipe configuration
        current_pipe_response = await client.request("GET", f"{API_TRAFFICSHAPER_SETTINGS_GET_PIPE}/{pipe_uuid}",
                                                   operation="get_pipe_for_update")

        if "pipe" not in current_pipe_response:
            raise ResourceNotFoundError(f"Pipe with UUID {pipe_uuid} not found")

        current_pipe = current_pipe_response["pipe"]

        # Update only provided fields
        if bandwidth is not None:
            if bandwidth <= 0:
                raise ValidationError("Bandwidth must be a positive integer",
                                    context={"bandwidth": bandwidth})
            current_pipe["bandwidth"] = str(bandwidth)

        if bandwidth_metric is not None:
            if bandwidth_metric not in ["bit/s", "Kbit/s", "Mbit/s", "Gbit/s"]:
                raise ValidationError("Invalid bandwidth metric",
                                    context={"bandwidth_metric": bandwidth_metric})
            current_pipe["bandwidthMetric"] = bandwidth_metric

        if queue_size is not None:
            if not (2 <= queue_size <= 100):
                raise ValidationError("Queue size must be between 2 and 100",
                                    context={"queue_size": queue_size})
            current_pipe["queue"] = str(queue_size)

        if scheduler is not None:
            if scheduler not in ["FIFO", "DRR", "QFQ", "FQ-CoDel", "FQ-PIE"]:
                raise ValidationError("Invalid scheduler",
                                    context={"scheduler": scheduler})
            current_pipe["scheduler"] = scheduler

        if description is not None:
            current_pipe["description"] = description

        if enabled is not None:
            current_pipe["enabled"] = "1" if enabled else "0"

        # Prepare update data
        pipe_data = {"pipe": current_pipe}

        # Update the pipe
        response = await client.request("POST", f"{API_TRAFFICSHAPER_SETTINGS_SET_PIPE}/{pipe_uuid}",
                                      data=pipe_data, operation="update_traffic_shaper_pipe")

        # Apply configuration if update was successful
        if response.get("result") == "saved":
            await client.request("POST", API_TRAFFICSHAPER_SERVICE_RECONFIGURE, operation="reconfigure_after_pipe_update")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_update_pipe", e)


@mcp.tool(name="traffic_shaper_delete_pipe", description="Delete a traffic shaper pipe")
async def traffic_shaper_delete_pipe(ctx: Context, pipe_uuid: str) -> str:
    """Delete a traffic shaper pipe.

    Note: This will also delete any queues and rules that reference this pipe.

    Args:
        ctx: MCP context
        pipe_uuid: UUID of the pipe to delete

    Returns:
        JSON string with deletion result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID
        validate_uuid(pipe_uuid, "pipe_uuid")

        # Delete the pipe
        response = await client.request("POST", f"{API_TRAFFICSHAPER_SETTINGS_DEL_PIPE}/{pipe_uuid}",
                                      operation="delete_traffic_shaper_pipe")

        # Apply configuration if deletion was successful
        if response.get("result") == "deleted":
            await client.request("POST", API_TRAFFICSHAPER_SERVICE_RECONFIGURE, operation="reconfigure_after_pipe_delete")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_delete_pipe", e)


@mcp.tool(name="traffic_shaper_toggle_pipe", description="Enable or disable a traffic shaper pipe")
async def traffic_shaper_toggle_pipe(ctx: Context, pipe_uuid: str, enabled: bool) -> str:
    """Enable or disable a traffic shaper pipe.

    Args:
        ctx: MCP context
        pipe_uuid: UUID of the pipe to toggle
        enabled: True to enable, False to disable

    Returns:
        JSON string with toggle result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID
        validate_uuid(pipe_uuid, "pipe_uuid")

        # Toggle the pipe
        enabled_int = 1 if enabled else 0
        response = await client.request("POST", f"{API_TRAFFICSHAPER_SETTINGS_TOGGLE_PIPE}/{pipe_uuid}/{enabled_int}",
                                      operation="toggle_traffic_shaper_pipe")

        # Apply configuration if toggle was successful
        if response.get("result") == "saved":
            await client.request("POST", API_TRAFFICSHAPER_SERVICE_RECONFIGURE, operation="reconfigure_after_pipe_toggle")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_toggle_pipe", e)


# ========== QUEUE MANAGEMENT ==========

@mcp.tool(name="traffic_shaper_list_queues", description="List all traffic shaper queues with optional filtering")
async def traffic_shaper_list_queues(ctx: Context) -> str:
    """List all traffic shaper queues with their configurations.

    Args:
        ctx: MCP context

    Returns:
        JSON string with list of all queues
    """
    try:
        client = await get_opnsense_client()

        response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_SEARCH_QUEUES, operation="search_traffic_shaper_queues")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_list_queues", e)


@mcp.tool(name="traffic_shaper_get_queue", description="Get details of a specific traffic shaper queue")
async def traffic_shaper_get_queue(ctx: Context, queue_uuid: Optional[str] = None) -> str:
    """Get details of a specific traffic shaper queue or all queues.

    Args:
        ctx: MCP context
        queue_uuid: UUID of specific queue to retrieve (optional - if not provided, returns all queues)

    Returns:
        JSON string with queue details
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID if provided
        if queue_uuid:
            validate_uuid(queue_uuid, "queue_uuid")
            endpoint = f"{API_TRAFFICSHAPER_SETTINGS_GET_QUEUE}/{queue_uuid}"
        else:
            endpoint = API_TRAFFICSHAPER_SETTINGS_GET_QUEUE

        response = await client.request("GET", endpoint, operation="get_traffic_shaper_queue")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_get_queue", e)


@mcp.tool(name="traffic_shaper_create_queue", description="Create a new traffic shaper queue for weighted bandwidth sharing")
async def traffic_shaper_create_queue(
    ctx: Context,
    pipe_uuid: str,
    weight: int = 10,
    description: str = "",
    enabled: bool = True
) -> str:
    """Create a new traffic shaper queue for weighted bandwidth sharing within a pipe.

    Args:
        ctx: MCP context
        pipe_uuid: UUID of the parent pipe that this queue belongs to
        weight: Weight for bandwidth allocation within pipe (1-100)
        description: Description for the queue
        enabled: Whether the queue should be enabled

    Returns:
        JSON string with creation result and new queue UUID
    """
    try:
        client = await get_opnsense_client()

        # Validate parameters
        validate_uuid(pipe_uuid, "pipe_uuid")

        if not (1 <= weight <= 100):
            raise ValidationError("Weight must be between 1 and 100",
                                context={"weight": weight})

        # Verify the pipe exists
        pipe_response = await client.request("GET", f"{API_TRAFFICSHAPER_SETTINGS_GET_PIPE}/{pipe_uuid}",
                                           operation="verify_pipe_exists")
        if "pipe" not in pipe_response:
            raise ResourceNotFoundError(f"Parent pipe with UUID {pipe_uuid} not found")

        # Prepare queue data
        queue_data = {
            "queue": {
                "enabled": "1" if enabled else "0",
                "pipe": pipe_uuid,
                "weight": str(weight),
                "description": description
            }
        }

        # Create the queue
        response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_ADD_QUEUE,
                                      data=queue_data, operation="create_traffic_shaper_queue")

        # Apply configuration if creation was successful
        if response.get("result") == "saved":
            await client.request("POST", API_TRAFFICSHAPER_SERVICE_RECONFIGURE, operation="reconfigure_after_queue_create")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_create_queue", e)


@mcp.tool(name="traffic_shaper_update_queue", description="Update an existing traffic shaper queue configuration")
async def traffic_shaper_update_queue(
    ctx: Context,
    queue_uuid: str,
    pipe_uuid: Optional[str] = None,
    weight: Optional[int] = None,
    description: Optional[str] = None,
    enabled: Optional[bool] = None
) -> str:
    """Update an existing traffic shaper queue configuration.

    Args:
        ctx: MCP context
        queue_uuid: UUID of the queue to update
        pipe_uuid: UUID of the parent pipe (optional)
        weight: Weight for bandwidth allocation within pipe (1-100, optional)
        description: Description for the queue (optional)
        enabled: Whether the queue should be enabled (optional)

    Returns:
        JSON string with update result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUIDs
        validate_uuid(queue_uuid, "queue_uuid")
        if pipe_uuid:
            validate_uuid(pipe_uuid, "pipe_uuid")

        # Get current queue configuration
        current_queue_response = await client.request("GET", f"{API_TRAFFICSHAPER_SETTINGS_GET_QUEUE}/{queue_uuid}",
                                                    operation="get_queue_for_update")

        if "queue" not in current_queue_response:
            raise ResourceNotFoundError(f"Queue with UUID {queue_uuid} not found")

        current_queue = current_queue_response["queue"]

        # Update only provided fields
        if pipe_uuid is not None:
            # Verify the new pipe exists
            pipe_response = await client.request("GET", f"{API_TRAFFICSHAPER_SETTINGS_GET_PIPE}/{pipe_uuid}",
                                               operation="verify_new_pipe_exists")
            if "pipe" not in pipe_response:
                raise ResourceNotFoundError(f"Parent pipe with UUID {pipe_uuid} not found")
            current_queue["pipe"] = pipe_uuid

        if weight is not None:
            if not (1 <= weight <= 100):
                raise ValidationError("Weight must be between 1 and 100",
                                    context={"weight": weight})
            current_queue["weight"] = str(weight)

        if description is not None:
            current_queue["description"] = description

        if enabled is not None:
            current_queue["enabled"] = "1" if enabled else "0"

        # Prepare update data
        queue_data = {"queue": current_queue}

        # Update the queue
        response = await client.request("POST", f"{API_TRAFFICSHAPER_SETTINGS_SET_QUEUE}/{queue_uuid}",
                                      data=queue_data, operation="update_traffic_shaper_queue")

        # Apply configuration if update was successful
        if response.get("result") == "saved":
            await client.request("POST", API_TRAFFICSHAPER_SERVICE_RECONFIGURE, operation="reconfigure_after_queue_update")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_update_queue", e)


@mcp.tool(name="traffic_shaper_delete_queue", description="Delete a traffic shaper queue")
async def traffic_shaper_delete_queue(ctx: Context, queue_uuid: str) -> str:
    """Delete a traffic shaper queue.

    Note: This will also delete any rules that reference this queue.

    Args:
        ctx: MCP context
        queue_uuid: UUID of the queue to delete

    Returns:
        JSON string with deletion result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID
        validate_uuid(queue_uuid, "queue_uuid")

        # Delete the queue
        response = await client.request("POST", f"{API_TRAFFICSHAPER_SETTINGS_DEL_QUEUE}/{queue_uuid}",
                                      operation="delete_traffic_shaper_queue")

        # Apply configuration if deletion was successful
        if response.get("result") == "deleted":
            await client.request("POST", API_TRAFFICSHAPER_SERVICE_RECONFIGURE, operation="reconfigure_after_queue_delete")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_delete_queue", e)


@mcp.tool(name="traffic_shaper_toggle_queue", description="Enable or disable a traffic shaper queue")
async def traffic_shaper_toggle_queue(ctx: Context, queue_uuid: str, enabled: bool) -> str:
    """Enable or disable a traffic shaper queue.

    Args:
        ctx: MCP context
        queue_uuid: UUID of the queue to toggle
        enabled: True to enable, False to disable

    Returns:
        JSON string with toggle result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID
        validate_uuid(queue_uuid, "queue_uuid")

        # Toggle the queue
        enabled_int = 1 if enabled else 0
        response = await client.request("POST", f"{API_TRAFFICSHAPER_SETTINGS_TOGGLE_QUEUE}/{queue_uuid}/{enabled_int}",
                                      operation="toggle_traffic_shaper_queue")

        # Apply configuration if toggle was successful
        if response.get("result") == "saved":
            await client.request("POST", API_TRAFFICSHAPER_SERVICE_RECONFIGURE, operation="reconfigure_after_queue_toggle")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_toggle_queue", e)


# ========== RULE MANAGEMENT ==========

@mcp.tool(name="traffic_shaper_list_rules", description="List all traffic shaper rules with optional filtering")
async def traffic_shaper_list_rules(ctx: Context) -> str:
    """List all traffic shaper rules with their configurations.

    Args:
        ctx: MCP context

    Returns:
        JSON string with list of all rules
    """
    try:
        client = await get_opnsense_client()

        response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_SEARCH_RULES, operation="search_traffic_shaper_rules")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_list_rules", e)


@mcp.tool(name="traffic_shaper_get_rule", description="Get details of a specific traffic shaper rule")
async def traffic_shaper_get_rule(ctx: Context, rule_uuid: Optional[str] = None) -> str:
    """Get details of a specific traffic shaper rule or all rules.

    Args:
        ctx: MCP context
        rule_uuid: UUID of specific rule to retrieve (optional - if not provided, returns all rules)

    Returns:
        JSON string with rule details
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID if provided
        if rule_uuid:
            validate_uuid(rule_uuid, "rule_uuid")
            endpoint = f"{API_TRAFFICSHAPER_SETTINGS_GET_RULE}/{rule_uuid}"
        else:
            endpoint = API_TRAFFICSHAPER_SETTINGS_GET_RULE

        response = await client.request("GET", endpoint, operation="get_traffic_shaper_rule")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_get_rule", e)


@mcp.tool(name="traffic_shaper_create_rule", description="Create a new traffic shaper rule to apply QoS policies")
async def traffic_shaper_create_rule(
    ctx: Context,
    target_uuid: str,
    interface: str,
    protocol: str = "IP",
    source: str = "any",
    destination: str = "any",
    sequence: int = 1,
    description: str = "",
    enabled: bool = True
) -> str:
    """Create a new traffic shaper rule to apply QoS policies to specific traffic flows.

    Args:
        ctx: MCP context
        target_uuid: UUID of the target pipe or queue to apply traffic shaping
        interface: Interface name where rule applies (e.g., 'wan', 'lan')
        protocol: Protocol to match (IP, TCP, UDP, ICMP, etc.)
        source: Source network/address (default: 'any')
        destination: Destination network/address (default: 'any')
        sequence: Rule evaluation order (1-1000000)
        description: Description for the rule
        enabled: Whether the rule should be enabled

    Returns:
        JSON string with creation result and new rule UUID
    """
    try:
        client = await get_opnsense_client()

        # Validate parameters
        validate_uuid(target_uuid, "target_uuid")

        if not (1 <= sequence <= 1000000):
            raise ValidationError("Sequence must be between 1 and 1000000",
                                context={"sequence": sequence})

        # Verify the target (pipe or queue) exists
        target_exists = False
        try:
            pipe_response = await client.request("GET", f"{API_TRAFFICSHAPER_SETTINGS_GET_PIPE}/{target_uuid}",
                                               operation="verify_target_pipe")
            if "pipe" in pipe_response:
                target_exists = True
        except ResourceNotFoundError:
            pass

        if not target_exists:
            try:
                queue_response = await client.request("GET", f"{API_TRAFFICSHAPER_SETTINGS_GET_QUEUE}/{target_uuid}",
                                                   operation="verify_target_queue")
                if "queue" in queue_response:
                    target_exists = True
            except ResourceNotFoundError:
                pass

        if not target_exists:
            raise ResourceNotFoundError(f"Target pipe or queue with UUID {target_uuid} not found")

        # Prepare rule data
        rule_data = {
            "rule": {
                "enabled": "1" if enabled else "0",
                "sequence": str(sequence),
                "interface": interface,
                "protocol": protocol,
                "source": source,
                "destination": destination,
                "target": target_uuid,
                "description": description
            }
        }

        # Create the rule
        response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_ADD_RULE,
                                      data=rule_data, operation="create_traffic_shaper_rule")

        # Apply configuration if creation was successful
        if response.get("result") == "saved":
            await client.request("POST", API_TRAFFICSHAPER_SERVICE_RECONFIGURE, operation="reconfigure_after_rule_create")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_create_rule", e)


@mcp.tool(name="traffic_shaper_update_rule", description="Update an existing traffic shaper rule configuration")
async def traffic_shaper_update_rule(
    ctx: Context,
    rule_uuid: str,
    target_uuid: Optional[str] = None,
    interface: Optional[str] = None,
    protocol: Optional[str] = None,
    source: Optional[str] = None,
    destination: Optional[str] = None,
    sequence: Optional[int] = None,
    description: Optional[str] = None,
    enabled: Optional[bool] = None
) -> str:
    """Update an existing traffic shaper rule configuration.

    Args:
        ctx: MCP context
        rule_uuid: UUID of the rule to update
        target_uuid: UUID of the target pipe or queue (optional)
        interface: Interface name (optional)
        protocol: Protocol to match (optional)
        source: Source network/address (optional)
        destination: Destination network/address (optional)
        sequence: Rule evaluation order (1-1000000, optional)
        description: Description for the rule (optional)
        enabled: Whether the rule should be enabled (optional)

    Returns:
        JSON string with update result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUIDs
        validate_uuid(rule_uuid, "rule_uuid")
        if target_uuid:
            validate_uuid(target_uuid, "target_uuid")

        # Get current rule configuration
        current_rule_response = await client.request("GET", f"{API_TRAFFICSHAPER_SETTINGS_GET_RULE}/{rule_uuid}",
                                                   operation="get_rule_for_update")

        if "rule" not in current_rule_response:
            raise ResourceNotFoundError(f"Rule with UUID {rule_uuid} not found")

        current_rule = current_rule_response["rule"]

        # Update only provided fields
        if target_uuid is not None:
            # Verify the new target exists
            target_exists = False
            try:
                pipe_response = await client.request("GET", f"{API_TRAFFICSHAPER_SETTINGS_GET_PIPE}/{target_uuid}",
                                                   operation="verify_new_target_pipe")
                if "pipe" in pipe_response:
                    target_exists = True
            except ResourceNotFoundError:
                pass

            if not target_exists:
                try:
                    queue_response = await client.request("GET", f"{API_TRAFFICSHAPER_SETTINGS_GET_QUEUE}/{target_uuid}",
                                                        operation="verify_new_target_queue")
                    if "queue" in queue_response:
                        target_exists = True
                except ResourceNotFoundError:
                    pass

            if not target_exists:
                raise ResourceNotFoundError(f"Target pipe or queue with UUID {target_uuid} not found")

            current_rule["target"] = target_uuid

        if interface is not None:
            current_rule["interface"] = interface

        if protocol is not None:
            current_rule["protocol"] = protocol

        if source is not None:
            current_rule["source"] = source

        if destination is not None:
            current_rule["destination"] = destination

        if sequence is not None:
            if not (1 <= sequence <= 1000000):
                raise ValidationError("Sequence must be between 1 and 1000000",
                                    context={"sequence": sequence})
            current_rule["sequence"] = str(sequence)

        if description is not None:
            current_rule["description"] = description

        if enabled is not None:
            current_rule["enabled"] = "1" if enabled else "0"

        # Prepare update data
        rule_data = {"rule": current_rule}

        # Update the rule
        response = await client.request("POST", f"{API_TRAFFICSHAPER_SETTINGS_SET_RULE}/{rule_uuid}",
                                      data=rule_data, operation="update_traffic_shaper_rule")

        # Apply configuration if update was successful
        if response.get("result") == "saved":
            await client.request("POST", API_TRAFFICSHAPER_SERVICE_RECONFIGURE, operation="reconfigure_after_rule_update")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_update_rule", e)


@mcp.tool(name="traffic_shaper_delete_rule", description="Delete a traffic shaper rule")
async def traffic_shaper_delete_rule(ctx: Context, rule_uuid: str) -> str:
    """Delete a traffic shaper rule.

    Args:
        ctx: MCP context
        rule_uuid: UUID of the rule to delete

    Returns:
        JSON string with deletion result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID
        validate_uuid(rule_uuid, "rule_uuid")

        # Delete the rule
        response = await client.request("POST", f"{API_TRAFFICSHAPER_SETTINGS_DEL_RULE}/{rule_uuid}",
                                      operation="delete_traffic_shaper_rule")

        # Apply configuration if deletion was successful
        if response.get("result") == "deleted":
            await client.request("POST", API_TRAFFICSHAPER_SERVICE_RECONFIGURE, operation="reconfigure_after_rule_delete")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_delete_rule", e)


@mcp.tool(name="traffic_shaper_toggle_rule", description="Enable or disable a traffic shaper rule")
async def traffic_shaper_toggle_rule(ctx: Context, rule_uuid: str, enabled: bool) -> str:
    """Enable or disable a traffic shaper rule.

    Args:
        ctx: MCP context
        rule_uuid: UUID of the rule to toggle
        enabled: True to enable, False to disable

    Returns:
        JSON string with toggle result
    """
    try:
        client = await get_opnsense_client()

        # Validate UUID
        validate_uuid(rule_uuid, "rule_uuid")

        # Toggle the rule
        enabled_int = 1 if enabled else 0
        response = await client.request("POST", f"{API_TRAFFICSHAPER_SETTINGS_TOGGLE_RULE}/{rule_uuid}/{enabled_int}",
                                      operation="toggle_traffic_shaper_rule")

        # Apply configuration if toggle was successful
        if response.get("result") == "saved":
            await client.request("POST", API_TRAFFICSHAPER_SERVICE_RECONFIGURE, operation="reconfigure_after_rule_toggle")

        return json.dumps(response, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_toggle_rule", e)


# ========== COMMON QOS USE CASE HELPERS ==========

@mcp.tool(name="traffic_shaper_limit_user_bandwidth", description="Helper to create per-user bandwidth limiting setup")
async def traffic_shaper_limit_user_bandwidth(
    ctx: Context,
    user_ip: str,
    download_limit_mbps: int,
    upload_limit_mbps: int,
    interface: str = "lan",
    description: str = ""
) -> str:
    """Helper tool to quickly set up per-user bandwidth limiting.

    This creates a complete bandwidth limiting setup for a specific user:
    - Download pipe (for traffic TO the user)
    - Upload pipe (for traffic FROM the user)
    - Download rule (targeting user as destination)
    - Upload rule (targeting user as source)

    Args:
        ctx: MCP context
        user_ip: IP address of the user to limit
        download_limit_mbps: Download bandwidth limit in Mbps
        upload_limit_mbps: Upload bandwidth limit in Mbps
        interface: Interface where rules apply (default: 'lan')
        description: Description prefix for created objects

    Returns:
        JSON string with created objects (pipes and rules)
    """
    try:
        client = await get_opnsense_client()
        results = {
            "download_pipe": None,
            "upload_pipe": None,
            "download_rule": None,
            "upload_rule": None
        }

        desc_prefix = description or f"User {user_ip} bandwidth limit"

        # Create download pipe (traffic TO user)
        download_pipe_data = {
            "pipe": {
                "enabled": "1",
                "bandwidth": str(download_limit_mbps),
                "bandwidthMetric": "Mbit/s",
                "queue": "50",
                "scheduler": "FQ-CoDel",
                "description": f"{desc_prefix} - Download"
            }
        }

        download_pipe_response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_ADD_PIPE,
                                                    data=download_pipe_data, operation="create_user_download_pipe")
        results["download_pipe"] = download_pipe_response

        # Create upload pipe (traffic FROM user)
        upload_pipe_data = {
            "pipe": {
                "enabled": "1",
                "bandwidth": str(upload_limit_mbps),
                "bandwidthMetric": "Mbit/s",
                "queue": "50",
                "scheduler": "FQ-CoDel",
                "description": f"{desc_prefix} - Upload"
            }
        }

        upload_pipe_response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_ADD_PIPE,
                                                  data=upload_pipe_data, operation="create_user_upload_pipe")
        results["upload_pipe"] = upload_pipe_response

        # Get the UUIDs of the created pipes
        download_pipe_uuid = download_pipe_response.get("uuid")
        upload_pipe_uuid = upload_pipe_response.get("uuid")

        if download_pipe_uuid and upload_pipe_uuid:
            # Create download rule (traffic TO user as destination)
            download_rule_data = {
                "rule": {
                    "enabled": "1",
                    "sequence": "1000",
                    "interface": interface,
                    "protocol": "IP",
                    "source": "any",
                    "destination": user_ip,
                    "target": download_pipe_uuid,
                    "description": f"{desc_prefix} - Download Rule"
                }
            }

            download_rule_response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_ADD_RULE,
                                                        data=download_rule_data, operation="create_user_download_rule")
            results["download_rule"] = download_rule_response

            # Create upload rule (traffic FROM user as source)
            upload_rule_data = {
                "rule": {
                    "enabled": "1",
                    "sequence": "1001",
                    "interface": interface,
                    "protocol": "IP",
                    "source": user_ip,
                    "destination": "any",
                    "target": upload_pipe_uuid,
                    "description": f"{desc_prefix} - Upload Rule"
                }
            }

            upload_rule_response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_ADD_RULE,
                                                      data=upload_rule_data, operation="create_user_upload_rule")
            results["upload_rule"] = upload_rule_response

        # Apply configuration
        await client.request("POST", API_TRAFFICSHAPER_SERVICE_RECONFIGURE, operation="reconfigure_after_user_bandwidth_setup")

        return json.dumps(results, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_limit_user_bandwidth", e)


@mcp.tool(name="traffic_shaper_prioritize_voip", description="Helper to set up VoIP traffic prioritization")
async def traffic_shaper_prioritize_voip(
    ctx: Context,
    total_bandwidth_mbps: int,
    voip_bandwidth_mbps: int,
    voip_ports: str = "5060,10000-20000",
    interface: str = "wan"
) -> str:
    """Helper tool to set up VoIP traffic prioritization with guaranteed bandwidth.

    This creates a complete VoIP QoS setup:
    - Main bandwidth pipe for total connection
    - High-priority queue for VoIP traffic
    - Best-effort queue for other traffic
    - Rules to classify VoIP traffic by port

    Args:
        ctx: MCP context
        total_bandwidth_mbps: Total connection bandwidth in Mbps
        voip_bandwidth_mbps: Guaranteed bandwidth for VoIP in Mbps
        voip_ports: VoIP ports to prioritize (default: SIP + RTP range)
        interface: Interface where rules apply (default: 'wan')

    Returns:
        JSON string with created objects (pipe, queues, rules)
    """
    try:
        client = await get_opnsense_client()
        results = {
            "main_pipe": None,
            "voip_queue": None,
            "data_queue": None,
            "voip_rule": None,
            "data_rule": None
        }

        # Create main pipe with total bandwidth
        main_pipe_data = {
            "pipe": {
                "enabled": "1",
                "bandwidth": str(total_bandwidth_mbps),
                "bandwidthMetric": "Mbit/s",
                "queue": "100",
                "scheduler": "FQ-CoDel",
                "description": "VoIP Main Bandwidth Pipe"
            }
        }

        main_pipe_response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_ADD_PIPE,
                                                data=main_pipe_data, operation="create_voip_main_pipe")
        results["main_pipe"] = main_pipe_response
        main_pipe_uuid = main_pipe_response.get("uuid")

        if main_pipe_uuid:
            # Create high-priority VoIP queue (weight 90)
            voip_queue_data = {
                "queue": {
                    "enabled": "1",
                    "pipe": main_pipe_uuid,
                    "weight": "90",
                    "description": f"VoIP Priority Queue ({voip_bandwidth_mbps} Mbps guaranteed)"
                }
            }

            voip_queue_response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_ADD_QUEUE,
                                                     data=voip_queue_data, operation="create_voip_priority_queue")
            results["voip_queue"] = voip_queue_response
            voip_queue_uuid = voip_queue_response.get("uuid")

            # Create best-effort data queue (weight 10)
            data_queue_data = {
                "queue": {
                    "enabled": "1",
                    "pipe": main_pipe_uuid,
                    "weight": "10",
                    "description": "Best Effort Data Queue"
                }
            }

            data_queue_response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_ADD_QUEUE,
                                                     data=data_queue_data, operation="create_data_best_effort_queue")
            results["data_queue"] = data_queue_response
            data_queue_uuid = data_queue_response.get("uuid")

            if voip_queue_uuid and data_queue_uuid:
                # Create VoIP rule (high priority - sequence 100)
                voip_rule_data = {
                    "rule": {
                        "enabled": "1",
                        "sequence": "100",
                        "interface": interface,
                        "protocol": "UDP",
                        "source": "any",
                        "destination": f"any:{voip_ports}",
                        "target": voip_queue_uuid,
                        "description": f"VoIP Traffic Priority (ports {voip_ports})"
                    }
                }

                voip_rule_response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_ADD_RULE,
                                                        data=voip_rule_data, operation="create_voip_priority_rule")
                results["voip_rule"] = voip_rule_response

                # Create catch-all data rule (low priority - sequence 9999)
                data_rule_data = {
                    "rule": {
                        "enabled": "1",
                        "sequence": "9999",
                        "interface": interface,
                        "protocol": "IP",
                        "source": "any",
                        "destination": "any",
                        "target": data_queue_uuid,
                        "description": "Default Data Traffic (Best Effort)"
                    }
                }

                data_rule_response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_ADD_RULE,
                                                        data=data_rule_data, operation="create_data_best_effort_rule")
                results["data_rule"] = data_rule_response

        # Apply configuration
        await client.request("POST", API_TRAFFICSHAPER_SERVICE_RECONFIGURE, operation="reconfigure_after_voip_setup")

        return json.dumps(results, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_prioritize_voip", e)


@mcp.tool(name="traffic_shaper_setup_gaming_priority", description="Helper to optimize traffic for gaming")
async def traffic_shaper_setup_gaming_priority(
    ctx: Context,
    total_bandwidth_mbps: int,
    gaming_ports: str = "3478-3480,27000-27050",
    interface: str = "wan"
) -> str:
    """Helper tool to set up gaming traffic optimization with low latency priority.

    This creates a gaming-optimized QoS setup:
    - Main bandwidth pipe with optimized scheduler
    - High-priority queue for gaming traffic (low latency)
    - Medium-priority queue for interactive traffic
    - Low-priority queue for bulk downloads
    - Rules to classify traffic appropriately

    Args:
        ctx: MCP context
        total_bandwidth_mbps: Total connection bandwidth in Mbps
        gaming_ports: Gaming ports to prioritize (default: Steam, Xbox Live, etc.)
        interface: Interface where rules apply (default: 'wan')

    Returns:
        JSON string with created objects (pipe, queues, rules)
    """
    try:
        client = await get_opnsense_client()
        results = {
            "main_pipe": None,
            "gaming_queue": None,
            "interactive_queue": None,
            "bulk_queue": None,
            "gaming_rule": None,
            "interactive_rule": None,
            "bulk_rule": None
        }

        # Create main pipe optimized for gaming (low latency scheduler)
        main_pipe_data = {
            "pipe": {
                "enabled": "1",
                "bandwidth": str(total_bandwidth_mbps),
                "bandwidthMetric": "Mbit/s",
                "queue": "25",  # Smaller queue for lower latency
                "scheduler": "FQ-CoDel",  # Best for gaming latency
                "description": "Gaming Optimized Main Pipe"
            }
        }

        main_pipe_response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_ADD_PIPE,
                                                data=main_pipe_data, operation="create_gaming_main_pipe")
        results["main_pipe"] = main_pipe_response
        main_pipe_uuid = main_pipe_response.get("uuid")

        if main_pipe_uuid:
            # Create gaming queue (weight 70 - highest priority)
            gaming_queue_data = {
                "queue": {
                    "enabled": "1",
                    "pipe": main_pipe_uuid,
                    "weight": "70",
                    "description": "Gaming Traffic - Highest Priority"
                }
            }

            gaming_queue_response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_ADD_QUEUE,
                                                       data=gaming_queue_data, operation="create_gaming_priority_queue")
            results["gaming_queue"] = gaming_queue_response
            gaming_queue_uuid = gaming_queue_response.get("uuid")

            # Create interactive queue (weight 25 - medium priority for web, SSH, etc.)
            interactive_queue_data = {
                "queue": {
                    "enabled": "1",
                    "pipe": main_pipe_uuid,
                    "weight": "25",
                    "description": "Interactive Traffic - Medium Priority"
                }
            }

            interactive_queue_response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_ADD_QUEUE,
                                                            data=interactive_queue_data, operation="create_interactive_priority_queue")
            results["interactive_queue"] = interactive_queue_response
            interactive_queue_uuid = interactive_queue_response.get("uuid")

            # Create bulk download queue (weight 5 - lowest priority)
            bulk_queue_data = {
                "queue": {
                    "enabled": "1",
                    "pipe": main_pipe_uuid,
                    "weight": "5",
                    "description": "Bulk Downloads - Lowest Priority"
                }
            }

            bulk_queue_response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_ADD_QUEUE,
                                                     data=bulk_queue_data, operation="create_bulk_download_queue")
            results["bulk_queue"] = bulk_queue_response
            bulk_queue_uuid = bulk_queue_response.get("uuid")

            if gaming_queue_uuid and interactive_queue_uuid and bulk_queue_uuid:
                # Create gaming rule (highest priority - sequence 50)
                gaming_rule_data = {
                    "rule": {
                        "enabled": "1",
                        "sequence": "50",
                        "interface": interface,
                        "protocol": "UDP",
                        "source": "any",
                        "destination": f"any:{gaming_ports}",
                        "target": gaming_queue_uuid,
                        "description": f"Gaming Traffic Priority (ports {gaming_ports})"
                    }
                }

                gaming_rule_response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_ADD_RULE,
                                                          data=gaming_rule_data, operation="create_gaming_priority_rule")
                results["gaming_rule"] = gaming_rule_response

                # Create interactive rule (medium priority - sequence 500)
                interactive_rule_data = {
                    "rule": {
                        "enabled": "1",
                        "sequence": "500",
                        "interface": interface,
                        "protocol": "TCP",
                        "source": "any",
                        "destination": "any:22,53,80,443",
                        "target": interactive_queue_uuid,
                        "description": "Interactive Traffic (SSH, DNS, HTTP, HTTPS)"
                    }
                }

                interactive_rule_response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_ADD_RULE,
                                                               data=interactive_rule_data, operation="create_interactive_priority_rule")
                results["interactive_rule"] = interactive_rule_response

                # Create bulk download rule (lowest priority - sequence 9999)
                bulk_rule_data = {
                    "rule": {
                        "enabled": "1",
                        "sequence": "9999",
                        "interface": interface,
                        "protocol": "IP",
                        "source": "any",
                        "destination": "any",
                        "target": bulk_queue_uuid,
                        "description": "Bulk Downloads and Default Traffic"
                    }
                }

                bulk_rule_response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_ADD_RULE,
                                                        data=bulk_rule_data, operation="create_bulk_download_rule")
                results["bulk_rule"] = bulk_rule_response

        # Apply configuration
        await client.request("POST", API_TRAFFICSHAPER_SERVICE_RECONFIGURE, operation="reconfigure_after_gaming_setup")

        return json.dumps(results, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_setup_gaming_priority", e)


@mcp.tool(name="traffic_shaper_create_guest_limits", description="Helper to set up guest network bandwidth limitations")
async def traffic_shaper_create_guest_limits(
    ctx: Context,
    guest_network: str,
    max_bandwidth_mbps: int,
    per_user_limit_mbps: Optional[int] = None,
    interface: str = "lan"
) -> str:
    """Helper tool to set up bandwidth limitations for guest networks.

    This creates guest network QoS setup:
    - Total bandwidth pipe for the entire guest network
    - Per-user limitation queue (if specified)
    - Rules to apply limits to guest network traffic

    Args:
        ctx: MCP context
        guest_network: Guest network CIDR (e.g., "192.168.100.0/24")
        max_bandwidth_mbps: Maximum total bandwidth for guest network in Mbps
        per_user_limit_mbps: Optional per-user bandwidth limit in Mbps
        interface: Interface where rules apply (default: 'lan')

    Returns:
        JSON string with created objects (pipes, queues, rules)
    """
    try:
        client = await get_opnsense_client()
        results = {
            "guest_pipe": None,
            "guest_queue": None,
            "guest_download_rule": None,
            "guest_upload_rule": None
        }

        # Create main guest network pipe
        guest_pipe_data = {
            "pipe": {
                "enabled": "1",
                "bandwidth": str(max_bandwidth_mbps),
                "bandwidthMetric": "Mbit/s",
                "queue": "50",
                "scheduler": "FQ-CoDel",
                "description": f"Guest Network Bandwidth Limit ({guest_network})"
            }
        }

        guest_pipe_response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_ADD_PIPE,
                                                 data=guest_pipe_data, operation="create_guest_network_pipe")
        results["guest_pipe"] = guest_pipe_response
        guest_pipe_uuid = guest_pipe_response.get("uuid")

        target_uuid = guest_pipe_uuid

        # If per-user limits are specified, create a queue
        if per_user_limit_mbps and guest_pipe_uuid:
            guest_queue_data = {
                "queue": {
                    "enabled": "1",
                    "pipe": guest_pipe_uuid,
                    "weight": "50",
                    "description": f"Guest Per-User Queue ({per_user_limit_mbps} Mbps limit)"
                }
            }

            guest_queue_response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_ADD_QUEUE,
                                                       data=guest_queue_data, operation="create_guest_user_queue")
            results["guest_queue"] = guest_queue_response
            target_uuid = guest_queue_response.get("uuid") or guest_pipe_uuid

        if target_uuid:
            # Create guest download rule (traffic TO guest network)
            guest_download_rule_data = {
                "rule": {
                    "enabled": "1",
                    "sequence": "200",
                    "interface": interface,
                    "protocol": "IP",
                    "source": "any",
                    "destination": guest_network,
                    "target": target_uuid,
                    "description": f"Guest Network Download Limit ({guest_network})"
                }
            }

            guest_download_rule_response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_ADD_RULE,
                                                              data=guest_download_rule_data, operation="create_guest_download_rule")
            results["guest_download_rule"] = guest_download_rule_response

            # Create guest upload rule (traffic FROM guest network)
            guest_upload_rule_data = {
                "rule": {
                    "enabled": "1",
                    "sequence": "201",
                    "interface": interface,
                    "protocol": "IP",
                    "source": guest_network,
                    "destination": "any",
                    "target": target_uuid,
                    "description": f"Guest Network Upload Limit ({guest_network})"
                }
            }

            guest_upload_rule_response = await client.request("POST", API_TRAFFICSHAPER_SETTINGS_ADD_RULE,
                                                             data=guest_upload_rule_data, operation="create_guest_upload_rule")
            results["guest_upload_rule"] = guest_upload_rule_response

        # Apply configuration
        await client.request("POST", API_TRAFFICSHAPER_SERVICE_RECONFIGURE, operation="reconfigure_after_guest_setup")

        return json.dumps(results, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "traffic_shaper_create_guest_limits", e)
