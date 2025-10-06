"""
OPNsense MCP Server - Logging Domain

This module provides comprehensive logging and log management tools for OPNsense.
It includes log retrieval, search, export, analysis, and security event detection capabilities.
"""

import json
import logging
from datetime import datetime

from mcp.server.fastmcp import Context

from ..core import (
    APIError,
    ResourceNotFoundError,
)
from ..main import mcp
from ..shared.constants import (
    API_DIAGNOSTICS_LOG_ACCESS,
    API_DIAGNOSTICS_LOG_AUTHENTICATION,
    API_DIAGNOSTICS_LOG_CLEAR,
    API_DIAGNOSTICS_LOG_DHCP,
    API_DIAGNOSTICS_LOG_DNS,
    API_DIAGNOSTICS_LOG_EXPORT,
    API_DIAGNOSTICS_LOG_FIREWALL,
    API_DIAGNOSTICS_LOG_HAPROXY,
    API_DIAGNOSTICS_LOG_IPSEC,
    API_DIAGNOSTICS_LOG_OPENVPN,
    API_DIAGNOSTICS_LOG_SET_SETTINGS,
    API_DIAGNOSTICS_LOG_SETTINGS,
    API_DIAGNOSTICS_LOG_SQUID,
    API_DIAGNOSTICS_LOG_STATS,
    API_DIAGNOSTICS_LOG_SYSTEM,
)
from ..shared.error_handlers import handle_tool_error

logger = logging.getLogger("opnsense-mcp")


# ========== HELPER FUNCTIONS ==========


async def get_opnsense_client():
    """Get OPNsense client from server state with validation."""
    from ..main import server_state

    return await server_state.get_client()


# ========== CORE LOGGING TOOLS ==========


@mcp.tool()
async def get_system_logs(
    ctx: Context,
    log_type: str = "system",
    count: int = 100,
    filter_text: str = "",
    severity: str = "all",
) -> str:
    """
    Retrieve system logs from OPNsense with filtering capabilities.

    Args:
        log_type: Type of log to retrieve (system, access, authentication, dhcp, dns)
        count: Number of log entries to retrieve (default: 100, max: 1000)
        filter_text: Optional text to filter log entries
        severity: Log severity filter (all, emergency, alert, critical, error, warning, notice, info, debug)

    Returns:
        JSON response with log entries
    """
    try:
        client = await get_opnsense_client()
        if not client:
            return "Error: OPNsense connection not configured. Use configure_opnsense_connection first."

        # Validate parameters
        valid_log_types = ["system", "access", "authentication", "dhcp", "dns", "openvpn", "ipsec"]
        if log_type not in valid_log_types:
            return json.dumps(
                {"error": f"Invalid log type '{log_type}'. Valid types: {valid_log_types}"},
                indent=2,
            )

        valid_severities = [
            "all",
            "emergency",
            "alert",
            "critical",
            "error",
            "warning",
            "notice",
            "info",
            "debug",
        ]
        if severity not in valid_severities:
            return json.dumps(
                {"error": f"Invalid severity '{severity}'. Valid severities: {valid_severities}"},
                indent=2,
            )

        # Limit count to reasonable maximum
        if count > 1000:
            count = 1000

        # Map log type to API endpoint
        endpoint_map = {
            "system": API_DIAGNOSTICS_LOG_SYSTEM,
            "access": API_DIAGNOSTICS_LOG_ACCESS,
            "authentication": API_DIAGNOSTICS_LOG_AUTHENTICATION,
            "dhcp": API_DIAGNOSTICS_LOG_DHCP,
            "dns": API_DIAGNOSTICS_LOG_DNS,
            "openvpn": API_DIAGNOSTICS_LOG_OPENVPN,
            "ipsec": API_DIAGNOSTICS_LOG_IPSEC,
        }

        endpoint = endpoint_map.get(log_type, API_DIAGNOSTICS_LOG_SYSTEM)

        # Build parameters
        params = {"limit": count}
        if filter_text:
            params["filter"] = filter_text
        if severity != "all":
            params["severity"] = severity

        response = await client.request("GET", endpoint, params=params, operation="get_system_logs")

        return json.dumps(
            {
                "log_type": log_type,
                "count": count,
                "filter_applied": filter_text,
                "severity_filter": severity,
                "entries": response,
            },
            indent=2,
        )

    except Exception as e:
        return await handle_tool_error(ctx, "get_system_logs", e)


@mcp.tool()
async def get_service_logs(
    ctx: Context, service_name: str, count: int = 100, filter_text: str = ""
) -> str:
    """
    Retrieve logs for specific OPNsense services.

    Args:
        service_name: Name of the service (squid, haproxy, openvpn, ipsec, dhcp, dns)
        count: Number of log entries to retrieve (default: 100)
        filter_text: Optional text to filter log entries

    Returns:
        JSON response with service log entries
    """
    try:
        client = await get_opnsense_client()
        if not client:
            return "Error: OPNsense connection not configured. Use configure_opnsense_connection first."

        # Map service names to endpoints
        service_endpoints = {
            "squid": API_DIAGNOSTICS_LOG_SQUID,
            "haproxy": API_DIAGNOSTICS_LOG_HAPROXY,
            "openvpn": API_DIAGNOSTICS_LOG_OPENVPN,
            "ipsec": API_DIAGNOSTICS_LOG_IPSEC,
            "dhcp": API_DIAGNOSTICS_LOG_DHCP,
            "dns": API_DIAGNOSTICS_LOG_DNS,
        }

        if service_name not in service_endpoints:
            return json.dumps(
                {
                    "error": f"Service '{service_name}' not supported. Available services: {list(service_endpoints.keys())}"
                },
                indent=2,
            )

        endpoint = service_endpoints[service_name]
        params = {"limit": count}
        if filter_text:
            params["filter"] = filter_text

        response = await client.request(
            "GET", endpoint, params=params, operation="get_service_logs"
        )

        return json.dumps(
            {
                "service": service_name,
                "count": count,
                "filter_applied": filter_text,
                "entries": response,
            },
            indent=2,
        )

    except Exception as e:
        return await handle_tool_error(ctx, "get_service_logs", e)


# ========== SEARCH & EXPORT TOOLS ==========


@mcp.tool()
async def search_logs(
    ctx: Context,
    search_query: str,
    log_types: str = "system,firewall",
    max_results: int = 200,
    case_sensitive: bool = False,
) -> str:
    """
    Search across multiple log types for specific patterns or text.

    Args:
        search_query: Text or pattern to search for
        log_types: Comma-separated list of log types to search (system,firewall,access,authentication,dhcp,dns)
        max_results: Maximum number of results to return per log type
        case_sensitive: Whether to perform case-sensitive search

    Returns:
        JSON response with search results from all specified log types
    """
    try:
        client = await get_opnsense_client()
        if not client:
            return "Error: OPNsense connection not configured. Use configure_opnsense_connection first."

        if not search_query or len(search_query.strip()) < 2:
            return json.dumps(
                {"error": "Search query must be at least 2 characters long"}, indent=2
            )

        # Parse log types
        requested_types = [t.strip().lower() for t in log_types.split(",")]
        available_types = [
            "system",
            "firewall",
            "access",
            "authentication",
            "dhcp",
            "dns",
            "openvpn",
            "ipsec",
        ]

        invalid_types = [t for t in requested_types if t not in available_types]
        if invalid_types:
            return json.dumps(
                {"error": f"Invalid log types: {invalid_types}. Available: {available_types}"},
                indent=2,
            )

        search_results = {}

        for log_type in requested_types:
            try:
                # Use the appropriate endpoint for each log type
                if log_type == "firewall":
                    endpoint = API_DIAGNOSTICS_LOG_FIREWALL
                else:
                    endpoint_map = {
                        "system": API_DIAGNOSTICS_LOG_SYSTEM,
                        "access": API_DIAGNOSTICS_LOG_ACCESS,
                        "authentication": API_DIAGNOSTICS_LOG_AUTHENTICATION,
                        "dhcp": API_DIAGNOSTICS_LOG_DHCP,
                        "dns": API_DIAGNOSTICS_LOG_DNS,
                        "openvpn": API_DIAGNOSTICS_LOG_OPENVPN,
                        "ipsec": API_DIAGNOSTICS_LOG_IPSEC,
                    }
                    endpoint = endpoint_map.get(log_type)

                if not endpoint:
                    continue

                params = {"limit": max_results, "filter": search_query}
                if not case_sensitive:
                    params["case_insensitive"] = "true"

                response = await client.request(
                    "GET", endpoint, params=params, operation=f"search_{log_type}_logs"
                )

                # Extract relevant data and count matches
                if isinstance(response, dict) and "rows" in response:
                    entries = response["rows"]
                elif isinstance(response, list):
                    entries = response
                else:
                    entries = [response] if response else []

                search_results[log_type] = {
                    "matches_found": len(entries),
                    "entries": entries[:max_results],  # Ensure we don't exceed limit
                }

            except Exception as log_error:
                search_results[log_type] = {
                    "error": f"Failed to search {log_type} logs: {log_error!s}",
                    "matches_found": 0,
                    "entries": [],
                }

        # Calculate total matches
        total_matches = sum(result.get("matches_found", 0) for result in search_results.values())

        return json.dumps(
            {
                "search_query": search_query,
                "log_types_searched": requested_types,
                "case_sensitive": case_sensitive,
                "total_matches": total_matches,
                "results_by_log_type": search_results,
            },
            indent=2,
        )

    except Exception as e:
        return await handle_tool_error(ctx, "search_logs", e)


@mcp.tool()
async def export_logs(
    ctx: Context,
    log_type: str,
    export_format: str = "json",
    date_range: str = "today",
    include_filters: str = "",
) -> str:
    """
    Export logs in various formats for analysis or archival.

    Args:
        log_type: Type of log to export (system, firewall, access, authentication, dhcp, dns)
        export_format: Export format (json, csv, text)
        date_range: Date range for export (today, yesterday, week, month, custom)
        include_filters: Optional filters to apply during export

    Returns:
        JSON response with export information and download details
    """
    try:
        client = await get_opnsense_client()
        if not client:
            return "Error: OPNsense connection not configured. Use configure_opnsense_connection first."

        # Validate parameters
        valid_formats = ["json", "csv", "text"]
        if export_format not in valid_formats:
            return json.dumps(
                {
                    "error": f"Invalid export format '{export_format}'. Valid formats: {valid_formats}"
                },
                indent=2,
            )

        valid_ranges = ["today", "yesterday", "week", "month", "custom"]
        if date_range not in valid_ranges:
            return json.dumps(
                {"error": f"Invalid date range '{date_range}'. Valid ranges: {valid_ranges}"},
                indent=2,
            )

        # Try using export API endpoint first
        params = {"format": export_format, "range": date_range}
        if include_filters:
            params["filters"] = include_filters

        try:
            export_response = await client.request(
                "GET",
                f"{API_DIAGNOSTICS_LOG_EXPORT}/{log_type}",
                params=params,
                operation="export_logs",
            )

            return json.dumps(
                {
                    "export_status": "completed",
                    "log_type": log_type,
                    "format": export_format,
                    "date_range": date_range,
                    "filters_applied": include_filters,
                    "export_data": export_response,
                },
                indent=2,
            )

        except (APIError, ResourceNotFoundError):
            # If export endpoint doesn't exist, fall back to retrieving logs and formatting
            endpoint_map = {
                "system": API_DIAGNOSTICS_LOG_SYSTEM,
                "firewall": API_DIAGNOSTICS_LOG_FIREWALL,
                "access": API_DIAGNOSTICS_LOG_ACCESS,
                "authentication": API_DIAGNOSTICS_LOG_AUTHENTICATION,
                "dhcp": API_DIAGNOSTICS_LOG_DHCP,
                "dns": API_DIAGNOSTICS_LOG_DNS,
                "openvpn": API_DIAGNOSTICS_LOG_OPENVPN,
                "ipsec": API_DIAGNOSTICS_LOG_IPSEC,
            }

            endpoint = endpoint_map.get(log_type)
            if not endpoint:
                return json.dumps(
                    {"error": f"Unsupported log type for export: {log_type}"}, indent=2
                )

            # Retrieve logs with larger limit for export
            retrieve_params = {"limit": 10000}
            if include_filters:
                retrieve_params["filter"] = include_filters

            logs_response = await client.request(
                "GET", endpoint, params=retrieve_params, operation="retrieve_logs_for_export"
            )

            return json.dumps(
                {
                    "export_status": "completed_via_retrieval",
                    "log_type": log_type,
                    "format": export_format,
                    "date_range": date_range,
                    "filters_applied": include_filters,
                    "note": "Export completed by retrieving logs (export API not available)",
                    "entry_count": len(logs_response) if isinstance(logs_response, list) else 1,
                    "export_data": logs_response,
                },
                indent=2,
            )

    except Exception as e:
        return await handle_tool_error(ctx, "export_logs", e)


# ========== ANALYSIS TOOLS ==========


@mcp.tool()
async def get_log_statistics(ctx: Context, log_type: str = "all", time_period: str = "24h") -> str:
    """
    Get statistical analysis of log entries including counts, patterns, and trends.

    Args:
        log_type: Type of log to analyze (all, system, firewall, access, authentication)
        time_period: Time period for analysis (1h, 6h, 24h, 7d, 30d)

    Returns:
        JSON response with log statistics and analysis
    """
    try:
        client = await get_opnsense_client()
        if not client:
            return "Error: OPNsense connection not configured. Use configure_opnsense_connection first."

        # Try using statistics API endpoint
        try:
            params = {"period": time_period}
            stats_response = await client.request(
                "GET",
                f"{API_DIAGNOSTICS_LOG_STATS}/{log_type}",
                params=params,
                operation="get_log_statistics",
            )

            return json.dumps(
                {
                    "statistics_source": "api_endpoint",
                    "log_type": log_type,
                    "time_period": time_period,
                    "statistics": stats_response,
                },
                indent=2,
            )

        except (APIError, ResourceNotFoundError):
            # If stats endpoint doesn't exist, generate basic statistics
            if log_type == "all":
                log_types_to_check = ["system", "firewall", "access", "authentication"]
            else:
                log_types_to_check = [log_type]

            statistics = {}

            for check_type in log_types_to_check:
                try:
                    # Get recent logs for analysis
                    endpoint_map = {
                        "system": API_DIAGNOSTICS_LOG_SYSTEM,
                        "firewall": API_DIAGNOSTICS_LOG_FIREWALL,
                        "access": API_DIAGNOSTICS_LOG_ACCESS,
                        "authentication": API_DIAGNOSTICS_LOG_AUTHENTICATION,
                    }

                    endpoint = endpoint_map.get(check_type)
                    if not endpoint:
                        continue

                    response = await client.request(
                        "GET", endpoint, params={"limit": 1000}, operation=f"get_{check_type}_stats"
                    )

                    # Generate basic statistics
                    if isinstance(response, list):
                        entries = response
                    elif isinstance(response, dict) and "rows" in response:
                        entries = response["rows"]
                    else:
                        entries = []

                    statistics[check_type] = {
                        "total_entries": len(entries),
                        "sample_period": time_period,
                        "entries_per_hour": (
                            round(len(entries) / 24, 2) if time_period == "24h" else "N/A"
                        ),
                    }

                except Exception as type_error:
                    statistics[check_type] = {
                        "error": f"Failed to get statistics: {type_error!s}",
                        "total_entries": 0,
                    }

            return json.dumps(
                {
                    "statistics_source": "calculated_from_logs",
                    "log_type": log_type,
                    "time_period": time_period,
                    "statistics": statistics,
                    "note": "Statistics calculated from log retrieval (stats API not available)",
                },
                indent=2,
            )

    except Exception as e:
        return await handle_tool_error(ctx, "get_log_statistics", e)


@mcp.tool()
async def analyze_security_events(
    ctx: Context, time_window: str = "24h", event_types: str = "all"
) -> str:
    """
    Analyze logs for security-related events and potential threats.

    Args:
        time_window: Time window for analysis (1h, 6h, 24h, 7d)
        event_types: Types of events to analyze (all, authentication, firewall, intrusion)

    Returns:
        JSON response with security event analysis
    """
    try:
        client = await get_opnsense_client()
        if not client:
            return "Error: OPNsense connection not configured. Use configure_opnsense_connection first."

        analysis_results = {}

        # Define security event patterns to search for
        security_patterns = {
            "failed_authentication": [
                "authentication failure",
                "login failed",
                "invalid user",
                "auth fail",
            ],
            "firewall_blocks": ["blocked", "denied", "drop"],
            "brute_force": ["multiple failed", "repeated attempts", "too many"],
            "port_scans": ["port scan", "probe", "reconnaissance"],
            "suspicious_ips": ["suspicious", "malicious", "blacklist"],
        }

        # Get logs from relevant sources
        log_sources = ["system", "firewall", "authentication", "access"]
        if event_types != "all":
            requested_types = [t.strip() for t in event_types.split(",")]
            log_sources = [t for t in log_sources if t in requested_types]

        for log_source in log_sources:
            try:
                # Get recent logs for analysis
                endpoint_map = {
                    "system": API_DIAGNOSTICS_LOG_SYSTEM,
                    "firewall": API_DIAGNOSTICS_LOG_FIREWALL,
                    "authentication": API_DIAGNOSTICS_LOG_AUTHENTICATION,
                    "access": API_DIAGNOSTICS_LOG_ACCESS,
                }

                endpoint = endpoint_map.get(log_source)
                if not endpoint:
                    continue

                # Retrieve logs (larger sample for analysis)
                logs_response = await client.request(
                    "GET",
                    endpoint,
                    params={"limit": 5000},
                    operation=f"analyze_{log_source}_security",
                )

                # Extract log entries
                if isinstance(logs_response, dict) and "rows" in logs_response:
                    log_entries = logs_response["rows"]
                elif isinstance(logs_response, list):
                    log_entries = logs_response
                else:
                    log_entries = []

                # Analyze for security patterns
                source_analysis = {"total_entries": len(log_entries)}

                for pattern_name, pattern_keywords in security_patterns.items():
                    matching_entries = []

                    for entry in log_entries:
                        # Convert entry to searchable text
                        entry_text = str(entry).lower() if entry else ""

                        # Check if any pattern keywords match
                        if any(keyword.lower() in entry_text for keyword in pattern_keywords):
                            matching_entries.append(entry)

                    source_analysis[pattern_name] = {
                        "count": len(matching_entries),
                        "percentage": round(
                            (len(matching_entries) / max(len(log_entries), 1)) * 100, 2
                        ),
                        "sample_entries": matching_entries[:5],  # First 5 matches as samples
                    }

                analysis_results[log_source] = source_analysis

            except Exception as source_error:
                analysis_results[log_source] = {
                    "error": f"Failed to analyze {log_source}: {source_error!s}",
                    "total_entries": 0,
                }

        # Generate security summary
        total_events = sum(source.get("total_entries", 0) for source in analysis_results.values())
        high_risk_indicators = []

        # Check for high-risk patterns
        for source, data in analysis_results.items():
            if isinstance(data, dict):
                for pattern, details in data.items():
                    if isinstance(details, dict) and details.get("count", 0) > 10:
                        high_risk_indicators.append(
                            f"{source}: {pattern} ({details['count']} events)"
                        )

        return json.dumps(
            {
                "analysis_period": time_window,
                "event_types_analyzed": log_sources,
                "total_log_entries": total_events,
                "high_risk_indicators": high_risk_indicators,
                "detailed_analysis": analysis_results,
                "recommendation": (
                    "Review high-count security events and consider implementing additional security measures"
                    if high_risk_indicators
                    else "No significant security events detected"
                ),
            },
            indent=2,
        )

    except Exception as e:
        return await handle_tool_error(ctx, "analyze_security_events", e)


@mcp.tool()
async def generate_log_report(
    ctx: Context,
    report_type: str = "summary",
    time_period: str = "24h",
    include_details: bool = False,
) -> str:
    """
    Generate comprehensive log reports for analysis and compliance.

    Args:
        report_type: Type of report (summary, detailed, security, compliance)
        time_period: Time period for report (1h, 6h, 24h, 7d, 30d)
        include_details: Whether to include detailed log entries in report

    Returns:
        JSON response with generated log report
    """
    try:
        client = await get_opnsense_client()
        if not client:
            return "Error: OPNsense connection not configured. Use configure_opnsense_connection first."

        # Validate parameters
        valid_report_types = ["summary", "detailed", "security", "compliance"]
        if report_type not in valid_report_types:
            return json.dumps(
                {
                    "error": f"Invalid report type '{report_type}'. Valid types: {valid_report_types}"
                },
                indent=2,
            )

        report_data = {
            "report_type": report_type,
            "time_period": time_period,
            "generated_at": datetime.utcnow().isoformat(),
            "sections": {},
        }

        # Get data from multiple log sources
        log_sources = ["system", "firewall", "authentication", "access"]

        for source in log_sources:
            try:
                endpoint_map = {
                    "system": API_DIAGNOSTICS_LOG_SYSTEM,
                    "firewall": API_DIAGNOSTICS_LOG_FIREWALL,
                    "authentication": API_DIAGNOSTICS_LOG_AUTHENTICATION,
                    "access": API_DIAGNOSTICS_LOG_ACCESS,
                }

                endpoint = endpoint_map.get(source)
                if not endpoint:
                    continue

                # Get logs for report
                limit = 10000 if include_details else 1000
                response = await client.request(
                    "GET", endpoint, params={"limit": limit}, operation=f"report_{source}_logs"
                )

                # Extract entries
                if isinstance(response, dict) and "rows" in response:
                    entries = response["rows"]
                elif isinstance(response, list):
                    entries = response
                else:
                    entries = []

                # Create section data based on report type
                section_data = {"entry_count": len(entries), "source": source}

                if report_type == "summary":
                    section_data["summary"] = f"{len(entries)} entries in {time_period}"

                elif report_type == "detailed" and include_details:
                    section_data["entries"] = entries[:100]  # Limit detailed entries

                elif report_type == "security":
                    # Focus on security-relevant entries
                    security_keywords = ["fail", "error", "block", "deny", "suspicious", "attack"]
                    security_entries = []

                    for entry in entries:
                        entry_text = str(entry).lower()
                        if any(keyword in entry_text for keyword in security_keywords):
                            security_entries.append(entry)

                    section_data["security_events"] = len(security_entries)
                    if include_details:
                        section_data["security_entries"] = security_entries[:50]

                elif report_type == "compliance":
                    # Focus on compliance-relevant information
                    section_data["compliance_summary"] = {
                        "logging_active": len(entries) > 0,
                        "entry_count": len(entries),
                        "time_coverage": time_period,
                    }

                report_data["sections"][source] = section_data

            except Exception as source_error:
                report_data["sections"][source] = {
                    "error": f"Failed to generate report for {source}: {source_error!s}",
                    "entry_count": 0,
                }

        # Add report summary
        total_entries = sum(
            section.get("entry_count", 0) for section in report_data["sections"].values()
        )
        report_data["report_summary"] = {
            "total_entries": total_entries,
            "sources_included": len([s for s in report_data["sections"] if not s.get("error")]),
            "sources_with_errors": len([s for s in report_data["sections"] if s.get("error")]),
        }

        return json.dumps(report_data, indent=2)

    except Exception as e:
        return await handle_tool_error(ctx, "generate_log_report", e)


# ========== MANAGEMENT TOOLS ==========


@mcp.tool()
async def clear_logs(ctx: Context, log_type: str, confirmation: str = "") -> str:
    """
    Clear specific log files with confirmation requirement.

    Args:
        log_type: Type of log to clear (system, firewall, access, authentication, dhcp, dns)
        confirmation: Must be "CONFIRM_CLEAR" to proceed with clearing

    Returns:
        JSON response with clear operation status
    """
    try:
        client = await get_opnsense_client()
        if not client:
            return "Error: OPNsense connection not configured. Use configure_opnsense_connection first."

        # Require explicit confirmation
        if confirmation != "CONFIRM_CLEAR":
            return json.dumps(
                {
                    "error": "Log clearing requires explicit confirmation",
                    "instruction": "Set confirmation parameter to 'CONFIRM_CLEAR' to proceed",
                    "warning": "This action will permanently delete log entries and cannot be undone",
                },
                indent=2,
            )

        # Validate log type
        valid_log_types = [
            "system",
            "firewall",
            "access",
            "authentication",
            "dhcp",
            "dns",
            "openvpn",
            "ipsec",
        ]
        if log_type not in valid_log_types:
            return json.dumps(
                {"error": f"Invalid log type '{log_type}'. Valid types: {valid_log_types}"},
                indent=2,
            )

        try:
            # Try using dedicated clear API
            clear_response = await client.request(
                "POST", f"{API_DIAGNOSTICS_LOG_CLEAR}/{log_type}", operation="clear_logs"
            )

            return json.dumps(
                {
                    "clear_status": "completed",
                    "log_type": log_type,
                    "message": f"Successfully cleared {log_type} logs",
                    "response": clear_response,
                },
                indent=2,
            )

        except (APIError, ResourceNotFoundError):
            return json.dumps(
                {
                    "clear_status": "api_unavailable",
                    "log_type": log_type,
                    "message": f"Clear API not available for {log_type} logs",
                    "recommendation": "Use OPNsense web interface: Firewall > Log Files > Clear Logs",
                },
                indent=2,
            )

    except Exception as e:
        return await handle_tool_error(ctx, "clear_logs", e)


@mcp.tool()
async def configure_logging(
    ctx: Context,
    log_level: str = "info",
    remote_logging: bool = False,
    remote_server: str = "",
    log_rotation: str = "daily",
) -> str:
    """
    Configure logging settings for OPNsense system.

    Args:
        log_level: Logging level (emergency, alert, critical, error, warning, notice, info, debug)
        remote_logging: Whether to enable remote logging
        remote_server: Remote syslog server (required if remote_logging is True)
        log_rotation: Log rotation schedule (daily, weekly, monthly)

    Returns:
        JSON response with configuration status
    """
    try:
        client = await get_opnsense_client()
        if not client:
            return "Error: OPNsense connection not configured. Use configure_opnsense_connection first."

        # Validate parameters
        valid_levels = [
            "emergency",
            "alert",
            "critical",
            "error",
            "warning",
            "notice",
            "info",
            "debug",
        ]
        if log_level not in valid_levels:
            return json.dumps(
                {"error": f"Invalid log level '{log_level}'. Valid levels: {valid_levels}"},
                indent=2,
            )

        valid_rotations = ["daily", "weekly", "monthly"]
        if log_rotation not in valid_rotations:
            return json.dumps(
                {
                    "error": f"Invalid log rotation '{log_rotation}'. Valid options: {valid_rotations}"
                },
                indent=2,
            )

        if remote_logging and not remote_server:
            return json.dumps(
                {"error": "Remote server must be specified when remote logging is enabled"},
                indent=2,
            )

        # Get current settings first
        try:
            current_settings = await client.request(
                "GET", API_DIAGNOSTICS_LOG_SETTINGS, operation="get_current_log_settings"
            )
        except (APIError, ResourceNotFoundError):
            current_settings = {}

        # Prepare configuration data
        config_data = {
            "log_level": log_level,
            "remote_logging": "1" if remote_logging else "0",
            "log_rotation": log_rotation,
        }

        if remote_logging and remote_server:
            config_data["remote_server"] = remote_server

        try:
            # Try to apply settings via API
            set_response = await client.request(
                "POST",
                API_DIAGNOSTICS_LOG_SET_SETTINGS,
                data=config_data,
                operation="configure_logging",
            )

            return json.dumps(
                {
                    "configuration_status": "completed",
                    "previous_settings": current_settings,
                    "new_settings": config_data,
                    "response": set_response,
                },
                indent=2,
            )

        except (APIError, ResourceNotFoundError):
            return json.dumps(
                {
                    "configuration_status": "api_unavailable",
                    "message": "Logging configuration API not available",
                    "intended_settings": config_data,
                    "recommendation": "Use OPNsense web interface: System > Settings > Logging",
                },
                indent=2,
            )

    except Exception as e:
        return await handle_tool_error(ctx, "configure_logging", e)
