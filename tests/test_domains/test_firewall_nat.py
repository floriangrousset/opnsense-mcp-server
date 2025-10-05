"""
Tests for OPNsense MCP Server firewall and NAT domains.

This module tests firewall rule management and NAT configuration tools.
"""

import pytest
import json
from unittest.mock import AsyncMock, Mock, patch

from src.opnsense_mcp.core.exceptions import ValidationError, APIError


@pytest.mark.asyncio
class TestFirewallDomain:
    """Test firewall domain tools."""

    async def test_firewall_get_rules(self, mock_mcp_context, mock_http_success_response):
        """Test retrieving firewall rules."""
        from src.opnsense_mcp.domains.firewall import firewall_get_rules

        with patch('src.opnsense_mcp.domains.firewall.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={
                "rows": [{"uuid": "rule1", "action": "pass"}],
                "rowCount": 1
            })
            mock_get_client.return_value = mock_client

            result = await firewall_get_rules(ctx=mock_mcp_context)

            result_data = json.loads(result)
            assert "rows" in result_data
            assert len(result_data["rows"]) == 1

    async def test_firewall_add_rule(self, mock_mcp_context):
        """Test adding a firewall rule."""
        from src.opnsense_mcp.domains.firewall import firewall_add_rule

        with patch('src.opnsense_mcp.domains.firewall.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={"result": "saved", "uuid": "new-rule"})
            mock_get_client.return_value = mock_client

            result = await firewall_add_rule(
                ctx=mock_mcp_context,
                description="Test rule",
                action="pass",
                interface="lan",
                direction="in",
                protocol="tcp",
                source_net="any",
                destination_net="any"
            )

            assert "success" in result.lower() or "saved" in result.lower()

    async def test_firewall_delete_rule(self, mock_mcp_context):
        """Test deleting a firewall rule."""
        from src.opnsense_mcp.domains.firewall import firewall_delete_rule

        with patch('src.opnsense_mcp.domains.firewall.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={"result": "deleted"})
            mock_get_client.return_value = mock_client

            result = await firewall_delete_rule(
                ctx=mock_mcp_context,
                uuid="rule-uuid-123"
            )

            assert "success" in result.lower() or "deleted" in result.lower()

    async def test_get_firewall_aliases(self, mock_mcp_context):
        """Test retrieving firewall aliases."""
        from src.opnsense_mcp.domains.firewall import get_firewall_aliases

        with patch('src.opnsense_mcp.domains.firewall.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={
                "rows": [{"name": "WebServers", "type": "host"}]
            })
            mock_get_client.return_value = mock_client

            result = await get_firewall_aliases(ctx=mock_mcp_context)

            result_data = json.loads(result)
            assert "rows" in result_data


@pytest.mark.asyncio
class TestNATDomain:
    """Test NAT domain tools."""

    async def test_nat_list_outbound_rules(self, mock_mcp_context):
        """Test listing NAT outbound rules."""
        from src.opnsense_mcp.domains.nat import nat_list_outbound_rules

        with patch('src.opnsense_mcp.domains.nat.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={
                "rows": [{"uuid": "nat1", "source": "192.168.1.0/24"}]
            })
            mock_get_client.return_value = mock_client

            result = await nat_list_outbound_rules(ctx=mock_mcp_context)

            result_data = json.loads(result)
            assert "rows" in result_data

    async def test_nat_add_outbound_rule(self, mock_mcp_context):
        """Test adding NAT outbound rule."""
        from src.opnsense_mcp.domains.nat import nat_add_outbound_rule

        with patch('src.opnsense_mcp.domains.nat.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={"result": "saved"})
            mock_get_client.return_value = mock_client

            result = await nat_add_outbound_rule(
                ctx=mock_mcp_context,
                interface="wan",
                source="192.168.1.0/24",
                destination="any",
                description="Test NAT"
            )

            assert "success" in result.lower() or "saved" in result.lower()

    async def test_nat_list_one_to_one_rules(self, mock_mcp_context):
        """Test listing one-to-one NAT rules."""
        from src.opnsense_mcp.domains.nat import nat_list_one_to_one_rules

        with patch('src.opnsense_mcp.domains.nat.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_client.request = AsyncMock(return_value={
                "rows": [{"external": "203.0.113.10", "internal": "192.168.1.100"}]
            })
            mock_get_client.return_value = mock_client

            result = await nat_list_one_to_one_rules(ctx=mock_mcp_context)

            result_data = json.loads(result)
            assert "rows" in result_data


@pytest.mark.asyncio
class TestValidation:
    """Test input validation in firewall and NAT domains."""

    async def test_invalid_firewall_parameters(self, mock_mcp_context):
        """Test that invalid firewall parameters are rejected."""
        from src.opnsense_mcp.domains.firewall import firewall_add_rule

        with patch('src.opnsense_mcp.domains.firewall.get_opnsense_client', new_callable=AsyncMock) as mock_get_client:
            mock_client = Mock()
            mock_get_client.return_value = mock_client

            # Invalid action
            result = await firewall_add_rule(
                ctx=mock_mcp_context,
                description="Invalid test",
                action="invalid_action",
                interface="lan",
                direction="in",
                protocol="tcp",
                source_net="any",
                destination_net="any"
            )

            assert "error" in result.lower() or "invalid" in result.lower()
