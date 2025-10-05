"""
Tests for OPNsense MCP Server API endpoint constants.

This module tests that all API endpoint constants are properly defined
and follow the expected format for OPNsense API endpoints.
"""

import pytest
from src.opnsense_mcp.shared import constants


class TestAPIConstants:
    """Test API endpoint constants."""

    def test_core_system_constants_defined(self):
        """Test that core system API constants are defined."""
        assert hasattr(constants, 'API_CORE_MENU_GET_ITEMS')
        assert hasattr(constants, 'API_CORE_FIRMWARE_STATUS')
        assert hasattr(constants, 'API_CORE_SYSTEM_INFO')
        assert hasattr(constants, 'API_CORE_SERVICE_SEARCH')
        assert hasattr(constants, 'API_CORE_SERVICE_RESTART')
        assert hasattr(constants, 'API_CORE_BACKUP_DOWNLOAD')

    def test_firewall_filter_constants_defined(self):
        """Test that firewall filter API constants are defined."""
        assert hasattr(constants, 'API_FIREWALL_FILTER_SEARCH_RULE')
        assert hasattr(constants, 'API_FIREWALL_FILTER_ADD_RULE')
        assert hasattr(constants, 'API_FIREWALL_FILTER_DEL_RULE')
        assert hasattr(constants, 'API_FIREWALL_FILTER_TOGGLE_RULE')
        assert hasattr(constants, 'API_FIREWALL_FILTER_APPLY')

    def test_firewall_alias_constants_defined(self):
        """Test that firewall alias API constants are defined."""
        assert hasattr(constants, 'API_FIREWALL_ALIAS_SEARCH_ITEM')
        assert hasattr(constants, 'API_FIREWALL_ALIAS_UTIL_ADD')
        assert hasattr(constants, 'API_FIREWALL_ALIAS_UTIL_DELETE')
        assert hasattr(constants, 'API_FIREWALL_ALIAS_RECONFIGURE')

    def test_nat_constants_defined(self):
        """Test that NAT API constants are defined."""
        assert hasattr(constants, 'API_FIREWALL_NAT_OUTBOUND_SEARCH')
        assert hasattr(constants, 'API_FIREWALL_NAT_ONETOONE_SEARCH')

    def test_interface_constants_defined(self):
        """Test that interface API constants are defined."""
        assert hasattr(constants, 'API_INTERFACES_OVERVIEW_INFO')
        assert hasattr(constants, 'API_INTERFACES_OVERVIEW_GET_INTERFACE')
        assert hasattr(constants, 'API_INTERFACES_OVERVIEW_RELOAD_INTERFACE')

    def test_vlan_constants_defined(self):
        """Test that VLAN API constants are defined."""
        assert hasattr(constants, 'API_INTERFACES_VLAN_SEARCH')
        assert hasattr(constants, 'API_INTERFACES_VLAN_GET')
        assert hasattr(constants, 'API_INTERFACES_VLAN_ADD')
        assert hasattr(constants, 'API_INTERFACES_VLAN_SET')
        assert hasattr(constants, 'API_INTERFACES_VLAN_DEL')
        assert hasattr(constants, 'API_INTERFACES_VLAN_RECONFIGURE')

    def test_constants_are_strings(self):
        """Test that all constants are strings."""
        constants_to_check = [
            constants.API_CORE_FIRMWARE_STATUS,
            constants.API_CORE_SYSTEM_INFO,
            constants.API_FIREWALL_FILTER_SEARCH_RULE,
            constants.API_INTERFACES_OVERVIEW_INFO,
        ]

        for constant in constants_to_check:
            assert isinstance(constant, str)

    def test_constants_start_with_slash(self):
        """Test that all endpoint constants start with /."""
        constants_to_check = [
            constants.API_CORE_FIRMWARE_STATUS,
            constants.API_CORE_SYSTEM_INFO,
            constants.API_FIREWALL_FILTER_SEARCH_RULE,
            constants.API_FIREWALL_ALIAS_SEARCH_ITEM,
            constants.API_INTERFACES_OVERVIEW_INFO,
        ]

        for constant in constants_to_check:
            assert constant.startswith('/'), f"Constant {constant} should start with /"

    def test_core_firmware_status_endpoint(self):
        """Test specific core firmware status endpoint."""
        assert constants.API_CORE_FIRMWARE_STATUS == "/core/firmware/status"

    def test_core_system_info_endpoint(self):
        """Test specific core system info endpoint."""
        assert constants.API_CORE_SYSTEM_INFO == "/core/system/info"

    def test_firewall_filter_search_endpoint(self):
        """Test specific firewall filter search endpoint."""
        assert constants.API_FIREWALL_FILTER_SEARCH_RULE == "/firewall/filter/searchRule"

    def test_firewall_filter_add_endpoint(self):
        """Test specific firewall filter add endpoint."""
        assert constants.API_FIREWALL_FILTER_ADD_RULE == "/firewall/filter/addRule"

    def test_interfaces_overview_info_endpoint(self):
        """Test specific interfaces overview info endpoint."""
        assert constants.API_INTERFACES_OVERVIEW_INFO == "/interfaces/overview/interfacesInfo"

    def test_vlan_search_endpoint(self):
        """Test specific VLAN search endpoint."""
        assert constants.API_INTERFACES_VLAN_SEARCH == "/interfaces/vlan_settings/search_item"

    def test_certificate_constants_defined(self):
        """Test that certificate API constants are defined."""
        assert hasattr(constants, 'API_TRUST_CERT_SEARCH')
        assert hasattr(constants, 'API_TRUST_CA_SEARCH')

    def test_dhcp_constants_defined(self):
        """Test that DHCP API constants are defined."""
        assert hasattr(constants, 'API_DHCPV4_LEASES_SEARCH')
        assert hasattr(constants, 'API_DHCPV4_SERVICE_GET')

    def test_dns_constants_defined(self):
        """Test that DNS API constants are defined."""
        assert hasattr(constants, 'API_UNBOUND_SETTINGS_GET')
        assert hasattr(constants, 'API_UNBOUND_SERVICE_RESTART')

    def test_vpn_constants_defined(self):
        """Test that VPN API constants are defined."""
        assert hasattr(constants, 'API_OPENVPN_SERVICE_SEARCH_SESSIONS')
        assert hasattr(constants, 'API_IPSEC_SESSIONS')

    def test_traffic_shaper_constants_defined(self):
        """Test that traffic shaper API constants are defined."""
        assert hasattr(constants, 'API_TRAFFICSHAPER_SETTINGS_GET')
        assert hasattr(constants, 'API_TRAFFICSHAPER_SERVICE_RECONFIGURE')

    def test_user_management_constants_defined(self):
        """Test that user management API constants are defined."""
        assert hasattr(constants, 'API_SYSTEM_USER_SEARCH')
        assert hasattr(constants, 'API_SYSTEM_GROUP_SEARCH')

    def test_all_constants_non_empty(self):
        """Test that no constants are empty strings."""
        # Get all constants that start with API_
        api_constants = [
            getattr(constants, attr) for attr in dir(constants)
            if attr.startswith('API_') and not attr.startswith('__')
        ]

        assert len(api_constants) > 0, "Should have at least some API constants"

        for constant in api_constants:
            assert constant != "", f"Constant should not be empty"
            assert len(constant) > 1, f"Constant {constant} should have meaningful content"

    def test_endpoint_pattern_consistency(self):
        """Test that endpoints follow consistent naming patterns."""
        # Check that endpoints use consistent path separators
        constants_to_check = [
            constants.API_CORE_FIRMWARE_STATUS,
            constants.API_FIREWALL_FILTER_SEARCH_RULE,
            constants.API_INTERFACES_OVERVIEW_INFO,
        ]

        for constant in constants_to_check:
            # Should not have double slashes
            assert '//' not in constant, f"Endpoint {constant} should not have double slashes"
            # Should not end with slash (unless it's a single /)
            if len(constant) > 1:
                assert not constant.endswith('/'), f"Endpoint {constant} should not end with slash"

    def test_constants_module_has_expected_count(self):
        """Test that constants module has a reasonable number of API endpoints."""
        # Count all API_ constants
        api_constants = [
            attr for attr in dir(constants)
            if attr.startswith('API_') and not attr.startswith('__')
        ]

        # Should have at least 100 constants (we have 166 tools, so likely many endpoints)
        assert len(api_constants) >= 100, f"Expected at least 100 API constants, got {len(api_constants)}"

    def test_dhcpv4_leases_search_endpoint(self):
        """Test specific DHCP v4 leases search endpoint."""
        assert constants.API_DHCPV4_LEASES_SEARCH == "/dhcpv4/leases/searchLease"

    def test_unbound_settings_get_endpoint(self):
        """Test specific Unbound settings get endpoint."""
        assert constants.API_UNBOUND_SETTINGS_GET == "/unbound/settings/get"

    def test_traffic_shaper_pipe_search_endpoint(self):
        """Test specific traffic shaper pipe search endpoint."""
        assert constants.API_TRAFFICSHAPER_SETTINGS_SEARCH_PIPES == "/trafficshaper/settings/searchPipes"

    def test_system_user_search_endpoint(self):
        """Test specific system user search endpoint."""
        assert constants.API_SYSTEM_USER_SEARCH == "/system/user/searchUsers"

    def test_trust_cert_search_endpoint(self):
        """Test specific trust certificate search endpoint."""
        assert constants.API_TRUST_CERT_SEARCH == "/trust/cert/search"
