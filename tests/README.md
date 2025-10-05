# OPNsense MCP Server Test Suite

Comprehensive test suite for the OPNsense MCP Server covering all 166 tools across 12 domain modules.

## Test Structure

```
tests/
├── conftest.py                    # Shared fixtures and pytest configuration
├── fixtures/                      # Mock data and test fixtures
│   ├── __init__.py
│   └── mock_responses.py         # Mock API responses for all domains
├── test_core/                     # Core module tests (7 files)
│   ├── test_exceptions.py        # Exception hierarchy tests
│   ├── test_models.py            # Pydantic model tests
│   ├── test_retry.py             # Retry mechanism tests
│   ├── test_connection.py        # Connection pool tests
│   ├── test_state.py             # Server state tests
│   ├── test_client_basic.py      # Client initialization tests
│   └── test_client_advanced.py   # Client request handling tests
├── test_shared/                   # Shared utility tests (2 files)
│   ├── test_constants.py         # API endpoint constants tests
│   └── test_error_handlers.py    # Error handling tests
├── test_domains/                  # Domain module tests (6 files)
│   ├── test_configuration.py     # Configuration domain (2 tools)
│   ├── test_system.py            # System domain (8 tools)
│   ├── test_firewall_nat.py      # Firewall & NAT domains (16 tools)
│   ├── test_utilities_vpn.py     # Utilities & VPN domains (2 tools)
│   ├── test_network_services.py  # Network, DNS/DHCP, Certificates (80 tools)
│   └── test_advanced_domains.py  # Users, Logging, Traffic Shaping (58 tools)
├── test_integration.py            # Integration tests
├── pytest.ini                     # Pytest configuration
├── .coveragerc                    # Coverage configuration
└── README.md                      # This file
```

## Running Tests

### Run all tests
```bash
pytest
```

### Run specific test categories
```bash
# Core module tests only
pytest tests/test_core/

# Domain tests only
pytest tests/test_domains/

# Integration tests only
pytest tests/test_integration.py -m integration

# Unit tests only (fast)
pytest -m unit
```

### Run with coverage
```bash
# Generate coverage report
pytest --cov=src/opnsense_mcp --cov-report=html

# View HTML coverage report
open htmlcov/index.html
```

### Run specific test files
```bash
pytest tests/test_core/test_exceptions.py
pytest tests/test_domains/test_configuration.py
```

### Run specific test classes or functions
```bash
pytest tests/test_core/test_exceptions.py::TestOPNsenseError
pytest tests/test_core/test_exceptions.py::TestOPNsenseError::test_basic_exception_creation
```

## Test Coverage

### Core Modules (100% coverage target)
- **exceptions.py**: All exception classes with context and serialization
- **models.py**: Pydantic model validation
- **retry.py**: Retry mechanism with exponential backoff
- **connection.py**: Connection pooling and rate limiting
- **state.py**: Server state lifecycle and session management
- **client.py**: HTTP client with error handling and logging

### Shared Utilities
- **constants.py**: 100+ API endpoint constants
- **error_handlers.py**: Error responses and validation helpers

### Domain Modules (166 tools)
- **configuration**: Connection setup and API discovery (2 tools)
- **system**: System monitoring and management (8 tools)
- **firewall**: Rule and alias management (8 tools)
- **nat**: NAT configuration (8 tools)
- **network**: Interface and VLAN management (26 tools)
- **dns_dhcp**: DNS and DHCP services (27 tools)
- **certificates**: Certificate lifecycle management (27 tools)
- **users**: User and group management (24 tools)
- **logging**: Log retrieval and analysis (9 tools)
- **traffic_shaping**: QoS and bandwidth management (25 tools)
- **vpn**: VPN monitoring (1 tool)
- **utilities**: Custom API calls (1 tool)

## Test Fixtures

### Shared Fixtures (conftest.py)
- `mock_opnsense_config`: Mock OPNsense configuration
- `mock_opnsense_client`: Mock API client
- `mock_server_state`: Mock server state
- `mock_http_transport`: Mock HTTP transport for testing
- `mock_mcp_context`: Mock MCP context for tool testing

### Mock Responses (fixtures/mock_responses.py)
Comprehensive mock API responses for:
- System status and health metrics
- Firewall rules and aliases
- NAT rules
- Network interfaces and VLANs
- DHCP leases and DNS settings
- Certificates and CAs
- Users, groups, and privileges
- Traffic shaping configuration
- VPN connections
- Log entries

## Test Patterns

### Async Testing
```python
@pytest.mark.asyncio
async def test_async_function():
    result = await some_async_function()
    assert result == expected_value
```

### Mocking API Clients
```python
with patch('module.get_opnsense_client') as mock_get_client:
    mock_client = Mock()
    mock_client.request = AsyncMock(return_value={"status": "ok"})
    mock_get_client.return_value = mock_client

    result = await tool_function(ctx=mock_mcp_context)
    assert "ok" in result
```

### Error Handling Tests
```python
async def test_error_handling(mock_mcp_context):
    with patch('module.get_opnsense_client') as mock_get_client:
        mock_get_client.side_effect = APIError("Test error")

        result = await tool_function(ctx=mock_mcp_context)
        assert "Error" in result
        mock_mcp_context.error.assert_called_once()
```

## Continuous Integration

Tests are designed to run in CI/CD pipelines with:
- Fast execution (< 2 minutes for full suite)
- No external dependencies
- Deterministic results
- Clear failure messages

## Contributing

When adding new features:

1. **Write tests first** (TDD approach)
2. **Maintain coverage** (aim for 90%+ coverage)
3. **Follow patterns** (use existing tests as templates)
4. **Add fixtures** (for reusable mock data)
5. **Test error cases** (not just happy paths)

### Test Checklist for New Tools
- [ ] Successful operation test
- [ ] Configuration error handling
- [ ] API error handling
- [ ] Input validation
- [ ] MCP context integration
- [ ] JSON response validation
- [ ] Edge cases

## Troubleshooting

### ImportError issues
```bash
# Ensure you're in the project root
cd /path/to/opnsense-mcp-server

# Install test dependencies
uv pip install -r requirements.txt
```

### Async warnings
If you see warnings about event loops, ensure tests use `@pytest.mark.asyncio` decorator.

### Coverage issues
```bash
# Clear coverage cache
rm -rf .coverage htmlcov/

# Run tests with coverage
pytest --cov=src/opnsense_mcp
```

## References

- [pytest documentation](https://docs.pytest.org/)
- [pytest-asyncio documentation](https://pytest-asyncio.readthedocs.io/)
- [Coverage.py documentation](https://coverage.readthedocs.io/)
- [OPNsense API documentation](https://docs.opnsense.org/development/api.html)
