# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an OPNsense MCP (Model Context Protocol) Server - a Python application that enables AI clients like Claude Desktop to manage OPNsense firewalls through natural language. The server translates AI requests into OPNsense API calls.

## Key Architecture

The project uses a **modular, domain-driven architecture** with 166 tools organized across 12 specialized domain modules:

```
src/opnsense_mcp/
├── main.py                    # FastMCP server initialization & entry point
├── core/                      # Core infrastructure
│   ├── client.py              # OPNsenseClient (HTTP client, authentication)
│   ├── connection.py          # ConnectionPool & rate limiting
│   ├── exceptions.py          # Exception hierarchy
│   ├── models.py              # Pydantic models
│   ├── retry.py               # Retry mechanisms
│   └── state.py               # ServerState management
├── shared/                    # Shared utilities
│   ├── constants.py           # API endpoint constants
│   ├── error_handlers.py      # Error handling helpers
│   └── validators.py          # Input validators
└── domains/                   # Feature-specific modules (166 tools)
    ├── configuration.py       # Connection setup (2 tools)
    ├── system.py              # System management (8 tools)
    ├── firewall.py            # Firewall rules & aliases (8 tools)
    ├── nat.py                 # NAT management (7 tools)
    ├── network.py             # Interfaces, VLANs, bridges, LAGG, VIPs (20 tools)
    ├── dns_dhcp.py            # DNS & DHCP services (28 tools)
    ├── certificates.py        # Certificate lifecycle (25 tools)
    ├── users.py               # User & group management (31 tools)
    ├── logging.py             # Log management & analysis (11 tools)
    ├── traffic_shaping.py     # QoS & traffic shaping (23 tools)
    ├── vpn.py                 # VPN connections (1 tool)
    └── utilities.py           # Custom API calls & utilities (4 tools)
```

### Core Design Principles

- **Domain-driven structure**: Tools grouped by functional area for maintainability
- **FastMCP framework**: Uses Anthropic's FastMCP library for MCP protocol handling
- **Centralized client**: `OPNsenseClient` in `core/client.py` handles all API communication
- **Global state**: `ServerState` in `core/state.py` manages connection lifecycle
- **Secure credential storage**: `ConfigLoader` in `core/config_loader.py` handles local-only credential storage
- **CLI management**: `cli/` directory provides secure credential setup and management commands
- **Tool registration**: Each domain module imports `mcp` from `main.py` and uses `@mcp.tool()` decorators
- **Backward compatibility**: Root `opnsense-mcp-server.py` wrapper maintains compatibility with older setups

### Security Architecture

**Local-Only Credential Storage**: As of v1.1.0, the server implements secure credential storage where credentials are never sent to the LLM.

**Credential Sources (Priority Order)**:
1. **Environment Variables** (highest priority) - for CI/CD and containers
   - `OPNSENSE_URL`, `OPNSENSE_API_KEY`, `OPNSENSE_API_SECRET`, `OPNSENSE_VERIFY_SSL`
2. **Config File** (~/.opnsense-mcp/config.json) - for local development with profile support
3. **System Keyring** (backward compatibility) - legacy method for existing installations

**ConfigLoader** (`core/config_loader.py`):
- Manages cascading credential loading from multiple sources
- Enforces secure file permissions (0600)
- Provides profile management for multiple firewalls
- Never exposes credentials in logs or tool responses

**CLI Tools** (`cli/` directory):
- `opnsense-mcp setup` - Interactive credential configuration
- `opnsense-mcp list-profiles` - List configured profiles
- `opnsense-mcp test-connection` - Test firewall connectivity
- `opnsense-mcp delete-profile` - Remove credential profiles

**Tool Signature Change**:
```python
# OLD (Insecure - credentials exposed to LLM)
configure_opnsense_connection(url, api_key, api_secret, verify_ssl)

# NEW (Secure - only profile name sent to LLM)
configure_opnsense_connection(profile="default")
```

## Development Commands

### Setup Environment
```bash
# Install uv (Python package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create virtual environment
uv venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install dependencies
uv pip install -r requirements.txt
```

### Running the Server
```bash
# Run as Python module (recommended)
python -m src.opnsense_mcp.main

# Or run via entry point (if installed)
opnsense-mcp-server

# Or use backward compatibility wrapper
python opnsense-mcp-server.py
```

### Testing
```bash
# Install dev dependencies
uv pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=src/opnsense_mcp

# Run specific test module
pytest tests/test_core/test_client.py
```

### Code Quality
```bash
# Format code with black
black src/ tests/

# Lint with ruff
ruff check src/ tests/

# Type checking with mypy
mypy src/
```

### Docker Support
```bash
# Build image
docker build -t opnsense-mcp-server .

# Run with docker-compose
docker-compose up -d
```

## Key Implementation Details

### Working with Domain Modules

When adding or modifying tools, follow this pattern:

1. **Locate the appropriate domain module** in `src/opnsense_mcp/domains/`
2. **Import required dependencies**:
   ```python
   from ..core.client import get_opnsense_client
   from ..core.exceptions import OPNsenseClientError
   from ..shared.constants import API_ENDPOINTS
   from ..main import mcp
   ```
3. **Define tools with decorators**:
   ```python
   @mcp.tool(name="tool_name", description="Tool description")
   async def tool_name(param: str) -> dict:
       client = get_opnsense_client()
       result = await client.request("GET", API_ENDPOINTS["endpoint"])
       return result
   ```

### Authentication
- Uses HTTP Basic Auth with base64-encoded API key/secret
- Configured via `configure_opnsense_connection` tool at runtime (in `domains/configuration.py`)
- Connection state managed by `ServerState` in `core/state.py`
- No persistent configuration storage for security

### Error Handling
- Exception hierarchy defined in `core/exceptions.py`
- All tools check for initialized client via `get_opnsense_client()`
- Error handling helpers in `shared/error_handlers.py`
- Comprehensive logging via `core/client.py`

### API Patterns
- Constants defined in `shared/constants.py` for all OPNsense API endpoints
- Consistent request/response handling in `OPNsenseClient.request()` method
- POST requests for configuration changes are followed by "apply" calls where needed
- Retry logic with exponential backoff in `core/retry.py`
- Connection pooling and rate limiting in `core/connection.py`

### Tool Organization by Domain

Each domain module contains related tools and is independently testable:

- **`domains/configuration.py`** (2 tools): Connection setup, API endpoint discovery
- **`domains/system.py`** (8 tools): System status, health monitoring, services, plugins, backup, audit
- **`domains/firewall.py`** (8 tools): Firewall rules CRUD, aliases management, rule toggling
- **`domains/nat.py`** (7 tools): Outbound NAT, one-to-one NAT, port forwarding guidance
- **`domains/network.py`** (20 tools): Interfaces, VLANs, bridges, LAGG, virtual IPs
- **`domains/dns_dhcp.py`** (28 tools): DHCP server/leases/mappings, DNS resolver/forwarder, host/domain overrides
- **`domains/certificates.py`** (25 tools): CA management, certificate lifecycle, CSRs, ACME/Let's Encrypt, validation
- **`domains/users.py`** (31 tools): User/group CRUD, privileges, authentication, role-based helpers
- **`domains/logging.py`** (11 tools): Log access, search, export, statistics, security analysis, reporting
- **`domains/traffic_shaping.py`** (23 tools): Pipes, queues, rules, QoS helpers for common scenarios
- **`domains/vpn.py`** (1 tool): VPN connection status monitoring
- **`domains/utilities.py`** (4 tools): Custom API calls, backup, service management

See README.md for complete tool listings and capabilities within each domain (166 tools total).

### Module Development Guidelines

When extending functionality:

1. **Choose the right domain**: Add tools to the most relevant domain module
2. **Follow naming conventions**: Use descriptive snake_case names prefixed with domain context
3. **Maintain consistency**: Follow existing patterns within the domain
4. **Document thoroughly**: Include comprehensive docstrings with parameter descriptions
5. **Handle errors gracefully**: Use custom exceptions from `core/exceptions.py`
6. **Log appropriately**: Use the logger for debugging and error tracking
7. **Test independently**: Each domain should have corresponding tests in `tests/test_domains/`

### Adding a New Domain Module

If creating a completely new domain (rare):

1. Create `src/opnsense_mcp/domains/new_domain.py`
2. Import `mcp` from `..main`
3. Import required core/shared utilities
4. Define tools with `@mcp.tool()` decorators
5. Import the module in `src/opnsense_mcp/main.py`
6. Create corresponding test file in `tests/test_domains/test_new_domain.py`
7. Update CLAUDE.md and README.md documentation

### Key Domain-Specific Implementation Notes

#### Traffic Shaping (`domains/traffic_shaping.py`)
Hierarchical QoS model: Pipes (hard limits) → Queues (weighted sharing) → Rules (traffic classification). Supports multiple schedulers (FQ-CoDel recommended) and includes high-level helpers for common scenarios.

#### Certificate Management (`domains/certificates.py`)
Full PKI lifecycle support including CA management, CSR generation, and ACME/Let's Encrypt automation. UUID-based resource management with automatic service reconfiguration.

#### User Management (`domains/users.py`)
RBAC-based system with UUID resource identification. Includes helper tools for common scenarios (admin creation, bulk imports, group templates). Effective privileges calculated by combining user and group permissions.

#### Logging (`domains/logging.py`)
Multi-source log access with API-first design and graceful fallbacks. Built-in security event analysis and threat detection patterns. Supports export to JSON/CSV/text formats.

#### Network (`domains/network.py`)
Manages interfaces, VLANs (tag validation 1-4094), bridges (STP support), LAGG (LACP/failover/loadbalance), and virtual IPs (CARP for HA). Automatic conflict detection and topology-aware validation.

#### DNS & DHCP (`domains/dns_dhcp.py`)
Interface-aware DHCP server management with static mappings and lease analysis. DNS resolver (Unbound) and forwarder (dnsmasq) configuration with host/domain overrides.

For comprehensive feature details, refer to README.md.

## Architecture History & Migration

This project was completely restructured from a monolithic 9,529-line single file (`opnsense-mcp-server.py`) into a modern modular architecture. The transformation is documented in `PLAN.md`.

### Before (Monolithic)
- Single file: 9,529 lines, 341.5KB
- 166 tools in one namespace
- Difficult to test, navigate, and maintain

### After (Modular)
- 25+ files across core/shared/domains
- Same 166 tools organized by domain
- Independent testing and development
- Backward compatible via wrapper

### Package Structure

The project follows modern Python packaging standards:

- **`pyproject.toml`**: Primary project configuration (PEP 517/518 compliant)
- **`setup.py`**: Minimal compatibility shim for older tools
- **`requirements.txt`**: Production dependencies
- **`src/` layout**: Prevents accidental imports of local modules
- **Entry point**: `opnsense-mcp-server` command after installation

Install in development mode:
```bash
uv pip install -e ".[dev]"
```

## Claude Desktop Integration

The `setup-claude.sh` script automatically configures Claude Desktop to use this MCP server by modifying the `claude_desktop_config.json` file with the appropriate server entry. It intelligently detects virtual environments and creates backups before modifications.

## Development Workflow

When developing new features:

1. **Switch to develop branch**: `git checkout develop && git pull`
2. **Create feature branch**: `git checkout -b feat/your-feature-name`
3. **Implement with commits**: Make multiple logical commits during development
4. **Run tests**: `pytest tests/` before creating PR
5. **Create pull request**: PR from feature branch to develop branch
6. **Request review**: Ask for PR merge approval before proceeding to next feature

### Commit Message Conventions

- `feat:` - New feature or enhancement
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `refactor:` - Code restructuring without behavior change
- `test:` - Adding or updating tests
- `chore:` - Build process, dependencies, tooling