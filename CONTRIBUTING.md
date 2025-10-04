# Contributing to OPNsense MCP Server

Thank you for considering contributing to the OPNsense MCP Server project! We welcome contributions from the community.

## Project Architecture

This project uses a **modular, domain-driven architecture** with 166 tools organized across 12 specialized domain modules. Before contributing, familiarize yourself with:

- **CLAUDE.md** - Comprehensive architecture guide and development patterns
- **src/opnsense_mcp/domains/** - 12 domain modules (configuration, system, firewall, nat, network, dns_dhcp, certificates, users, logging, traffic_shaping, vpn, utilities)
- **src/opnsense_mcp/core/** - Core infrastructure (client, connection, exceptions, models, retry, state)
- **src/opnsense_mcp/shared/** - Shared utilities (constants, error handlers, validators)

## How Can I Contribute?

### Reporting Bugs

- Ensure the bug was not already reported by searching the issue tracker
- If you're unable to find an open issue addressing the problem, open a new one
- Include a **title and clear description**, as much relevant information as possible
- Include a **code sample** or **executable test case** demonstrating the expected behavior
- Clearly describe the steps to reproduce the bug
- Specify which domain module is affected (if applicable)

### Suggesting Enhancements

- Open a new issue on the issue tracker
- Clearly describe the enhancement and the motivation for it
- Explain why this enhancement would be useful to users
- Identify which domain module(s) would be affected
- Provide code examples or API call examples if possible

### Pull Requests

#### Workflow

1. **Fork the repository**
2. **Clone and setup**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/opnsense-mcp-server
   cd opnsense-mcp-server
   uv venv && source .venv/bin/activate
   uv pip install -e ".[dev]"
   ```
3. **Create a branch** from `develop`:
   ```bash
   git checkout develop
   git pull origin develop
   git checkout -b feat/your-feature-name
   # or: git checkout -b fix/your-bugfix-name
   # or: git checkout -b docs/your-doc-update
   ```
4. **Make your changes** following the guidelines below
5. **Add tests** for your changes (see Testing section)
6. **Run quality checks**:
   ```bash
   # Format code
   black src/ tests/

   # Lint code
   ruff check src/ tests/

   # Type check
   mypy src/

   # Run tests
   pytest tests/
   ```
7. **Commit your changes** with clear, descriptive messages:
   ```bash
   git commit -m "feat: add support for XYZ feature"
   ```
8. **Push to your fork**:
   ```bash
   git push origin feat/your-feature-name
   ```
9. **Create a Pull Request** to the `develop` branch
   - Provide a clear description of the problem and solution
   - Link to any relevant issues
   - Include test results and coverage reports if applicable

## Development Guidelines

### Code Style

- **Follow PEP 8** - Python coding conventions
- **Use Black** for code formatting (line length: 100)
- **Use Ruff** for linting
- **Use type hints** where appropriate
- **Document thoroughly** - Include comprehensive docstrings

### Adding New Tools

When adding a new tool to an existing domain:

1. **Locate the appropriate domain module** in `src/opnsense_mcp/domains/`
2. **Import required dependencies**:
   ```python
   from ..core.client import get_opnsense_client
   from ..core.exceptions import OPNsenseClientError
   from ..shared.constants import API_ENDPOINTS
   from ..main import mcp
   ```
3. **Define your tool**:
   ```python
   @mcp.tool(name="your_tool_name", description="Clear description")
   async def your_tool_name(param: str) -> dict:
       """
       Comprehensive docstring explaining what the tool does.

       Args:
           param: Description of parameter

       Returns:
           dict: Description of return value

       Raises:
           OPNsenseClientError: When connection fails
       """
       client = get_opnsense_client()
       result = await client.request("GET", API_ENDPOINTS["your_endpoint"])
       return result
   ```
4. **Update documentation** in README.md with the new tool

### Adding a New Domain Module

If creating a completely new domain (rare):

1. Create `src/opnsense_mcp/domains/new_domain.py`
2. Import `mcp` from `..main`
3. Import required core/shared utilities
4. Define tools with `@mcp.tool()` decorators
5. Import the module in `src/opnsense_mcp/main.py`
6. Create corresponding test file in `tests/test_domains/test_new_domain.py`
7. Update CLAUDE.md and README.md documentation

### Testing

We use pytest for testing:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/opnsense_mcp --cov-report=html

# Run specific test module
pytest tests/test_core/test_client.py

# Run specific test
pytest tests/test_core/test_client.py::test_client_initialization
```

Test files should mirror the source structure:
```
tests/
├── test_core/
│   ├── test_client.py
│   ├── test_connection.py
│   └── test_exceptions.py
├── test_domains/
│   ├── test_configuration.py
│   ├── test_system.py
│   └── ... (one per domain)
└── test_shared/
    └── test_constants.py
```

### Commit Message Conventions

Use semantic commit messages:

- `feat:` - New feature or enhancement
- `fix:` - Bug fix
- `docs:` - Documentation changes only
- `refactor:` - Code restructuring without behavior change
- `test:` - Adding or updating tests
- `chore:` - Build process, dependencies, tooling
- `perf:` - Performance improvements
- `ci:` - CI/CD configuration changes

Examples:
```
feat: add support for WireGuard configuration in VPN domain
fix: correct DHCP lease parsing in dns_dhcp module
docs: update README with new certificate management tools
test: add unit tests for firewall rule validation
```

### Error Handling

- Use custom exceptions from `core/exceptions.py`
- All tools should check for initialized client via `get_opnsense_client()`
- Provide clear, actionable error messages to users
- Log errors with appropriate context for debugging

### API Patterns

- Define API endpoints in `shared/constants.py`
- Use consistent request/response handling via `OPNsenseClient.request()`
- POST requests for configuration changes should be followed by "apply" calls where needed
- Leverage retry logic with exponential backoff from `core/retry.py`

## Questions?

- Read **CLAUDE.md** for architectural guidance
- Check existing domain modules for examples
- Open an issue for clarification
- Join discussions in the issue tracker

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Follow the principle of least surprise in your contributions

Thank you for contributing to making OPNsense management more accessible through AI! 🚀
