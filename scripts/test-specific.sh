#!/bin/bash
# Run specific tests by category or file

set -e  # Exit on error

CATEGORY=$1

if [ -z "$CATEGORY" ]; then
    echo "🧪 OPNsense MCP Server - Run Specific Tests"
    echo "==========================================="
    echo ""
    echo "Usage: $0 <category>"
    echo ""
    echo "Available categories:"
    echo "  core          - Core module tests"
    echo "  shared        - Shared utility tests"
    echo "  domains       - All domain tests"
    echo "  integration   - Integration tests"
    echo "  configuration - Configuration domain"
    echo "  system        - System domain"
    echo "  firewall      - Firewall domain"
    echo "  network       - Network domain"
    echo "  users         - Users domain"
    echo ""
    echo "Examples:"
    echo "  $0 core"
    echo "  $0 domains"
    echo "  $0 configuration"
    exit 1
fi

# Check if we're in the project root
if [ ! -f "pytest.ini" ]; then
    echo "❌ Error: Must be run from project root directory"
    exit 1
fi

# Install dependencies
python -m pip install -q pytest pytest-asyncio 2>/dev/null || {
    echo "❌ Failed to install dependencies"
    exit 1
}

# Determine test path
case $CATEGORY in
    core)
        TEST_PATH="tests/test_core/"
        ;;
    shared)
        TEST_PATH="tests/test_shared/"
        ;;
    domains)
        TEST_PATH="tests/test_domains/"
        ;;
    integration)
        TEST_PATH="tests/test_integration.py"
        ;;
    configuration)
        TEST_PATH="tests/test_domains/test_configuration.py"
        ;;
    system)
        TEST_PATH="tests/test_domains/test_system.py"
        ;;
    firewall)
        TEST_PATH="tests/test_domains/test_firewall_nat.py"
        ;;
    network)
        TEST_PATH="tests/test_domains/test_network_services.py"
        ;;
    users)
        TEST_PATH="tests/test_domains/test_advanced_domains.py"
        ;;
    *)
        echo "❌ Unknown category: $CATEGORY"
        echo "Run '$0' without arguments to see available categories"
        exit 1
        ;;
esac

echo "🧪 Running tests: $CATEGORY"
echo ""

python -m pytest $TEST_PATH -v "${@:2}"

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ Tests passed!"
else
    echo "❌ Some tests failed (exit code: $EXIT_CODE)"
fi

exit $EXIT_CODE
