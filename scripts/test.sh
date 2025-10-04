#!/bin/bash
# Run the complete test suite for OPNsense MCP Server

set -e  # Exit on error

echo "🧪 OPNsense MCP Server - Test Suite"
echo "===================================="
echo ""

# Check if we're in the project root
if [ ! -f "pytest.ini" ]; then
    echo "❌ Error: Must be run from project root directory"
    exit 1
fi

# Check if virtual environment is activated
if [ -z "$VIRTUAL_ENV" ]; then
    echo "⚠️  Warning: No virtual environment detected"
    echo "   It's recommended to activate .venv first:"
    echo "   source .venv/bin/activate"
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Install test dependencies if needed
echo "📦 Checking dependencies..."
python -m pip install -q pytest pytest-asyncio pytest-cov 2>/dev/null || {
    echo "❌ Failed to install test dependencies"
    exit 1
}

echo "✅ Dependencies ready"
echo ""

# Run tests
echo "🏃 Running test suite..."
echo ""

python -m pytest tests/ \
    -v \
    --tb=short \
    "$@"

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ All tests passed!"
else
    echo "❌ Some tests failed (exit code: $EXIT_CODE)"
fi

exit $EXIT_CODE
