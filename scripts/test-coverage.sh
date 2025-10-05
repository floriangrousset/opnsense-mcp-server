#!/bin/bash
# Run tests with coverage reporting

set -e  # Exit on error

echo "🧪 OPNsense MCP Server - Test Coverage"
echo "======================================"
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
fi

# Install dependencies
echo "📦 Installing dependencies..."
python -m pip install -q pytest pytest-asyncio pytest-cov 2>/dev/null || {
    echo "❌ Failed to install dependencies"
    exit 1
}

echo "✅ Dependencies ready"
echo ""

# Run tests with coverage
echo "🏃 Running tests with coverage..."
echo ""

python -m pytest tests/ \
    --cov=src/opnsense_mcp \
    --cov-report=term-missing \
    --cov-report=html:htmlcov \
    --cov-branch \
    -v \
    "$@"

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ Tests completed successfully!"
    echo ""
    echo "📊 Coverage report generated:"
    echo "   - Terminal: See above"
    echo "   - HTML: htmlcov/index.html"
    echo ""
    echo "To view HTML report:"
    echo "   open htmlcov/index.html"
else
    echo "❌ Some tests failed (exit code: $EXIT_CODE)"
fi

exit $EXIT_CODE
