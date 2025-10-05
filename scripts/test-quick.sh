#!/bin/bash
# Quick test run - fast tests only, minimal output

set -e  # Exit on error

echo "⚡ OPNsense MCP Server - Quick Test"
echo "==================================="
echo ""

# Check if we're in the project root
if [ ! -f "pytest.ini" ]; then
    echo "❌ Error: Must be run from project root directory"
    exit 1
fi

# Install dependencies quietly
python -m pip install -q pytest pytest-asyncio 2>/dev/null || {
    echo "❌ Failed to install dependencies"
    exit 1
}

# Run tests with minimal output
python -m pytest tests/ \
    -q \
    --tb=line \
    -x \
    "$@"

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ Quick test passed!"
else
    echo "❌ Test failed (exit code: $EXIT_CODE)"
fi

exit $EXIT_CODE
