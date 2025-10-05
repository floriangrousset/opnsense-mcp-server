#!/bin/bash
# Setup test environment and install all dependencies

set -e  # Exit on error

echo "🔧 OPNsense MCP Server - Setup Test Environment"
echo "==============================================="
echo ""

# Check if we're in the project root
if [ ! -f "requirements.txt" ]; then
    echo "❌ Error: Must be run from project root directory"
    exit 1
fi

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "✅ Python version: $PYTHON_VERSION"
echo ""

# Check for uv
if ! command -v uv &> /dev/null; then
    echo "⚠️  'uv' package manager not found"
    echo "   Install with: curl -LsSf https://astral.sh/uv/install.sh | sh"
    echo ""
    USE_PIP=true
else
    echo "✅ uv package manager found"
    USE_PIP=false
fi
echo ""

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "📦 Creating virtual environment..."
    if [ "$USE_PIP" = true ]; then
        python3 -m venv .venv
    else
        uv venv
    fi
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment exists"
fi
echo ""

# Activate virtual environment
echo "🔌 Activating virtual environment..."
source .venv/bin/activate
echo "✅ Virtual environment activated"
echo ""

# Install dependencies
echo "📥 Installing dependencies..."
if [ "$USE_PIP" = true ]; then
    pip install --upgrade pip
    pip install -r requirements.txt
    pip install pytest pytest-asyncio pytest-cov
else
    uv pip install -r requirements.txt
    uv pip install pytest pytest-asyncio pytest-cov
fi

echo ""
echo "✅ All dependencies installed"
echo ""

# Verify installation
echo "🔍 Verifying installation..."
python -c "import pytest; import pytest_asyncio; import pytest_cov; print('✅ pytest and plugins installed')"
python -c "import src.opnsense_mcp; print('✅ opnsense_mcp package importable')"
echo ""

echo "✅ Test environment setup complete!"
echo ""
echo "Next steps:"
echo "  1. Activate virtual environment:"
echo "     source .venv/bin/activate"
echo ""
echo "  2. Run tests:"
echo "     ./scripts/test.sh"
echo "     ./scripts/test-coverage.sh"
echo "     ./scripts/test-quick.sh"
echo ""
