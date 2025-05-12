#!/bin/bash

# This script requires 'jq' (a command-line JSON processor) to be installed.
# You can typically install it using your system's package manager (e.g., apt, yum, brew).

# Configuration for Claude Desktop to use the OPNsense MCP Server
# This script helps set up the Claude Desktop configuration

# Default Claude Desktop config location
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    CONFIG_DIR="$HOME/Library/Application Support/Claude"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    CONFIG_DIR="$HOME/.config/Claude Desktop"
elif [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "win32" ]]; then
    # Windows
    CONFIG_DIR="$APPDATA/Claude"
else
    echo "Unsupported operating system"
    exit 1
fi

CONFIG_FILE="$CONFIG_DIR/claude_desktop_config.json"

# Create directory if it doesn't exist
mkdir -p "$CONFIG_DIR"

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_PATH="$SCRIPT_DIR/opnsense_mcp_server.py"

# Check if the config file exists
if [ -f "$CONFIG_FILE" ]; then
    # Check if the file is valid JSON
    if jq empty "$CONFIG_FILE" 2>/dev/null; then
        echo "Existing valid config file found. Updating..."
        # Add our server to the existing config
        jq --arg path "$SERVER_PATH" '.mcpServers.opnsense = {"command": "python", "args": [$path], "env": {}}' "$CONFIG_FILE" > "$CONFIG_FILE.tmp"
        mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
    else
        echo "Existing config file is not valid JSON. Creating new config..."
        # Create a new config file
        echo "{\"mcpServers\": {\"opnsense\": {\"command\": \"python\", \"args\": [\"$SERVER_PATH\"], \"env\": {}}}}" > "$CONFIG_FILE"
    fi
else
    echo "No existing config file found. Creating new config..."
    # Create a new config file
    echo "{\"mcpServers\": {\"opnsense\": {\"command\": \"python\", \"args\": [\"$SERVER_PATH\"], \"env\": {}}}}" > "$CONFIG_FILE"
fi

echo "Claude Desktop configuration updated."
echo "Config file location: $CONFIG_FILE"
echo "Please restart Claude Desktop to apply the changes."
