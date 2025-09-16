#!/bin/bash

# This script requires 'jq' (a command-line JSON processor) to be installed.
# You can typically install it using your system's package manager (e.g., apt, yum, brew).

# Configuration for Claude Desktop to use the OPNsense MCP Server
# This script helps set up the Claude Desktop configuration

# Default Claude Desktop config location (allow override via CONFIG_DIR env var)
if [ -z "$CONFIG_DIR" ]; then
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
fi

CONFIG_FILE="$CONFIG_DIR/claude_desktop_config.json"

# Create directory if it doesn't exist
mkdir -p "$CONFIG_DIR"

# Get the script directory and server path
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_PATH="$SCRIPT_DIR/opnsense-mcp-server.py"

# Determine Python command to use (prefer virtual environment)
if [ -f "$SCRIPT_DIR/.venv/bin/python" ]; then
    PYTHON_CMD="$SCRIPT_DIR/.venv/bin/python"
    echo "✓ Using virtual environment Python: $PYTHON_CMD"
elif [ -f "$SCRIPT_DIR/venv/bin/python" ]; then
    PYTHON_CMD="$SCRIPT_DIR/venv/bin/python"
    echo "✓ Using virtual environment Python: $PYTHON_CMD"
else
    PYTHON_CMD="python"
    echo "⚠ Using system Python (virtual environment not found): $PYTHON_CMD"
fi

# Function to create backup of config file
backup_config() {
    local backup_file="${CONFIG_FILE}.backup.$(date +%Y%m%d-%H%M%S)"
    cp "$CONFIG_FILE" "$backup_file"
    echo "✓ Backup created: $backup_file"
}

# Function to display current opnsense config
show_current_config() {
    echo "Current 'opnsense' configuration:"
    jq '.mcpServers.opnsense' "$CONFIG_FILE"
}

# Function to display proposed new config
show_new_config() {
    echo "Proposed new 'opnsense' configuration:"
    echo "{
  \"command\": \"$PYTHON_CMD\",
  \"args\": [\"$SERVER_PATH\"],
  \"env\": {}
}"
}

# Function to ask for user confirmation
ask_confirmation() {
    echo
    show_current_config
    echo
    show_new_config
    echo
    read -p "Do you want to update the configuration? [y/N]: " response
    case "$response" in
        [yY]|[yY][eE][sS])
            return 0
            ;;
        *)
            echo "Configuration update cancelled."
            return 1
            ;;
    esac
}

# Check if the config file exists
if [ -f "$CONFIG_FILE" ]; then
    # Check if the file is valid JSON
    if jq empty "$CONFIG_FILE" 2>/dev/null; then
        echo "Existing valid config file found."

        # Check if 'opnsense' server already exists
        if jq -e '.mcpServers.opnsense' "$CONFIG_FILE" >/dev/null 2>&1; then
            echo "⚠ 'opnsense' server already exists in configuration."

            if ask_confirmation; then
                backup_config
                # Update the existing config
                jq --arg cmd "$PYTHON_CMD" --arg path "$SERVER_PATH" '.mcpServers.opnsense = {"command": $cmd, "args": [$path], "env": {}}' "$CONFIG_FILE" > "$CONFIG_FILE.tmp"
                mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
                echo "✓ Configuration updated successfully."
            else
                exit 0
            fi
        else
            echo "Adding 'opnsense' server to existing configuration..."
            backup_config
            # Add our server to the existing config
            jq --arg cmd "$PYTHON_CMD" --arg path "$SERVER_PATH" '.mcpServers.opnsense = {"command": $cmd, "args": [$path], "env": {}}' "$CONFIG_FILE" > "$CONFIG_FILE.tmp"
            mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
            echo "✓ Configuration updated successfully."
        fi
    else
        echo "Existing config file is not valid JSON. Creating new config..."
        backup_config
        # Create a new config file
        echo "{\"mcpServers\": {\"opnsense\": {\"command\": \"$PYTHON_CMD\", \"args\": [\"$SERVER_PATH\"], \"env\": {}}}}" > "$CONFIG_FILE"
        echo "✓ New configuration created successfully."
    fi
else
    echo "No existing config file found. Creating new config..."
    # Create a new config file
    echo "{\"mcpServers\": {\"opnsense\": {\"command\": \"$PYTHON_CMD\", \"args\": [\"$SERVER_PATH\"], \"env\": {}}}}" > "$CONFIG_FILE"
    echo "✓ New configuration created successfully."
fi

echo "Claude Desktop configuration updated."
echo "Config file location: $CONFIG_FILE"
echo "Please restart Claude Desktop to apply the changes."
