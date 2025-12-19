#!/bin/bash

# Simple sample plugin for resh
# Demonstrates basic plugin functionality

VERSION="0.1.0"
PLUGIN_NAME="sample.hello"

# Function to output JSON response
output_json() {
    local success="$1"
    local message="$2"
    local code="${3:-0}"
    
    cat <<EOF
{
  "op": "plugin.${PLUGIN_NAME}.execute",
  "ok": ${success},
  "code": ${code},
  "ts": "$(date -Iseconds)",
  "target": "plugin://${PLUGIN_NAME}",
  "result": {
    "message": "${message}",
    "version": "${VERSION}"
  },
  "error": null
}
EOF
}

# Main plugin logic
case "${1:-help}" in
    "greet")
        NAME="${2:-World}"
        output_json "true" "Hello, ${NAME}! This is the resh sample plugin v${VERSION}"
        ;;
    "version")
        output_json "true" "Sample plugin version ${VERSION}"
        ;;
    "help")
        output_json "true" "Available commands: greet [name], version, help"
        ;;
    *)
        output_json "false" "Unknown command: $1. Use 'help' for available commands" 1
        exit 1
        ;;
esac