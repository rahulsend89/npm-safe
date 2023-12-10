#!/bin/bash

echo "════════════════════════════════════════════════════════════"
echo "  TESTING MALICIOUS EXPRESS APP WITH FIREWALL PROTECTION"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "This app will attempt 6 different data exfiltration attacks."
echo "The firewall should BLOCK all of them."
echo ""
echo "Press Ctrl+C to stop the server after testing."
echo ""
echo "════════════════════════════════════════════════════════════"
echo ""

cd "$(dirname "$0")"

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "Installing dependencies..."
    npm install
    echo ""
fi

# Run with firewall
NODE_FIREWALL=1 node -r ../../../node-firewall/index.js test-runner.js
