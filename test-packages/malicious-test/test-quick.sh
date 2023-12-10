#!/bin/bash

# Quick test with just bypass tests
cd "$(dirname "$0")"

export FIREWALL_TEST_MODE=1
export NODE_FIREWALL=1
export npm_lifecycle_event=install

echo "Running bypass tests (no timeout, direct execution)..."
echo ""

node -r ../../lib/fs-interceptor-v2.js -r ../../lib/child-process-interceptor.js test-bypass-attacks.js 2>&1 | tail -25
