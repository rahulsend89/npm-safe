#!/bin/bash

# Test a single Node.js version
# Usage: ./test-single-version.sh <version>
# Example: ./test-single-version.sh 16.13.2

set -e

VERSION=$1

if [ -z "$VERSION" ]; then
  echo "Usage: $0 <node-version>"
  echo "Example: $0 16.13.2"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Testing Node.js v${VERSION}${NC}"
echo ""

# Source nvm
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

# Check if version is installed
if ! nvm ls "$VERSION" &> /dev/null; then
  echo -e "${RED}Version not installed. Install with: nvm install $VERSION${NC}"
  exit 1
fi

# Switch to version
nvm use "$VERSION"

echo ""
echo "Running integration test..."
echo ""

# Run integration test
if node test/integration-test.js; then
  echo ""
  echo -e "${GREEN}✓ All tests passed for Node.js v${VERSION}${NC}"
  exit 0
else
  echo ""
  echo -e "${RED}✗ Tests failed for Node.js v${VERSION}${NC}"
  exit 1
fi
