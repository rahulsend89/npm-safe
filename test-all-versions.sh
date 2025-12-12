#!/bin/bash

# Integration test script for all Node.js versions
# Tests version detection, loader selection, and firewall functionality

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results
PASSED=0
FAILED=0
SKIPPED=0

# Node.js versions to test
VERSIONS=(
  "14.15.4"
  "14.20.0"
  "14.21.3"
  "16.13.2"
  "16.19.0"
  "18.14.2"
  "18.16.0"
  "20.11.1"
  "20.12.2"
  "20.17.0"
  "22.5.1"
  "22.17.1"
)

echo "╔════════════════════════════════════════════════════╗"
echo "║  Node.js Firewall - Multi-Version Integration Test ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""

# Source nvm
export NVM_DIR="$HOME/.nvm"
if [ -s "$NVM_DIR/nvm.sh" ]; then
  \. "$NVM_DIR/nvm.sh"
elif [ -s "/usr/local/opt/nvm/nvm.sh" ]; then
  # Homebrew installation
  \. "/usr/local/opt/nvm/nvm.sh"
elif [ -s "$(brew --prefix nvm 2>/dev/null)/nvm.sh" ]; then
  # Homebrew with custom prefix
  \. "$(brew --prefix nvm)/nvm.sh"
fi

# Check if nvm is available
if ! command -v nvm &> /dev/null; then
  echo -e "${RED}✗ nvm not found${NC}"
  echo "Please install nvm or source it manually"
  echo "Try: source ~/.nvm/nvm.sh"
  exit 1
fi

echo "Running tests across ${#VERSIONS[@]} Node.js versions..."
echo ""

# Function to run test for a specific version
test_version() {
  local version=$1
  local test_name=$2
  local test_command=$3
  
  echo -n "  Testing: $test_name... "
  
  if eval "$test_command" > /tmp/test-output-$version.log 2>&1; then
    echo -e "${GREEN}✓${NC}"
    return 0
  else
    echo -e "${RED}✗${NC}"
    echo "    Error output:"
    cat /tmp/test-output-$version.log | head -10 | sed 's/^/    /'
    return 1
  fi
}

# Main test loop
for version in "${VERSIONS[@]}"; do
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -e "${BLUE}Testing Node.js v${version}${NC}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  
  # Check if version is installed
  if ! nvm ls "$version" &> /dev/null; then
    echo -e "${YELLOW}[-] Version not installed, skipping${NC}"
    ((SKIPPED++))
    echo ""
    continue
  fi
  
  # Switch to version
  nvm use "$version" > /dev/null 2>&1
  
  # Get actual version
  ACTUAL_VERSION=$(node --version)
  echo "Active: $ACTUAL_VERSION"
  
  # Determine expected behavior
  MAJOR=$(echo "$version" | cut -d. -f1)
  MINOR=$(echo "$version" | cut -d. -f2)
  
  VERSION_FAILED=0
  
  # Test 1: Version detection
  test_version "$version" "Version detection" \
    "node $SCRIPT_DIR/test/version-detection-test.js" || ((VERSION_FAILED++))
  
  # Test 2: Loader selection
  test_version "$version" "Loader selection" \
    "node $SCRIPT_DIR/test/loader-selection-test.js" || ((VERSION_FAILED++))
  
  # Test 3: Basic firewall init
  test_version "$version" "Firewall initialization" \
    "NODE_FIREWALL=1 node -e 'const fw = require(\"./lib/firewall-core.js\"); console.log(\"OK\")'" || ((VERSION_FAILED++))
  
  # Test 4: Config loading
  test_version "$version" "Config loading" \
    "node -e 'const config = require(\"./lib/config-loader.js\"); config.load(); console.log(\"OK\")'" || ((VERSION_FAILED++))
  
  # Test 5: ESM loader (if supported)
  if [ "$MAJOR" -gt 16 ] || ([ "$MAJOR" -eq 16 ] && [ "$MINOR" -ge 12 ]); then
    if [ "$MAJOR" -gt 20 ] || ([ "$MAJOR" -eq 20 ] && [ "$MINOR" -ge 6 ]); then
      # Test --import
      test_version "$version" "ESM hooks (--import)" \
        "node --import ./lib/init.mjs -e 'console.log(\"OK\")'" || ((VERSION_FAILED++))
    else
      # Test --loader or --experimental-loader
      if [ "$MAJOR" -ge 19 ] || ([ "$MAJOR" -eq 18 ] && [ "$MINOR" -ge 19 ]); then
        LOADER_FLAG="--loader"
      else
        LOADER_FLAG="--experimental-loader"
      fi
      test_version "$version" "ESM hooks ($LOADER_FLAG)" \
        "NODE_FIREWALL=1 node $LOADER_FLAG ./lib/legacy-loader.mjs -e 'console.log(\"OK\")' 2>&1 | grep -q OK" || ((VERSION_FAILED++))
    fi
  else
    echo -e "  ${YELLOW}[-] ESM loader not supported (Node < 16.12)${NC}"
  fi
  
  # Test 6: npm-safe wrapper
  test_version "$version" "npm-safe wrapper" \
    "node ./bin/npm-safe --version 2>&1 | grep -q 'npm-safe'" || ((VERSION_FAILED++))
  
  # Test 7: Child process interception
  test_version "$version" "Child process interception" \
    "NODE_FIREWALL=1 node -r ./lib/child-process-interceptor.js -e 'console.log(\"OK\")'" || ((VERSION_FAILED++))
  
  # Test 8: FS interception
  test_version "$version" "FS interception" \
    "NODE_FIREWALL=1 node -r ./lib/fs-interceptor-v2.js -e 'console.log(\"OK\")'" || ((VERSION_FAILED++))
  
  # Summary for this version
  echo ""
  if [ $VERSION_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed for Node.js v${version}${NC}"
    ((PASSED++))
  else
    echo -e "${RED}✗ ${VERSION_FAILED} test(s) failed for Node.js v${version}${NC}"
    ((FAILED++))
  fi
  echo ""
done

# Final summary
echo "╔════════════════════════════════════════════════════╗"
echo "║              Test Summary                          ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}Passed:  ${PASSED}${NC}"
echo -e "${RED}Failed:  ${FAILED}${NC}"
echo -e "${YELLOW}Skipped: ${SKIPPED}${NC}"
echo ""

# Cleanup
rm -f /tmp/test-output-*.log

# Exit with error if any tests failed
if [ $FAILED -gt 0 ]; then
  echo -e "${RED}Some tests failed. Please review the output above.${NC}"
  exit 1
else
  echo -e "${GREEN}All tests passed!${NC}"
  exit 0
fi
