#!/bin/bash

# Simple multi-version test runner
# This script tests each Node.js version sequentially

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "╔════════════════════════════════════════════════════╗"
echo "║  Node.js Firewall - Multi-Version Tests           ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""

# Test results
PASSED=0
FAILED=0
declare -a FAILED_VERSIONS

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

# Test each version
for version in "${VERSIONS[@]}"; do
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -e "${BLUE}Testing Node.js v${version}${NC}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  
  # Run test for this version
  if bash test-single-version.sh "$version" 2>&1; then
    echo -e "${GREEN}✓ v${version} PASSED${NC}"
    ((PASSED++))
  else
    echo -e "${RED}✗ v${version} FAILED${NC}"
    ((FAILED++))
    FAILED_VERSIONS+=("$version")
  fi
  
  echo ""
done

# Final summary
echo "╔════════════════════════════════════════════════════╗"
echo "║              Final Summary                         ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}Passed: ${PASSED}/${#VERSIONS[@]}${NC}"
echo -e "${RED}Failed: ${FAILED}/${#VERSIONS[@]}${NC}"
echo ""

if [ $FAILED -gt 0 ]; then
  echo "Failed versions:"
  for v in "${FAILED_VERSIONS[@]}"; do
    echo -e "  ${RED}✗ v${v}${NC}"
  done
  echo ""
  exit 1
else
  echo -e "${GREEN}All versions passed! ✓${NC}"
  exit 0
fi
