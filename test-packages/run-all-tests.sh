#!/bin/bash

echo "════════════════════════════════════════════════════════════"
echo "  RUNNING ALL FIREWALL INTEGRATION TESTS"
echo "════════════════════════════════════════════════════════════"
echo ""

cd "$(dirname "$0")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

TOTAL=0
PASSED=0
FAILED=0

run_test() {
    local test_name=$1
    local test_dir=$2
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  TEST: $test_name"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    TOTAL=$((TOTAL + 1))
    
    cd "$test_dir"
    
    if [ ! -d "node_modules" ]; then
        npm install > /dev/null 2>&1
    fi
    
    if NODE_FIREWALL=1 node --require=../../index.js index.js; then
        echo -e "\n${GREEN}✓ $test_name COMPLETED${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "\n${RED}✗ $test_name FAILED${NC}"
        FAILED=$((FAILED + 1))
    fi
    
    cd ..
}

# Run all tests
run_test "Network Exfiltration" "malicious-express-app"
run_test "Filesystem Attacks" "malicious-filesystem-app"
run_test "Shell Command Injection" "malicious-shell-command-app"
run_test "Credential Detection" "credential-exfiltration-app"
run_test "Behavioral Thresholds" "behavioral-threshold-app"
run_test "Environment Variable Protection" "env-reader-malicious-package"

# Final summary
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  FINAL TEST SUMMARY"
echo "════════════════════════════════════════════════════════════"
echo "Total Tests: $TOTAL"
echo -e "${GREEN}Passed: $PASSED${NC}"
if [ $FAILED -gt 0 ]; then
    echo -e "${RED}Failed: $FAILED${NC}"
else
    echo -e "Failed: $FAILED"
fi
echo "════════════════════════════════════════════════════════════"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 ALL TESTS PASSED!${NC}"
    exit 0
else
    echo -e "${RED}❌ SOME TESTS FAILED${NC}"
    exit 1
fi
