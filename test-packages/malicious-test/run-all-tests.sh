#!/bin/bash

echo "╔════════════════════════════════════════════════════════════╗"
echo "║        COMPREHENSIVE FIREWALL SECURITY TEST SUITE         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

cd "$(dirname "$0")"

export FIREWALL_TEST_MODE=1
export NODE_FIREWALL=1
export npm_lifecycle_event=install

# Timeout wrapper (bash-only, works on macOS and Linux)
run_test_with_timeout() {
  local timeout=$1
  local script=$2
  local grep_lines=$3
  local output_file=$(mktemp)
  
  echo "⏱️  Timeout: ${timeout}s | Running: $script"
  
  # Start the node process in background
  node -r ../../lib/fs-interceptor-v2.js -r ../../lib/child-process-interceptor.js "$script" \
    > "$output_file" 2>&1 &
  
  local pid=$!
  local count=0
  local timed_out=0
  
  # Monitor with timeout
  while [ $count -lt $timeout ]; do
    if ! kill -0 $pid 2>/dev/null; then
      # Process finished
      break
    fi
    sleep 1
    ((count++))
  done
  
  # If still running, kill it
  if kill -0 $pid 2>/dev/null; then
    echo ""
    echo "⏱️  Timeout reached (${timeout}s), killing process..."
    
    # Try graceful termination first
    kill -TERM $pid 2>/dev/null
    sleep 2
    
    # Force kill if still alive
    if kill -0 $pid 2>/dev/null; then
      kill -9 $pid 2>/dev/null
      
      # Kill entire process group
      pkill -9 -P $pid 2>/dev/null
    fi
    
    wait $pid 2>/dev/null
    timed_out=1
  else
    wait $pid 2>/dev/null
  fi
  
  local exit_code=$?
  
  # Show summary from output
  if [ -f "$output_file" ]; then
    echo ""
    grep -A $grep_lines "FINAL SUMMARY" "$output_file" 2>/dev/null || {
      if [ $timed_out -eq 1 ]; then
        echo "Test timed out before completion"
      else
        echo "Test did not complete (no summary found)"
      fi
      echo "Last 10 lines of output:"
      tail -10 "$output_file"
    }
  fi
  
  # Clean up
  rm -f "$output_file"
  
  # Return appropriate code
  if [ $timed_out -eq 1 ]; then
    return 124
  fi
  
  return $exit_code
}

echo "🧪 Test Suite 1: Basic Attacks (Common Supply Chain)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
run_test_with_timeout 30 test-runner.js 20
if [ $? -eq 124 ]; then
  echo "❌ Test Suite 1 TIMED OUT (killed after 30s)"
fi

echo ""
echo ""
echo "🧪 Test Suite 2: Advanced Attacks (Sophisticated Techniques)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
run_test_with_timeout 30 test-advanced-attacks.js 20
if [ $? -eq 124 ]; then
  echo "❌ Test Suite 2 TIMED OUT (killed after 30s)"
fi

echo ""
echo ""
echo "🧪 Test Suite 3: Bypass Attacks (Adversarial Red Team)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
run_test_with_timeout 30 test-bypass-attacks.js 30
if [ $? -eq 124 ]; then
  echo "❌ Test Suite 3 TIMED OUT (killed after 30s)"
fi

echo ""
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║              OVERALL PROTECTION SUMMARY                    ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "📊 Analyzing test results..."
echo ""

# Try to get actual results from JSON reports if they exist
if [ -f "bypass-attack-report.json" ]; then
  echo "✅ Using actual test results from JSON reports"
  echo ""
  echo "For detailed results see:"
  echo "  - bypass-attack-report.json (Primary bypass tests)"
  echo "  - test-runner-report.json (Basic attacks)"
  echo "  - advanced-attack-report.json (Advanced attacks)"
else
  echo "Note: Run individual test suites to generate JSON reports"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "Run 'npm run test:bypass' for detailed bypass protection test"
echo "════════════════════════════════════════════════════════════"
echo ""
