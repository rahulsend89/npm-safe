#!/bin/bash

cd "$(dirname "$0")"

echo "════════════════════════════════════════════════════════════"
echo "  QUICK TEST - All Firewall Integration Tests"
echo "════════════════════════════════════════════════════════════"

echo ""
echo "[1/5] Testing Filesystem Protection..."
cd malicious-filesystem-app && NODE_FIREWALL=1 node --require=../../index.js index.js 2>&1 | grep -E "TEST SUMMARY|Total|Blocked|Succeeded" | tail -5
cd ..

echo ""
echo "[2/5] Testing Shell Command Protection..."
cd malicious-shell-command-app && NODE_FIREWALL=1 node --require=../../index.js index.js 2>&1 | grep -E "TEST SUMMARY|Total|Blocked|Succeeded" | tail -5
cd ..

echo ""
echo "[3/5] Testing Credential Detection..."
cd credential-exfiltration-app && NODE_FIREWALL=1 node --require=../../index.js index.js 2>&1 | grep -E "TEST SUMMARY|Total|Blocked|Succeeded" | tail -5
cd ..

echo ""
echo "[4/5] Testing Behavioral Thresholds..."
cd behavioral-threshold-app && NODE_FIREWALL=1 node --require=../../index.js index.js 2>&1 | grep -E "TEST SUMMARY|Network Requests|File Writes|Process Spawns" | tail -6
cd ..

echo ""
echo "[5/5] Testing Environment Variable Protection..."
cd env-reader-malicious-package && NODE_FIREWALL=1 node --require=../../index.js index.js 2>&1 | grep -E "TEST SUMMARY|Total|Hidden|Readable" | tail -5
cd ..

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  TESTS COMPLETE"
echo "════════════════════════════════════════════════════════════"
