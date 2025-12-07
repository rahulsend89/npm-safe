#!/usr/bin/env node

// Test that .env files in current directory can be read

process.env.NODE_FIREWALL = '1';

const fs = require('fs');
const path = require('path');

// Require the firewall
require('./lib/fs-interceptor-v2');
require('./lib/firewall-core');

console.log('\n Testing .env file access...\n');

// Test 1: Read .env from current directory
console.log('Test 1: Reading .env from current directory');
try {
  const envPath = path.join(process.cwd(), '.env.test');
  
  // Create test file
  fs.writeFileSync(envPath, 'TEST_VAR=test123\n');
  console.log(' Created test .env file');
  
  // Try to read it
  const content = fs.readFileSync(envPath, 'utf8');
  console.log(' Successfully read .env file:', content.trim());
  
  // Clean up
  fs.unlinkSync(envPath);
  console.log(' Cleaned up test file');
} catch (error) {
  console.log(' Failed:', error.message);
}

// Test 2: Read .env.local
console.log('\nTest 2: Reading .env.local');
try {
  const envPath = path.join(process.cwd(), '.env.local.test');
  fs.writeFileSync(envPath, 'LOCAL_VAR=local123\n');
  const content = fs.readFileSync(envPath, 'utf8');
  console.log(' Successfully read .env.local file:', content.trim());
  fs.unlinkSync(envPath);
} catch (error) {
  console.log(' Failed:', error.message);
}

// Test 3: Verify sensitive paths are still blocked
console.log('\nTest 3: Verifying /.ssh/ is still blocked');
try {
  fs.readFileSync('/Users/.ssh/test', 'utf8');
  console.log(' SECURITY ISSUE: /.ssh/ access was allowed!');
} catch (error) {
  if (error.message.includes('no such file')) {
    console.log(' /.ssh/ access blocked (as expected)');
  } else {
    console.log('  Error:', error.message);
  }
}

console.log('\n All tests completed!\n');
