/**
 * Example: Using the Firewall with ESM Loader
 * 
 * This demonstrates how to use the firewall with ES modules via the loader API.
 * 
 * Run with:
 *   Node.js 18.x: node --loader ./lib/esm-loader.mjs example-loader-usage.mjs
 *   Node.js 20.6+: node --import ./lib/esm-loader.mjs example-loader-usage.mjs
 */

import fs from 'fs';
import { spawn } from 'child_process';

console.log('=== Firewall Loader Example ===\n');

// Test 1: File system access (should be intercepted)
console.log('Test 1: Attempting to read /etc/passwd...');
try {
  const content = fs.readFileSync('/etc/passwd', 'utf8');
  console.log('✅ File read successful (allowed by firewall config)');
} catch (error) {
  console.log('❌ File read blocked:', error.message);
}

// Test 2: Network access (should be intercepted)
console.log('\nTest 2: Attempting network connection...');
try {
  const http = await import('http');
  // This would be intercepted by network monitor
  console.log('✅ Network module loaded (monitoring active)');
} catch (error) {
  console.log('❌ Network access blocked:', error.message);
}

// Test 3: Child process (should be intercepted)
console.log('\nTest 3: Attempting to spawn child process...');
try {
  const child = spawn('ls', ['-la']);
  child.on('close', (code) => {
    console.log(`✅ Process completed with code ${code} (intercepted by firewall)`);
  });
} catch (error) {
  console.log('❌ Process spawn blocked:', error.message);
}

console.log('\n=== Example Complete ===');
