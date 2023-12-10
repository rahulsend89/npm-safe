#!/usr/bin/env node

/**
 * Malicious Test Package - Main Entry Point
 * Simulates supply chain attack for firewall testing
 */

console.log('\n╔╗');
console.log('  Malicious Test Package Loaded                     ');
console.log('╚╝\n');

console.log('This package simulates supply chain attacks for testing.');
console.log('');
console.log('Available test commands:');
console.log('  npm run test:all      - Run comprehensive test suite');
console.log('  npm run test:files    - Test file-based attacks');
console.log('  npm run test:network  - Test network-based attacks');
console.log('  npm run test:commands - Test command execution attacks');
console.log('');
console.log('Or require this module and use the test functions:');
console.log('');
console.log('  const tests = require(\'malicious-test-package\');');
console.log('  tests.runFileAttacks();');
console.log('  tests.runNetworkAttacks();');
console.log('  tests.runCommandAttacks();');
console.log('');

module.exports = {
  runFileAttacks: () => {
    console.log('Running file attacks...');
    require('./test-file-attacks');
  },
  
  runNetworkAttacks: () => {
    console.log('Running network attacks...');
    require('./test-network-attacks');
  },
  
  runCommandAttacks: () => {
    console.log('Running command attacks...');
    require('./test-command-attacks');
  },
  
  runAllAttacks: () => {
    console.log('Running comprehensive test suite...');
    require('./test-all-attacks');
  }
};
