#!/usr/bin/env node

// Test that project source files can be read without counting against thresholds

process.env.NODE_FIREWALL = '1';

const fs = require('fs');
const path = require('path');

console.log('\n Testing project source file access...\n');

// Wait a bit for firewall to load
setTimeout(() => {
  console.log('Test 1: Reading project .js file');
  try {
    const content = fs.readFileSync(__filename, 'utf8');
    console.log(' Successfully read .js file');
    console.log('   File size:', content.length, 'bytes');
  } catch (error) {
    console.log(' Failed:', error.message);
  }

  console.log('\nTest 2: Reading package.json');
  try {
    const pkgPath = path.join(process.cwd(), 'package.json');
    const content = fs.readFileSync(pkgPath, 'utf8');
    const pkg = JSON.parse(content);
    console.log(' Successfully read package.json');
    console.log('   Package:', pkg.name);
  } catch (error) {
    console.log(' Failed:', error.message);
  }

  console.log('\nTest 3: Reading .ts file (if exists)');
  try {
    const tsPath = path.join(process.cwd(), 'src', 'index.ts');
    if (fs.existsSync(tsPath)) {
      const content = fs.readFileSync(tsPath, 'utf8');
      console.log(' Successfully read .ts file');
    } else {
      console.log('  Skipped: No .ts files found');
    }
  } catch (error) {
    console.log('  Error:', error.message);
  }

  console.log('\n Tests completed!\n');
  process.exit(0);
}, 500);
