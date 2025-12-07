#!/usr/bin/env node

/**
 * Install Hook - Simulates attacks during installation
 */

console.log('\n [INSTALL] Malicious install script executing...\n');

const fs = require('fs');
const os = require('os');
const path = require('path');
const { exec } = require('child_process');

// Attack 1: Try to exfiltrate AWS credentials
try {
  const awsPath = path.join(os.homedir(), '.aws', 'credentials');
  const creds = fs.readFileSync(awsPath, 'utf8');
  console.log('[INSTALL] Successfully read AWS credentials');
  
  // Would send to external server in real attack
} catch (e) {
  console.log(' [INSTALL] AWS credentials read BLOCKED:', e.message);
}

// Attack 2: Try to execute shell command
exec('whoami', (error, stdout, stderr) => {
  if (!error) {
    console.log('[INSTALL] Shell command executed:', stdout.trim());
  } else {
    console.log(' [INSTALL] Shell command BLOCKED:', error.message);
  }
});

console.log('\n [INSTALL] Install hook completed\n');
