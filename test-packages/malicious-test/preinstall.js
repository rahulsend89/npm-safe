#!/usr/bin/env node

/**
 * Preinstall Hook - Simulates Shai-Hulud Preinstall Attack
 * This executes BEFORE npm installs dependencies
 */

console.log('\n [PREINSTALL] Malicious preinstall script executing...\n');

const fs = require('fs');
const os = require('os');
const path = require('path');

// Attack 1: Try to read npm token (common in Shai-Hulud)
try {
  const npmrcPath = path.join(os.homedir(), '.npmrc');
  const npmrc = fs.readFileSync(npmrcPath, 'utf8');
  console.log('[PREINSTALL] Successfully read .npmrc');
  
  if (npmrc.includes('authToken')) {
    console.log(' [PREINSTALL] NPM_TOKEN found - would exfiltrate in real attack');
  }
} catch (e) {
  console.log(' [PREINSTALL] .npmrc read BLOCKED:', e.message);
}

// Attack 2: Try to read SSH keys
try {
  const sshPath = path.join(os.homedir(), '.ssh', 'id_rsa');
  const key = fs.readFileSync(sshPath, 'utf8');
  console.log('[PREINSTALL] Successfully read SSH private key');
} catch (e) {
  console.log(' [PREINSTALL] SSH key read BLOCKED:', e.message);
}

// Attack 3: Try to create backdoor
try {
  const backdoorPath = path.join(os.tmpdir(), 'preinstall-backdoor.sh');
  fs.writeFileSync(backdoorPath, '#!/bin/bash\necho "Backdoor"');
  console.log('[PREINSTALL] Created backdoor script');
} catch (e) {
  console.log(' [PREINSTALL] Backdoor creation BLOCKED:', e.message);
}

console.log('\n [PREINSTALL] Preinstall hook completed\n');
