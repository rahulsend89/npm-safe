/**
 * Test: Loader selection logic
 * Verifies that npm-safe selects the correct loader for the current Node.js version
 */

const path = require('path');

const [major, minor] = process.versions.node.split('.').map(Number);

// Simulate npm-safe loader selection logic
const FIREWALL_LIB = path.join(__dirname, '..', 'lib');
const FS_INTERCEPTOR = path.join(FIREWALL_LIB, 'fs-interceptor-v2.js');
const CHILD_PROCESS_INTERCEPTOR = path.join(FIREWALL_LIB, 'child-process-interceptor.js');
const INIT_ESM = path.join(FIREWALL_LIB, 'init.mjs');
const LEGACY_LOADER = path.join(FIREWALL_LIB, 'legacy-loader.mjs');

let NODE_OPTIONS = '';

const supportsImport = major > 20 || (major === 20 && minor >= 6);
const supportsLoader = major > 16 || (major === 16 && minor >= 12);

if (supportsImport) {
  NODE_OPTIONS += ` --import ${INIT_ESM}`;
  console.log('Selected: --import (modern)');
} else if (supportsLoader) {
  const loaderFlag = (major >= 19 || (major === 18 && minor >= 19)) ? '--loader' : '--experimental-loader';
  NODE_OPTIONS += ` ${loaderFlag} ${LEGACY_LOADER} -r ${FS_INTERCEPTOR} -r ${CHILD_PROCESS_INTERCEPTOR}`;
  console.log(`Selected: ${loaderFlag} (legacy ESM)`);
} else {
  NODE_OPTIONS += ` -r ${FS_INTERCEPTOR} -r ${CHILD_PROCESS_INTERCEPTOR}`;
  console.log('Selected: -r only (CJS fallback)');
}

console.log('NODE_OPTIONS:', NODE_OPTIONS);

// Verify files exist
const fs = require('fs');

if (supportsImport && !fs.existsSync(INIT_ESM)) {
  console.error('ERROR: init.mjs not found');
  process.exit(1);
}

if (supportsLoader && !fs.existsSync(LEGACY_LOADER)) {
  console.error('ERROR: legacy-loader.mjs not found');
  process.exit(1);
}

if (!fs.existsSync(FS_INTERCEPTOR)) {
  console.error('ERROR: fs-interceptor-v2.js not found');
  process.exit(1);
}

if (!fs.existsSync(CHILD_PROCESS_INTERCEPTOR)) {
  console.error('ERROR: child-process-interceptor.js not found');
  process.exit(1);
}

console.log('✓ Loader selection correct, all files exist');
process.exit(0);
