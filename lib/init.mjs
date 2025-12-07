/**
 * Node Firewall - ESM Initialization (Node.js 20+)
 * Usage: node --import ./lib/init.mjs app.js
 */

import { register } from 'node:module';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

// 1. Register ESM Hooks
// This enables interception of 'import' statements
try {
  // Fix: Resolve relative to this file, not CWD
  const hooksUrl = new URL('./hooks.mjs', import.meta.url).href;
  register(hooksUrl);
  console.log('[Firewall] ESM Hooks registered');
} catch (e) {
  // Fallback for older Node versions or if register fails
  console.warn('[Firewall] Could not register ESM hooks:', e.message);
}

// 2. Initialize Runtime Firewall (CJS compatibility)
// This loads the fs-interceptor, process-interceptor, etc.
try {
  const require = createRequire(import.meta.url);
  
  // Force enable firewall
  process.env.NODE_FIREWALL = '1';
  
  // Load the main entry point which initializes everything synchronously
  // Using fileURLToPath for proper Windows path conversion
  const mainPath = fileURLToPath(new URL('../index.js', import.meta.url));
  require(mainPath);
  
} catch (e) {
  console.error('[Firewall] Failed to initialize runtime protection:', e);
  process.exit(1);
}
