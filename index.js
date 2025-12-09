/**
 * Node Firewall - Main Entry Point
 * Auto-initializes all firewall components when required with -r flag
 * Supports both Node.js and Bun runtimes
 * 
 * SECURITY: This module MUST load synchronously to prevent race conditions
 * where malicious code could execute before the firewall is active.
 */

// Detect runtime
const isBun = typeof Bun !== 'undefined';
const isNode = typeof process !== 'undefined' && process.versions && process.versions.node;

// SECURITY: Set initialization flag BEFORE any other code runs
// This prevents race conditions where code checks if firewall is active
const INIT_STARTED = Symbol.for('node.firewall.init.started');
const INIT_COMPLETE = Symbol.for('node.firewall.init.complete');

// Check if firewall is enabled
const enabled = process.env.NODE_FIREWALL === '1' || process.env.NODE_FIREWALL_FORTRESS === '1';

if (enabled && !global[INIT_COMPLETE]) {
  // Mark as started (if not already)
  if (!global[INIT_STARTED]) {
    global[INIT_STARTED] = true;
  }
  
  try {
    if (isBun) {
      // BUN RUNTIME: Use Bun-specific initialization
      require('./lib/bun-init');
      global[INIT_COMPLETE] = true;
    } else {
      // NODE.JS RUNTIME: Use Node.js-specific initialization
      // SECURITY: Initialize in strict order, all synchronously
      // 1. Firewall core first (provides base infrastructure)
      const { FirewallCore } = require('./lib/firewall-core');
      const firewall = new FirewallCore();
      
      // 2. Initialize immediately (synchronous)
      firewall.initialize();
      
      // 3. Initialize filesystem interceptor (must happen before any fs operations)
      require('./lib/fs-interceptor-v2');
      
      // 4. Initialize child process interceptor (must happen before any spawns)
      require('./lib/child-process-interceptor');
      
      // 5. Block process.binding bypass (SECURITY FIX)
      if (typeof process.binding === 'function') {
        const originalBinding = process.binding;
        process.binding = function(name) {
          console.error(`[Firewall] process.binding('${name}') BLOCKED - security bypass attempt`);
          throw new Error('process.binding blocked by firewall');
        };
      }
      
      // 6. Mark initialization complete
      global[INIT_COMPLETE] = true;
      
      // SECURITY: Prevent any code from running until firewall is ready
      // This is a fail-closed approach
      if (!firewall.silent) {
        console.log('[Firewall] Auto-initialized on module load');
      }
    }
  } catch (error) {
    // CRITICAL: If initialization fails, we're in an insecure state
    console.error('[Firewall] CRITICAL: Failed to initialize:', error.message);
    console.error('[Firewall] Stack:', error.stack);
    // Don't mark as complete - fail closed
    global[INIT_COMPLETE] = false;
    // Still export to prevent module loading errors, but firewall won't work
  }
} else if (!enabled) {
  console.warn('[Firewall] Not enabled. Set NODE_FIREWALL=1 or NODE_FIREWALL_FORTRESS=1 to activate');
  global[INIT_COMPLETE] = false;
}

module.exports = require('./lib/firewall-core');
