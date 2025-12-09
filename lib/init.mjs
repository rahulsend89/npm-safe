/**
 * Node Firewall - ESM Initialization (Node.js 20+)
 * Usage: node --import ./lib/init.mjs app.js
 * 
 * SECURITY: This module initializes all firewall components and sets up
 * cleanup handlers to ensure proper shutdown and reporting.
 */

import { register } from 'node:module';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

// Detect runtime
const isBun = typeof Bun !== 'undefined';

// SECURITY: Set initialization flags to track state
const INIT_STARTED = Symbol.for('node.firewall.init.started');
const INIT_COMPLETE = Symbol.for('node.firewall.init.complete');

if (!global[INIT_STARTED]) {
  global[INIT_STARTED] = true;

  // 1. Register ESM Hooks (Node.js only - Bun has different module system)
  // This enables interception of 'import' statements
  if (!isBun) {
    try {
      // Fix: Resolve relative to this file, not CWD
      const hooksUrl = new URL('./hooks.mjs', import.meta.url).href;
      register(hooksUrl);
      console.log('[Firewall] ESM Hooks registered');
    } catch (e) {
      // Fallback for older Node versions or if register fails
      console.warn('[Firewall] Could not register ESM hooks:', e.message);
    }
  }

  // 2. Initialize Runtime Firewall (CJS compatibility)
  // This loads the fs-interceptor, process-interceptor, etc.
  let firewall = null;
  try {
    const require = createRequire(import.meta.url);
    
    // Force enable firewall
    // SECURITY: Fortress mode requires base firewall to be active
    // Both NODE_FIREWALL and NODE_FIREWALL_FORTRESS must be set when fortress mode is enabled
    // so that base interceptors (fs-interceptor-v2.js, child-process-interceptor.js) activate
    process.env.NODE_FIREWALL = '1';
    
    // Load the main entry point which initializes everything synchronously
    // Using fileURLToPath for proper Windows path conversion
    const mainPath = fileURLToPath(new URL('../index.js', import.meta.url));
    const firewallModule = require(mainPath);
    
    // Get firewall instance for cleanup
    if (firewallModule && firewallModule.getInstance) {
      firewall = firewallModule.getInstance();
    }
    
    global[INIT_COMPLETE] = true;
    
  } catch (e) {
    console.error('[Firewall] Failed to initialize runtime protection:', e);
    global[INIT_COMPLETE] = false;
    process.exit(1);
  }

  // 3. Setup cleanup handlers for proper shutdown
  // SECURITY: Use global flag to prevent duplicate cleanup handlers
  const CLEANUP_REGISTERED = Symbol.for('node.firewall.cleanup.registered');
  
  if (!global[CLEANUP_REGISTERED]) {
    global[CLEANUP_REGISTERED] = true;
    
    let cleanupExecuted = false;
    
    const cleanup = () => {
      if (cleanupExecuted) return;
      cleanupExecuted = true;
      
      try {
        // Generate behavior report if firewall is initialized
        if (firewall && firewall.behaviorMonitor) {
          const assessment = firewall.behaviorMonitor.printSummary();
          
          // Set exit code based on risk level
          if (assessment.risk === 'high') {
            console.error('\n⚠️  HIGH RISK ACTIVITY DETECTED!');
            console.error('   Review the behavior report before trusting this package.\n');
            process.exitCode = 1;
          } else if (assessment.risk === 'medium') {
            console.warn('\n⚠️  UNUSUAL ACTIVITY DETECTED');
            console.warn('   Review the behavior report for details.\n');
          }
          
          // Generate report file
          firewall.behaviorMonitor.generateReport();
        }
      } catch (e) {
        // Silent fail - don't prevent exit
      }
    };
    
    // Register cleanup handlers
    process.on('exit', cleanup);
    process.on('SIGINT', () => {
      cleanup();
      process.exit(130);
    });
    process.on('SIGTERM', () => {
      cleanup();
      process.exit(143);
    });
  }
  
  // 4. Setup error handlers to catch uncaught exceptions
  // This prevents malicious code from crashing the firewall
  process.on('uncaughtException', (error) => {
    // Prevent infinite loops if console.error fails (e.g. EPIPE)
    try {
      if (error.code !== 'EPIPE' && !error.message.includes('EPIPE')) {
        console.error('[Firewall] Uncaught exception:', error.message);
        console.error('[Firewall] Stack:', error.stack);
      }
    } catch (e) {
      // Ignore console errors during exception handling
    }
    
    // Log to audit if available
    if (firewall && firewall.auditLogger) {
      try {
        firewall.auditLogger.log({
          type: 'ERROR',
          operation: 'uncaughtException',
          target: error.message,
          allowed: false,
          severity: 'critical',
          stack: error.stack
        });
      } catch (e) {
        // Prevent audit logging from causing another exception
      }
    }
    
    // Don't exit - let the application handle it
  });
  
  process.on('unhandledRejection', (reason, promise) => {
    // Prevent infinite loops if console.error fails (e.g. EPIPE)
    try {
      const reasonStr = String(reason);
      if (!reasonStr.includes('EPIPE')) {
        console.error('[Firewall] Unhandled rejection:', reason);
      }
    } catch (e) {
      // Ignore console errors during rejection handling
    }
    
    // Log to audit if available
    if (firewall && firewall.auditLogger) {
      try {
        firewall.auditLogger.log({
          type: 'ERROR',
          operation: 'unhandledRejection',
          target: String(reason),
          allowed: false,
          severity: 'high'
        });
      } catch (e) {
        // Prevent audit logging from causing another exception
      }
    }
  });
}
