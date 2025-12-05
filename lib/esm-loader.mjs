/**
 * ESM Loader for Node Firewall
 * 
 * This loader initializes the firewall before any modules are loaded,
 * providing earlier interception than the -r flag approach.
 * 
 * Usage:
 *   Node.js 18.x: node --loader ./lib/esm-loader.mjs script.mjs
 *   Node.js 20.6+: node --import ./lib/esm-loader.mjs script.mjs
 * 
 * Note: This loader works with ES modules. For CommonJS, use the -r flag.
 */

import { createRequire } from 'module';
import { pathToFileURL } from 'url';
import { fileURLToPath } from 'url';
import path from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const require = createRequire(import.meta.url);

// Initialize firewall flag
let firewallInitialized = false;

/**
 * Initialize the firewall synchronously
 * This must complete before any modules are loaded
 */
function initializeFirewall() {
  if (firewallInitialized) {
    return;
  }

  try {
    // Enable firewall via environment variable
    process.env.NODE_FIREWALL = '1';
    
    // Get the path to firewall modules (relative to this loader)
    const firewallPath = path.resolve(__dirname, '..');
    
    // Initialize firewall core
    const firewallCore = require(path.join(firewallPath, 'lib', 'firewall-core'));
    const firewall = firewallCore.getInstance();
    
    // Ensure firewall is initialized
    if (!firewall.initialized) {
      firewall.initialize();
    }
    
    // Initialize filesystem interceptor
    require(path.join(firewallPath, 'lib', 'fs-interceptor-v2'));
    
    // Initialize child process interceptor
    require(path.join(firewallPath, 'lib', 'child-process-interceptor'));
    
    firewallInitialized = true;
    
    if (!firewall.silent) {
      console.log('[Firewall Loader] Firewall initialized before module loading');
    }
  } catch (error) {
    console.error('[Firewall Loader] CRITICAL: Failed to initialize firewall:', error.message);
    console.error('[Firewall Loader] Stack:', error.stack);
    // Fail closed - exit if initialization fails
    process.exit(1);
  }
}

// Initialize firewall immediately when loader is loaded
// This happens before any user modules are processed
initializeFirewall();

/**
 * ESM Loader Hook: resolve
 * 
 * Called for each module import to resolve the module specifier.
 * This is the first hook that runs for each module.
 * 
 * @param {string} specifier - The module specifier (e.g., './module.js', 'fs')
 * @param {object} context - Context object with parentURL
 * @param {Function} nextResolve - Next resolve hook in the chain
 * @returns {Promise<{url: string}>} Resolved module URL
 */
export async function resolve(specifier, context, nextResolve) {
  // Ensure firewall is initialized (defensive check)
  if (!firewallInitialized) {
    initializeFirewall();
  }
  
  // Call the next resolve hook in the chain
  // This allows other loaders to also process the module
  return nextResolve(specifier, context);
}

/**
 * ESM Loader Hook: load
 * 
 * Called to load the module source. Can transform the source before execution.
 * 
 * @param {string} url - The resolved module URL
 * @param {object} context - Context object
 * @param {Function} nextLoad - Next load hook in the chain
 * @returns {Promise<{format: string, source: string|ArrayBuffer}>} Module source
 */
export async function load(url, context, nextLoad) {
  // Ensure firewall is initialized (defensive check)
  if (!firewallInitialized) {
    initializeFirewall();
  }
  
  // Call the next load hook in the chain
  // This loads the actual module source
  return nextLoad(url, context);
  
  // Future enhancement: Could transform source here for additional security
  // const result = await nextLoad(url, context);
  // if (result.format === 'module') {
  //   // Transform source if needed
  //   return { ...result, source: transformedSource };
  // }
  // return result;
}

/**
 * ESM Loader Hook: getFormat (optional, for Node.js < 20.6)
 * 
 * Determines the format of a module (e.g., 'module', 'commonjs', 'json')
 * 
 * @param {string} url - The module URL
 * @param {object} context - Context object
 * @param {Function} getFormat - Next getFormat hook
 * @returns {Promise<{format: string}>} Module format
 */
export async function getFormat(url, context, getFormat) {
  // Ensure firewall is initialized
  if (!firewallInitialized) {
    initializeFirewall();
  }
  
  return getFormat(url, context);
}

/**
 * ESM Loader Hook: getSource (optional, for Node.js < 20.6)
 * 
 * Can transform the source before it's parsed
 * 
 * @param {string} url - The module URL
 * @param {object} context - Context object
 * @param {Function} getSource - Next getSource hook
 * @returns {Promise<{source: string|ArrayBuffer}>} Module source
 */
export async function getSource(url, context, getSource) {
  // Ensure firewall is initialized
  if (!firewallInitialized) {
    initializeFirewall();
  }
  
  return getSource(url, context);
}
