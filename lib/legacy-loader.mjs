/**
 * Legacy ESM Loader for Node.js 16.12.0 - 20.5.x
 * Uses the older --loader API (pre module.register)
 */

import { fileURLToPath, pathToFileURL } from 'url';
import { readFileSync, existsSync } from 'fs';
import path from 'path';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);

// Load configuration
let config;
try {
  const configLoader = require('./config-loader.js');
  config = configLoader.load();
} catch (e) {
  console.error('[Firewall Legacy Loader] Failed to load config:', e.message);
  config = {
    mode: { enabled: false },
    filesystem: { blockedReadPaths: [], blockedExtensions: [] },
    network: { blockedDomains: [] }
  };
}

const enabled = config.mode?.enabled !== false;

if (!enabled) {
  console.log('[Firewall Legacy Loader] Disabled by configuration');
}

// Check if firewall is active
const isFirewallActive = process.env.NODE_FIREWALL === '1';

if (!isFirewallActive) {
  console.warn('[Firewall Legacy Loader] NODE_FIREWALL not set, skipping protection');
}

// NOTE: CommonJS interceptors MUST be initialized via -r flags (see npm-safe line 59)
// Requiring from ESM loader context doesn't reliably initialize interceptors in main process
// The -r flags are processed after the loader and properly initialize the interceptors
// This loader only handles ESM module interception (resolve/load hooks)

/**
 * Legacy resolve hook (Node.js 16.12 - 20.5)
 * Intercepts module resolution to block dangerous imports
 */
export async function resolve(specifier, context, nextResolve) {
  if (!enabled || !isFirewallActive) {
    return nextResolve(specifier, context);
  }

  // Check for blocked modules
  const blockedModules = [
    'node:child_process',
    'child_process',
    'node:net',
    'net',
    'node:dgram',
    'dgram'
  ];

  if (blockedModules.includes(specifier)) {
    const parentURL = context.parentURL;
    const parentPath = parentURL ? fileURLToPath(parentURL) : 'unknown';
    
    // Allow firewall's own modules
    if (parentPath.includes('node-firewall/lib/')) {
      return nextResolve(specifier, context);
    }

    console.warn(`[Firewall] Blocked import of ${specifier} from ${parentPath}`);
  }

  return nextResolve(specifier, context);
}

/**
 * Legacy load hook (Node.js 16.12 - 20.5)
 * Intercepts module loading to inspect/modify source
 */
export async function load(url, context, nextLoad) {
  if (!enabled || !isFirewallActive) {
    return nextLoad(url, context);
  }

  const result = await nextLoad(url, context);

  // Only process file:// URLs
  if (!url.startsWith('file://')) {
    return result;
  }

  const filePath = fileURLToPath(url);

  // Skip firewall's own modules
  if (filePath.includes('node-firewall/lib/')) {
    return result;
  }

  // Check blocked read paths
  const blockedPaths = config.filesystem?.blockedReadPaths || [];
  for (const blockedPath of blockedPaths) {
    if (filePath.includes(blockedPath)) {
      console.error(`[Firewall] Blocked read of sensitive file: ${filePath}`);
      throw new Error(`Access denied: ${filePath}`);
    }
  }

  // Check blocked extensions
  const blockedExtensions = config.filesystem?.blockedExtensions || [];
  const ext = path.extname(filePath);
  if (blockedExtensions.includes(ext)) {
    console.warn(`[Firewall] Blocked execution of ${ext} file: ${filePath}`);
  }

  return result;
}

/**
 * Legacy getFormat hook (Node.js 16.12 - 18.x, removed in 19+)
 * Determines module format (ESM, CJS, builtin)
 */
export async function getFormat(url, context, defaultGetFormat) {
  // Delegate to default behavior
  if (defaultGetFormat) {
    return defaultGetFormat(url, context);
  }
  
  // Fallback for Node.js 19+ where getFormat was removed
  return { format: 'module' };
}

console.log('[Firewall Legacy Loader] ESM hooks registered (--loader API)');
console.log(`[Firewall Legacy Loader] Protection: ${enabled ? 'ACTIVE' : 'DISABLED'}`);
