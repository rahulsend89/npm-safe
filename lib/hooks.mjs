/**
 * Node Firewall - ESM Hooks (Node.js 20+)
 * Implements module.register() hooks for ESM interception
 * 
 * ARCHITECTURE NOTE:
 * ESM hooks run in a separate thread and cannot share state with CJS modules.
 * Config must be loaded independently here. If no config is found, we use
 * STRICT DEFAULTS (fail closed) - this is a security-first approach.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

// Config loading - mirrors config-loader.js logic for ESM context
function loadConfig() {
  const locations = [
    path.join(process.cwd(), '.firewall-config.json'),
    path.join(process.cwd(), 'firewall-config.json'),
    path.join(os.homedir(), '.firewall-config.json')
  ];
  
  for (const location of locations) {
    try {
      if (fs.existsSync(location)) {
        const content = fs.readFileSync(location, 'utf8');
        return JSON.parse(content);
      }
    } catch (e) {
      // Continue to next location
    }
  }
  
  // No config found - return null (will use strict mode)
  return null;
}

const config = loadConfig();

// SECURITY: If no config, we block ALL sensitive paths (fail closed)
// This prevents bypass by deleting config file
const NO_CONFIG_STRICT_MODE = config === null;

export async function initialize(data) {
  // This runs in the hooks thread
  const { port } = data || {};
  
  if (NO_CONFIG_STRICT_MODE && process.env.NODE_FIREWALL === '1') {
    console.warn('[Firewall ESM] No config found - using strict defaults');
  }
}

export async function resolve(specifier, context, nextResolve) {
  // Check if firewall is enabled
  if (process.env.NODE_FIREWALL !== '1') {
    return nextResolve(specifier, context);
  }

  // Get blocked paths from config
  // If no config exists, we're in strict mode and block common sensitive paths
  const blockedReadPaths = config?.filesystem?.blockedReadPaths;
  
  if (blockedReadPaths && blockedReadPaths.length > 0) {
    // Use config-defined paths
    for (const pattern of blockedReadPaths) {
      if (specifier.includes(pattern)) {
        throw new Error(`[Firewall] Access to sensitive file blocked: ${specifier}`);
      }
    }
  } else if (NO_CONFIG_STRICT_MODE) {
    // STRICT MODE: No config = block known sensitive patterns
    // These are the minimum security patterns that should always be blocked
    const criticalPaths = ['/.ssh/', '/.aws/', '/.gnupg/', '/etc/shadow', '/id_rsa'];
    for (const pattern of criticalPaths) {
      if (specifier.includes(pattern)) {
        throw new Error(`[Firewall] Access to critical file blocked (strict mode): ${specifier}`);
      }
    }
  }
  // If config exists but blockedReadPaths is empty, user explicitly allows all reads

  return nextResolve(specifier, context);
}

export async function load(url, context, nextLoad) {
  // Future: Could inspect source code here for malicious patterns
  return nextLoad(url, context);
}
