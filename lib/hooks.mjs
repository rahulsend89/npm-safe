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

  // Redirect critical node: builtins to CJS bridge modules so that
  // Module.prototype.require interception can wrap them consistently.
  // This avoids eager preloading in the main runtime and ensures ESM
  // imports flow through the same firewall hooks as CJS requires.
  // Support both 'node:*' and bare specifiers (e.g., 'http', 'fs').
  const builtinRedirects = {
    'node:http': './esm-builtins/http.cjs',
    'http': './esm-builtins/http.cjs',
    'node:https': './esm-builtins/https.cjs',
    'https': './esm-builtins/https.cjs',
    'node:net': './esm-builtins/net.cjs',
    'net': './esm-builtins/net.cjs',
    'node:dns': './esm-builtins/dns.cjs',
    'dns': './esm-builtins/dns.cjs',
    'node:dgram': './esm-builtins/dgram.cjs',
    'dgram': './esm-builtins/dgram.cjs',
    'node:http2': './esm-builtins/http2.cjs',
    'http2': './esm-builtins/http2.cjs',
    'node:fs': './esm-builtins/fs.cjs',
    'fs': './esm-builtins/fs.cjs',
    'node:fs/promises': './esm-builtins/fs-promises.cjs',
    'fs/promises': './esm-builtins/fs-promises.cjs',
    'node:child_process': './esm-builtins/child_process.cjs',
    'child_process': './esm-builtins/child_process.cjs'
  };

  if (builtinRedirects[specifier]) {
    const redirected = new URL(builtinRedirects[specifier], import.meta.url).href;
    return nextResolve(redirected, context);
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
  // Check if firewall is enabled
  if (process.env.NODE_FIREWALL !== '1') {
    return nextLoad(url, context);
  }

  // Load the module source
  const result = await nextLoad(url, context);
  
  // Skip node: internals
  if (url.startsWith('node:')) {
    return result;
  }
  
  // Only inspect JavaScript/TypeScript modules
  // Focus on node_modules but also check project files for critical patterns
  const isNodeModule = url.includes('node_modules');
  const isProjectFile = !isNodeModule && (url.endsWith('.js') || url.endsWith('.mjs') || url.endsWith('.cjs'));
  
  // Get source code
  const source = result.source;
  if (!source) return result;
  
  const sourceStr = typeof source === 'string' ? source : source.toString();
  
  // SECURITY: Detect malicious patterns in module source code
  const maliciousPatterns = [
    // Code obfuscation (common in malware)
    { pattern: /eval\s*\(\s*atob\s*\(/, desc: 'Base64 eval obfuscation', severity: 'critical' },
    { pattern: /eval\s*\(\s*Buffer\.from\([^)]+,\s*['"]base64['"]\)/, desc: 'Buffer base64 eval', severity: 'critical' },
    { pattern: /Function\s*\(\s*atob\s*\(/, desc: 'Base64 Function constructor', severity: 'critical' },
    
    // Excessive obfuscation (hex/unicode escapes)
    { pattern: /\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}/i, desc: 'Hex escape obfuscation', severity: 'high' },
    { pattern: /\\u[0-9a-f]{4}.*\\u[0-9a-f]{4}.*\\u[0-9a-f]{4}/i, desc: 'Unicode escape obfuscation', severity: 'medium' },
    
    // Suspicious credential exfiltration
    { pattern: /process\.env\[.*\].*\.(post|send|write)\(/i, desc: 'Env var exfiltration', severity: 'high' },
    { pattern: /require\(['"]child_process['"]\)\.exec\(.*process\.env/i, desc: 'Env var in shell command', severity: 'critical' },
    
    // Reverse shell patterns
    { pattern: /net\.connect.*\/bin\/(bash|sh)/i, desc: 'Reverse shell attempt', severity: 'critical' },
    { pattern: /spawn\(['"]\/bin\/(bash|sh)['"].*-i/i, desc: 'Interactive shell spawn', severity: 'critical' },
    
    // Suspicious downloads
    { pattern: /https?:\/\/[^'"]+\.(sh|bash|py|exe|dll|so)['"].*exec/i, desc: 'Download and execute', severity: 'critical' },
    
    // VM escape attempts
    { pattern: /constructor\s*\.\s*constructor\s*\(/i, desc: 'VM escape attempt', severity: 'critical' },
    { pattern: /process\.binding\(['"]natives['"]\)/i, desc: 'Native module access', severity: 'high' }
  ];
  
  const threats = [];
  for (const { pattern, desc, severity } of maliciousPatterns) {
    if (pattern.test(sourceStr)) {
      threats.push({ pattern: pattern.toString(), desc, severity });
    }
  }
  
  // If threats found, handle based on severity and source
  if (threats.length > 0) {
    const criticalThreats = threats.filter(t => t.severity === 'critical');
    
    // STRICT: Always block critical threats in node_modules
    // LENIENT: Warn for project files (developer may be testing)
    if (criticalThreats.length > 0) {
      if (isNodeModule && !config?.mode?.alertOnly) {
        console.error(`\n[FIREWALL ESM] BLOCKED: Malicious code detected in dependency`);
        console.error(`  Module: ${url}`);
        console.error(`  Threats: ${criticalThreats.map(t => t.desc).join(', ')}`);
        
        throw new Error(`[Firewall] Malicious code detected: ${criticalThreats[0].desc}`);
      } else if (isProjectFile) {
        // Project file with critical pattern - warn strongly but allow (dev may be testing)
        console.warn(`\n[FIREWALL ESM] CRITICAL WARNING: Dangerous code in project file`);
        console.warn(`  File: ${url}`);
        console.warn(`  Threats: ${criticalThreats.map(t => t.desc).join(', ')}`);
        console.warn(`  This would be BLOCKED if found in node_modules`);
      }
    }
    
    // Non-critical threats: always warn
    const nonCriticalThreats = threats.filter(t => t.severity !== 'critical');
    if (nonCriticalThreats.length > 0) {
      console.warn(`\n[FIREWALL ESM] WARNING: Suspicious code detected`);
      console.warn(`  Module: ${url}`);
      console.warn(`  Threats: ${nonCriticalThreats.map(t => t.desc).join(', ')}`);
    }
  }
  
  return result;
}
