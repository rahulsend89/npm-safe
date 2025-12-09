/**
 * Configuration Feature Tests
 * Quick tests to verify all config features are working
 */

const { FirewallCore } = require('../lib/firewall-core');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

console.log('======================================================');
console.log('   Configuration Feature Tests');
console.log('======================================================\n');

let passed = 0;
let failed = 0;

function test(name, fn) {
  process.stdout.write(`Testing ${name}... `);
  try {
    fn();
    console.log('✓');
    passed++;
  } catch (e) {
    console.log('✗');
    console.error(`  Error: ${e.message}`);
    failed++;
  }
}

// Load config
const configLoader = require('../lib/config-loader');
const config = configLoader.load();

// ============================================
// 1. MODE CONFIGURATION
// ============================================
console.log('[1] Mode Configuration\n');

test('mode.enabled is loaded', () => {
  if (config.mode.enabled !== true) throw new Error('Not enabled');
});

test('mode.interactive is loaded', () => {
  if (config.mode.interactive !== true) throw new Error('Not loaded');
});

test('mode.strictMode is loaded', () => {
  if (config.mode.strictMode !== false) throw new Error('Not loaded');
});

test('mode.alertOnly is loaded', () => {
  if (config.mode.alertOnly !== false) throw new Error('Not loaded');
});

// ============================================
// 2. FILESYSTEM CONFIGURATION
// ============================================
console.log('\n[2] Filesystem Configuration\n');

test('filesystem.blockedReadPaths loaded', () => {
  if (!Array.isArray(config.filesystem.blockedReadPaths)) throw new Error('Not an array');
  if (!config.filesystem.blockedReadPaths.includes('/.ssh/')) throw new Error('Missing /.ssh/');
  if (!config.filesystem.blockedReadPaths.includes('/.aws/')) throw new Error('Missing /.aws/');
});

test('filesystem.blockedWritePaths loaded', () => {
  if (!Array.isArray(config.filesystem.blockedWritePaths)) throw new Error('Not an array');
  if (!config.filesystem.blockedWritePaths.includes('/etc/')) throw new Error('Missing /etc/');
});

test('filesystem.blockedExtensions loaded', () => {
  if (!Array.isArray(config.filesystem.blockedExtensions)) throw new Error('Not an array');
  if (!config.filesystem.blockedExtensions.includes('.sh')) throw new Error('Missing .sh');
});

test('filesystem.allowedPaths loaded', () => {
  if (!Array.isArray(config.filesystem.allowedPaths)) throw new Error('Not an array');
  if (!config.filesystem.allowedPaths.includes('/tmp/')) throw new Error('Missing /tmp/');
});

// ============================================
// 3. NETWORK CONFIGURATION
// ============================================
console.log('\n[3] Network Configuration\n');

test('network.enabled is loaded', () => {
  if (config.network.enabled !== true) throw new Error('Not enabled');
});

test('network.mode is loaded', () => {
  if (config.network.mode !== 'block') throw new Error('Wrong mode');
});

test('network.blockedDomains loaded', () => {
  if (!Array.isArray(config.network.blockedDomains)) throw new Error('Not an array');
  if (!config.network.blockedDomains.includes('paste.ee')) throw new Error('Missing paste.ee');
});

test('network.allowedDomains loaded', () => {
  if (!Array.isArray(config.network.allowedDomains)) throw new Error('Not an array');
  if (!config.network.allowedDomains.includes('registry.npmjs.org')) throw new Error('Missing npm registry');
});

test('network.suspiciousPorts loaded', () => {
  if (!Array.isArray(config.network.suspiciousPorts)) throw new Error('Not an array');
  if (!config.network.suspiciousPorts.includes(4444)) throw new Error('Missing port 4444');
});

test('network.credentialPatterns loaded', () => {
  if (!Array.isArray(config.network.credentialPatterns)) throw new Error('Not an array');
  if (!config.network.credentialPatterns.some(p => p.includes('GITHUB_TOKEN'))) {
    throw new Error('Missing GITHUB_TOKEN pattern');
  }
});

// ============================================
// 4. ENVIRONMENT CONFIGURATION
// ============================================
console.log('\n[4] Environment Configuration\n');

test('environment.protectedVariables loaded', () => {
  if (!Array.isArray(config.environment.protectedVariables)) throw new Error('Not an array');
  if (!config.environment.protectedVariables.includes('GITHUB_TOKEN')) {
    throw new Error('Missing GITHUB_TOKEN');
  }
  if (!config.environment.protectedVariables.includes('AWS_ACCESS_KEY_ID')) {
    throw new Error('Missing AWS_ACCESS_KEY_ID');
  }
});

test('environment.allowTrustedModulesAccess loaded', () => {
  if (config.environment.allowTrustedModulesAccess !== true) throw new Error('Not enabled');
});

// ============================================
// 5. COMMANDS CONFIGURATION
// ============================================
console.log('\n[5] Commands Configuration\n');

test('commands.blockedPatterns loaded', () => {
  if (!Array.isArray(config.commands.blockedPatterns)) throw new Error('Not an array');
  const hasWget = config.commands.blockedPatterns.some(p => p.pattern.includes('wget'));
  if (!hasWget) throw new Error('Missing wget pattern');
});

test('commands.allowedCommands loaded', () => {
  if (!Array.isArray(config.commands.allowedCommands)) throw new Error('Not an array');
  if (!config.commands.allowedCommands.includes('npm')) throw new Error('Missing npm');
  if (!config.commands.allowedCommands.includes('node')) throw new Error('Missing node');
});

// ============================================
// 6. TRUSTED MODULES
// ============================================
console.log('\n[6] Trusted Modules Configuration\n');

test('trustedModules loaded', () => {
  if (!Array.isArray(config.trustedModules)) throw new Error('Not an array');
  if (!config.trustedModules.includes('npm')) throw new Error('Missing npm');
  if (!config.trustedModules.includes('@aws-sdk')) throw new Error('Missing @aws-sdk');
});

test('FirewallCore.isTrustedModule works', () => {
  const firewall = new FirewallCore();
  if (!firewall.isTrustedModule('npm')) throw new Error('npm not trusted');
  if (!firewall.isTrustedModule('@aws-sdk/client-s3')) throw new Error('@aws-sdk not trusted');
  if (firewall.isTrustedModule('evil-package')) throw new Error('evil-package is trusted!');
});

// ============================================
// 7. EXCEPTIONS
// ============================================
console.log('\n[7] Exceptions Configuration\n');

test('exceptions.modules loaded', () => {
  if (!config.exceptions || !config.exceptions.modules) throw new Error('Not loaded');
  if (!config.exceptions.modules['example-package']) throw new Error('Missing example-package');
});

test('exception allowFilesystem loaded', () => {
  const ex = config.exceptions.modules['example-package'];
  if (!Array.isArray(ex.allowFilesystem)) throw new Error('Not an array');
  if (!ex.allowFilesystem.includes('/.config/example/')) throw new Error('Missing path');
});

test('exception allowNetwork loaded', () => {
  const ex = config.exceptions.modules['example-package'];
  if (!Array.isArray(ex.allowNetwork)) throw new Error('Not an array');
  if (!ex.allowNetwork.includes('api.example.com')) throw new Error('Missing domain');
});

test('exception allowCommands loaded', () => {
  const ex = config.exceptions.modules['example-package'];
  if (!Array.isArray(ex.allowCommands)) throw new Error('Not an array');
  if (!ex.allowCommands.includes('example-cli')) throw new Error('Missing command');
});

// ============================================
// 8. BEHAVIORAL CONFIGURATION
// ============================================
console.log('\n[8] Behavioral Configuration\n');

test('behavioral.monitorLifecycleScripts loaded', () => {
  if (config.behavioral.monitorLifecycleScripts !== true) throw new Error('Not enabled');
});

test('behavioral.maxNetworkRequests loaded', () => {
  if (config.behavioral.maxNetworkRequests !== 10) throw new Error('Wrong value');
});

test('behavioral.maxFileWrites loaded', () => {
  if (config.behavioral.maxFileWrites !== 50) throw new Error('Wrong value');
});

test('behavioral.maxProcessSpawns loaded', () => {
  if (config.behavioral.maxProcessSpawns !== 5) throw new Error('Wrong value');
});

test('behavioral.alertThresholds loaded', () => {
  if (!config.behavioral.alertThresholds) throw new Error('Not loaded');
  if (config.behavioral.alertThresholds.fileReads !== 100) throw new Error('Wrong fileReads');
  if (config.behavioral.alertThresholds.networkRequests !== 20) throw new Error('Wrong networkRequests');
});

// ============================================
// 9. REPORTING CONFIGURATION
// ============================================
console.log('\n[9] Reporting Configuration\n');

test('reporting.logLevel loaded', () => {
  if (config.reporting.logLevel !== 'info') throw new Error('Wrong value');
});

test('reporting.logFile loaded', () => {
  if (config.reporting.logFile !== 'fs-firewall.log') throw new Error('Wrong value');
});

test('reporting.alertOnSuspicious loaded', () => {
  if (config.reporting.alertOnSuspicious !== true) throw new Error('Not enabled');
});

test('reporting.generateReport loaded', () => {
  if (config.reporting.generateReport !== true) throw new Error('Not enabled');
});

test('reporting.reportFile loaded', () => {
  if (config.reporting.reportFile !== 'firewall-report.json') throw new Error('Wrong value');
});

// ============================================
// 10. GITHUB API CONFIGURATION
// ============================================
console.log('\n[10] GitHub API Configuration\n');

test('githubApi.monitorRepoCreation loaded', () => {
  if (config.githubApi.monitorRepoCreation !== true) throw new Error('Not enabled');
});

test('githubApi.monitorWorkflowCreation loaded', () => {
  if (config.githubApi.monitorWorkflowCreation !== true) throw new Error('Not enabled');
});

test('githubApi.blockedRepoNames loaded', () => {
  if (!Array.isArray(config.githubApi.blockedRepoNames)) throw new Error('Not an array');
  if (!config.githubApi.blockedRepoNames.includes('shai-hulud')) throw new Error('Missing shai-hulud');
  if (!config.githubApi.blockedRepoNames.includes('secrets')) throw new Error('Missing secrets');
});

test('githubApi.blockedWorkflowPatterns loaded', () => {
  if (!Array.isArray(config.githubApi.blockedWorkflowPatterns)) throw new Error('Not an array');
  if (!config.githubApi.blockedWorkflowPatterns.includes('discussion.yaml')) {
    throw new Error('Missing discussion.yaml');
  }
});

// ============================================
// SUMMARY
// ============================================
console.log('\n======================================================');
console.log('Summary:');
console.log(`  Passed: ${passed}`);
console.log(`  Failed: ${failed}`);
console.log('======================================================\n');

if (failed === 0) {
  console.log('All configuration features verified! ✓\n');
  process.exit(0);
} else {
  console.log(`${failed} test(s) failed.\n`);
  process.exit(1);
}
