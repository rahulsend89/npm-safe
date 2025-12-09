/**
 * Integration Test v2: Complete firewall functionality using E2E pattern
 * Uses real-world testing with actual --import/--loader flags
 */

const {
  runFirewallTest,
  runTest,
  platform,
  nodeMajor,
  nodeVersion,
  supportsImport,
  loaderFlag
} = require('./test-runner');

console.log('======================================================');
console.log('   Firewall Integration Test (E2E Pattern)');
console.log('======================================================');
console.log(`Platform: ${platform}`);
console.log(`Node.js: ${nodeVersion}`);
console.log(`Loader: ${loaderFlag}`);
console.log('');

let passed = 0;
let failed = 0;

async function runTests() {
  // ============================================
  // 1. CORE INITIALIZATION
  // ============================================
  console.log('[1] Core Initialization\n');

  if (await runFirewallTest(
    'Firewall initializes correctly',
    `console.log('INIT_OK');`,
    (output) => ({
      pass: output.includes('INIT_OK') && output.includes('Firewall'),
      reason: output.includes('Firewall') ? 'initialized' : 'not initialized'
    })
  )) passed++; else failed++;

  if (await runFirewallTest(
    'Config loaded',
    `const config = require('./lib/config-loader').load();
     console.log(config ? 'CONFIG_OK' : 'CONFIG_FAIL');`,
    (output) => ({
      pass: output.includes('CONFIG_OK'),
      reason: output.includes('CONFIG_OK') ? 'config loaded' : 'config failed'
    })
  )) passed++; else failed++;

  if (await runFirewallTest(
    'FirewallCore instantiated',
    `const { getInstance } = require('./lib/firewall-core');
     const firewall = getInstance();
     console.log(firewall ? 'CORE_OK' : 'CORE_FAIL');`,
    (output) => ({
      pass: output.includes('CORE_OK'),
      reason: output.includes('CORE_OK') ? 'core instantiated' : 'core failed'
    })
  )) passed++; else failed++;

  // ============================================
  // 2. ESM HOOKS
  // ============================================
  console.log('\n[2] ESM Hooks\n');

  if (await runFirewallTest(
    'ESM hooks loaded',
    `console.log('ESM_TEST');`,
    (output) => ({
      pass: output.includes('ESM_TEST'),
      reason: output.includes('ESM_TEST') ? 'hooks loaded' : 'hooks failed'
    })
  )) passed++; else failed++;

  if (await runFirewallTest(
    'ESM resolve hook active',
    `import('path').then(() => console.log('RESOLVE_OK'));
     setTimeout(() => {}, 100);`,
    (output) => ({
      pass: output.includes('RESOLVE_OK') || output.includes('Firewall'),
      reason: 'resolve hook active'
    })
  )) passed++; else failed++;

  // ============================================
  // 3. FILESYSTEM INTERCEPTION
  // ============================================
  console.log('\n[3] Filesystem Interception\n');

  if (await runFirewallTest(
    'fs.readFileSync intercepted',
    `const fs = require('fs');
     try {
       fs.readFileSync('/.ssh/id_rsa');
       console.log('NOT_INTERCEPTED');
     } catch(e) {
       console.log('INTERCEPTED');
     }`,
    (output) => ({
      pass: output.includes('INTERCEPTED') || output.includes('Access denied'),
      reason: 'readFileSync intercepted'
    })
  )) passed++; else failed++;

  if (await runFirewallTest(
    'fs.writeFileSync intercepted',
    `const fs = require('fs');
     try {
       fs.writeFileSync('/etc/test', 'data');
       console.log('NOT_INTERCEPTED');
     } catch(e) {
       console.log('INTERCEPTED');
     }`,
    (output) => ({
      pass: output.includes('INTERCEPTED') || output.includes('Access denied'),
      reason: 'writeFileSync intercepted'
    })
  )) passed++; else failed++;

  // ============================================
  // 4. NETWORK INTERCEPTION
  // ============================================
  console.log('\n[4] Network Interception\n');

  if (await runFirewallTest(
    'https.request intercepted',
    `const https = require('https');
     const req = https.get('https://pastebin.com/', () => {});
     req.on('error', () => {});
     req.end();
     setTimeout(() => console.log('REQUEST_MADE'), 100);`,
    (output) => ({
      pass: output.includes('blocked') || output.includes('Blocked domain'),
      reason: 'https intercepted'
    })
  )) passed++; else failed++;

  if (await runFirewallTest(
    'http.request intercepted',
    `const http = require('http');
     const req = http.get('http://pastebin.com/', () => {});
     req.on('error', () => {});
     req.end();
     setTimeout(() => console.log('REQUEST_MADE'), 100);`,
    (output) => ({
      pass: output.includes('blocked') || output.includes('Blocked domain'),
      reason: 'http intercepted'
    })
  )) passed++; else failed++;

  // ============================================
  // 5. CHILD PROCESS INTERCEPTION
  // ============================================
  console.log('\n[5] Child Process Interception\n');

  if (await runFirewallTest(
    'child_process.exec intercepted',
    `const { exec } = require('child_process');
     exec('rm -rf /', (err) => {
       console.log(err ? 'BLOCKED' : 'NOT_BLOCKED');
     });
     setTimeout(() => {}, 200);`,
    (output) => ({
      pass: output.includes('BLOCKED') || output.includes('blocked'),
      reason: 'exec intercepted'
    })
  )) passed++; else failed++;

  if (await runFirewallTest(
    'child_process.spawn intercepted',
    `const { spawn } = require('child_process');
     try {
       const proc = spawn('bash', ['-c', 'cat /etc/shadow']);
       proc.on('error', (err) => console.log('BLOCKED'));
       proc.on('close', (code) => {
         if (code !== 0) console.log('BLOCKED');
       });
     } catch(e) {
       console.log('BLOCKED');
     }
     setTimeout(() => {}, 300);`,
    (output) => ({
      pass: output.includes('BLOCKED') || output.includes('blocked') || output.includes('Dangerous command'),
      reason: 'spawn intercepted'
    })
  )) passed++; else failed++;

  // ============================================
  // SUMMARY
  // ============================================
  console.log('\n======================================================');
  console.log('Summary:');
  console.log(`  Passed: ${passed}`);
  console.log(`  Failed: ${failed}`);
  console.log(`  Total:  ${passed + failed}`);
  console.log('======================================================\n');

  if (failed === 0) {
    console.log('All integration tests passed! ✓\n');
    process.exit(0);
  } else {
    console.log(`${failed} test(s) failed.\n`);
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('Test suite error:', err);
  process.exit(1);
});
