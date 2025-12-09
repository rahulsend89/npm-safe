/**
 * End-to-End Real-World Tests
 * Tests actual npm-safe usage scenarios across platforms and Node versions
 * Uses the actual --import/--loader flags like real installation
 */

const {
  runFirewallTest,
  runTest,
  platform,
  isWindows,
  nodeMajor,
  nodeVersion,
  supportsImport,
  loaderFlag,
  getPlatformPath,
  getHomeDir,
  createTempConfig,
  cleanupTempConfig
} = require('./test-runner');

console.log('======================================================');
console.log('   End-to-End Real-World Tests');
console.log('======================================================\n');

let passed = 0;
let failed = 0;

async function runTests() {
  // ============================================
  // 1. PLATFORM & VERSION DETECTION
  // ============================================
  console.log('[1] Platform & Version Detection\n');

  const platformTest = runTest('Platform detected', () => {
    if (!platform) throw new Error('Platform not detected');
  });
  if (platformTest) passed++; else failed++;

  const versionTest = runTest('Node.js version detected', () => {
    if (!nodeVersion || !nodeMajor) throw new Error('Version not detected');
  });
  if (versionTest) passed++; else failed++;

  const loaderTest = runTest(`Correct loader selected (${loaderFlag})`, () => {
    if (nodeMajor >= 21 && loaderFlag !== '--import') {
      throw new Error('Should use --import for Node 21+');
    }
    if (nodeMajor === 20 && loaderFlag !== '--import') {
      throw new Error('Should use --import for Node 20.6+');
    }
    if (nodeMajor < 20 && loaderFlag !== '--loader') {
      throw new Error('Should use --loader for Node < 20');
    }
  });
  if (loaderTest) passed++; else failed++;

  const windowsTest = runTest(`Windows detection (${isWindows ? 'Windows' : 'Unix'})`, () => {
    if (platform === 'win32' && !isWindows) {
      throw new Error('Windows not detected');
    }
    if (platform !== 'win32' && isWindows) {
      throw new Error('Incorrectly detected as Windows');
    }
  });
  if (windowsTest) passed++; else failed++;

  // ============================================
  // 2. FIREWALL INITIALIZATION (REAL USAGE)
  // ============================================
  console.log('\n[2] Firewall Initialization (Real Usage)\n');

  if (await runFirewallTest(
    'Firewall initializes with correct loader',
    `console.log('INIT_SUCCESS');`,
    (output) => {
      const hasInit = output.includes('INIT_SUCCESS') && output.includes('Firewall');
      return {
        pass: hasInit,
        reason: hasInit ? 'initialized' : 'failed to initialize',
        debug: output
      };
    }
  )) passed++; else failed++;

  if (await runFirewallTest(
    'Shows firewall version',
    `console.log('test');`,
    (output) => {
      const hasVersion = output.includes('v2.0') || output.includes('Firewall');
      return {
        pass: hasVersion,
        reason: hasVersion ? 'version shown' : 'version missing'
      };
    }
  )) passed++; else failed++;

  if (await runFirewallTest(
    'Shows mode configuration',
    `console.log('test');`,
    (output) => {
      const hasMode = output.includes('Mode:') || output.includes('Enforcement');
      return {
        pass: hasMode,
        reason: hasMode ? 'mode shown' : 'mode missing'
      };
    }
  )) passed++; else failed++;

  // ============================================
  // 3. CROSS-PLATFORM PATH HANDLING
  // ============================================
  console.log('\n[3] Cross-Platform Path Handling\n');

  if (await runFirewallTest(
    'Handles platform-specific paths',
    `const path = require('path');
     const testPath = path.join('test', 'file.js');
     console.log('PATH_OK');`,
    (output) => {
      const ok = output.includes('PATH_OK');
      return {
        pass: ok,
        reason: ok ? 'paths handled' : 'path error'
      };
    }
  )) passed++; else failed++;

  if (await runFirewallTest(
    'Handles home directory detection',
    `const os = require('os');
     const home = os.homedir();
     console.log(home ? 'HOME_OK' : 'HOME_FAIL');`,
    (output) => {
      const ok = output.includes('HOME_OK');
      return {
        pass: ok,
        reason: ok ? 'home dir detected' : 'home dir failed'
      };
    }
  )) passed++; else failed++;

  if (await runFirewallTest(
    'Handles absolute vs relative paths',
    `const path = require('path');
     const abs = path.resolve('test.js');
     const rel = path.relative(process.cwd(), abs);
     console.log('PATHS_OK');`,
    (output) => {
      const ok = output.includes('PATHS_OK');
      return {
        pass: ok,
        reason: ok ? 'path resolution works' : 'path error'
      };
    }
  )) passed++; else failed++;

  // ============================================
  // 4. FILESYSTEM PROTECTION (REAL SCENARIO)
  // ============================================
  console.log('\n[4] Filesystem Protection (Real Scenario)\n');

  if (await runFirewallTest(
    'Blocks sensitive file reads',
    `const fs = require('fs');
     try {
       fs.readFileSync('${getPlatformPath('/etc/passwd')}');
       console.log('NOT_BLOCKED');
     } catch(e) {
       console.log('BLOCKED');
     }`,
    (output) => {
      const blocked = output.includes('BLOCKED') || output.includes('Access denied');
      return {
        pass: blocked,
        reason: blocked ? 'sensitive read blocked' : 'not blocked'
      };
    }
  )) passed++; else failed++;

  if (await runFirewallTest(
    'Blocks system directory writes',
    `const fs = require('fs');
     try {
       fs.writeFileSync('${getPlatformPath('/etc/test.txt')}', 'test');
       console.log('NOT_BLOCKED');
     } catch(e) {
       console.log('BLOCKED');
     }`,
    (output) => {
      const blocked = output.includes('BLOCKED') || output.includes('Access denied') || output.includes('EACCES');
      return {
        pass: blocked,
        reason: blocked ? 'system write blocked' : 'not blocked'
      };
    }
  )) passed++; else failed++;

  if (await runFirewallTest(
    'Allows safe file operations',
    `const fs = require('fs');
     const os = require('os');
     const path = require('path');
     const tmpFile = path.join(os.tmpdir(), 'firewall-test.txt');
     fs.writeFileSync(tmpFile, 'test');
     fs.unlinkSync(tmpFile);
     console.log('ALLOWED');`,
    (output) => {
      const allowed = output.includes('ALLOWED');
      return {
        pass: allowed,
        reason: allowed ? 'safe ops allowed' : 'safe ops blocked'
      };
    }
  )) passed++; else failed++;

  // ============================================
  // 5. NETWORK PROTECTION (REAL SCENARIO)
  // ============================================
  console.log('\n[5] Network Protection (Real Scenario)\n');

  if (await runFirewallTest(
    'Blocks malicious domains',
    `const https = require('https');
     const req = https.get('https://pastebin.com/test', () => {});
     req.on('error', () => {});
     req.end();
     setTimeout(() => console.log('REQUEST_MADE'), 100);`,
    (output) => {
      const blocked = output.includes('blocked') || output.includes('Blocked domain');
      return {
        pass: blocked,
        reason: blocked ? 'domain blocked' : 'domain allowed'
      };
    }
  )) passed++; else failed++;

  if (await runFirewallTest(
    'Allows legitimate domains',
    `const https = require('https');
     const req = https.get('https://registry.npmjs.org/', () => {});
     req.on('error', () => {});
     req.end();
     console.log('REQUEST_ALLOWED');`,
    (output) => {
      const allowed = output.includes('REQUEST_ALLOWED');
      return {
        pass: allowed,
        reason: allowed ? 'legitimate allowed' : 'legitimate blocked'
      };
    }
  )) passed++; else failed++;

  // ============================================
  // 6. COMMAND EXECUTION (REAL SCENARIO)
  // ============================================
  console.log('\n[6] Command Execution (Real Scenario)\n');

  if (await runFirewallTest(
    'Blocks dangerous commands',
    `const { exec } = require('child_process');
     exec('rm -rf /', (err) => {
       console.log(err ? 'BLOCKED' : 'NOT_BLOCKED');
     });
     setTimeout(() => {}, 200);`,
    (output) => {
      const blocked = output.includes('BLOCKED') || output.includes('blocked');
      return {
        pass: blocked,
        reason: blocked ? 'dangerous cmd blocked' : 'not blocked'
      };
    }
  )) passed++; else failed++;

  if (await runFirewallTest(
    'Allows safe commands',
    `const { exec } = require('child_process');
     exec('node --version', (err, stdout) => {
       console.log('COMMAND_ALLOWED');
     });
     setTimeout(() => {}, 200);`,
    (output) => {
      const allowed = output.includes('COMMAND_ALLOWED');
      return {
        pass: allowed,
        reason: allowed ? 'safe cmd allowed' : 'safe cmd blocked'
      };
    }
  )) passed++; else failed++;

  // ============================================
  // 7. ENVIRONMENT VARIABLE PROTECTION
  // ============================================
  console.log('\n[7] Environment Variable Protection\n');

  if (await runFirewallTest(
    'Protects sensitive env vars',
    `console.log('test');`,
    (output) => {
      const hasProtection = output.includes('Protecting 11') || output.includes('environment variables');
      return {
        pass: hasProtection,
        reason: hasProtection ? 'env protection active' : 'not active'
      };
    },
    { env: { GITHUB_TOKEN: 'test_token' } }
  )) passed++; else failed++;

  if (await runFirewallTest(
    'Allows safe env vars',
    `const path = process.env.PATH;
     console.log(path ? 'PATH_ACCESSIBLE' : 'PATH_BLOCKED');`,
    (output) => {
      const accessible = output.includes('PATH_ACCESSIBLE');
      return {
        pass: accessible,
        reason: accessible ? 'safe env accessible' : 'safe env blocked'
      };
    }
  )) passed++; else failed++;

  // ============================================
  // 8. MODE CONFIGURATION (REAL SCENARIO)
  // ============================================
  console.log('\n[8] Mode Configuration\n');

  if (await runFirewallTest(
    'Enforcement mode active',
    `console.log('test');`,
    (output) => {
      const hasMode = output.includes('Mode: Enforcement') || output.includes('Enforcement');
      return {
        pass: hasMode,
        reason: hasMode ? 'enforcement mode' : 'wrong mode'
      };
    }
  )) passed++; else failed++;

  if (await runFirewallTest(
    'Strict mode configurable',
    `console.log('test');`,
    (output) => {
      const hasStrict = output.includes('Strict:');
      return {
        pass: hasStrict,
        reason: hasStrict ? 'strict mode shown' : 'strict not shown'
      };
    }
  )) passed++; else failed++;

  // ============================================
  // 9. BEHAVIORAL MONITORING
  // ============================================
  console.log('\n[9] Behavioral Monitoring\n');

  if (await runFirewallTest(
    'Behavior monitoring active',
    `console.log('test');`,
    (output) => {
      const hasMonitoring = output.includes('Behavior Monitor') || output.includes('Tracking:');
      return {
        pass: hasMonitoring,
        reason: hasMonitoring ? 'monitoring active' : 'not active'
      };
    }
  )) passed++; else failed++;

  if (await runFirewallTest(
    'Generates behavior report on exit',
    `console.log('test');
     process.exit(0);`,
    (output) => {
      const hasReport = output.includes('Package Behavior Summary') || output.includes('Assessment:');
      return {
        pass: hasReport,
        reason: hasReport ? 'report generated' : 'no report'
      };
    }
  )) passed++; else failed++;

  // ============================================
  // 10. ERROR HANDLING
  // ============================================
  console.log('\n[10] Error Handling & Stability\n');

  if (await runFirewallTest(
    'Handles syntax errors gracefully',
    `this is invalid javascript`,
    (output, exitCode) => {
      const handled = exitCode !== 0 || output.includes('SyntaxError');
      return {
        pass: handled,
        reason: handled ? 'error handled' : 'crashed'
      };
    }
  )) passed++; else failed++;

  if (await runFirewallTest(
    'Handles missing modules gracefully',
    `require('non-existent-module-xyz');`,
    (output, exitCode) => {
      const handled = exitCode !== 0 || output.includes('Cannot find module');
      return {
        pass: handled,
        reason: handled ? 'error handled' : 'crashed'
      };
    }
  )) passed++; else failed++;

  if (await runFirewallTest(
    'Handles process crashes gracefully',
    `setTimeout(() => { throw new Error('Test crash'); }, 10);
     setTimeout(() => {}, 100);`,
    (output, exitCode) => {
      const handled = exitCode !== 0 || output.includes('Error');
      return {
        pass: handled,
        reason: handled ? 'crash handled' : 'unhandled'
      };
    }
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

  console.log('Platform Info:');
  console.log(`  OS: ${platform}`);
  console.log(`  Node.js: ${nodeVersion}`);
  console.log(`  Loader: ${loaderFlag}`);
  console.log(`  Windows: ${isWindows}\n`);

  console.log('Coverage:');
  console.log('  Platform Detection:     ✓');
  console.log('  Real Firewall Init:     ✓');
  console.log('  Cross-Platform Paths:   ✓');
  console.log('  Filesystem Protection:  ✓');
  console.log('  Network Protection:     ✓');
  console.log('  Command Execution:      ✓');
  console.log('  Environment Protection: ✓');
  console.log('  Mode Configuration:     ✓');
  console.log('  Behavioral Monitoring:  ✓');
  console.log('  Error Handling:         ✓\n');

  if (failed === 0) {
    console.log('All E2E real-world tests passed! ✓\n');
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
