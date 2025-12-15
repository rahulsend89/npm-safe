/**
 * Advanced Bypass Tests
 * Tests for sophisticated bypass techniques beyond basic ESM imports
 */

const {
  setupTestDir,
  cleanupTestDir,
  writeMinimalConfig,
  runWithFirewall,
  isBlocked,
  TestTracker
} = require('../utils');

async function runAdvancedBypassTests() {
  const tracker = new TestTracker('advanced-bypass');
  
  console.log('\n════════════════════════════════════════════════════════════');
  console.log('[ADVANCED] ADVANCED BYPASS TECHNIQUES');
  console.log('════════════════════════════════════════════════════════════\n');
  
  // =========================================================================
  // NON-NODE: ESM IMPORTS
  // =========================================================================
  console.log('--- Non-node: ESM Imports ---\n');
  
  await tracker.runTest('import("http") without node: prefix bypasses', async () => {
    const testDir = setupTestDir('adv-esm-no-prefix');
    
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
            const http = await import('http');
            const req = http.request({
              hostname: 'evil.com',
              port: 80,
              path: '/',
              method: 'GET'
            }, (res) => {
              console.log('NO_PREFIX_BYPASS_SUCCESS');
            });
            req.on('error', (e) => {
              console.log('NO_PREFIX_BLOCKED:' + e.message);
            });
            req.end();
            setTimeout(() => process.exit(0), 2000);
          } catch (e) {
            console.log('NO_PREFIX_BLOCKED:' + e.message);
          }
        })();
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 5000 });
      
      return {
        pass: isBlocked(result.output) || result.output.includes('NO_PREFIX_BLOCKED'),
        reason: result.output.includes('NO_PREFIX_BYPASS_SUCCESS') ? 'BYPASS: import("http") not intercepted' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // =========================================================================
  // DYNAMIC REQUIRE BYPASSES
  // =========================================================================
  console.log('\n--- Dynamic Require Bypasses ---\n');
  
  await tracker.runTest('require(variable) bypasses interception', async () => {
    const testDir = setupTestDir('adv-dynamic-require');
    
    try {
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: ['/.ssh/'],
          blockedWritePaths: [],
          allowedPaths: []
        }
      });
      
      const code = `
        try {
          const moduleName = 'fs';
          const fs = require(moduleName);
          const content = fs.readFileSync('/.ssh/id_rsa', 'utf8');
          console.log('DYNAMIC_REQUIRE_BYPASS_SUCCESS');
        } catch (e) {
          console.log('DYNAMIC_REQUIRE_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 5000 });
      
      return {
        pass: isBlocked(result.output) || result.output.includes('DYNAMIC_REQUIRE_BLOCKED'),
        reason: result.output.includes('DYNAMIC_REQUIRE_BYPASS_SUCCESS') ? 'BYPASS: dynamic require not intercepted' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  await tracker.runTest('Function constructor require bypasses', async () => {
    const testDir = setupTestDir('adv-function-require');
    
    try {
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: ['/.ssh/'],
          blockedWritePaths: [],
          allowedPaths: []
        }
      });
      
      const code = `
        try {
          const getRequire = new Function('return require');
          const req = getRequire();
          const fs = req('fs');
          const content = fs.readFileSync('/.ssh/id_rsa', 'utf8');
          console.log('FUNCTION_REQUIRE_BYPASS_SUCCESS');
        } catch (e) {
          console.log('FUNCTION_REQUIRE_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 5000 });
      
      return {
        pass: isBlocked(result.output) || result.output.includes('FUNCTION_REQUIRE_BLOCKED'),
        reason: result.output.includes('FUNCTION_REQUIRE_BYPASS_SUCCESS') ? 'BYPASS: Function() require not intercepted' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // =========================================================================
  // VM MODULE BYPASSES
  // =========================================================================
  console.log('\n--- VM Module Context Escapes ---\n');
  
  await tracker.runTest('vm.runInNewContext accesses original builtins', async () => {
    const testDir = setupTestDir('adv-vm-context');
    
    try {
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: ['/.ssh/'],
          blockedWritePaths: [],
          allowedPaths: []
        }
      });
      
      const code = `
        const vm = require('vm');
        try {
          const sandbox = { require };
          const result = vm.runInNewContext(\`
            const fs = require('fs');
            try {
              fs.readFileSync('/.ssh/id_rsa', 'utf8');
              'VM_BYPASS_SUCCESS';
            } catch (e) {
              'VM_BLOCKED:' + e.message;
            }
          \`, sandbox);
          console.log(result);
        } catch (e) {
          console.log('VM_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 5000 });
      
      return {
        pass: isBlocked(result.output) || result.output.includes('VM_BLOCKED'),
        reason: result.output.includes('VM_BYPASS_SUCCESS') ? 'BYPASS: vm.runInNewContext escapes firewall' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // =========================================================================
  // PROTOTYPE MANIPULATION
  // =========================================================================
  console.log('\n--- Prototype Manipulation ---\n');
  
  await tracker.runTest('Deleting wrapped method restores original', async () => {
    const testDir = setupTestDir('adv-proto-delete');
    
    try {
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: ['/.ssh/'],
          blockedWritePaths: [],
          allowedPaths: []
        }
      });
      
      const code = `
        const fs = require('fs');
        try {
          // Try to delete the wrapped method
          delete fs.readFileSync;
          
          // Try to access via prototype
          const proto = Object.getPrototypeOf(fs);
          if (proto && proto.readFileSync) {
            const content = proto.readFileSync.call(fs, '/.ssh/id_rsa', 'utf8');
            console.log('PROTO_BYPASS_SUCCESS');
          } else {
            console.log('PROTO_BLOCKED:no_prototype_method');
          }
        } catch (e) {
          console.log('PROTO_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 5000 });
      
      return {
        pass: isBlocked(result.output) || result.output.includes('PROTO_BLOCKED'),
        reason: result.output.includes('PROTO_BYPASS_SUCCESS') ? 'BYPASS: prototype manipulation works' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // =========================================================================
  // WORKER THREADS CONTEXT
  // =========================================================================
  console.log('\n--- Worker Threads Context ---\n');
  
  await tracker.runTest('worker_threads with eval bypasses firewall', async () => {
    const testDir = setupTestDir('adv-worker-eval');
    
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
        const { Worker } = require('worker_threads');
        
        const workerCode = \`
          const http = require('http');
          const { parentPort } = require('worker_threads');
          
          const req = http.request({
            hostname: 'evil.com',
            port: 80,
            path: '/',
            method: 'GET'
          }, (res) => {
            parentPort.postMessage('WORKER_EVAL_BYPASS_SUCCESS');
          });
          
          req.on('error', (e) => {
            parentPort.postMessage('WORKER_EVAL_BLOCKED:' + e.message);
          });
          
          req.end();
        \`;
        
        try {
          const worker = new Worker(workerCode, { eval: true });
          
          worker.on('message', (msg) => {
            console.log(msg);
            worker.terminate();
          });
          
          worker.on('error', (e) => {
            console.log('WORKER_EVAL_BLOCKED:' + e.message);
          });
          
          setTimeout(() => {
            worker.terminate();
            process.exit(0);
          }, 2500);
        } catch (e) {
          console.log('WORKER_EVAL_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 5000 });
      
      return {
        pass: isBlocked(result.output) || result.output.includes('WORKER_EVAL_BLOCKED'),
        reason: result.output.includes('WORKER_EVAL_BYPASS_SUCCESS') ? 'BYPASS: worker eval escapes firewall' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // =========================================================================
  // NATIVE BINDING ACCESS
  // =========================================================================
  console.log('\n--- Native Binding Access ---\n');
  
  await tracker.runTest('process.binding("fs") bypasses fs interceptor', async () => {
    const testDir = setupTestDir('adv-binding-fs');
    
    try {
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: ['/.ssh/'],
          blockedWritePaths: [],
          allowedPaths: []
        }
      });
      
      const code = `
        try {
          const binding = process.binding('fs');
          const fd = binding.open('/.ssh/id_rsa', 0, 0o666);
          if (fd >= 0) {
            console.log('BINDING_FS_BYPASS_SUCCESS');
            binding.close(fd);
          } else {
            console.log('BINDING_FS_BLOCKED:open_failed');
          }
        } catch (e) {
          console.log('BINDING_FS_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 5000 });
      
      return {
        pass: isBlocked(result.output) || result.output.includes('BINDING_FS_BLOCKED'),
        reason: result.output.includes('BINDING_FS_BYPASS_SUCCESS') ? 'BYPASS: process.binding("fs") works (enable fortress mode)' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  return tracker.getSummary();
}

module.exports = { runAdvancedBypassTests };

// Allow direct execution
if (require.main === module) {
  runAdvancedBypassTests().then(summary => {
    console.log('\nAdvanced Bypass Tests Summary:');
    console.log(`  Passed: ${summary.passed}`);
    console.log(`  Failed: ${summary.failed}`);
    console.log(`  Skipped: ${summary.skipped}`);
    process.exit(summary.failed > 0 ? 1 : 0);
  });
}
