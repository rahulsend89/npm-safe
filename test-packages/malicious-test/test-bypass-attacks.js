#!/usr/bin/env node

/**
 * Bypass Attack Tests - Adversarial Red Team
 * Tests sophisticated bypass techniques that attackers who know our code would use
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const results = {
  bypasses: [],
  stats: { total: 0, blocked: 0, succeeded: 0 }
};

console.log('\n╔╗');
console.log('         BYPASS ATTACK TESTS - RED TEAM                     ');
console.log('    Testing attacks from someone who knows our code         ');
console.log('╚╝\n');

function runTest(name, description, testFn) {
  return new Promise(async (resolve) => {
    console.log(`\n[${'='.repeat(60)}]`);
    console.log(`Test: ${name}`);
    console.log(`Description: ${description}`);
    console.log(`${''.repeat(62)}`);
    
    try {
      const result = await testFn();
      const status = result.blocked ? ' BLOCKED' : ' BYPASSED';
      const color = result.blocked ? '\x1b[32m' : '\x1b[31m';
      
      console.log(`${color}${status}\x1b[0m`);
      if (result.details) {
        console.log(`Details: ${result.details}`);
      }
      if (result.recommendation && !result.blocked) {
        console.log(` Fix: ${result.recommendation}`);
      }
      
      results.bypasses.push({
        test: name,
        description,
        blocked: result.blocked,
        details: result.details,
        recommendation: result.recommendation
      });
      
      results.stats.total++;
      if (result.blocked) {
        results.stats.blocked++;
      } else {
        results.stats.succeeded++;
      }
    } catch (e) {
      console.log(` BLOCKED (threw error)`);
      console.log(`Details: ${e.message}`);
      
      results.bypasses.push({
        test: name,
        description,
        blocked: true,
        details: `Exception: ${e.message}`
      });
      results.stats.total++;
      results.stats.blocked++;
    }
    
    resolve();
  });
}

// ==========================================
// BYPASS 1: Require.cache Manipulation
// ==========================================

async function testRequireCacheBypass() {
  return runTest('REQUIRE_CACHE_POISON', 'Delete firewall from require.cache and reload fs', async () => {
    try {
      // Try to find and delete firewall from cache
      const firewallKeys = Object.keys(require.cache).filter(k => 
        k.includes('firewall') || k.includes('interceptor')
      );
      
      if (firewallKeys.length === 0) {
        return {
          blocked: true,
          details: 'Firewall modules not found in require.cache (good protection)'
        };
      }
      
      // Try to delete them
      firewallKeys.forEach(key => {
        delete require.cache[key];
      });
      
      // Now try to reload fs without firewall
      console.log('[TEST] Attempting to delete fs from cache...');
      delete require.cache[require.resolve('fs')];
      console.log('[TEST] Requiring fresh fs...');
      const freshFs = require('fs');
      
      // Try to read sensitive file
      const sshPath = path.join(os.homedir(), '.ssh', 'id_rsa');
      console.log('[TEST] Attempting to read:', sshPath);
      const data = freshFs.readFileSync(sshPath, 'utf8');
      console.log('[TEST]  READ SUCCEEDED! Bypass successful!');
      
      return {
        blocked: false,
        details: 'Successfully bypassed by deleting from require.cache',
        recommendation: 'Object.freeze(require.cache) or use non-deletable properties'
      };
    } catch (e) {
      return {
        blocked: true,
        details: `Blocked: ${e.message}`
      };
    }
  });
}

// ==========================================
// BYPASS 2: Prototype Pollution
// ==========================================

async function testPrototypePollution() {
  return runTest('PROTOTYPE_POLLUTION', 'Poison Object.prototype to disable checks', async () => {
    try {
      // Pollute prototype to make everything "allowed"
      Object.prototype.enabled = false;
      Object.prototype.alertOnly = true;
      Object.prototype.allowed = true;
      
      // Try to read sensitive file
      const sshPath = path.join(os.homedir(), '.ssh', 'id_rsa');
      fs.readFileSync(sshPath, 'utf8');
      
      // Cleanup
      delete Object.prototype.enabled;
      delete Object.prototype.alertOnly;
      delete Object.prototype.allowed;
      
      return {
        blocked: false,
        details: 'Prototype pollution bypassed firewall checks',
        recommendation: 'Use Object.create(null) for configs, hasOwnProperty checks'
      };
    } catch (e) {
      // Cleanup
      delete Object.prototype.enabled;
      delete Object.prototype.alertOnly;
      delete Object.prototype.allowed;
      
      return {
        blocked: true,
        details: `Blocked: ${e.message}`
      };
    }
  });
}

// ==========================================
// BYPASS 3: Worker Threads
// ==========================================

async function testWorkerThreadBypass() {
  return runTest('WORKER_THREAD_BYPASS', 'Use worker threads (separate context)', async () => {
    try {
      const { Worker } = require('worker_threads');
      
      return new Promise((resolve) => {
        const worker = new Worker(`
          const fs = require('fs');
          const path = require('path');
          const os = require('os');
          try {
            const sshPath = path.join(os.homedir(), '.ssh', 'id_rsa');
            const content = fs.readFileSync(sshPath, 'utf8');
            require('worker_threads').parentPort.postMessage({ 
              success: true, 
              length: content.length 
            });
          } catch (e) {
            require('worker_threads').parentPort.postMessage({ 
              success: false, 
              error: e.message 
            });
          }
        `, { eval: true });
        
        worker.on('message', (msg) => {
          worker.terminate();
          if (msg.success) {
            resolve({
              blocked: false,
              details: `Worker bypassed firewall, read ${msg.length} bytes`,
              recommendation: 'Intercept worker_threads, inject firewall into workers'
            });
          } else {
            resolve({
              blocked: true,
              details: `Worker blocked: ${msg.error}`
            });
          }
        });
        
        worker.on('error', (err) => {
          resolve({
            blocked: true,
            details: `Worker creation blocked: ${err.message}`
          });
        });
        
        setTimeout(() => {
          worker.terminate();
          resolve({
            blocked: true,
            details: 'Worker timeout (likely blocked)'
          });
        }, 3000);
      });
    } catch (e) {
      return {
        blocked: true,
        details: `Blocked: ${e.message}`
      };
    }
  });
}

// ==========================================
// BYPASS 4: VM Module Escape
// ==========================================

async function testVMEscape() {
  return runTest('VM_MODULE_ESCAPE', 'Escape sandbox via vm.runInContext', async () => {
    try {
      const vm = require('vm');
      const sandbox = {};
      vm.createContext(sandbox);
      
      // Try constructor escape
      const code = `
        const fs = this.constructor.constructor('return require("fs")')();
        const path = this.constructor.constructor('return require("path")')();
        const os = this.constructor.constructor('return require("os")')();
        const sshPath = path.join(os.homedir(), '.ssh', 'id_rsa');
        fs.readFileSync(sshPath, 'utf8');
      `;
      
      vm.runInContext(code, sandbox);
      
      return {
        blocked: false,
        details: 'VM escape succeeded via constructor',
        recommendation: 'Intercept vm module, block Function constructor'
      };
    } catch (e) {
      return {
        blocked: true,
        details: `Blocked: ${e.message}`
      };
    }
  });
}

// ==========================================
// BYPASS 5: Process.binding() Direct Access
// ==========================================

async function testProcessBinding() {
  return runTest('PROCESS_BINDING_SYSCALL', 'Direct syscalls via process.binding', async () => {
    try {
      // Just check if process.binding is accessible
      if (typeof process.binding === 'function') {
        // Try to call it (don't actually use the result to avoid crashes)
        try {
          process.binding('fs');
          return {
            blocked: false,
            details: 'process.binding is accessible (potential bypass)',
            recommendation: 'Override or disable process.binding() during npm install'
          };
        } catch (e) {
          return {
            blocked: true,
            details: `process.binding blocked: ${e.message}`
          };
        }
      }
      
      return {
        blocked: true,
        details: 'process.binding not available'
      };
    } catch (e) {
      return {
        blocked: true,
        details: `Blocked: ${e.message}`
      };
    }
  });
}

// ==========================================
// BYPASS 6: Native Addon (.node files)
// ==========================================

async function testNativeAddon() {
  return runTest('NATIVE_ADDON_BYPASS', 'Load native .node addon', async () => {
    try {
      // Try to load a .node file (if exists)
      // Most systems won't have malicious .node files, but test the concept
      
      // Try process.dlopen if available
      if (typeof process.dlopen === 'function') {
        // Actually try to CALL it with dummy args to see if it's blocked
        try {
          // This will fail but we want to see if it throws our error or a different error
          process.dlopen({}, '/fake/path.node');
          
          return {
            blocked: false,
            details: 'process.dlopen executed (no blocking)',
            recommendation: 'Override process.dlopen or block .node loading'
          };
        } catch (e) {
          // Check if it's OUR blocking error
          if (e.message.includes('blocked') || e.message.includes('BLOCKED')) {
            return {
              blocked: true,
              details: `Blocked: ${e.message}`
            };
          }
          
          // Different error (file not found, etc) means it tried to execute
          return {
            blocked: false,
            details: `process.dlopen accessible (error: ${e.message})`,
            recommendation: 'Add blocking for process.dlopen during install'
          };
        }
      }
      
      return {
        blocked: true,
        details: 'process.dlopen not accessible'
      };
    } catch (e) {
      return {
        blocked: true,
        details: `Blocked: ${e.message}`
      };
    }
  });
}

// ==========================================
// BYPASS 7: Child Process NODE_OPTIONS Override
// ==========================================

async function testChildProcessEnvBypass() {
  return runTest('CHILD_PROCESS_ENV_OVERRIDE', 'Spawn child with cleared NODE_OPTIONS', async () => {
    try {
      const { spawn } = require('child_process');
      
      return new Promise((resolve) => {
        // Try to spawn node without firewall
        const child = spawn('node', ['-e', 
          `const fs = require('fs'); 
           const os = require('os'); 
           const path = require('path');
           console.log(fs.readFileSync(path.join(os.homedir(), '.ssh', 'id_rsa'), 'utf8'));`
        ], {
          env: { PATH: process.env.PATH }, // Only PATH, no NODE_OPTIONS
          timeout: 2000
        });
        
        let output = '';
        child.stdout.on('data', (data) => {
          output += data.toString();
        });
        
        child.stderr.on('data', (data) => {
          output += data.toString();
        });
        
        child.on('close', (code) => {
          console.log(`[TEST] Child exit: ${code}, output: ${output.substring(0, 150)}`);
          
          // Check if blocked by firewall
          const wasBlocked = output.includes('BLOCKED') || 
                            output.includes('Firewall') ||
                            code !== 0;
          
          const hadData = output.includes('PRIVATE KEY') || output.includes('ssh-rsa') || output.includes('BEGIN');
          
          if (hadData && !wasBlocked) {
            resolve({
              blocked: false,
              details: 'Child process bypassed by clearing NODE_OPTIONS',
              recommendation: 'Block child spawns that modify NODE_OPTIONS'
            });
          } else {
            resolve({
              blocked: true,
              details: `Child process blocked (exit: ${code}, blocked: ${wasBlocked})`
            });
          }
        });
        
        child.on('error', (err) => {
          resolve({
            blocked: true,
            details: `Blocked: ${err.message}`
          });
        });
      });
    } catch (e) {
      return {
        blocked: true,
        details: `Blocked: ${e.message}`
      };
    }
  });
}

// ==========================================
// BYPASS 8: V8 Heap Snapshot
// ==========================================

async function testHeapSnapshot() {
  return runTest('HEAP_SNAPSHOT_EXFIL', 'Extract secrets via heap snapshot', async () => {
    try {
      const v8 = require('v8');
      
      // Put a fake secret in memory
      const fakeSecret = 'FAKE_AWS_KEY_123456789';
      
      // Try to create heap snapshot
      const snapshotPath = v8.writeHeapSnapshot();
      
      if (snapshotPath && fs.existsSync(snapshotPath)) {
        // Cleanup
        try { fs.unlinkSync(snapshotPath); } catch (e) {}
        
        return {
          blocked: false,
          details: 'Heap snapshot created (could contain secrets)',
          recommendation: 'Block v8.writeHeapSnapshot() or monitor snapshot creation'
        };
      }
      
      return {
        blocked: true,
        details: 'Heap snapshot blocked'
      };
    } catch (e) {
      return {
        blocked: true,
        details: `Blocked: ${e.message}`
      };
    }
  });
}

// ==========================================
// BYPASS 9: Inspector Protocol
// ==========================================

async function testInspectorBypass() {
  return runTest('INSPECTOR_PROTOCOL', 'Use V8 inspector for code execution', async () => {
    try {
      const inspector = require('inspector');
      
      // Check if inspector can be opened
      if (inspector.url()) {
        return {
          blocked: false,
          details: 'Inspector is already open (security risk)',
          recommendation: 'Block --inspect flag, monitor inspector.open()'
        };
      }
      
      // Try to open inspector
      inspector.open();
      const url = inspector.url();
      inspector.close();
      
      if (url) {
        return {
          blocked: false,
          details: 'Inspector can be opened (bypass possible)',
          recommendation: 'Block inspector.open() during npm install'
        };
      }
      
      return {
        blocked: true,
        details: 'Inspector blocked'
      };
    } catch (e) {
      return {
        blocked: true,
        details: `Blocked: ${e.message}`
      };
    }
  });
}

// ==========================================
// BYPASS 10: Memory Buffer Manipulation
// ==========================================

async function testBufferBypass() {
  return runTest('BUFFER_MEMORY_ACCESS', 'Direct memory access via Buffer', async () => {
    try {
      // Try to access process memory directly
      // This is more theoretical - checking if unsafe operations are allowed
      
      if (typeof SharedArrayBuffer !== 'undefined') {
        const sab = new SharedArrayBuffer(1024);
        
        return {
          blocked: false,
          details: 'SharedArrayBuffer available (potential bypass channel)',
          recommendation: 'Monitor SharedArrayBuffer in worker communication'
        };
      }
      
      return {
        blocked: true,
        details: 'SharedArrayBuffer not available'
      };
    } catch (e) {
      return {
        blocked: true,
        details: `Blocked: ${e.message}`
      };
    }
  });
}

// ==========================================
// RUN ALL TESTS
// ==========================================

async function runAllTests() {
  console.log('Starting bypass attack tests...\n');
  console.log('⏳ Waiting for firewall startup phase to complete...\n');
  
  // Wait 200ms to ensure fortress mode startup phase is complete
  await new Promise(resolve => setTimeout(resolve, 200));
  
  console.log('\n╔╗');
  console.log('       JAVASCRIPT RUNTIME BYPASSES                          ');
  console.log('╚╝');
  
  await testRequireCacheBypass();
  await testPrototypePollution();
  await testWorkerThreadBypass();
  await testVMEscape();
  await testProcessBinding();
  
  console.log('\n\n╔╗');
  console.log('         NATIVE & PROCESS BYPASSES                          ');
  console.log('╚╝');
  
  await testNativeAddon();
  await testChildProcessEnvBypass();
  
  console.log('\n\n╔╗');
  console.log('         V8 & MEMORY BYPASSES                               ');
  console.log('╚╝');
  
  await testHeapSnapshot();
  await testInspectorBypass();
  await testBufferBypass();
  
  // Generate summary
  generateSummary();
}

function generateSummary() {
  console.log('\n\n');
  console.log(''.repeat(64));
  console.log('           BYPASS TESTS - FINAL SUMMARY');
  console.log(''.repeat(64));
  console.log('');
  
  const { total, blocked, succeeded } = results.stats;
  const rate = Math.round((blocked / total) * 100);
  
  console.log(`Total Bypass Attempts:  ${total}`);
  console.log(`Blocked:                ${blocked} `);
  console.log(`Bypassed:               ${succeeded} `);
  console.log(`Protection Rate:        ${rate}%`);
  console.log('');
  
  // Grade
  let grade;
  if (rate === 100) grade = 'A+ - PERFECT';
  else if (rate >= 90) grade = 'A - EXCELLENT';
  else if (rate >= 75) grade = 'B - GOOD';
  else if (rate >= 60) grade = 'C - MODERATE';
  else grade = 'D - VULNERABLE';
  
  console.log(`Grade:                  ${grade}`);
  console.log('');
  
  // Critical failures
  const bypasses = results.bypasses.filter(t => !t.blocked);
  
  if (bypasses.length === 0) {
    console.log(' ALL BYPASS ATTEMPTS BLOCKED! Fortress-level security!');
  } else {
    console.log(''.repeat(64));
    console.log('   CRITICAL: SUCCESSFUL BYPASSES (MUST FIX!)');
    console.log(''.repeat(64));
    console.log('');
    
    bypasses.forEach((bypass, idx) => {
      console.log(`${idx + 1}. ${bypass.test}`);
      console.log(`   Attack: ${bypass.description}`);
      console.log(`   Status: ${bypass.details}`);
      if (bypass.recommendation) {
        console.log(`   🔧 Fix: ${bypass.recommendation}`);
      }
      console.log('');
    });
  }
  
  // Save report
  try {
    fs.writeFileSync('bypass-attack-report.json', JSON.stringify(results, null, 2));
    console.log('📄 Detailed report saved to: bypass-attack-report.json\n');
  } catch (e) {
    console.error('Failed to save report:', e.message);
  }
  
  console.log(''.repeat(64));
  console.log('            BYPASS TEST COMPLETE');
  console.log(''.repeat(64));
  console.log('');
  
  // Exit with appropriate code
  process.exit(bypasses.length > 0 ? 1 : 0);
}

// Run tests
runAllTests().catch(console.error);
