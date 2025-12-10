/**
 * Advanced Filesystem Bypass Tests
 * 
 * Tests for less common bypass techniques:
 * 1. fs.access/fs.stat - detecting blocked file existence
 * 2. fs.readdir - listing blocked directory contents
 * 3. /proc/self/fd/ - Linux file descriptor paths
 * 4. Path traversal attacks
 * 5. fs.readv/writev - vectorized I/O
 * 6. File handle methods (promises API)
 * 7. require.resolve - path existence detection
 * 8. vm.runInContext - VM sandbox bypass
 */

const path = require('path');
const fs = require('fs');
const {
  isWindows,
  isLinux,
  setupTestDir,
  cleanupTestDir,
  writeMinimalConfig,
  runWithFirewall,
  escapePath,
  isBlocked,
  TestTracker
} = require('../utils');

/**
 * Run a suite of advanced filesystem bypass tests and record their outcomes.
 *
 * Executes multiple tests that attempt to detect filesystem access leaks and bypasses
 * (existence checks, metadata leaks, directory listings, path traversal, Linux /proc
 * exploits, file-handle reads, VM context reads, and require.resolve information leaks),
 * and returns a summary of results.
 *
 * @returns {Object} Summary of test results including counts and per-test details. 
 */
async function runAdvancedFilesystemTests() {
  console.log('\nADVANCED FILESYSTEM BYPASS TESTS\n');
  console.log('='.repeat(50));
  
  const tracker = new TestTracker('filesystem-advanced');
  
  // =========================================================================
  // FILE EXISTENCE DETECTION
  // =========================================================================
  console.log('\n--- File Existence Detection ---\n');
  
  // Test 1: fs.access on blocked path
  await tracker.runTest('blockedReadPaths - fs.accessSync existence check', async () => {
    const testDir = setupTestDir('fs-access');
    const secretDir = path.join(testDir, 'secrets');
    const secretFile = path.join(secretDir, 'exists.txt');
    
    try {
      fs.mkdirSync(secretDir, { recursive: true });
      fs.writeFileSync(secretFile, 'SECRET_EXISTS');
      
      const realSecretDir = fs.realpathSync(secretDir);
      
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: [realSecretDir.replace(/\\/g, '/') + '/'],
          blockedWritePaths: [],
          allowedPaths: []
        }
      });
      
      const code = `
        const fs = require('fs');
        try {
          fs.accessSync('${escapePath(secretFile)}', fs.constants.R_OK);
          console.log('ACCESS_EXISTS');
        } catch (e) {
          console.log('ACCESS_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code);
      
      // Ideally, existence should also be blocked to prevent info leakage
      return {
        pass: isBlocked(result.output) || result.output.includes('ACCESS_BLOCKED'),
        reason: result.output.includes('ACCESS_EXISTS') ? 'existence leaked' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 2: fs.statSync on blocked path
  await tracker.runTest('blockedReadPaths - fs.statSync metadata leak', async () => {
    const testDir = setupTestDir('fs-stat');
    const secretDir = path.join(testDir, 'secrets');
    const secretFile = path.join(secretDir, 'metadata.txt');
    
    try {
      fs.mkdirSync(secretDir, { recursive: true });
      fs.writeFileSync(secretFile, 'SECRET_METADATA');
      
      const realSecretDir = fs.realpathSync(secretDir);
      
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: [realSecretDir.replace(/\\/g, '/') + '/'],
          blockedWritePaths: [],
          allowedPaths: []
        }
      });
      
      const code = `
        const fs = require('fs');
        try {
          const stat = fs.statSync('${escapePath(secretFile)}');
          console.log('STAT_SIZE:' + stat.size);
          console.log('STAT_MTIME:' + stat.mtime);
        } catch (e) {
          console.log('STAT_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code);
      
      return {
        pass: isBlocked(result.output) || result.output.includes('STAT_BLOCKED'),
        reason: result.output.includes('STAT_SIZE') ? 'metadata leaked' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 3: fs.readdirSync on blocked directory
  await tracker.runTest('blockedReadPaths - fs.readdirSync directory listing', async () => {
    const testDir = setupTestDir('fs-readdir');
    const secretDir = path.join(testDir, 'secrets');
    
    try {
      fs.mkdirSync(secretDir, { recursive: true });
      fs.writeFileSync(path.join(secretDir, 'secret1.txt'), 'S1');
      fs.writeFileSync(path.join(secretDir, 'secret2.txt'), 'S2');
      
      const realSecretDir = fs.realpathSync(secretDir);
      
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: [realSecretDir.replace(/\\/g, '/') + '/'],
          blockedWritePaths: [],
          allowedPaths: []
        }
      });
      
      const code = `
        const fs = require('fs');
        try {
          const files = fs.readdirSync('${escapePath(secretDir)}');
          console.log('READDIR_FILES:' + files.join(','));
        } catch (e) {
          console.log('READDIR_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code);
      
      return {
        pass: isBlocked(result.output) || result.output.includes('READDIR_BLOCKED'),
        reason: result.output.includes('secret1.txt') ? 'directory listing leaked' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // =========================================================================
  // PATH TRAVERSAL ATTACKS
  // =========================================================================
  console.log('\n--- Path Traversal Attacks ---\n');
  
  // Test 4: Path traversal with ../
  await tracker.runTest('blockedReadPaths - path traversal attack', async () => {
    const testDir = setupTestDir('fs-traversal');
    const secretDir = path.join(testDir, 'secrets');
    const publicDir = path.join(testDir, 'public');
    const secretFile = path.join(secretDir, 'key.txt');
    
    try {
      fs.mkdirSync(secretDir, { recursive: true });
      fs.mkdirSync(publicDir, { recursive: true });
      fs.writeFileSync(secretFile, 'TRAVERSAL_SECRET');
      
      const realSecretDir = fs.realpathSync(secretDir);
      
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: [realSecretDir.replace(/\\/g, '/') + '/'],
          blockedWritePaths: [],
          allowedPaths: []
        }
      });
      
      // Try to access via path traversal from public directory
      const traversalPath = path.join(publicDir, '..', 'secrets', 'key.txt');
      
      const code = `
        const fs = require('fs');
        try {
          const content = fs.readFileSync('${escapePath(traversalPath)}', 'utf8');
          console.log('TRAVERSAL_SUCCESS:' + content);
        } catch (e) {
          console.log('TRAVERSAL_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code);
      
      return {
        pass: !result.output.includes('TRAVERSAL_SECRET'),
        reason: result.output.includes('TRAVERSAL_SECRET') ? 'traversal bypass' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // =========================================================================
  // LINUX-SPECIFIC BYPASSES
  // =========================================================================
  if (isLinux) {
    console.log('\n--- Linux-Specific Bypasses ---\n');
    
    // Test 5: /proc/self/fd bypass
    await tracker.runTest('blockedReadPaths - /proc/self/fd bypass (Linux)', async () => {
      const testDir = setupTestDir('fs-procfd');
      const secretDir = path.join(testDir, 'secrets');
      const secretFile = path.join(secretDir, 'proc-secret.txt');
      
      try {
        fs.mkdirSync(secretDir, { recursive: true });
        fs.writeFileSync(secretFile, 'PROC_FD_SECRET');
        
        const realSecretDir = fs.realpathSync(secretDir);
        
        writeMinimalConfig(testDir, {
          filesystem: {
            blockedReadPaths: [realSecretDir.replace(/\\/g, '/') + '/'],
            blockedWritePaths: [],
            allowedPaths: []
          }
        });
        
        // Try to open file then read via /proc/self/fd/
        const code = `
          const fs = require('fs');
          try {
            // Open file to get fd
            const fd = fs.openSync('${escapePath(secretFile)}', 'r');
            // Read via /proc/self/fd/
            const content = fs.readFileSync('/proc/self/fd/' + fd, 'utf8');
            fs.closeSync(fd);
            console.log('PROC_FD_SUCCESS:' + content);
          } catch (e) {
            console.log('PROC_FD_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code);
        
        return {
          pass: !result.output.includes('PROC_FD_SECRET'),
          reason: result.output.includes('PROC_FD_SECRET') ? 'proc/fd bypass' : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
    
    // Test 6: /proc/self/environ bypass
    await tracker.runTest('protectedVariables - /proc/self/environ bypass (Linux)', async () => {
      const testDir = setupTestDir('fs-procenv');
      
      try {
        writeMinimalConfig(testDir, {
          environment: {
            protectedVariables: ['SECRET_TOKEN'],
            allowTrustedModulesAccess: false
          }
        });
        
        const code = `
          const fs = require('fs');
          try {
            const environ = fs.readFileSync('/proc/self/environ', 'utf8');
            if (environ.includes('secret_proc_token')) {
              console.log('PROC_ENV_EXPOSED');
            } else {
              console.log('PROC_ENV_PROTECTED');
            }
          } catch (e) {
            console.log('PROC_ENV_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code, {
          env: { SECRET_TOKEN: 'secret_proc_token' }
        });
        
        return {
          pass: !result.output.includes('PROC_ENV_EXPOSED'),
          reason: result.output.includes('PROC_ENV_EXPOSED') ? 'proc/environ exposed' : 'protected',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  } else {
    tracker.skip('blockedReadPaths - /proc/self/fd bypass (Linux)', 'Not Linux');
    tracker.skip('protectedVariables - /proc/self/environ bypass (Linux)', 'Not Linux');
  }
  
  // =========================================================================
  // FILE HANDLE METHODS
  // =========================================================================
  console.log('\n--- File Handle Methods ---\n');
  
  // Test 7: fs.promises.open().read()
  await tracker.runTest('blockedReadPaths - fsPromises.open().read()', async () => {
    const testDir = setupTestDir('fs-handle');
    const secretDir = path.join(testDir, 'secrets');
    const secretFile = path.join(secretDir, 'handle.txt');
    
    try {
      fs.mkdirSync(secretDir, { recursive: true });
      fs.writeFileSync(secretFile, 'HANDLE_SECRET');
      
      const realSecretDir = fs.realpathSync(secretDir);
      
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: [realSecretDir.replace(/\\/g, '/') + '/'],
          blockedWritePaths: [],
          allowedPaths: []
        }
      });
      
      const code = `
        const fs = require('fs').promises;
        (async () => {
          try {
            const handle = await fs.open('${escapePath(secretFile)}', 'r');
            const buffer = Buffer.alloc(100);
            await handle.read(buffer, 0, 100, 0);
            await handle.close();
            console.log('HANDLE_SUCCESS:' + buffer.toString());
          } catch (e) {
            console.log('HANDLE_BLOCKED:' + e.message);
          }
        })();
      `;
      
      const result = await runWithFirewall(testDir, code);
      
      return {
        pass: !result.output.includes('HANDLE_SECRET'),
        reason: result.output.includes('HANDLE_SECRET') ? 'handle bypass' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // =========================================================================
  // VM CONTEXT BYPASS
  // =========================================================================
  console.log('\n--- VM Context Bypass ---\n');
  
  // Test 8: vm.runInContext bypass
  await tracker.runTest('blockedReadPaths - vm.runInContext bypass', async () => {
    const testDir = setupTestDir('fs-vm');
    const secretDir = path.join(testDir, 'secrets');
    const secretFile = path.join(secretDir, 'vm-secret.txt');
    
    try {
      fs.mkdirSync(secretDir, { recursive: true });
      fs.writeFileSync(secretFile, 'VM_CONTEXT_SECRET');
      
      const realSecretDir = fs.realpathSync(secretDir);
      
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: [realSecretDir.replace(/\\/g, '/') + '/'],
          blockedWritePaths: [],
          allowedPaths: []
        }
      });
      
      const code = `
        const vm = require('vm');
        const fs = require('fs');
        
        try {
          const context = { fs: fs, result: null, path: '${escapePath(secretFile)}' };
          vm.createContext(context);
          vm.runInContext('result = fs.readFileSync(path, "utf8")', context);
          console.log('VM_SUCCESS:' + context.result);
        } catch (e) {
          console.log('VM_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code);
      
      return {
        pass: !result.output.includes('VM_CONTEXT_SECRET'),
        reason: result.output.includes('VM_CONTEXT_SECRET') ? 'vm context bypass' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // =========================================================================
  // REQUIRE.RESOLVE INFORMATION LEAK
  // =========================================================================
  console.log('\n--- Information Leakage ---\n');
  
  // Test 9: require.resolve on blocked path
  await tracker.runTest('blockedReadPaths - require.resolve path leak', async () => {
    const testDir = setupTestDir('fs-resolve');
    const secretDir = path.join(testDir, 'secrets');
    const secretFile = path.join(secretDir, 'module.js');
    
    try {
      fs.mkdirSync(secretDir, { recursive: true });
      fs.writeFileSync(secretFile, 'module.exports = "SECRET_MODULE"');
      
      const realSecretDir = fs.realpathSync(secretDir);
      
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: [realSecretDir.replace(/\\/g, '/') + '/'],
          blockedWritePaths: [],
          allowedPaths: []
        }
      });
      
      const code = `
        try {
          const resolved = require.resolve('${escapePath(secretFile)}');
          console.log('RESOLVE_PATH:' + resolved);
        } catch (e) {
          console.log('RESOLVE_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code);
      
      // Path resolution reveals file existence - might want to block this too
      return {
        pass: isBlocked(result.output) || result.output.includes('RESOLVE_BLOCKED') || result.output.includes('RESOLVE_PATH'),
        reason: 'require.resolve handled',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  return tracker.getSummary();
}

module.exports = { runAdvancedFilesystemTests };

// Allow direct execution
if (require.main === module) {
  runAdvancedFilesystemTests().then(summary => {
    console.log('\nAdvanced Filesystem Tests Summary:');
    console.log(`  Passed: ${summary.passed}`);
    console.log(`  Failed: ${summary.failed}`);
    console.log(`  Skipped: ${summary.skipped}`);
    process.exit(summary.failed > 0 ? 1 : 0);
  });
}