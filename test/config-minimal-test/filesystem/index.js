/**
 * Filesystem Protection Tests
 * 
 * Tests multiple bypass techniques for filesystem access:
 * 1. Direct fs module access
 * 2. Child process with shell commands (cat, type, echo)
 * 3. execSync/spawn with piped commands
 * 4. Script execution (.sh, .py files)
 * 5. Pipe bypass attempts (cmd1 | cmd2)
 * 6. File descriptor methods (fs.open, fs.read)
 */

const path = require('path');
const fs = require('fs');
const {
  isWindows,
  setupTestDir,
  cleanupTestDir,
  writeMinimalConfig,
  writeTestScript,
  runWithFirewall,
  runWithoutFirewall,
  escapePath,
  isBlocked,
  TestTracker,
  getCatCommand,
  getEchoToFileCommand
} = require('../utils');

async function runFilesystemTests() {
  console.log('\nFILESYSTEM PROTECTION TESTS\n');
  console.log('=' .repeat(50));
  
  const tracker = new TestTracker('filesystem');
  
  // =========================================================================
  // BLOCKED READ PATHS TESTS
  // =========================================================================
  console.log('\n--- Blocked Read Paths ---\n');
  
  // Test 1: Direct fs.readFileSync
  await tracker.runTest('blockedReadPaths - fs.readFileSync', async () => {
    const testDir = setupTestDir('fs-read-direct');
    const secretDir = path.join(testDir, 'secrets');
    const secretFile = path.join(secretDir, 'api-key.txt');
    
    try {
      fs.mkdirSync(secretDir, { recursive: true });
      fs.writeFileSync(secretFile, 'SECRET_API_KEY=sk_live_abc123');
      
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: [secretDir.replace(/\\/g, '/') + '/'],
          blockedWritePaths: [],
          allowedPaths: []
        }
      });
      
      const code = `
        const fs = require('fs');
        try {
          const content = fs.readFileSync('${escapePath(secretFile)}', 'utf8');
          console.log('READ_SUCCESS:' + content);
        } catch (e) {
          console.log('READ_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code);
      
      return {
        pass: !result.output.includes('sk_live_abc123') && (isBlocked(result.output) || result.output.includes('READ_BLOCKED')),
        reason: isBlocked(result.output) ? 'blocked' : 'secret exposed',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 2: fs.promises.readFile (async API)
  await tracker.runTest('blockedReadPaths - fs.promises.readFile', async () => {
    const testDir = setupTestDir('fs-read-promises');
    const secretDir = path.join(testDir, 'secrets');
    const secretFile = path.join(secretDir, 'token.txt');
    
    try {
      fs.mkdirSync(secretDir, { recursive: true });
      fs.writeFileSync(secretFile, 'GITHUB_TOKEN=ghp_secret789');
      
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: [secretDir.replace(/\\/g, '/') + '/'],
          blockedWritePaths: [],
          allowedPaths: []
        }
      });
      
      const code = `
        const fs = require('fs').promises;
        (async () => {
          try {
            const content = await fs.readFile('${escapePath(secretFile)}', 'utf8');
            console.log('READ_SUCCESS:' + content);
          } catch (e) {
            console.log('READ_BLOCKED:' + e.message);
          }
        })();
      `;
      
      const result = await runWithFirewall(testDir, code);
      
      return {
        pass: !result.output.includes('ghp_secret789') && (isBlocked(result.output) || result.output.includes('READ_BLOCKED')),
        reason: isBlocked(result.output) ? 'blocked' : 'secret exposed',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 3: Child process - cat/type command
  await tracker.runTest('blockedReadPaths - child_process cat/type', async () => {
    const testDir = setupTestDir('fs-read-child');
    const secretDir = path.join(testDir, 'secrets');
    const secretFile = path.join(secretDir, 'password.txt');
    
    try {
      fs.mkdirSync(secretDir, { recursive: true });
      fs.writeFileSync(secretFile, 'DB_PASSWORD=super_secret_pass');
      
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: [secretDir.replace(/\\/g, '/') + '/'],
          blockedWritePaths: [],
          allowedPaths: []
        }
      });
      
      const catCmd = getCatCommand(secretFile);
      const code = `
        const { execSync } = require('child_process');
        try {
          const content = execSync('${catCmd.replace(/'/g, "\\'")}').toString();
          console.log('READ_SUCCESS:' + content);
        } catch (e) {
          console.log('READ_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code);
      
      return {
        pass: !result.output.includes('super_secret_pass') && (isBlocked(result.output) || result.output.includes('READ_BLOCKED')),
        reason: isBlocked(result.output) ? 'blocked' : 'secret exposed via shell',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 4: Pipe bypass attempt - cat file | grep pattern
  if (!isWindows) {
    await tracker.runTest('blockedReadPaths - pipe bypass (cat | grep)', async () => {
      const testDir = setupTestDir('fs-read-pipe');
      const secretDir = path.join(testDir, 'secrets');
      const secretFile = path.join(secretDir, 'creds.txt');
      
      try {
        fs.mkdirSync(secretDir, { recursive: true });
        fs.writeFileSync(secretFile, 'AWS_KEY=AKIAIOSFODNN7EXAMPLE');
        
        writeMinimalConfig(testDir, {
          filesystem: {
            blockedReadPaths: [secretDir.replace(/\\/g, '/') + '/'],
            blockedWritePaths: [],
            allowedPaths: []
          }
        });
        
        const code = `
          const { execSync } = require('child_process');
          try {
            const content = execSync('cat "${secretFile}" | grep AWS').toString();
            console.log('READ_SUCCESS:' + content);
          } catch (e) {
            console.log('READ_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code);
        
        return {
          pass: !result.output.includes('AKIAIOSFODNN7EXAMPLE') && (isBlocked(result.output) || result.output.includes('READ_BLOCKED')),
          reason: isBlocked(result.output) ? 'blocked' : 'pipe bypass worked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  } else {
    tracker.skip('blockedReadPaths - pipe bypass (cat | grep)', 'Windows');
  }
  
  // Test 5: fs.open + fs.read (file descriptor bypass)
  await tracker.runTest('blockedReadPaths - fs.openSync + fs.readSync', async () => {
    const testDir = setupTestDir('fs-read-fd');
    const secretDir = path.join(testDir, 'secrets');
    const secretFile = path.join(secretDir, 'private.key');
    
    try {
      fs.mkdirSync(secretDir, { recursive: true });
      fs.writeFileSync(secretFile, '-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBg...');
      
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: [secretDir.replace(/\\/g, '/') + '/'],
          blockedWritePaths: [],
          allowedPaths: []
        }
      });
      
      const code = `
        const fs = require('fs');
        try {
          const fd = fs.openSync('${escapePath(secretFile)}', 'r');
          const buffer = Buffer.alloc(100);
          fs.readSync(fd, buffer, 0, 100, 0);
          fs.closeSync(fd);
          console.log('READ_SUCCESS:' + buffer.toString());
        } catch (e) {
          console.log('READ_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code);
      
      return {
        pass: !result.output.includes('BEGIN PRIVATE KEY') && (isBlocked(result.output) || result.output.includes('READ_BLOCKED')),
        reason: isBlocked(result.output) ? 'blocked' : 'fd bypass worked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 6: Script execution (.sh file reading another file)
  // SECURITY FIX: The firewall now inspects script content before execution
  // and blocks scripts that contain references to blocked paths.
  // This test verifies the script content inspection feature works.
  if (!isWindows) {
    await tracker.runTest('blockedReadPaths - .sh script content inspection', async () => {
      const testDir = setupTestDir('fs-read-script');
      const secretDir = path.join(testDir, 'secrets');
      const secretFile = path.join(secretDir, 'env.txt');
      
      try {
        fs.mkdirSync(secretDir, { recursive: true });
        fs.writeFileSync(secretFile, 'NPM_TOKEN=npm_secret123');
        
        // Create a shell script that reads the file
        // The firewall should inspect this script and see it references the blocked path
        const scriptPath = writeTestScript(testDir, 'reader.sh', `#!/bin/bash\ncat "${secretFile}"`);
        
        // NOTE: We're NOT using blockedExtensions here - this tests the script content inspection
        writeMinimalConfig(testDir, {
          filesystem: {
            blockedReadPaths: [secretDir.replace(/\\/g, '/') + '/'],
            blockedWritePaths: [],
            allowedPaths: []
            // NO blockedExtensions - testing content inspection only
          }
        });
        
        const code = `
          const { execSync } = require('child_process');
          try {
            const content = execSync('${scriptPath}').toString();
            console.log('READ_SUCCESS:' + content);
          } catch (e) {
            console.log('READ_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code);
        
        // Script should be blocked because its content references the blocked path
        return {
          pass: !result.output.includes('npm_secret123') && 
                (isBlocked(result.output) || result.output.includes('READ_BLOCKED')),
          reason: result.output.includes('npm_secret123') ? 'script bypass worked' : 'script content blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  } else {
    tracker.skip('blockedReadPaths - .sh script content inspection', 'Windows');
  }
  
  // =========================================================================
  // BLOCKED WRITE PATHS TESTS
  // =========================================================================
  console.log('\n--- Blocked Write Paths ---\n');
  
  // Test 7: Direct fs.writeFileSync
  await tracker.runTest('blockedWritePaths - fs.writeFileSync', async () => {
    const testDir = setupTestDir('fs-write-direct');
    const protectedDir = path.join(testDir, 'system');
    
    try {
      fs.mkdirSync(protectedDir, { recursive: true });
      
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: [],
          blockedWritePaths: [protectedDir.replace(/\\/g, '/') + '/'],
          allowedPaths: []
        }
      });
      
      const targetFile = path.join(protectedDir, 'malware.txt');
      const code = `
        const fs = require('fs');
        try {
          fs.writeFileSync('${escapePath(targetFile)}', 'MALICIOUS_PAYLOAD');
          console.log('WRITE_SUCCESS');
        } catch (e) {
          console.log('WRITE_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code);
      const fileExists = fs.existsSync(targetFile);
      
      return {
        pass: !fileExists && (isBlocked(result.output) || result.output.includes('WRITE_BLOCKED')),
        reason: fileExists ? 'file was created' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 8: Child process - echo > file
  await tracker.runTest('blockedWritePaths - child_process echo redirect', async () => {
    const testDir = setupTestDir('fs-write-child');
    const protectedDir = path.join(testDir, 'system');
    
    try {
      fs.mkdirSync(protectedDir, { recursive: true });
      
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: [],
          blockedWritePaths: [protectedDir.replace(/\\/g, '/') + '/'],
          allowedPaths: []
        }
      });
      
      const targetFile = path.join(protectedDir, 'hacked.txt');
      const echoCmd = getEchoToFileCommand('HACKED', targetFile);
      
      const code = `
        const { execSync } = require('child_process');
        try {
          execSync('${echoCmd.replace(/'/g, "\\'")}');
          console.log('WRITE_SUCCESS');
        } catch (e) {
          console.log('WRITE_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code);
      const fileExists = fs.existsSync(targetFile);
      
      return {
        pass: !fileExists || isBlocked(result.output) || result.output.includes('WRITE_BLOCKED'),
        reason: fileExists ? 'file was created via shell' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 9: Pipe write attempt - echo data | tee file
  if (!isWindows) {
    await tracker.runTest('blockedWritePaths - pipe bypass (echo | tee)', async () => {
      const testDir = setupTestDir('fs-write-pipe');
      const protectedDir = path.join(testDir, 'system');
      
      try {
        fs.mkdirSync(protectedDir, { recursive: true });
        
        writeMinimalConfig(testDir, {
          filesystem: {
            blockedReadPaths: [],
            blockedWritePaths: [protectedDir.replace(/\\/g, '/') + '/'],
            allowedPaths: []
          }
        });
        
        const targetFile = path.join(protectedDir, 'tee-attack.txt');
        const code = `
          const { execSync } = require('child_process');
          try {
            execSync('echo MALICIOUS | tee "${targetFile}"');
            console.log('WRITE_SUCCESS');
          } catch (e) {
            console.log('WRITE_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code);
        const fileExists = fs.existsSync(targetFile);
        
        return {
          pass: !fileExists || isBlocked(result.output) || result.output.includes('WRITE_BLOCKED'),
          reason: fileExists ? 'tee bypass worked' : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  } else {
    tracker.skip('blockedWritePaths - pipe bypass (echo | tee)', 'Windows');
  }
  
  // Test 10: fs.appendFileSync
  await tracker.runTest('blockedWritePaths - fs.appendFileSync', async () => {
    const testDir = setupTestDir('fs-write-append');
    const protectedDir = path.join(testDir, 'system');
    
    try {
      fs.mkdirSync(protectedDir, { recursive: true });
      const targetFile = path.join(protectedDir, 'log.txt');
      fs.writeFileSync(targetFile, 'Original content\n');
      
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: [],
          blockedWritePaths: [protectedDir.replace(/\\/g, '/') + '/'],
          allowedPaths: []
        }
      });
      
      const code = `
        const fs = require('fs');
        try {
          fs.appendFileSync('${escapePath(targetFile)}', 'APPENDED_MALWARE');
          console.log('WRITE_SUCCESS');
        } catch (e) {
          console.log('WRITE_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code);
      const content = fs.readFileSync(targetFile, 'utf8');
      const wasAppended = content.includes('APPENDED_MALWARE');
      
      return {
        pass: !wasAppended || isBlocked(result.output) || result.output.includes('WRITE_BLOCKED'),
        reason: wasAppended ? 'append succeeded' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 11: fs.createWriteStream
  await tracker.runTest('blockedWritePaths - fs.createWriteStream', async () => {
    const testDir = setupTestDir('fs-write-stream');
    const protectedDir = path.join(testDir, 'system');
    
    try {
      fs.mkdirSync(protectedDir, { recursive: true });
      
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: [],
          blockedWritePaths: [protectedDir.replace(/\\/g, '/') + '/'],
          allowedPaths: []
        }
      });
      
      const targetFile = path.join(protectedDir, 'stream.txt');
      const code = `
        const fs = require('fs');
        try {
          const stream = fs.createWriteStream('${escapePath(targetFile)}');
          stream.write('STREAMED_MALWARE');
          stream.end();
          console.log('WRITE_SUCCESS');
        } catch (e) {
          console.log('WRITE_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code);
      // Give stream time to write
      await new Promise(r => setTimeout(r, 100));
      const fileExists = fs.existsSync(targetFile);
      
      return {
        pass: !fileExists || isBlocked(result.output) || result.output.includes('WRITE_BLOCKED'),
        reason: fileExists ? 'stream bypass worked' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 12: cp/copy command bypass
  if (!isWindows) {
    await tracker.runTest('blockedWritePaths - cp command bypass', async () => {
      const testDir = setupTestDir('fs-write-cp');
      const protectedDir = path.join(testDir, 'system');
      const sourceFile = path.join(testDir, 'source.txt');
      
      try {
        fs.mkdirSync(protectedDir, { recursive: true });
        fs.writeFileSync(sourceFile, 'MALICIOUS_CONTENT');
        
        writeMinimalConfig(testDir, {
          filesystem: {
            blockedReadPaths: [],
            blockedWritePaths: [protectedDir.replace(/\\/g, '/') + '/'],
            allowedPaths: []
          }
        });
        
        const targetFile = path.join(protectedDir, 'copied.txt');
        const code = `
          const { execSync } = require('child_process');
          try {
            execSync('cp "${sourceFile}" "${targetFile}"');
            console.log('WRITE_SUCCESS');
          } catch (e) {
            console.log('WRITE_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code);
        const fileExists = fs.existsSync(targetFile);
        
        return {
          pass: !fileExists || isBlocked(result.output) || result.output.includes('WRITE_BLOCKED'),
          reason: fileExists ? 'cp bypass worked' : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  } else {
    tracker.skip('blockedWritePaths - cp command bypass', 'Windows');
  }
  
  // Test 12.5: fs.copyFileSync bypass attempt
  await tracker.runTest('blockedWritePaths - fs.copyFileSync', async () => {
    const testDir = setupTestDir('fs-write-copyfile');
    const protectedDir = path.join(testDir, 'system');
    const sourceFile = path.join(testDir, 'source.txt');
    
    try {
      fs.mkdirSync(protectedDir, { recursive: true });
      fs.writeFileSync(sourceFile, 'MALICIOUS_PAYLOAD');
      
      // Get real paths for proper blocking on Linux (handles /tmp -> /private/tmp on macOS)
      const realProtectedDir = fs.realpathSync(protectedDir);
      
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: [],
          blockedWritePaths: [realProtectedDir.replace(/\\/g, '/') + '/'],
          allowedPaths: []
        }
      });
      
      const targetFile = path.join(protectedDir, 'copied.txt');
      // Use real path for the target file in the test code to match the blocked path
      const realTargetFile = path.join(realProtectedDir, 'copied.txt');
      const code = `
        const fs = require('fs');
        try {
          fs.copyFileSync('${escapePath(sourceFile)}', '${escapePath(realTargetFile)}');
          console.log('COPY_SUCCESS');
        } catch (e) {
          console.log('COPY_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code);
      // Check both paths since realpath may differ
      const fileExists = fs.existsSync(targetFile) || fs.existsSync(realTargetFile);
      
      return {
        pass: !fileExists || isBlocked(result.output) || result.output.includes('COPY_BLOCKED'),
        reason: fileExists ? 'copyFileSync bypass worked' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 12.6: fs.rename bypass attempt (move to protected path)
  await tracker.runTest('blockedWritePaths - fs.renameSync', async () => {
    const testDir = setupTestDir('fs-write-rename');
    const protectedDir = path.join(testDir, 'system');
    const sourceFile = path.join(testDir, 'source.txt');
    
    try {
      fs.mkdirSync(protectedDir, { recursive: true });
      fs.writeFileSync(sourceFile, 'PAYLOAD_DATA');
      
      // Get real paths for proper blocking on Linux
      const realProtectedDir = fs.realpathSync(protectedDir);
      
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: [],
          blockedWritePaths: [realProtectedDir.replace(/\\/g, '/') + '/'],
          allowedPaths: []
        }
      });
      
      const targetFile = path.join(protectedDir, 'moved.txt');
      // Use real path for the target file in the test code to match the blocked path
      const realTargetFile = path.join(realProtectedDir, 'moved.txt');
      const code = `
        const fs = require('fs');
        try {
          fs.renameSync('${escapePath(sourceFile)}', '${escapePath(realTargetFile)}');
          console.log('RENAME_SUCCESS');
        } catch (e) {
          console.log('RENAME_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code);
      // Check both paths since realpath may differ
      const fileExists = fs.existsSync(targetFile) || fs.existsSync(realTargetFile);
      
      return {
        pass: !fileExists || isBlocked(result.output) || result.output.includes('RENAME_BLOCKED'),
        reason: fileExists ? 'renameSync bypass worked' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 12.7: symlink bypass attempt
  if (!isWindows) {
    await tracker.runTest('blockedReadPaths - symlink bypass attempt', async () => {
      const testDir = setupTestDir('fs-symlink');
      const secretDir = path.join(testDir, 'secrets');
      const secretFile = path.join(secretDir, 'password.txt');
      
      try {
        fs.mkdirSync(secretDir, { recursive: true });
        fs.writeFileSync(secretFile, 'SUPER_SECRET_PASS');
        
        writeMinimalConfig(testDir, {
          filesystem: {
            blockedReadPaths: [secretDir.replace(/\\/g, '/') + '/'],
            blockedWritePaths: [],
            allowedPaths: []
          }
        });
        
        const symlinkPath = path.join(testDir, 'link-to-secret');
        const code = `
          const fs = require('fs');
          try {
            // Create symlink to blocked directory
            fs.symlinkSync('${escapePath(secretFile)}', '${escapePath(symlinkPath)}');
            // Try to read via symlink
            const content = fs.readFileSync('${escapePath(symlinkPath)}', 'utf8');
            console.log('SYMLINK_BYPASS:' + content);
          } catch (e) {
            console.log('SYMLINK_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code);
        
        return {
          pass: !result.output.includes('SUPER_SECRET_PASS'),
          reason: result.output.includes('SUPER_SECRET_PASS') ? 'symlink bypass worked' : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  } else {
    tracker.skip('blockedReadPaths - symlink bypass attempt', 'Windows');
  }
  
  // Test 12.8: fs.createReadStream bypass
  await tracker.runTest('blockedReadPaths - fs.createReadStream', async () => {
    const testDir = setupTestDir('fs-read-stream');
    const secretDir = path.join(testDir, 'secrets');
    const secretFile = path.join(secretDir, 'data.txt');
    
    try {
      fs.mkdirSync(secretDir, { recursive: true });
      fs.writeFileSync(secretFile, 'STREAMING_SECRET_DATA');
      
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: [secretDir.replace(/\\/g, '/') + '/'],
          blockedWritePaths: [],
          allowedPaths: []
        }
      });
      
      const code = `
        const fs = require('fs');
        try {
          const stream = fs.createReadStream('${escapePath(secretFile)}');
          let data = '';
          stream.on('data', chunk => data += chunk);
          stream.on('end', () => console.log('STREAM_READ:' + data));
          stream.on('error', e => console.log('STREAM_BLOCKED:' + e.message));
          setTimeout(() => process.exit(0), 2000);
        } catch (e) {
          console.log('STREAM_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 5000 });
      
      return {
        pass: !result.output.includes('STREAMING_SECRET_DATA'),
        reason: result.output.includes('STREAMING_SECRET_DATA') ? 'stream read bypass' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // =========================================================================
  // BLOCKED EXTENSIONS TESTS
  // =========================================================================
  console.log('\n--- Blocked Extensions ---\n');
  
  // Test: Windows batch file execution
  if (isWindows) {
    await tracker.runTest('blockedReadPaths - .bat script bypass (Windows)', async () => {
      const testDir = setupTestDir('fs-read-bat');
      const secretDir = path.join(testDir, 'secrets');
      const secretFile = path.join(secretDir, 'data.txt');
      
      try {
        fs.mkdirSync(secretDir, { recursive: true });
        fs.writeFileSync(secretFile, 'WINDOWS_SECRET_DATA');
        
        const scriptPath = writeTestScript(testDir, 'reader.bat', `@echo off\ntype "${secretFile}"`);
        
        writeMinimalConfig(testDir, {
          filesystem: {
            blockedReadPaths: [secretDir.replace(/\\/g, '/') + '/'],
            blockedWritePaths: [],
            allowedPaths: []
          }
        });
        
        const code = `
          const { execSync } = require('child_process');
          try {
            const content = execSync('${escapePath(scriptPath)}').toString();
            console.log('READ_SUCCESS:' + content);
          } catch (e) {
            console.log('READ_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code);
        
        return {
          pass: !result.output.includes('WINDOWS_SECRET_DATA'),
          reason: result.output.includes('WINDOWS_SECRET_DATA') ? 'bat script bypass' : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  }
  
  // Test 13: Block .sh file creation
  await tracker.runTest('blockedExtensions - .sh file creation', async () => {
    const testDir = setupTestDir('fs-ext-sh');
    
    try {
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: [],
          blockedWritePaths: [],
          allowedPaths: [],
          blockedExtensions: ['.sh', '.bash', '.py']
        }
      });
      
      const targetFile = path.join(testDir, 'malware.sh');
      const code = `
        const fs = require('fs');
        try {
          fs.writeFileSync('${escapePath(targetFile)}', '#!/bin/bash\\nrm -rf /');
          console.log('WRITE_SUCCESS');
        } catch (e) {
          console.log('WRITE_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code);
      const fileExists = fs.existsSync(targetFile);
      
      return {
        pass: !fileExists || isBlocked(result.output) || result.output.includes('WRITE_BLOCKED'),
        reason: fileExists ? '.sh file was created' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 14: Block .py file creation via shell
  if (!isWindows) {
    await tracker.runTest('blockedExtensions - .py file via shell', async () => {
      const testDir = setupTestDir('fs-ext-py');
      
      try {
        writeMinimalConfig(testDir, {
          filesystem: {
            blockedReadPaths: [],
            blockedWritePaths: [],
            allowedPaths: [],
            blockedExtensions: ['.sh', '.bash', '.py']
          }
        });
        
        const targetFile = path.join(testDir, 'evil.py');
        const code = `
          const { execSync } = require('child_process');
          try {
            execSync('echo "import os; os.system(\\'rm -rf /\\')" > "${targetFile}"');
            console.log('WRITE_SUCCESS');
          } catch (e) {
            console.log('WRITE_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code);
        const fileExists = fs.existsSync(targetFile);
        
        return {
          pass: !fileExists || isBlocked(result.output) || result.output.includes('WRITE_BLOCKED'),
          reason: fileExists ? '.py file was created via shell' : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  } else {
    tracker.skip('blockedExtensions - .py file via shell', 'Windows');
  }
  
  // =========================================================================
  // ALLOWED PATHS TESTS
  // =========================================================================
  console.log('\n--- Allowed Paths ---\n');
  
  // Test 15: Verify allowed path works
  await tracker.runTest('allowedPaths - allows access to whitelisted path', async () => {
    const testDir = setupTestDir('fs-allowed');
    const allowedDir = path.join(testDir, 'public');
    const allowedFile = path.join(allowedDir, 'readme.txt');
    
    try {
      fs.mkdirSync(allowedDir, { recursive: true });
      fs.writeFileSync(allowedFile, 'PUBLIC_CONTENT_OK');
      
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: [],
          blockedWritePaths: [],
          allowedPaths: [allowedDir.replace(/\\/g, '/') + '/']
        }
      });
      
      const code = `
        const fs = require('fs');
        try {
          const content = fs.readFileSync('${escapePath(allowedFile)}', 'utf8');
          console.log('READ_SUCCESS:' + content);
        } catch (e) {
          console.log('READ_ERROR:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code);
      
      return {
        pass: result.output.includes('PUBLIC_CONTENT_OK'),
        reason: result.output.includes('PUBLIC_CONTENT_OK') ? 'allowed path works' : 'allowed path blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // =========================================================================
  // ADVANCED BYPASS ATTEMPTS
  // =========================================================================
  console.log('\n--- Advanced Bypass Attempts ---\n');
  
  // Test: process.chdir to blocked directory
  await tracker.runTest('blockedReadPaths - process.chdir bypass attempt', async () => {
    const testDir = setupTestDir('fs-chdir');
    const secretDir = path.join(testDir, 'secrets');
    const secretFile = path.join(secretDir, 'key.txt');
    
    try {
      fs.mkdirSync(secretDir, { recursive: true });
      fs.writeFileSync(secretFile, 'CHDIR_SECRET_KEY');
      
      // IMPORTANT: Use realpath to handle /tmp -> /private/tmp on macOS
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
        const originalCwd = process.cwd();
        try {
          // Change to blocked directory and read with relative path
          process.chdir('${escapePath(secretDir)}');
          const content = fs.readFileSync('./key.txt', 'utf8');
          console.log('CHDIR_BYPASS:' + content);
        } catch (e) {
          console.log('CHDIR_BLOCKED:' + e.message);
        } finally {
          try { process.chdir(originalCwd); } catch(e) {}
        }
      `;
      
      const result = await runWithFirewall(testDir, code);
      
      return {
        pass: !result.output.includes('CHDIR_SECRET_KEY'),
        reason: result.output.includes('CHDIR_SECRET_KEY') ? 'chdir bypass worked' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test: Worker thread bypass attempt
  await tracker.runTest('blockedReadPaths - Worker thread bypass', async () => {
    const testDir = setupTestDir('fs-worker');
    const secretDir = path.join(testDir, 'secrets');
    const secretFile = path.join(secretDir, 'worker-secret.txt');
    
    try {
      fs.mkdirSync(secretDir, { recursive: true });
      fs.writeFileSync(secretFile, 'WORKER_THREAD_SECRET');
      
      writeMinimalConfig(testDir, {
        filesystem: {
          blockedReadPaths: [secretDir.replace(/\\/g, '/') + '/'],
          blockedWritePaths: [],
          allowedPaths: []
        }
      });
      
      // Worker code that tries to read the secret file
      const workerScript = path.join(testDir, 'worker.js');
      fs.writeFileSync(workerScript, `
        const { parentPort } = require('worker_threads');
        const fs = require('fs');
        try {
          const content = fs.readFileSync('${escapePath(secretFile)}', 'utf8');
          parentPort.postMessage({ success: true, content });
        } catch (e) {
          parentPort.postMessage({ success: false, error: e.message });
        }
      `);
      
      const code = `
        const { Worker } = require('worker_threads');
        const worker = new Worker('${escapePath(workerScript)}');
        worker.on('message', (msg) => {
          if (msg.success && msg.content.includes('WORKER_THREAD_SECRET')) {
            console.log('WORKER_BYPASS:' + msg.content);
          } else {
            console.log('WORKER_BLOCKED:' + (msg.error || 'no content'));
          }
          process.exit(0);
        });
        worker.on('error', (e) => {
          console.log('WORKER_ERROR:' + e.message);
          process.exit(0);
        });
        setTimeout(() => process.exit(0), 5000);
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 8000 });
      
      return {
        pass: !result.output.includes('WORKER_THREAD_SECRET'),
        reason: result.output.includes('WORKER_THREAD_SECRET') ? 'worker thread bypass' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test: fs.realpath to resolve blocked symlink
  if (!isWindows) {
    await tracker.runTest('blockedReadPaths - fs.realpath resolution', async () => {
      const testDir = setupTestDir('fs-realpath');
      const secretDir = path.join(testDir, 'secrets');
      const secretFile = path.join(secretDir, 'real.txt');
      
      try {
        fs.mkdirSync(secretDir, { recursive: true });
        fs.writeFileSync(secretFile, 'REALPATH_SECRET');
        
        // Create a symlink
        const symlinkPath = path.join(testDir, 'link');
        try {
          fs.symlinkSync(secretFile, symlinkPath);
        } catch (e) {
          // Symlink might fail on some systems
          return { pass: true, reason: 'symlink not supported', debug: e.message };
        }
        
        // IMPORTANT: Use realpath to handle /tmp -> /private/tmp on macOS
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
            // Get real path of symlink (should resolve to blocked path)
            const realPath = fs.realpathSync('${escapePath(symlinkPath)}');
            console.log('REALPATH:' + realPath);
            // Try to read the resolved path
            const content = fs.readFileSync(realPath, 'utf8');
            console.log('REALPATH_BYPASS:' + content);
          } catch (e) {
            console.log('REALPATH_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code);
        
        return {
          pass: !result.output.includes('REALPATH_SECRET'),
          reason: result.output.includes('REALPATH_SECRET') ? 'realpath bypass' : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  } else {
    tracker.skip('blockedReadPaths - fs.realpath resolution', 'Windows');
  }
  
  return tracker.getSummary();
}

module.exports = { runFilesystemTests };

// Allow direct execution
if (require.main === module) {
  runFilesystemTests().then(summary => {
    console.log('\nFilesystem Tests Summary:');
    console.log(`  Passed: ${summary.passed}`);
    console.log(`  Failed: ${summary.failed}`);
    console.log(`  Skipped: ${summary.skipped}`);
    process.exit(summary.failed > 0 ? 1 : 0);
  });
}
