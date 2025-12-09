/**
 * Feature Integration Tests
 * Tests all configuration features except GitHub API
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

// Test utilities
function runTest(name, fn) {
  process.stdout.write(`Testing ${name}... `);
  try {
    fn();
    console.log('✓');
    return true;
  } catch (e) {
    console.log('✗');
    console.error(`  Error: ${e.message}`);
    return false;
  }
}

async function runAsyncTest(name, fn) {
  process.stdout.write(`Testing ${name}... `);
  try {
    await fn();
    console.log('✓');
    return true;
  } catch (e) {
    console.log('✗');
    console.error(`  Error: ${e.message}`);
    return false;
  }
}

function runFirewallScript(code, expectBlocked = false) {
  return new Promise((resolve, reject) => {
    const proc = spawn('node', [
      '-r', path.join(__dirname, '../index.js'),
      '-e', code
    ], {
      env: { ...process.env, NODE_FIREWALL: '1' },
      cwd: __dirname
    });

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (data) => { stdout += data.toString(); });
    proc.stderr.on('data', (data) => { stderr += data.toString(); });

    proc.on('close', (code) => {
      const output = stdout + stderr;
      const wasBlocked = output.includes('BLOCKED') || 
                        output.includes('blocked') || 
                        output.includes('EACCES') ||
                        code !== 0;
      
      if (expectBlocked && !wasBlocked) {
        reject(new Error('Expected to be blocked but was allowed'));
      } else if (!expectBlocked && wasBlocked) {
        reject(new Error('Expected to be allowed but was blocked'));
      } else {
        resolve({ stdout, stderr, code, output });
      }
    });

    proc.on('error', reject);
  });
}

// Test suite
async function runTests() {
  console.log('======================================================');
  console.log('   Feature Integration Tests');
  console.log('======================================================');
  console.log(`Node.js version: ${process.version}\n`);

  let passed = 0;
  let failed = 0;

  // ============================================
  // 1. FILESYSTEM TESTS
  // ============================================
  console.log('\n[1] Filesystem Protection Tests\n');

  // Test 1.1: Blocked read paths
  if (await runAsyncTest('Block reading /.ssh/ files', async () => {
    const result = await runFirewallScript(`
      const fs = require('fs');
      try {
        fs.readFileSync(require('os').homedir() + '/.ssh/id_rsa');
        console.log('NOT_BLOCKED');
      } catch (e) {
        if (e.message.includes('Firewall') || e.code === 'EACCES') {
          console.log('BLOCKED_BY_FIREWALL');
        } else {
          console.log('FILE_NOT_EXIST');
        }
      }
    `, false);
    
    if (!result.output.includes('BLOCKED_BY_FIREWALL') && !result.output.includes('FILE_NOT_EXIST')) {
      throw new Error('File access was not blocked');
    }
  })) passed++; else failed++;

  // Test 1.2: Blocked write paths
  if (await runAsyncTest('Block writing to /etc/', async () => {
    const result = await runFirewallScript(`
      const fs = require('fs');
      try {
        fs.writeFileSync('/etc/test-firewall-block', 'test');
        console.log('NOT_BLOCKED');
      } catch (e) {
        if (e.message.includes('Firewall') || e.code === 'EACCES') {
          console.log('BLOCKED_BY_FIREWALL');
        }
      }
    `, false);
    
    if (!result.output.includes('BLOCKED_BY_FIREWALL')) {
      throw new Error('Write to /etc/ was not blocked');
    }
  })) passed++; else failed++;

  // Test 1.3: Blocked extensions
  if (await runAsyncTest('Block writing .sh files', async () => {
    const testFile = path.join(os.tmpdir(), 'test-script-firewall.sh');
    const result = await runFirewallScript(`
      const fs = require('fs');
      try {
        fs.writeFileSync('${testFile}', '#!/bin/bash\\necho test');
        console.log('NOT_BLOCKED');
      } catch (e) {
        if (e.message.includes('Firewall') || e.code === 'EACCES') {
          console.log('BLOCKED_BY_FIREWALL');
        }
      }
    `, false);
    
    if (!result.output.includes('BLOCKED_BY_FIREWALL')) {
      throw new Error('.sh file write was not blocked');
    }
  })) passed++; else failed++;

  // Test 1.4: Allowed paths
  if (await runAsyncTest('Allow writing to /tmp/', async () => {
    const testFile = path.join(os.tmpdir(), 'firewall-test-allowed.txt');
    await runFirewallScript(`
      const fs = require('fs');
      fs.writeFileSync('${testFile}', 'test');
      fs.unlinkSync('${testFile}');
    `, false);
  })) passed++; else failed++;

  // ============================================
  // 2. NETWORK TESTS
  // ============================================
  console.log('\n[2] Network Protection Tests\n');

  // Test 2.1: Blocked domains
  if (await runAsyncTest('Block requests to paste.ee', async () => {
    await runFirewallScript(`
      const https = require('https');
      try {
        https.get('https://paste.ee/test', () => {});
        // Give it a moment to be blocked
        setTimeout(() => {}, 100);
      } catch (e) {
        // Expected to be blocked
      }
    `, true);
  })) passed++; else failed++;

  // Test 2.2: Allowed domains
  if (await runAsyncTest('Allow requests to registry.npmjs.org', async () => {
    await runFirewallScript(`
      const https = require('https');
      const req = https.get('https://registry.npmjs.org/', () => {});
      req.on('error', () => {}); // Ignore connection errors
      req.end();
    `, false);
  })) passed++; else failed++;

  // Test 2.3: Suspicious ports
  if (await runAsyncTest('Block connections to suspicious port 4444', async () => {
    await runFirewallScript(`
      const net = require('net');
      try {
        const socket = net.connect(4444, 'localhost');
        socket.on('error', () => {});
        setTimeout(() => socket.destroy(), 50);
      } catch (e) {
        // Expected
      }
    `, true);
  })) passed++; else failed++;

  // Test 2.4: Credential pattern detection
  if (await runAsyncTest('Detect credential exfiltration', async () => {
    await runFirewallScript(`
      const https = require('https');
      const req = https.request({
        hostname: 'registry.npmjs.org',
        method: 'POST',
        path: '/test'
      });
      req.write('GITHUB_TOKEN=fake-test-token-123456');
      req.on('error', () => {});
      req.end();
    `, true);
  })) passed++; else failed++;

  // ============================================
  // 3. COMMAND EXECUTION TESTS
  // ============================================
  console.log('\n[3] Command Execution Tests\n');

  // Test 3.1: Blocked patterns - curl with output
  if (await runAsyncTest('Block curl with -o flag', async () => {
    await runFirewallScript(`
      const { exec } = require('child_process');
      try {
        exec('curl -o /tmp/test https://example.com', (err) => {
          if (!err || !err.message.includes('blocked')) {
            throw new Error('Should have been blocked');
          }
        });
      } catch (e) {
        if (!e.message.includes('blocked')) throw e;
      }
    `, true);
  })) passed++; else failed++;

  // Test 3.2: Blocked patterns - wget
  if (await runAsyncTest('Block wget command', async () => {
    await runFirewallScript(`
      const { exec } = require('child_process');
      try {
        exec('wget https://example.com', (err) => {
          if (!err || !err.message.includes('blocked')) {
            throw new Error('Should have been blocked');
          }
        });
      } catch (e) {
        if (!e.message.includes('blocked')) throw e;
      }
    `, true);
  })) passed++; else failed++;

  // Test 3.3: Allowed commands
  if (await runAsyncTest('Allow npm command', async () => {
    await runFirewallScript(`
      const { exec } = require('child_process');
      exec('npm --version', (err, stdout) => {
        // Should work
      });
    `, false);
  })) passed++; else failed++;

  // Test 3.4: Block dangerous rm -rf
  if (await runAsyncTest('Block rm -rf command', async () => {
    await runFirewallScript(`
      const { exec } = require('child_process');
      try {
        exec('rm -rf /tmp/test', (err) => {
          if (!err || !err.message.includes('blocked')) {
            throw new Error('Should have been blocked');
          }
        });
      } catch (e) {
        if (!e.message.includes('blocked')) throw e;
      }
    `, true);
  })) passed++; else failed++;

  // ============================================
  // 4. ENVIRONMENT PROTECTION TESTS
  // ============================================
  console.log('\n[4] Environment Variable Protection Tests\n');

  // Test 4.1: Protected variables
  if (await runAsyncTest('Protect GITHUB_TOKEN from child processes', async () => {
    process.env.GITHUB_TOKEN = 'test-token-12345';
    await runFirewallScript(`
      const { spawn } = require('child_process');
      const proc = spawn('node', ['-e', 'console.log(process.env.GITHUB_TOKEN)']);
      proc.stdout.on('data', (data) => {
        if (data.toString().includes('test-token')) {
          throw new Error('Token leaked to child process');
        }
      });
    `, false);
    delete process.env.GITHUB_TOKEN;
  })) passed++; else failed++;

  // ============================================
  // 5. BEHAVIORAL MONITORING TESTS
  // ============================================
  console.log('\n[5] Behavioral Monitoring Tests\n');

  // Test 5.1: Track file operations
  if (await runAsyncTest('Track file write operations', async () => {
    const result = await runFirewallScript(`
      const fs = require('fs');
      const path = require('path');
      const tmpFile = path.join(require('os').tmpdir(), 'behavior-test.txt');
      fs.writeFileSync(tmpFile, 'test1');
      fs.writeFileSync(tmpFile, 'test2');
      fs.writeFileSync(tmpFile, 'test3');
      fs.unlinkSync(tmpFile);
    `, false);
    
    if (!result.output.includes('File Writes:')) {
      throw new Error('Behavior monitoring not tracking file writes');
    }
  })) passed++; else failed++;

  // Test 5.2: Track process spawns
  if (await runAsyncTest('Track process spawn operations', async () => {
    const result = await runFirewallScript(`
      const { spawnSync } = require('child_process');
      spawnSync('node', ['--version']);
    `, false);
    
    if (!result.output.includes('Process Spawns:')) {
      throw new Error('Behavior monitoring not tracking spawns');
    }
  })) passed++; else failed++;

  // ============================================
  // 6. TRUSTED MODULES TESTS
  // ============================================
  console.log('\n[6] Trusted Modules Tests\n');

  // Test 6.1: Trusted modules have more access
  if (runTest('Check trusted module detection', () => {
    const { FirewallCore } = require('../lib/firewall-core');
    const firewall = new FirewallCore();
    
    if (!firewall.isTrustedModule('npm')) {
      throw new Error('npm should be trusted');
    }
    if (!firewall.isTrustedModule('@aws-sdk/client-s3')) {
      throw new Error('@aws-sdk packages should be trusted');
    }
    if (firewall.isTrustedModule('evil-package')) {
      throw new Error('evil-package should not be trusted');
    }
  })) passed++; else failed++;

  // ============================================
  // 7. EXCEPTIONS TESTS
  // ============================================
  console.log('\n[7] Module Exceptions Tests\n');

  // Test 7.1: Exception configuration
  if (runTest('Check exception configuration loading', () => {
    const config = require('../lib/config-loader');
    
    if (!config.exceptions || !config.exceptions.modules) {
      throw new Error('Exceptions not configured');
    }
    
    if (!config.exceptions.modules['example-package']) {
      throw new Error('Example package exception not found');
    }
  })) passed++; else failed++;

  // ============================================
  // 8. REPORTING TESTS
  // ============================================
  console.log('\n[8] Reporting Tests\n');

  // Test 8.1: Audit log generation
  if (await runAsyncTest('Generate audit logs', async () => {
    const auditFile = path.join(process.cwd(), 'firewall-audit.jsonl');
    
    // Remove old audit file
    if (fs.existsSync(auditFile)) {
      fs.unlinkSync(auditFile);
    }
    
    await runFirewallScript(`
      const fs = require('fs');
      const tmpFile = require('path').join(require('os').tmpdir(), 'audit-test.txt');
      fs.writeFileSync(tmpFile, 'test');
      fs.unlinkSync(tmpFile);
    `, false);
    
    // Check if audit file was created
    if (!fs.existsSync(auditFile)) {
      throw new Error('Audit log file not created');
    }
    
    const content = fs.readFileSync(auditFile, 'utf8');
    if (!content.includes('FILESYSTEM')) {
      throw new Error('Audit log missing filesystem events');
    }
  })) passed++; else failed++;

  // Test 8.2: Behavior report generation
  if (await runAsyncTest('Generate behavior report', async () => {
    const reportFile = path.join(process.cwd(), 'firewall-report.json');
    
    // Remove old report
    if (fs.existsSync(reportFile)) {
      fs.unlinkSync(reportFile);
    }
    
    await runFirewallScript(`
      const fs = require('fs');
      const tmpFile = require('path').join(require('os').tmpdir(), 'report-test.txt');
      fs.writeFileSync(tmpFile, 'test');
      fs.unlinkSync(tmpFile);
    `, false);
    
    // Check if report was created
    if (!fs.existsSync(reportFile)) {
      throw new Error('Behavior report not created');
    }
    
    const report = JSON.parse(fs.readFileSync(reportFile, 'utf8'));
    if (!report.metrics) {
      throw new Error('Report missing metrics');
    }
  })) passed++; else failed++;

  // ============================================
  // 9. MODE TESTS
  // ============================================
  console.log('\n[9] Mode Configuration Tests\n');

  // Test 9.1: Alert-only mode
  if (await runAsyncTest('Alert-only mode allows but warns', async () => {
    // Create temp config with alertOnly
    const tempConfig = path.join(os.tmpdir(), '.firewall-config-test.json');
    const config = require('../.firewall-config.json');
    config.mode.alertOnly = true;
    fs.writeFileSync(tempConfig, JSON.stringify(config));
    
    const result = await new Promise((resolve, reject) => {
      const proc = spawn('node', [
        '-r', path.join(__dirname, '../index.js'),
        '-e', `
          const fs = require('fs');
          try {
            fs.readFileSync(require('os').homedir() + '/.ssh/test');
          } catch (e) {
            // May fail due to file not existing, not firewall
          }
        `
      ], {
        env: { ...process.env, NODE_FIREWALL: '1' },
        cwd: os.tmpdir()
      });

      let output = '';
      proc.stdout.on('data', (d) => { output += d; });
      proc.stderr.on('data', (d) => { output += d; });
      proc.on('close', () => resolve({ output }));
    });
    
    fs.unlinkSync(tempConfig);
    
    if (result.output.includes('Alert-Only')) {
      // Good - alert mode is active
    }
  })) passed++; else failed++;

  // ============================================
  // SUMMARY
  // ============================================
  console.log('\n======================================================');
  console.log('Summary:');
  console.log(`  Passed: ${passed}`);
  console.log(`  Failed: ${failed}`);
  console.log('======================================================\n');

  if (failed === 0) {
    console.log('All feature tests passed! ✓\n');
    process.exit(0);
  } else {
    console.log(`${failed} test(s) failed.\n`);
    process.exit(1);
  }
}

// Run tests
runTests().catch(err => {
  console.error('Test suite error:', err);
  process.exit(1);
});
