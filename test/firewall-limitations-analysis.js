/**
 * Firewall Limitations Analysis
 * Tests to understand what the firewall CAN and CANNOT protect against
 */

const { runFirewallTest } = require('./test-runner');

console.log('======================================================');
console.log('   Firewall Limitations Analysis');
console.log('======================================================\n');

let canDo = [];
let cannotDo = [];

async function testLimitation(name, code, expectBlocked) {
  process.stdout.write(`Testing: ${name}... `);
  
  const result = await runFirewallTest(
    name,
    code,
    (output) => {
      const wasBlocked = output.includes('BLOCKED') || 
                        output.includes('blocked') ||
                        output.includes('Access denied') ||
                        output.includes('EACCES');
      const wasAllowed = output.includes('ALLOWED') || output.includes('SUCCESS');
      
      if (expectBlocked && wasBlocked) {
        console.log('✓ (Blocked as expected)');
        canDo.push(name);
        return { pass: true, reason: 'blocked' };
      } else if (!expectBlocked && wasAllowed) {
        console.log('✓ (Allowed as expected)');
        canDo.push(name);
        return { pass: true, reason: 'allowed' };
      } else if (expectBlocked && !wasBlocked) {
        console.log('✗ (NOT BLOCKED - LIMITATION!)');
        cannotDo.push(name);
        return { pass: false, reason: 'limitation - not blocked' };
      } else {
        console.log('✗ (Blocked unexpectedly)');
        return { pass: false, reason: 'unexpected block' };
      }
    },
    { timeout: 3000 }
  );
  
  return result;
}

/**
 * Run the full suite of firewall limitation tests and print a summary.
 *
 * Executes a series of categorized tests (child process, environment variables,
 * filesystem, network, code execution, and bypass attempts) using `testLimitation`,
 * collects which protections are present or missing, prints a final capabilities
 * summary, and terminates the process.
 *
 * Side effects:
 * - Writes progress and summary output to the console.
 * - Calls `process.exit(0)` when finished.
 */
async function runTests() {
  // ============================================
  // 1. CHILD PROCESS PROTECTION
  // ============================================
  console.log('[1] Child Process Protection\n');

  await testLimitation(
    'Block dangerous exec() command',
    `const { exec } = require('child_process');
     exec('rm -rf /', (err) => {
       console.log(err ? 'BLOCKED' : 'ALLOWED');
     });
     setTimeout(() => {}, 300);`,
    true
  );

  await testLimitation(
    'Block dangerous spawn() command',
    `const { spawn } = require('child_process');
     const proc = spawn('rm', ['-rf', '/']);
     proc.on('error', () => console.log('BLOCKED'));
     proc.on('exit', (code) => {
       if (code !== 0) console.log('BLOCKED');
     });
     setTimeout(() => {}, 300);`,
    true
  );

  await testLimitation(
    'Block dangerous execSync() command',
    `const { execSync } = require('child_process');
     try {
       execSync('rm -rf /');
       console.log('ALLOWED');
     } catch(e) {
       console.log('BLOCKED');
     }`,
    true
  );

  // ============================================
  // 2. ENVIRONMENT VARIABLE PROTECTION
  // ============================================
  console.log('\n[2] Environment Variable Protection\n');

  await testLimitation(
    'Block direct access to GITHUB_TOKEN',
    `try {
       const token = process.env.GITHUB_TOKEN;
       console.log(token ? 'ALLOWED' : 'BLOCKED');
     } catch(e) {
       console.log('BLOCKED');
     }`,
    true
  );

  await testLimitation(
    'Env vars leaked to child process',
    `const { execSync } = require('child_process');
     try {
       const result = execSync('echo $GITHUB_TOKEN').toString();
       console.log(result && result.trim() ? 'ALLOWED' : 'BLOCKED');
     } catch(e) {
       console.log('BLOCKED');
     }`,
    true  // We WANT this blocked
  );

  await testLimitation(
    'Env vars in spawn() environment',
    `const { spawn } = require('child_process');
     const proc = spawn('node', ['-e', 'console.log(process.env.GITHUB_TOKEN)']);
     proc.stdout.on('data', (data) => {
       const output = data.toString();
       console.log(output && output.trim() && output !== 'undefined' ? 'ALLOWED' : 'BLOCKED');
     });
     setTimeout(() => {}, 300);`,
    true  // We WANT this blocked
  );

  // ============================================
  // 3. FILESYSTEM PROTECTION
  // ============================================
  console.log('\n[3] Filesystem Protection\n');

  await testLimitation(
    'Block direct fs.readFileSync() on sensitive file',
    `const fs = require('fs');
     try {
       fs.readFileSync('/etc/passwd');
       console.log('ALLOWED');
     } catch(e) {
       console.log('BLOCKED');
     }`,
    true
  );

  await testLimitation(
    'Read via child process command',
    `const { execSync } = require('child_process');
     try {
       const result = execSync('cat /etc/passwd').toString();
       console.log(result ? 'ALLOWED' : 'BLOCKED');
     } catch(e) {
       console.log('BLOCKED');
     }`,
    true  // We WANT this blocked
  );

  await testLimitation(
    'Write to system directory',
    `const fs = require('fs');
     try {
       fs.writeFileSync('/etc/test.txt', 'test');
       console.log('ALLOWED');
     } catch(e) {
       console.log('BLOCKED');
     }`,
    true
  );

  // ============================================
  // 4. NETWORK PROTECTION
  // ============================================
  console.log('\n[4] Network Protection\n');

  await testLimitation(
    'Block https request to malicious domain',
    `const https = require('https');
     const req = https.get('https://pastebin.com/', () => {});
     req.on('error', () => console.log('BLOCKED'));
     setTimeout(() => {}, 300);`,
    true
  );

  await testLimitation(
    'Network via curl in child process',
    `const { exec } = require('child_process');
     exec('curl https://pastebin.com', (err) => {
       console.log(err ? 'BLOCKED' : 'ALLOWED');
     });
     setTimeout(() => {}, 300);`,
    true  // We WANT this blocked
  );

  // ============================================
  // 5. CODE EXECUTION PROTECTION
  // ============================================
  console.log('\n[5] Code Execution Protection\n');

  await testLimitation(
    'Block eval() with malicious code',
    `try {
       eval('require("child_process").execSync("rm -rf /")');
       console.log('ALLOWED');
     } catch(e) {
       console.log('BLOCKED');
     }`,
    true
  );

  await testLimitation(
    'Block Function constructor',
    `try {
       const fn = new Function('return require("child_process").execSync("rm -rf /")');
       fn();
       console.log('ALLOWED');
     } catch(e) {
       console.log('BLOCKED');
     }`,
    true
  );

  await testLimitation(
    'Block VM module',
    `try {
       const vm = require('vm');
       vm.runInNewContext('require("child_process").execSync("rm -rf /")');
       console.log('ALLOWED');
     } catch(e) {
       console.log('BLOCKED');
     }`,
    true
  );

  // ============================================
  // 6. BYPASS ATTEMPTS
  // ============================================
  console.log('\n[6] Common Bypass Attempts\n');

  await testLimitation(
    'Bypass via require.cache manipulation',
    `try {
       delete require.cache[require.resolve('fs')];
       const fs = require('fs');
       fs.readFileSync('/etc/passwd');
       console.log('ALLOWED');
     } catch(e) {
       console.log('BLOCKED');
     }`,
    true
  );

  await testLimitation(
    'Bypass via process.binding',
    `try {
       const fs = process.binding('fs');
       console.log(fs ? 'ALLOWED' : 'BLOCKED');
     } catch(e) {
       console.log('BLOCKED');
     }`,
    true
  );

  await testLimitation(
    'Bypass via dynamic import',
    `import('fs').then(fs => {
       try {
         fs.readFileSync('/etc/passwd');
         console.log('ALLOWED');
       } catch(e) {
         console.log('BLOCKED');
       }
     }).catch(() => console.log('BLOCKED'));
     setTimeout(() => {}, 300);`,
    true
  );

  // ============================================
  // SUMMARY
  // ============================================
  console.log('\n======================================================');
  console.log('FIREWALL CAPABILITIES:');
  console.log('======================================================\n');
  
  console.log('CAN PROTECT AGAINST:');
  canDo.forEach(item => console.log(`  - ${item}`));
  
  console.log('\nCANNOT PROTECT AGAINST (LIMITATIONS):');
  cannotDo.forEach(item => console.log(`  - ${item}`));
  
  console.log('\n======================================================');
  console.log('ANALYSIS COMPLETE');
  console.log('======================================================\n');

  process.exit(0);
}

runTests().catch(err => {
  console.error('Test error:', err);
  process.exit(1);
});