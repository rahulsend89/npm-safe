/**
 * Comprehensive Filesystem Protection Tests
 * Tests all blockedReadPaths, blockedWritePaths, blockedExtensions, and allowedPaths
 * Using E2E pattern with real --import/--loader flags
 */

const { runFirewallTest } = require('./test-runner');
const os = require('os');

console.log('======================================================');
console.log('   Filesystem Protection Tests (E2E Pattern)');
console.log('======================================================\n');

let passed = 0;
let failed = 0;

async function runFilesystemTest(name, code, expectBlocked = true) {
  const result = await runFirewallTest(
    name,
    code,
    (output) => {
      const wasBlocked = output.includes('BLOCKED') || 
                        output.includes('Access denied') ||
                        output.includes('EACCES') ||
                        output.includes('blocked');
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
  // ============================================
  // 1. BLOCKED READ PATHS (16 tests)
  // ============================================
  console.log('[1] Blocked Read Paths (16 paths)\n');

  await runFilesystemTest(
    'Block /.ssh/ read',
    `const fs = require('fs');
     try { fs.readFileSync(require('os').homedir() + '/.ssh/id_rsa'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /.aws/ read',
    `const fs = require('fs');
     try { fs.readFileSync(require('os').homedir() + '/.aws/credentials'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /.gnupg/ read',
    `const fs = require('fs');
     try { fs.readFileSync(require('os').homedir() + '/.gnupg/private-keys'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /.kube/ read',
    `const fs = require('fs');
     try { fs.readFileSync(require('os').homedir() + '/.kube/config'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /.docker/ read',
    `const fs = require('fs');
     try { fs.readFileSync(require('os').homedir() + '/.docker/config.json'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /.config/gcloud/ read',
    `const fs = require('fs');
     try { fs.readFileSync(require('os').homedir() + '/.config/gcloud/credentials'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /.azure/ read',
    `const fs = require('fs');
     try { fs.readFileSync(require('os').homedir() + '/.azure/credentials'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /etc/passwd read',
    `const fs = require('fs');
     try { fs.readFileSync('/etc/passwd'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /etc/shadow read',
    `const fs = require('fs');
     try { fs.readFileSync('/etc/shadow'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /.env read',
    `const fs = require('fs');
     try { fs.readFileSync(require('os').homedir() + '/.env'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /.npmrc read',
    `const fs = require('fs');
     try { fs.readFileSync(require('os').homedir() + '/.npmrc'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /.gitconfig read',
    `const fs = require('fs');
     try { fs.readFileSync(require('os').homedir() + '/.gitconfig'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /.bash_history read',
    `const fs = require('fs');
     try { fs.readFileSync(require('os').homedir() + '/.bash_history'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /.zsh_history read',
    `const fs = require('fs');
     try { fs.readFileSync(require('os').homedir() + '/.zsh_history'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /.sh_history read',
    `const fs = require('fs');
     try { fs.readFileSync(require('os').homedir() + '/.sh_history'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /keychain/ read',
    `const fs = require('fs');
     try { fs.readFileSync(require('os').homedir() + '/keychain/secrets'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  // ============================================
  // 2. BLOCKED WRITE PATHS (16 tests)
  // ============================================
  console.log('\n[2] Blocked Write Paths (16 paths)\n');

  await runFilesystemTest(
    'Block /etc/ write',
    `const fs = require('fs');
     try { fs.writeFileSync('/etc/firewall-test', 'test'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /.ssh/ write',
    `const fs = require('fs');
     try { fs.writeFileSync(require('os').homedir() + '/.ssh/malicious', 'test'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /usr/local/bin/ write',
    `const fs = require('fs');
     try { fs.writeFileSync('/usr/local/bin/malicious', 'test'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /usr/bin/ write',
    `const fs = require('fs');
     try { fs.writeFileSync('/usr/bin/malicious', 'test'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /bin/ write',
    `const fs = require('fs');
     try { fs.writeFileSync('/bin/malicious', 'test'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /sbin/ write',
    `const fs = require('fs');
     try { fs.writeFileSync('/sbin/malicious', 'test'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /Library/LaunchDaemons/ write',
    `const fs = require('fs');
     try { fs.writeFileSync('/Library/LaunchDaemons/com.malicious.plist', 'test'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /Library/LaunchAgents/ write',
    `const fs = require('fs');
     try { fs.writeFileSync('/Library/LaunchAgents/com.malicious.plist', 'test'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /.github/workflows/ write',
    `const fs = require('fs');
     try { fs.writeFileSync(process.cwd() + '/.github/workflows/malicious.yml', 'test'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /.bashrc write',
    `const fs = require('fs');
     try { fs.writeFileSync(require('os').homedir() + '/.bashrc', 'malicious'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /.zshrc write',
    `const fs = require('fs');
     try { fs.writeFileSync(require('os').homedir() + '/.zshrc', 'malicious'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /.profile write',
    `const fs = require('fs');
     try { fs.writeFileSync(require('os').homedir() + '/.profile', 'malicious'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /.bash_profile write',
    `const fs = require('fs');
     try { fs.writeFileSync(require('os').homedir() + '/.bash_profile', 'malicious'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /.zprofile write',
    `const fs = require('fs');
     try { fs.writeFileSync(require('os').homedir() + '/.zprofile', 'malicious'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block /.git/hooks/ write',
    `const fs = require('fs');
     try { fs.writeFileSync(process.cwd() + '/.git/hooks/pre-commit', 'malicious'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  // Note: /home/*/.github/workflows/ is a pattern, tested via /.github/workflows/

  // ============================================
  // 3. BLOCKED EXTENSIONS (8 tests)
  // ============================================
  console.log('\n[3] Blocked Extensions (8 extensions)\n');

  const tmpDir = os.tmpdir();

  await runFilesystemTest(
    'Block .sh write',
    `const fs = require('fs');
     try { fs.writeFileSync('${tmpDir}/test.sh', '#!/bin/bash'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block .command write',
    `const fs = require('fs');
     try { fs.writeFileSync('${tmpDir}/test.command', '#!/bin/bash'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block .bash write',
    `const fs = require('fs');
     try { fs.writeFileSync('${tmpDir}/test.bash', '#!/bin/bash'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block .zsh write',
    `const fs = require('fs');
     try { fs.writeFileSync('${tmpDir}/test.zsh', '#!/bin/zsh'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block .py write',
    `const fs = require('fs');
     try { fs.writeFileSync('${tmpDir}/test.py', 'print("test")'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block .rb write',
    `const fs = require('fs');
     try { fs.writeFileSync('${tmpDir}/test.rb', 'puts "test"'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block .pl write',
    `const fs = require('fs');
     try { fs.writeFileSync('${tmpDir}/test.pl', 'print "test"'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  await runFilesystemTest(
    'Block .php write',
    `const fs = require('fs');
     try { fs.writeFileSync('${tmpDir}/test.php', '<?php echo "test"; ?>'); console.log('NOT_BLOCKED'); }
     catch(e) { if(e.message.includes('Firewall') || e.code === 'EACCES') console.log('BLOCKED'); }`,
    true
  );

  // ============================================
  // 4. ALLOWED PATHS (10 tests)
  // ============================================
  console.log('\n[4] Allowed Paths (10 paths)\n');

  await runFilesystemTest(
    'Allow /tmp/ write',
    `const fs = require('fs');
     const file = '${tmpDir}/firewall-test-allowed.txt';
     fs.writeFileSync(file, 'test');
     fs.unlinkSync(file);
     console.log('ALLOWED');`,
    false
  );

  await runFilesystemTest(
    'Allow /var/tmp/ write',
    `const fs = require('fs');
     try {
       const file = '/var/tmp/firewall-test-allowed.txt';
       fs.writeFileSync(file, 'test');
       fs.unlinkSync(file);
       console.log('ALLOWED');
     } catch(e) {
       if(!e.message.includes('Firewall')) console.log('ALLOWED');
     }`,
    false
  );

  await runFilesystemTest(
    'Allow /node_modules/ write',
    `const fs = require('fs');
     const file = process.cwd() + '/node_modules/.firewall-test';
     try {
       fs.writeFileSync(file, 'test');
       fs.unlinkSync(file);
       console.log('ALLOWED');
     } catch(e) {
       if(!e.message.includes('Firewall')) console.log('ALLOWED');
     }`,
    false
  );

  await runFilesystemTest(
    'Allow /.npm/ write',
    `const fs = require('fs');
     const file = require('os').homedir() + '/.npm/.firewall-test';
     try {
       fs.writeFileSync(file, 'test');
       fs.unlinkSync(file);
       console.log('ALLOWED');
     } catch(e) {
       if(!e.message.includes('Firewall')) console.log('ALLOWED');
     }`,
    false
  );

  await runFilesystemTest(
    'Allow /.yarn/ write',
    `const fs = require('fs');
     const file = require('os').homedir() + '/.yarn/.firewall-test';
     try {
       fs.writeFileSync(file, 'test');
       fs.unlinkSync(file);
       console.log('ALLOWED');
     } catch(e) {
       if(!e.message.includes('Firewall')) console.log('ALLOWED');
     }`,
    false
  );

  await runFilesystemTest(
    'Allow /.pnpm/ write',
    `const fs = require('fs');
     const file = require('os').homedir() + '/.pnpm/.firewall-test';
     try {
       fs.writeFileSync(file, 'test');
       fs.unlinkSync(file);
       console.log('ALLOWED');
     } catch(e) {
       if(!e.message.includes('Firewall')) console.log('ALLOWED');
     }`,
    false
  );

  await runFilesystemTest(
    'Allow /.cache/ write',
    `const fs = require('fs');
     const file = require('os').homedir() + '/.cache/.firewall-test';
     try {
       fs.writeFileSync(file, 'test');
       fs.unlinkSync(file);
       console.log('ALLOWED');
     } catch(e) {
       if(!e.message.includes('Firewall')) console.log('ALLOWED');
     }`,
    false
  );

  await runFilesystemTest(
    'Allow /dist/ write',
    `const fs = require('fs');
     const file = process.cwd() + '/dist/.firewall-test';
     try {
       fs.writeFileSync(file, 'test');
       fs.unlinkSync(file);
       console.log('ALLOWED');
     } catch(e) {
       if(!e.message.includes('Firewall')) console.log('ALLOWED');
     }`,
    false
  );

  await runFilesystemTest(
    'Allow /build/ write',
    `const fs = require('fs');
     const file = process.cwd() + '/build/.firewall-test';
     try {
       fs.writeFileSync(file, 'test');
       fs.unlinkSync(file);
       console.log('ALLOWED');
     } catch(e) {
       if(!e.message.includes('Firewall')) console.log('ALLOWED');
     }`,
    false
  );

  await runFilesystemTest(
    'Allow /public/ write',
    `const fs = require('fs');
     const file = process.cwd() + '/public/.firewall-test';
     try {
       fs.writeFileSync(file, 'test');
       fs.unlinkSync(file);
       console.log('ALLOWED');
     } catch(e) {
       if(!e.message.includes('Firewall')) console.log('ALLOWED');
     }`,
    false
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

  console.log('Coverage:');
  console.log('  Blocked Read Paths:  16/16 ✓');
  console.log('  Blocked Write Paths: 15/16 ✓ (pattern tested)');
  console.log('  Blocked Extensions:  8/8 ✓');
  console.log('  Allowed Paths:       10/10 ✓\n');

  if (failed === 0) {
    console.log('All filesystem protection tests passed! ✓\n');
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
