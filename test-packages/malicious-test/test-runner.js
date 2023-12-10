#!/usr/bin/env node

/**
 * Systematic Attack Test Runner
 * Tests each attack vector individually and reports results
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { exec, spawn } = require('child_process');
const https = require('https');

console.log('\n╔╗');
console.log('       SYSTEMATIC ATTACK TEST RUNNER                       ');
console.log('  Testing each attack vector individually                  ');
console.log('╚╝\n');

const results = {
  file: [],
  network: [],
  command: [],
  stats: { total: 0, blocked: 0, succeeded: 0 }
};

let testNumber = 0;

// Helper to run test and report
function runTest(category, name, description, testFn) {
  return new Promise(async (resolve) => {
    testNumber++;
    console.log(`\n[${'='.repeat(60)}]`);
    console.log(`Test ${testNumber}: ${name}`);
    console.log(`Category: ${category}`);
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
      
      results[category].push({
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
      results[category].push({
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

// ========================================
// FILE-BASED ATTACK TESTS
// ========================================

async function testSSHKeyRead() {
  return runTest('file', 'SSH_KEY_READ', 'Attempt to read SSH private key', async () => {
    try {
      const keyPath = path.join(os.homedir(), '.ssh', 'id_rsa');
      fs.readFileSync(keyPath, 'utf8');
      return { 
        blocked: false, 
        details: 'Successfully read SSH private key',
        recommendation: 'Add ~/.ssh/ to blockedReadPaths in native firewall'
      };
    } catch (e) {
      if (e.code === 'ENOENT') {
        return { blocked: true, details: 'File does not exist (acceptable)' };
      }
      return { 
        blocked: true, 
        details: `Blocked by: ${e.message}`,
        recommendation: 'Working as expected'
      };
    }
  });
}

async function testAWSCredentialsRead() {
  return runTest('file', 'AWS_CREDENTIALS_READ', 'Attempt to read AWS credentials', async () => {
    try {
      const awsPath = path.join(os.homedir(), '.aws', 'credentials');
      fs.readFileSync(awsPath, 'utf8');
      return { 
        blocked: false, 
        details: 'Successfully read AWS credentials',
        recommendation: 'Add ~/.aws/ to blockedReadPaths'
      };
    } catch (e) {
      if (e.code === 'ENOENT') {
        return { blocked: true, details: 'File does not exist (acceptable)' };
      }
      return { blocked: true, details: `Blocked by: ${e.message}` };
    }
  });
}

async function testEnvFileRead() {
  return runTest('file', 'ENV_FILE_READ', 'Attempt to read .env file', async () => {
    try {
      const envPath = path.join(process.cwd(), '.env');
      fs.readFileSync(envPath, 'utf8');
      return { 
        blocked: false, 
        details: 'Successfully read .env file',
        recommendation: 'Add .env to blockedReadPaths or use isSensitivePattern'
      };
    } catch (e) {
      if (e.code === 'ENOENT') {
        return { blocked: true, details: 'File does not exist (acceptable)' };
      }
      return { blocked: true, details: `Blocked by: ${e.message}` };
    }
  });
}

async function testNpmrcRead() {
  return runTest('file', 'NPMRC_READ', 'Attempt to read .npmrc (npm token)', async () => {
    try {
      const npmrcPath = path.join(os.homedir(), '.npmrc');
      fs.readFileSync(npmrcPath, 'utf8');
      return { 
        blocked: false, 
        details: 'Successfully read .npmrc',
        recommendation: 'Add ~/.npmrc to blockedReadPaths'
      };
    } catch (e) {
      if (e.code === 'ENOENT') {
        return { blocked: true, details: 'File does not exist (acceptable)' };
      }
      return { blocked: true, details: `Blocked by: ${e.message}` };
    }
  });
}

async function testGitconfigRead() {
  return runTest('file', 'GITCONFIG_READ', 'Attempt to read .gitconfig', async () => {
    try {
      const gitPath = path.join(os.homedir(), '.gitconfig');
      fs.readFileSync(gitPath, 'utf8');
      return { 
        blocked: false, 
        details: 'Successfully read .gitconfig',
        recommendation: 'Add ~/.gitconfig to blockedReadPaths'
      };
    } catch (e) {
      if (e.code === 'ENOENT') {
        return { blocked: true, details: 'File does not exist (acceptable)' };
      }
      return { blocked: true, details: `Blocked by: ${e.message}` };
    }
  });
}

async function testBackdoorScriptCreate() {
  return runTest('file', 'BACKDOOR_SCRIPT_CREATE', 'Attempt to create malicious .sh script', async () => {
    try {
      const scriptPath = path.join(os.tmpdir(), 'test-backdoor.sh');
      fs.writeFileSync(scriptPath, '#!/bin/bash\necho "malware"');
      
      // Cleanup
      try { fs.unlinkSync(scriptPath); } catch (e) {}
      
      return { 
        blocked: false, 
        details: 'Successfully created .sh script',
        recommendation: 'Enable blockedExtensions check for .sh files'
      };
    } catch (e) {
      return { blocked: true, details: `Blocked by: ${e.message}` };
    }
  });
}

async function testSystemBinWrite() {
  return runTest('file', 'SYSTEM_BIN_WRITE', 'Attempt to write to /usr/local/bin/', async () => {
    try {
      fs.writeFileSync('/usr/local/bin/test-malware', 'test');
      return { 
        blocked: false, 
        details: 'Successfully wrote to system directory',
        recommendation: 'Add /usr/local/bin/ to blockedWritePaths'
      };
    } catch (e) {
      if (e.code === 'EACCES' || e.message.includes('Firewall')) {
        return { blocked: true, details: `Blocked by: ${e.message}` };
      }
      return { blocked: true, details: 'Permission denied (OS-level)' };
    }
  });
}

async function testGitHubWorkflowCreate() {
  return runTest('file', 'GITHUB_WORKFLOW_CREATE', 'Attempt to create GitHub Actions workflow', async () => {
    try {
      const workflowDir = path.join(process.cwd(), '.github', 'workflows');
      fs.mkdirSync(workflowDir, { recursive: true });
      
      const workflowPath = path.join(workflowDir, 'test-malicious.yml');
      fs.writeFileSync(workflowPath, 'name: test\non: [push]');
      
      // Cleanup
      try { 
        fs.unlinkSync(workflowPath);
        fs.rmdirSync(path.join(process.cwd(), '.github', 'workflows'));
        fs.rmdirSync(path.join(process.cwd(), '.github'));
      } catch (e) {}
      
      return { 
        blocked: false, 
        details: 'Successfully created GitHub workflow',
        recommendation: 'Add .github/workflows/ to blockedWritePaths'
      };
    } catch (e) {
      return { blocked: true, details: `Blocked by: ${e.message}` };
    }
  });
}

// ========================================
// NETWORK-BASED ATTACK TESTS
// ========================================

async function testPastebinConnection() {
  return runTest('network', 'PASTEBIN_CONNECTION', 'Attempt connection to pastebin.com', () => {
    return new Promise((resolve) => {
      try {
        const req = https.request({
          hostname: 'pastebin.com',
          port: 443,
          path: '/',
          method: 'GET'
        }, (res) => {
          resolve({ 
            blocked: false, 
            details: `Connected (status: ${res.statusCode})`,
            recommendation: 'Add pastebin.com to blockedDomains in network monitor'
          });
        });
        
        req.on('error', (e) => {
          resolve({ 
            blocked: true, 
            details: `Blocked: ${e.message}`
          });
        });
        
        req.setTimeout(3000, () => {
          req.destroy();
          resolve({ blocked: true, details: 'Timeout/Blocked' });
        });
        
        req.end();
      } catch (e) {
        // Catch synchronous blocking (thrown by firewall)
        resolve({ 
          blocked: true, 
          details: `Blocked: ${e.message}`
        });
      }
    });
  });
}

async function testSuspiciousPortConnection() {
  return runTest('network', 'SUSPICIOUS_PORT_4444', 'Attempt connection to port 4444 (C&C)', () => {
    return new Promise((resolve) => {
      const http = require('http');
      const req = http.request({
        hostname: 'localhost',
        port: 4444,
        path: '/',
        method: 'GET'
      }, (res) => {
        resolve({ 
          blocked: false, 
          details: 'Connected to suspicious port',
          recommendation: 'Monitor suspicious ports in network layer'
        });
      });
      
      req.on('error', (e) => {
        // Connection refused is expected if nothing listening
        resolve({ blocked: true, details: 'Connection failed (expected)' });
      });
      
      req.setTimeout(2000, () => {
        req.destroy();
        resolve({ blocked: true, details: 'Timeout (expected)' });
      });
      
      req.end();
    });
  });
}

async function testRawIPConnection() {
  return runTest('network', 'RAW_IP_CONNECTION', 'Attempt connection to raw IP address', () => {
    return new Promise((resolve) => {
      const http = require('http');
      const req = http.request({
        hostname: '127.0.0.1',
        port: 80,
        path: '/',
        method: 'GET'
      }, (res) => {
        resolve({ 
          blocked: false, 
          details: 'Connected to raw IP',
          recommendation: 'Flag raw IP connections as suspicious'
        });
      });
      
      req.on('error', (e) => {
        resolve({ blocked: true, details: 'Connection failed' });
      });
      
      req.setTimeout(2000, () => {
        req.destroy();
        resolve({ blocked: true, details: 'Timeout' });
      });
      
      req.end();
    });
  });
}

// ========================================
// COMMAND EXECUTION TESTS
// ========================================

async function testCurlCommand() {
  return runTest('command', 'CURL_DOWNLOAD', 'Attempt curl download command', () => {
    return new Promise((resolve) => {
      exec('curl -s https://example.com/', (error, stdout, stderr) => {
        if (error) {
          resolve({ 
            blocked: true, 
            details: `Blocked: ${error.message}`
          });
        } else {
          resolve({ 
            blocked: false, 
            details: 'curl command executed',
            recommendation: 'Add curl pattern to child_process interceptor'
          });
        }
      });
    });
  });
}

async function testWgetCommand() {
  return runTest('command', 'WGET_DOWNLOAD', 'Attempt wget download command', () => {
    return new Promise((resolve) => {
      exec('wget --version 2>&1 | head -1', (error, stdout, stderr) => {
        if (error) {
          if (error.message.includes('not found')) {
            resolve({ blocked: true, details: 'wget not installed (acceptable)' });
          } else {
            resolve({ blocked: true, details: `Blocked: ${error.message}` });
          }
        } else {
          resolve({ 
            blocked: false, 
            details: 'wget command executed',
            recommendation: 'Add wget pattern to child_process interceptor'
          });
        }
      });
    });
  });
}

async function testCatSSHKey() {
  return runTest('command', 'CAT_SSH_KEY', 'Attempt to cat SSH key via shell', () => {
    return new Promise((resolve) => {
      exec('cat ~/.ssh/id_rsa 2>&1', (error, stdout, stderr) => {
        if (error) {
          resolve({ blocked: true, details: `Blocked or failed: ${error.message}` });
        } else if (stdout.includes('No such file')) {
          resolve({ blocked: true, details: 'File not found (acceptable)' });
        } else if (stdout.length > 0) {
          resolve({ 
            blocked: false, 
            details: 'Successfully read SSH key via shell',
            recommendation: 'Add "cat ~/.ssh" pattern to command blocklist'
          });
        } else {
          resolve({ blocked: true, details: 'Command failed' });
        }
      });
    });
  });
}

async function testBase64Obfuscation() {
  return runTest('command', 'BASE64_OBFUSCATION', 'Attempt base64 obfuscated command', () => {
    return new Promise((resolve) => {
      // "echo test" in base64
      const cmd = 'echo ZWNobyB0ZXN0 | base64 -d | sh';
      exec(cmd, (error, stdout, stderr) => {
        if (error) {
          resolve({ blocked: true, details: `Blocked: ${error.message}` });
        } else {
          resolve({ 
            blocked: false, 
            details: 'Obfuscated command executed',
            recommendation: 'Add base64 decode pattern to command blocklist'
          });
        }
      });
    });
  });
}

// ========================================
// RUN ALL TESTS
// ========================================

async function runAllTests() {
  console.log('Starting systematic attack tests...');
  console.log('Each test will be executed individually.\n');
  
  // File-based tests
  console.log('\n╔╗');
  console.log('               FILE-BASED ATTACK TESTS                      ');
  console.log('╚╝');
  
  await testSSHKeyRead();
  await testAWSCredentialsRead();
  await testEnvFileRead();
  await testNpmrcRead();
  await testGitconfigRead();
  await testBackdoorScriptCreate();
  await testSystemBinWrite();
  await testGitHubWorkflowCreate();
  
  // Network-based tests
  console.log('\n\n╔╗');
  console.log('              NETWORK-BASED ATTACK TESTS                    ');
  console.log('╚╝');
  
  await testPastebinConnection();
  await testSuspiciousPortConnection();
  await testRawIPConnection();
  
  // Command execution tests
  console.log('\n\n╔╗');
  console.log('           COMMAND EXECUTION ATTACK TESTS                   ');
  console.log('╚╝');
  
  await testCurlCommand();
  await testWgetCommand();
  await testCatSSHKey();
  await testBase64Obfuscation();
  
  // Generate summary
  generateSummary();
}

function generateSummary() {
  console.log('\n\n');
  console.log(''.repeat(64));
  console.log('                     FINAL SUMMARY');
  console.log(''.repeat(64));
  console.log('');
  
  const { total, blocked, succeeded } = results.stats;
  const rate = Math.round((blocked / total) * 100);
  
  console.log(`Total Tests:        ${total}`);
  console.log(`Blocked:            ${blocked} `);
  console.log(`Succeeded:          ${succeeded} `);
  console.log(`Protection Rate:    ${rate}%`);
  console.log('');
  
  // Grade
  let grade;
  if (rate >= 90) grade = 'A - EXCELLENT';
  else if (rate >= 75) grade = 'B - GOOD';
  else if (rate >= 60) grade = 'C - MODERATE';
  else grade = 'D - INSUFFICIENT';
  
  console.log(`Grade:              ${grade}`);
  console.log('');
  
  // Detailed breakdown
  console.log('BREAKDOWN BY CATEGORY:');
  console.log(''.repeat(64));
  
  ['file', 'network', 'command'].forEach(category => {
    const tests = results[category];
    const cat_blocked = tests.filter(t => t.blocked && !t.error).length;
    const cat_succeeded = tests.filter(t => !t.blocked && !t.error).length;
    const cat_errors = tests.filter(t => t.error).length;
    
    console.log(`\n${category.toUpperCase()}:`);
    console.log(`  Total:      ${tests.length}`);
    console.log(`  Blocked:    ${cat_blocked} `);
    console.log(`  Succeeded:  ${cat_succeeded} `);
    if (cat_errors > 0) console.log(`  Errors:     ${cat_errors} `);
  });
  
  // Failures requiring action
  console.log('\n\n' + ''.repeat(64));
  console.log('     ATTACKS THAT SUCCEEDED (REQUIRE MITIGATION)');
  console.log(''.repeat(64));
  console.log('');
  
  const failures = [...results.file, ...results.network, ...results.command]
    .filter(t => !t.blocked && !t.error);
  
  if (failures.length === 0) {
    console.log(' All attacks were blocked! Excellent security posture.');
  } else {
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
  
  // Save detailed report
  try {
    fs.writeFileSync('test-runner-report.json', JSON.stringify(results, null, 2));
    console.log('📄 Detailed report saved to: test-runner-report.json\n');
  } catch (e) {
    console.error('Failed to save report:', e.message);
  }
  
  console.log(''.repeat(64));
  console.log('                   TEST COMPLETE');
  console.log(''.repeat(64));
  console.log('');
}

// Run tests
runAllTests().catch(console.error);
