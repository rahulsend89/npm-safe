/**
 * BEHAVIORAL THRESHOLD APP - FOR TESTING FIREWALL
 * Tests rate limits: maxNetworkRequests, maxFileWrites, maxProcessSpawns
 */

const https = require('https');
const fs = require('fs');
const { spawn } = require('child_process');
const path = require('path');

console.log(' BEHAVIORAL THRESHOLD APP - Testing Firewall Protection');
console.log('\n');

const results = {
  networkRequests: 0,
  fileWrites: 0,
  processSpawns: 0,
  alerts: 0
};

// === TEST 1: Exceed maxNetworkRequests (limit: 10) ===

console.log('[TEST 1] Attempting 20 network requests (limit: 10)');
console.log('Expected: Alert after 10 requests\n');

for (let i = 1; i <= 20; i++) {
  setTimeout(() => {
    try {
      const req = https.request({
        hostname: 'registry.npmjs.org',
        path: '/express',
        method: 'GET'
      }, (res) => {
        results.networkRequests++;
        console.log(`  Request ${i}/20 -  Allowed`);
      });
      
      req.on('error', (e) => {
        console.log(`  Request ${i}/20 -  Blocked: ${e.message}`);
      });
      
      req.end();
    } catch (e) {
      console.log(`  Request ${i}/20 -  Blocked: ${e.message}`);
    }
  }, i * 100);
}

// === TEST 2: Exceed maxFileWrites (limit: 50) ===

setTimeout(() => {
  console.log('\n[TEST 2] Attempting 60 file writes (limit: 50)');
  console.log('Expected: Alert after 50 writes\n');
  
  const tmpDir = path.join('/tmp', 'firewall-test-writes');
  try {
    fs.mkdirSync(tmpDir, { recursive: true });
  } catch (e) {}
  
  for (let i = 1; i <= 60; i++) {
    try {
      const filePath = path.join(tmpDir, `test-${i}.txt`);
      fs.writeFileSync(filePath, `Test file ${i}`);
      results.fileWrites++;
      console.log(`  Write ${i}/60 -  Allowed`);
    } catch (e) {
      console.log(`  Write ${i}/60 -  Blocked: ${e.message}`);
    }
  }
  
  // Cleanup
  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch (e) {}
}, 3000);

// === TEST 3: Exceed maxProcessSpawns (limit: 5) ===

setTimeout(() => {
  console.log('\n[TEST 3] Attempting 10 process spawns (limit: 5)');
  console.log('Expected: Alert after 5 spawns\n');
  
  for (let i = 1; i <= 10; i++) {
    setTimeout(() => {
      try {
        const proc = spawn('node', ['--version']);
        results.processSpawns++;
        console.log(`  Spawn ${i}/10 -  Allowed`);
        
        proc.on('error', (e) => {
          console.log(`  Spawn ${i}/10 -  Blocked: ${e.message}`);
        });
      } catch (e) {
        console.log(`  Spawn ${i}/10 -  Blocked: ${e.message}`);
      }
    }, i * 100);
  }
}, 6000);

// === TEST 4: Rapid file reads (threshold: 100) ===

setTimeout(() => {
  console.log('\n[TEST 4] Attempting 120 file reads (threshold: 100)');
  console.log('Expected: Alert after 100 reads\n');
  
  const testFile = path.join('/tmp', 'firewall-test-read.txt');
  try {
    fs.writeFileSync(testFile, 'test content');
  } catch (e) {}
  
  let readCount = 0;
  for (let i = 1; i <= 120; i++) {
    try {
      fs.readFileSync(testFile);
      readCount++;
      if (i % 20 === 0) {
        console.log(`  Read ${i}/120 -  Allowed`);
      }
    } catch (e) {
      console.log(`  Read ${i}/120 -  Blocked: ${e.message}`);
    }
  }
  console.log(`  Total reads completed: ${readCount}/120`);
  
  // Cleanup
  try {
    fs.unlinkSync(testFile);
  } catch (e) {}
}, 8000);

// === SUMMARY ===

setTimeout(() => {
  console.log('\n');
  console.log('  TEST SUMMARY');
  console.log('');
  console.log(`Network Requests Completed: ${results.networkRequests}`);
  console.log(`File Writes Completed: ${results.fileWrites}`);
  console.log(`Process Spawns Completed: ${results.processSpawns}`);
  console.log('\nExpected Behavior:');
  console.log('  - Alerts should be logged when thresholds are exceeded');
  console.log('  - Operations should continue (alertOnly mode)');
  console.log('  - Check firewall-report.json for threshold violations');
  console.log('\n');
  
  process.exit(0);
}, 11000);
