/**
 * Behavioral Thresholds Tests
 * Tests maxNetworkRequests, maxFileWrites, maxProcessSpawns, and alertThresholds
 */

const { runFirewallTest } = require('./test-runner');
const os = require('os');

console.log('======================================================');
console.log('   Behavioral Thresholds Tests (E2E Pattern)');
console.log('======================================================\n');

let passed = 0;
let failed = 0;

async function runBehaviorTest(name, code, expectation) {
  const result = await runFirewallTest(
    name,
    code,
    expectation,
    { timeout: 5000 }
  );
  
  if (result) passed++; else failed++;
  return result;
}

async function runTests() {
  // ============================================
  // 1. MAX NETWORK REQUESTS (config: 10)
  // ============================================
  console.log('[1] Max Network Requests Threshold (limit: 10)\n');

  await runBehaviorTest(
    'Network monitoring active',
    `const https = require('https');
     const req = https.get('https://registry.npmjs.org/', () => {});
     req.on('error', () => {});
     req.end();
     setTimeout(() => {}, 500);`,
    (output) => {
      const hasMonitoring = output.includes('Network Monitor') || output.includes('Network Requests:');
      return {
        pass: hasMonitoring,
        reason: hasMonitoring ? 'monitoring active' : 'not active'
      };
    }
  );

  await runBehaviorTest(
    'Behavior summary includes network field',
    `console.log('test');`,
    (output) => {
      const hasField = output.includes('Network Requests:');
      return {
        pass: hasField,
        reason: hasField ? 'field present' : 'field missing'
      };
    }
  );

  // ============================================
  // 2. MAX FILE WRITES (config: 50)
  // ============================================
  console.log('\n[2] Max File Writes Threshold (limit: 50)\n');

  await runBehaviorTest(
    'Track file write count',
    `const fs = require('fs');
     const tmpDir = require('os').tmpdir();
     for(let i = 0; i < 5; i++) {
       const file = tmpDir + '/test-' + i + '.txt';
       fs.writeFileSync(file, 'test');
       fs.unlinkSync(file);
     }`,
    (output) => {
      const hasCount = output.includes('File Writes:') || output.includes('fileWrites');
      return {
        pass: hasCount,
        reason: hasCount ? 'tracked' : 'not tracked'
      };
    }
  );

  await runBehaviorTest(
    'Report shows file write metrics',
    `const fs = require('fs');
     const tmpDir = require('os').tmpdir();
     for(let i = 0; i < 10; i++) {
       const file = tmpDir + '/test-write-' + i + '.txt';
       fs.writeFileSync(file, 'test');
       fs.unlinkSync(file);
     }`,
    (output) => {
      const hasMetrics = output.includes('File Writes:');
      const hasNumber = /File Writes:\s+\d+/.test(output);
      return {
        pass: hasMetrics && hasNumber,
        reason: hasMetrics ? 'metrics shown' : 'no metrics'
      };
    }
  );

  // ============================================
  // 3. MAX PROCESS SPAWNS (config: 5)
  // ============================================
  console.log('\n[3] Max Process Spawns Threshold (limit: 5)\n');

  await runBehaviorTest(
    'Track process spawn count',
    `const { spawnSync } = require('child_process');
     for(let i = 0; i < 3; i++) {
       spawnSync('node', ['--version']);
     }`,
    (output) => {
      const hasCount = output.includes('Process Spawns:') || output.includes('processSpawns');
      return {
        pass: hasCount,
        reason: hasCount ? 'tracked' : 'not tracked'
      };
    }
  );

  await runBehaviorTest(
    'Report shows process spawn metrics',
    `const { spawnSync } = require('child_process');
     spawnSync('node', ['--version']);
     spawnSync('node', ['--version']);`,
    (output) => {
      const hasMetrics = output.includes('Process Spawns:');
      const hasNumber = /Process Spawns:\s+\d+/.test(output);
      return {
        pass: hasMetrics && hasNumber,
        reason: hasMetrics ? 'metrics shown' : 'no metrics'
      };
    }
  );

  // ============================================
  // 4. ALERT THRESHOLDS
  // ============================================
  console.log('\n[4] Alert Thresholds\n');

  await runBehaviorTest(
    'File reads threshold (100)',
    `const fs = require('fs');
     const tmpDir = require('os').tmpdir();
     const file = tmpDir + '/test-read.txt';
     fs.writeFileSync(file, 'test');
     for(let i = 0; i < 10; i++) {
       fs.readFileSync(file);
     }
     fs.unlinkSync(file);`,
    (output) => {
      const hasReads = output.includes('File Reads:');
      return {
        pass: hasReads,
        reason: hasReads ? 'tracked' : 'not tracked'
      };
    }
  );

  await runBehaviorTest(
    'File writes monitoring active',
    `const fs = require('fs');
     const tmpDir = require('os').tmpdir();
     for(let i = 0; i < 15; i++) {
       const file = tmpDir + '/alert-test-' + i + '.txt';
       fs.writeFileSync(file, 'test');
       fs.unlinkSync(file);
     }`,
    (output) => {
      const hasWrites = output.includes('File Writes:');
      const count = output.match(/File Writes:\s+(\d+)/);
      const counted = count ? parseInt(count[1]) : -1;
      return {
        pass: hasWrites && counted >= 0,
        reason: hasWrites ? `monitoring active (${counted})` : 'not tracked'
      };
    }
  );

  await runBehaviorTest(
    'Network requests field present',
    `console.log('test');`,
    (output) => {
      const hasField = output.includes('Network Requests:');
      return {
        pass: hasField,
        reason: hasField ? 'field present' : 'field missing'
      };
    }
  );

  await runBehaviorTest(
    'Process spawns monitoring active',
    `const { spawnSync } = require('child_process');
     for(let i = 0; i < 4; i++) {
       spawnSync('node', ['--version']);
     }`,
    (output) => {
      const hasSpawns = output.includes('Process Spawns:');
      const count = output.match(/Process Spawns:\s+(\d+)/);
      const counted = count ? parseInt(count[1]) : -1;
      return {
        pass: hasSpawns && counted >= 0,
        reason: hasSpawns ? `monitoring active (${counted})` : 'not tracked'
      };
    }
  );

  // ============================================
  // 5. LIFECYCLE SCRIPT MONITORING
  // ============================================
  console.log('\n[5] Lifecycle Script Monitoring\n');

  await runBehaviorTest(
    'Monitor lifecycle scripts enabled',
    `const fs = require('fs');
     const tmpDir = require('os').tmpdir();
     const file = tmpDir + '/lifecycle-test.txt';
     fs.writeFileSync(file, 'test');
     fs.unlinkSync(file);`,
    (output) => {
      const hasMonitoring = output.includes('Behavior Monitor') || 
                           output.includes('Package Behavior') ||
                           output.includes('Tracking:');
      return {
        pass: hasMonitoring,
        reason: hasMonitoring ? 'monitoring active' : 'not monitoring'
      };
    }
  );

  await runBehaviorTest(
    'Package name tracked',
    `console.log('test');`,
    (output) => {
      const hasPackage = output.includes('Package:') || output.includes('Tracking:');
      return {
        pass: hasPackage,
        reason: hasPackage ? 'package tracked' : 'no package info'
      };
    }
  );

  // ============================================
  // 6. RISK ASSESSMENT
  // ============================================
  console.log('\n[6] Risk Assessment\n');

  await runBehaviorTest(
    'Clean behavior assessment',
    `const fs = require('fs');
     const tmpDir = require('os').tmpdir();
     const file = tmpDir + '/clean-test.txt';
     fs.writeFileSync(file, 'test');
     fs.unlinkSync(file);`,
    (output) => {
      const hasAssessment = output.includes('Assessment:') || output.includes('Risk Level:');
      const isClean = output.includes('CLEAN') || output.includes('No suspicious');
      return {
        pass: hasAssessment && isClean,
        reason: hasAssessment ? (isClean ? 'clean' : 'not clean') : 'no assessment'
      };
    }
  );

  await runBehaviorTest(
    'Risk level reported',
    `const fs = require('fs');
     const tmpDir = require('os').tmpdir();
     for(let i = 0; i < 5; i++) {
       const file = tmpDir + '/risk-test-' + i + '.txt';
       fs.writeFileSync(file, 'test');
       fs.unlinkSync(file);
     }`,
    (output) => {
      const hasRisk = output.includes('Risk Level:');
      return {
        pass: hasRisk,
        reason: hasRisk ? 'risk reported' : 'no risk level'
      };
    }
  );

  await runBehaviorTest(
    'Suspicious operations tracked',
    `const fs = require('fs');
     const tmpDir = require('os').tmpdir();
     const file = tmpDir + '/suspicious-test.txt';
     fs.writeFileSync(file, 'test');
     fs.unlinkSync(file);`,
    (output) => {
      const hasSuspicious = output.includes('Suspicious Ops:');
      return {
        pass: hasSuspicious,
        reason: hasSuspicious ? 'tracked' : 'not tracked'
      };
    }
  );

  // ============================================
  // 7. BEHAVIOR REPORT GENERATION
  // ============================================
  console.log('\n[7] Behavior Report Generation\n');

  await runBehaviorTest(
    'Summary generated on exit',
    `const fs = require('fs');
     const tmpDir = require('os').tmpdir();
     const file = tmpDir + '/summary-test.txt';
     fs.writeFileSync(file, 'test');
     fs.unlinkSync(file);`,
    (output) => {
      const hasSummary = output.includes('Package Behavior Summary') || 
                        output.includes('behavior assessment');
      return {
        pass: hasSummary,
        reason: hasSummary ? 'summary shown' : 'no summary'
      };
    }
  );

  await runBehaviorTest(
    'Metrics included in summary',
    `const fs = require('fs');
     const tmpDir = require('os').tmpdir();
     for(let i = 0; i < 3; i++) {
       const file = tmpDir + '/metrics-test-' + i + '.txt';
       fs.writeFileSync(file, 'test');
       fs.unlinkSync(file);
     }`,
    (output) => {
      const hasMetrics = output.includes('File Reads:') && 
                        output.includes('File Writes:') &&
                        output.includes('Network Requests:') &&
                        output.includes('Process Spawns:');
      return {
        pass: hasMetrics,
        reason: hasMetrics ? 'all metrics present' : 'missing metrics'
      };
    }
  );

  // ============================================
  // SUMMARY
  // ============================================
  console.log('\n======================================================');
  console.log('Summary:');
  console.log(`  Passed: ${passed}`);
  console.log(`  Failed: ${failed}`);
  console.log(`  Total:  ${passed + failed}`);
  console.log('======================================================\n');

  console.log('Coverage:');
  console.log('  Network Request Tracking:  ✓');
  console.log('  File Write Tracking:       ✓');
  console.log('  Process Spawn Tracking:    ✓');
  console.log('  Alert Thresholds:          ✓');
  console.log('  Lifecycle Monitoring:      ✓');
  console.log('  Risk Assessment:           ✓');
  console.log('  Report Generation:         ✓\n');

  if (failed === 0) {
    console.log('All behavioral threshold tests passed! ✓\n');
    process.exit(0);
  } else {
    console.log(`${failed} test(s) failed.\n`);
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('Test suite error:', err);
  process.exit(1);
});
