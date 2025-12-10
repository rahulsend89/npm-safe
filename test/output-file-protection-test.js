/**
 * Output File Protection Tests
 * Tests protection against malicious overwriting/deletion of firewall output files
 * 
 * Attack Vector: Shai-Hulud and similar attacks may attempt to:
 * 1. Delete firewall logs to hide tracks
 * 2. Overwrite audit logs with fake data
 * 3. Corrupt behavior reports
 */

const { runFirewallTest } = require('./test-runner');

async function runTests() {
  console.log('======================================================');
  console.log('   Output File Protection Tests');
  console.log('======================================================\n');

  let passed = 0;
  let failed = 0;

  // ============================================
  // 1. AUDIT LOG PROTECTION
  // ============================================
  console.log('[1] Audit Log Protection\n');

  if (await runFirewallTest(
    'Cannot delete firewall-audit.jsonl',
    `const fs = require('fs');
     const path = require('path');
     try {
       const auditPath = path.join(process.cwd(), 'firewall-audit.jsonl');
       fs.unlinkSync(auditPath);
       console.log('DELETED');
     } catch(e) {
       if(e.message.includes('Firewall') || e.code === 'EACCES') {
         console.log('PROTECTED');
       } else {
         console.log('FILE_NOT_EXIST');
       }
     }`,
    (output) => {
      // Either protected by firewall or file doesn't exist (both OK)
      const isProtected = output.includes('PROTECTED') || output.includes('FILE_NOT_EXIST');
      return {
        pass: isProtected,
        reason: isProtected ? 'protected or not exist' : 'deletion allowed'
      };
    }
  )) passed++; else failed++;

  if (await runFirewallTest(
    'Cannot overwrite firewall-audit.jsonl',
    `const fs = require('fs');
     const path = require('path');
     try {
       const auditPath = path.join(process.cwd(), 'firewall-audit.jsonl');
       fs.writeFileSync(auditPath, 'FAKE_DATA');
       console.log('OVERWRITTEN');
     } catch(e) {
       if(e.message.includes('Firewall') || e.code === 'EACCES') {
         console.log('PROTECTED');
       } else {
         console.log('ERROR');
       }
     }`,
    (output) => {
      // Should be protected or error (both OK)
      const isProtected = output.includes('PROTECTED') || output.includes('ERROR');
      return {
        pass: isProtected,
        reason: isProtected ? 'protected' : 'overwrite allowed'
      };
    }
  )) passed++; else failed++;

  // ============================================
  // 2. BEHAVIOR REPORT PROTECTION
  // ============================================
  console.log('\n[2] Behavior Report Protection\n');

  if (await runFirewallTest(
    'Cannot delete firewall-report.json',
    `const fs = require('fs');
     const path = require('path');
     try {
       const reportPath = path.join(process.cwd(), 'firewall-report.json');
       fs.unlinkSync(reportPath);
       console.log('DELETED');
     } catch(e) {
       if(e.message.includes('Firewall') || e.code === 'EACCES') {
         console.log('PROTECTED');
       } else {
         console.log('FILE_NOT_EXIST');
       }
     }`,
    (output) => {
      const isProtected = output.includes('PROTECTED') || output.includes('FILE_NOT_EXIST');
      return {
        pass: isProtected,
        reason: isProtected ? 'protected or not exist' : 'deletion allowed'
      };
    }
  )) passed++; else failed++;

  if (await runFirewallTest(
    'Cannot tamper with firewall-report.json',
    `const fs = require('fs');
     const path = require('path');
     try {
       const reportPath = path.join(process.cwd(), 'firewall-report.json');
       fs.writeFileSync(reportPath, '{"risk":"clean","fake":true}');
       console.log('TAMPERED');
     } catch(e) {
       if(e.message.includes('Firewall') || e.code === 'EACCES') {
         console.log('PROTECTED');
       } else {
         console.log('ERROR');
       }
     }`,
    (output) => {
      const isProtected = output.includes('PROTECTED') || output.includes('ERROR');
      return {
        pass: isProtected,
        reason: isProtected ? 'protected' : 'tampering allowed'
      };
    }
  )) passed++; else failed++;

  // ============================================
  // 3. FS LOG PROTECTION
  // ============================================
  console.log('\n[3] Filesystem Log Protection\n');

  if (await runFirewallTest(
    'Cannot delete fs-firewall.log',
    `const fs = require('fs');
     const path = require('path');
     try {
       const logPath = path.join(process.cwd(), 'fs-firewall.log');
       fs.unlinkSync(logPath);
       console.log('DELETED');
     } catch(e) {
       if(e.message.includes('Firewall') || e.code === 'EACCES') {
         console.log('PROTECTED');
       } else {
         console.log('FILE_NOT_EXIST');
       }
     }`,
    (output) => {
      const isProtected = output.includes('PROTECTED') || output.includes('FILE_NOT_EXIST');
      return {
        pass: isProtected,
        reason: isProtected ? 'protected or not exist' : 'deletion allowed'
      };
    }
  )) passed++; else failed++;

  if (await runFirewallTest(
    'Cannot overwrite fs-firewall.log',
    `const fs = require('fs');
     const path = require('path');
     try {
       const logPath = path.join(process.cwd(), 'fs-firewall.log');
       fs.writeFileSync(logPath, 'FAKE_LOG_DATA');
       console.log('OVERWRITTEN');
     } catch(e) {
       if(e.message.includes('Firewall') || e.code === 'EACCES') {
         console.log('PROTECTED');
       } else {
         console.log('ERROR');
       }
     }`,
    (output) => {
      const isProtected = output.includes('PROTECTED') || output.includes('ERROR');
      return {
        pass: isProtected,
        reason: isProtected ? 'protected' : 'overwrite allowed'
      };
    }
  )) passed++; else failed++;

  // ============================================
  // 4. ZERO-TRUST LOG PROTECTION
  // ============================================
  console.log('\n[4] Zero-Trust Log Protection\n');

  if (await runFirewallTest(
    'Cannot delete firewall-zero-trust.log',
    `const fs = require('fs');
     const path = require('path');
     try {
       const logPath = path.join(process.cwd(), 'firewall-zero-trust.log');
       fs.unlinkSync(logPath);
       console.log('DELETED');
     } catch(e) {
       if(e.message.includes('Firewall') || e.code === 'EACCES') {
         console.log('PROTECTED');
       } else {
         console.log('FILE_NOT_EXIST');
       }
     }`,
    (output) => {
      const isProtected = output.includes('PROTECTED') || output.includes('FILE_NOT_EXIST');
      return {
        pass: isProtected,
        reason: isProtected ? 'protected or not exist' : 'deletion allowed'
      };
    }
  )) passed++; else failed++;

  // ============================================
  // 5. BULK TAMPERING ATTEMPT
  // ============================================
  console.log('\n[5] Bulk Tampering Detection\n');

  if (await runFirewallTest(
    'Detects bulk log file tampering',
    `const fs = require('fs');
     const path = require('path');
     const files = [
       'firewall-audit.jsonl',
       'firewall-report.json',
       'fs-firewall.log',
       'firewall-zero-trust.log'
     ];
     let tampered = 0;
     files.forEach(file => {
       try {
         const filePath = path.join(process.cwd(), file);
         fs.writeFileSync(filePath, 'FAKE');
         tampered++;
       } catch(e) {}
     });
     console.log(\`TAMPERED_\${tampered}\`);`,
    (output) => {
      // Should tamper 0 or very few files
      const match = output.match(/TAMPERED_(\d+)/);
      const tamperedCount = match ? parseInt(match[1]) : 0;
      const isProtected = tamperedCount === 0;
      return {
        pass: isProtected,
        reason: isProtected ? 'all protected' : `${tamperedCount} files tampered`
      };
    }
  )) passed++; else failed++;

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
  console.log('  Audit Log Protection:       ✓');
  console.log('  Behavior Report Protection: ✓');
  console.log('  FS Log Protection:          ✓');
  console.log('  Zero-Trust Log Protection:  ✓');
  console.log('  Bulk Tampering Detection:   ✓\n');

  if (failed > 0) {
    console.log(`${failed} test(s) failed.\n`);
    process.exit(1);
  } else {
    console.log('All output file protection tests passed! ✓\n');
  }
}

runTests().catch(err => {
  console.error('Test runner error:', err);
  process.exit(1);
});
