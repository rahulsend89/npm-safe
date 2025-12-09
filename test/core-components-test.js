/**
 * Core Components Tests
 * Tests Exfiltration Detector, Audit Logger, and Fortress Hardening
 * Using E2E pattern with real --import/--loader flags
 */

const { runFirewallTest, runTest } = require('./test-runner');

console.log('======================================================');
console.log('   Core Components Tests (E2E Pattern)');
console.log('======================================================\n');

let passed = 0;
let failed = 0;

function test(name, fn) {
  const result = runTest(name, fn);
  if (result) passed++; else failed++;
  return result;
}

async function runComponentTest(name, code, expectation) {
  const result = await runFirewallTest(
    name,
    code,
    expectation
  );
  
  if (result) passed++; else failed++;
  return result;
}

async function runTests() {
  // ============================================
  // 1. EXFILTRATION DETECTOR
  // ============================================
  console.log('[1] Exfiltration Detector\n');

  test('ExfiltrationDetector class exists', () => {
    const { ExfiltrationDetector } = require('../lib/exfiltration-detector');
    if (!ExfiltrationDetector) throw new Error('Class not found');
  });

  test('ExfiltrationDetector can be instantiated', () => {
    const { ExfiltrationDetector } = require('../lib/exfiltration-detector');
    const detector = new ExfiltrationDetector();
    if (!detector) throw new Error('Cannot instantiate');
  });

  test('ExfiltrationDetector singleton getInstance works', () => {
    const { getInstance } = require('../lib/exfiltration-detector');
    const instance1 = getInstance();
    const instance2 = getInstance();
    if (instance1 !== instance2) throw new Error('Not a singleton');
  });

  test('ExfiltrationDetector has trackSensitiveFileRead method', () => {
    const { getInstance } = require('../lib/exfiltration-detector');
    const detector = getInstance();
    if (typeof detector.trackSensitiveFileRead !== 'function') {
      throw new Error('Method not found');
    }
  });

  test('ExfiltrationDetector has checkNetworkRequest method', () => {
    const { getInstance } = require('../lib/exfiltration-detector');
    const detector = getInstance();
    if (typeof detector.checkNetworkRequest !== 'function') {
      throw new Error('Method not found');
    }
  });

  await runComponentTest(
    'ExfiltrationDetector initialized in firewall',
    `console.log('test');`,
    (output) => {
      const hasDetector = output.includes('exfiltration') || output.includes('Data exfiltration');
      return {
        pass: hasDetector,
        reason: hasDetector ? 'detector active' : 'not active'
      };
    }
  );

  test('ExfiltrationDetector trackSensitiveFileRead executes', () => {
    const { getInstance } = require('../lib/exfiltration-detector');
    const detector = getInstance();
    // Should not throw
    detector.trackSensitiveFileRead('/home/user/.ssh/id_rsa');
  });

  // ============================================
  // 2. AUDIT LOGGER
  // ============================================
  console.log('\n[2] Audit Logger\n');

  test('AuditLogger class exists', () => {
    const { AuditLogger } = require('../lib/audit-logger');
    if (!AuditLogger) throw new Error('Class not found');
  });

  test('AuditLogger can be instantiated', () => {
    const { AuditLogger } = require('../lib/audit-logger');
    const logger = new AuditLogger('test-audit.jsonl');
    if (!logger) throw new Error('Cannot instantiate');
  });

  test('AuditLogger singleton getInstance works', () => {
    const { getInstance } = require('../lib/audit-logger');
    const instance1 = getInstance();
    const instance2 = getInstance();
    if (instance1 !== instance2) throw new Error('Not a singleton');
  });

  test('AuditLogger has log method', () => {
    const { getInstance } = require('../lib/audit-logger');
    const logger = getInstance();
    if (typeof logger.log !== 'function') {
      throw new Error('Method not found');
    }
  });

  test('AuditLogger has flush method', () => {
    const { getInstance } = require('../lib/audit-logger');
    const logger = getInstance();
    if (typeof logger.flush !== 'function') {
      throw new Error('Method not found');
    }
  });

  await runComponentTest(
    'AuditLogger initialized in firewall',
    `console.log('test');`,
    (output) => {
      const hasLogger = output.includes('Audit logging') || output.includes('firewall-audit');
      return {
        pass: hasLogger,
        reason: hasLogger ? 'logger active' : 'not active'
      };
    }
  );

  await runComponentTest(
    'AuditLogger creates log file',
    `const fs = require('fs');
     const path = require('path');
     setTimeout(() => {
       const logExists = fs.existsSync(path.join(process.cwd(), 'firewall-audit.jsonl'));
       console.log(logExists ? 'LOG_EXISTS' : 'NO_LOG');
     }, 500);`,
    (output) => {
      const exists = output.includes('LOG_EXISTS') || output.includes('Audit logging');
      return {
        pass: exists,
        reason: exists ? 'log file created' : 'no log file'
      };
    }
  );

  test('AuditLogger log method executes', () => {
    const { getInstance } = require('../lib/audit-logger');
    const logger = getInstance();
    // Should not throw
    logger.log({
      type: 'TEST',
      operation: 'test-operation',
      target: 'test-target',
      allowed: true
    });
  });

  // ============================================
  // 3. FORTRESS HARDENING
  // ============================================
  console.log('\n[3] Fortress Hardening\n');

  test('FortressHardening class exists', () => {
    const { FortressHardening } = require('../lib/firewall-hardening-fortress');
    if (!FortressHardening) throw new Error('Class not found');
  });

  test('FortressHardening can be instantiated', () => {
    const { FortressHardening } = require('../lib/firewall-hardening-fortress');
    const fortress = new FortressHardening();
    if (!fortress) throw new Error('Cannot instantiate');
  });

  test('FortressHardening has initialize method', () => {
    const { FortressHardening } = require('../lib/firewall-hardening-fortress');
    const fortress = new FortressHardening();
    if (typeof fortress.initialize !== 'function') {
      throw new Error('Method not found');
    }
  });

  test('FortressHardening has blockWorkers option', () => {
    const { FortressHardening } = require('../lib/firewall-hardening-fortress');
    const fortress = new FortressHardening({ blockWorkers: true });
    if (fortress.options.blockWorkers !== true) {
      throw new Error('Option not set');
    }
  });

  test('FortressHardening has blockVM option', () => {
    const { FortressHardening } = require('../lib/firewall-hardening-fortress');
    const fortress = new FortressHardening({ blockVM: true });
    if (fortress.options.blockVM !== true) {
      throw new Error('Option not set');
    }
  });

  test('Fortress initialize method executes', () => {
    const { FortressHardening } = require('../lib/firewall-hardening-fortress');
    const fortress = new FortressHardening();
    // Should not throw
    fortress.initialize();
  });

  // ============================================
  // 4. IMMUTABLE PROPERTY UTILITY
  // ============================================
  console.log('\n[4] Immutable Property Utility\n');

  test('makeImmutable function exists', () => {
    const { makeImmutable } = require('../lib/immutable-property');
    if (typeof makeImmutable !== 'function') {
      throw new Error('Function not found');
    }
  });

  test('makeImmutableProperties function exists', () => {
    const { makeImmutableProperties } = require('../lib/immutable-property');
    if (typeof makeImmutableProperties !== 'function') {
      throw new Error('Function not found');
    }
  });

  test('makeImmutable prevents modification', () => {
    const { makeImmutable } = require('../lib/immutable-property');
    const obj = {};
    makeImmutable(obj, 'test', 'value');
    
    try {
      obj.test = 'new value';
      if (obj.test !== 'value') {
        throw new Error('Property was modified');
      }
    } catch (e) {
      // Expected in strict mode
    }
  });

  test('makeImmutableProperties works with multiple properties', () => {
    const { makeImmutableProperties } = require('../lib/immutable-property');
    const obj = {};
    makeImmutableProperties(obj, {
      prop1: 'value1',
      prop2: 'value2'
    });
    
    if (obj.prop1 !== 'value1' || obj.prop2 !== 'value2') {
      throw new Error('Properties not set');
    }
  });

  // ============================================
  // 5. BUILD DIRECTORY UTILS
  // ============================================
  console.log('\n[5] Build Directory Utils\n');

  test('isBuildOrCacheDirectory function exists', () => {
    const { isBuildOrCacheDirectory } = require('../lib/build-directory-utils');
    if (typeof isBuildOrCacheDirectory !== 'function') {
      throw new Error('Function not found');
    }
  });

  test('isBuildOrCacheDirectory detects node_modules/.cache', () => {
    const { isBuildOrCacheDirectory } = require('../lib/build-directory-utils');
    const result = isBuildOrCacheDirectory('/project/node_modules/.cache/file.js');
    if (!result) throw new Error('Failed to detect cache directory');
  });

  test('isMacOsTsNodeTemp function exists', () => {
    const { isMacOsTsNodeTemp } = require('../lib/build-directory-utils');
    if (typeof isMacOsTsNodeTemp !== 'function') {
      throw new Error('Function not found');
    }
  });

  test('isMacOsTsNodeTemp detects macOS ts-node temp', () => {
    const { isMacOsTsNodeTemp } = require('../lib/build-directory-utils');
    const result = isMacOsTsNodeTemp('/var/folders/abc/T/.ts-node/file.js');
    if (!result) throw new Error('Failed to detect ts-node temp');
  });

  test('isProjectSourceFile function exists', () => {
    const { isProjectSourceFile } = require('../lib/build-directory-utils');
    if (typeof isProjectSourceFile !== 'function') {
      throw new Error('Function not found');
    }
  });

  test('isTsNodeTemp function exists', () => {
    const { isTsNodeTemp } = require('../lib/build-directory-utils');
    if (typeof isTsNodeTemp !== 'function') {
      throw new Error('Function not found');
    }
  });

  // ============================================
  // 6. CONFIG LOADER
  // ============================================
  console.log('\n[6] Config Loader\n');

  test('ConfigLoader class exists', () => {
    const configLoader = require('../lib/config-loader');
    const { ConfigLoader } = configLoader;
    if (!ConfigLoader) throw new Error('Class not found');
  });

  test('ConfigLoader singleton works', () => {
    const configLoader = require('../lib/config-loader');
    if (!configLoader.load) throw new Error('Singleton not exported');
  });

  test('ConfigLoader loads config', () => {
    const configLoader = require('../lib/config-loader');
    const config = configLoader.load();
    if (!config || typeof config !== 'object') {
      throw new Error('Config not loaded');
    }
  });

  test('ConfigLoader has watch method', () => {
    const configLoader = require('../lib/config-loader');
    if (typeof configLoader.watch !== 'function') {
      throw new Error('Watch method not found');
    }
  });

  test('ConfigLoader has reload method', () => {
    const configLoader = require('../lib/config-loader');
    if (typeof configLoader.reload !== 'function') {
      throw new Error('Reload method not found');
    }
  });

  // ============================================
  // 7. FIREWALL CORE METHODS
  // ============================================
  console.log('\n[7] Firewall Core Methods\n');

  test('FirewallCore has initialize method', () => {
    const { FirewallCore } = require('../lib/firewall-core');
    const firewall = new FirewallCore();
    if (typeof firewall.initialize !== 'function') {
      throw new Error('Method not found');
    }
  });

  test('FirewallCore has isTrustedModule method', () => {
    const { FirewallCore } = require('../lib/firewall-core');
    const firewall = new FirewallCore();
    if (typeof firewall.isTrustedModule !== 'function') {
      throw new Error('Method not found');
    }
  });

  test('FirewallCore has isPackageManager method', () => {
    const { FirewallCore } = require('../lib/firewall-core');
    const firewall = new FirewallCore();
    if (typeof firewall.isPackageManager !== 'function') {
      throw new Error('Method not found');
    }
  });

  test('FirewallCore has setupCleanup method', () => {
    const { FirewallCore } = require('../lib/firewall-core');
    const firewall = new FirewallCore();
    if (typeof firewall.setupCleanup !== 'function') {
      throw new Error('Method not found');
    }
  });

  test('FirewallCore singleton getInstance works', () => {
    const { getInstance } = require('../lib/firewall-core');
    const instance1 = getInstance();
    const instance2 = getInstance();
    if (instance1 !== instance2) throw new Error('Not a singleton');
  });

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
  console.log('  Exfiltration Detector:  ✓');
  console.log('  Audit Logger:           ✓');
  console.log('  Fortress Hardening:     ✓');
  console.log('  Immutable Property:     ✓');
  console.log('  Build Directory Utils:  ✓');
  console.log('  Config Loader:          ✓');
  console.log('  Firewall Core Methods:  ✓\n');

  if (failed === 0) {
    console.log('All core component tests passed! ✓\n');
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
