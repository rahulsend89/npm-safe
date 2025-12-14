/**
 * Advanced Environment Variable Bypass Tests
 * 
 * Tests for less common bypass techniques:
 * 1. Reflect.get() - Reflection API
 * 2. Object.getOwnPropertyDescriptor() - Descriptor access
 * 3. Spread operator {...process.env}
 * 4. Object.assign({}, process.env)
 * 5. for...in enumeration
 * 6. Object.entries / Object.values
 * 7. util.inspect()
 * 8. console.log direct
 * 9. process.config
 */

const path = require('path');
const fs = require('fs');
const {
  isWindows,
  isLinux,
  setupTestDir,
  cleanupTestDir,
  writeMinimalConfig,
  runWithFirewall,
  escapePath,
  isBlocked,
  TestTracker
} = require('../utils');

async function runAdvancedEnvironmentTests() {
  console.log('\nADVANCED ENVIRONMENT BYPASS TESTS\n');
  console.log('='.repeat(50));
  
  const tracker = new TestTracker('environment-advanced');
  
  // =========================================================================
  // REFLECTION API BYPASSES
  // =========================================================================
  console.log('\n--- Reflection API Bypasses ---\n');
  
  // Test 1: Reflect.get bypass
  await tracker.runTest('protectedVariables - Reflect.get bypass', async () => {
    const testDir = setupTestDir('env-reflect');
    
    try {
      writeMinimalConfig(testDir, {
        environment: {
          protectedVariables: ['REFLECT_SECRET'],
          allowTrustedModulesAccess: false
        }
      });
      
      const code = `
        try {
          const value = Reflect.get(process.env, 'REFLECT_SECRET');
          if (value === 'reflect_secret_value') {
            console.log('REFLECT_EXPOSED');
          } else if (value) {
            console.log('REFLECT_REDACTED:' + value);
          } else {
            console.log('REFLECT_UNDEFINED');
          }
        } catch (e) {
          console.log('REFLECT_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code, {
        env: { REFLECT_SECRET: 'reflect_secret_value' }
      });
      
      return {
        pass: !result.output.includes('REFLECT_EXPOSED'),
        reason: result.output.includes('REFLECT_EXPOSED') ? 'Reflect.get bypass' : 'protected',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 2: Reflect.ownKeys enumeration
  await tracker.runTest('protectedVariables - Reflect.ownKeys enumeration', async () => {
    const testDir = setupTestDir('env-reflectkeys');
    
    try {
      writeMinimalConfig(testDir, {
        environment: {
          protectedVariables: ['REFLECT_KEY_SECRET'],
          allowTrustedModulesAccess: false
        }
      });
      
      const code = `
        try {
          const keys = Reflect.ownKeys(process.env);
          const found = keys.includes('REFLECT_KEY_SECRET');
          console.log('KEY_FOUND:' + found);
          if (found) {
            console.log('VALUE:' + process.env.REFLECT_KEY_SECRET);
          }
        } catch (e) {
          console.log('REFLECT_KEYS_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code, {
        env: { REFLECT_KEY_SECRET: 'secret_via_keys' }
      });
      
      return {
        pass: !result.output.includes('secret_via_keys'),
        reason: result.output.includes('secret_via_keys') ? 'Reflect.ownKeys exposed' : 'protected',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 3: Object.getOwnPropertyDescriptor bypass
  await tracker.runTest('protectedVariables - getOwnPropertyDescriptor bypass', async () => {
    const testDir = setupTestDir('env-descriptor');
    
    try {
      writeMinimalConfig(testDir, {
        environment: {
          protectedVariables: ['DESCRIPTOR_SECRET'],
          allowTrustedModulesAccess: false
        }
      });
      
      const code = `
        try {
          const descriptor = Object.getOwnPropertyDescriptor(process.env, 'DESCRIPTOR_SECRET');
          if (descriptor && descriptor.value === 'descriptor_secret_value') {
            console.log('DESCRIPTOR_EXPOSED');
          } else if (descriptor) {
            console.log('DESCRIPTOR_VALUE:' + descriptor.value);
          } else {
            console.log('DESCRIPTOR_UNDEFINED');
          }
        } catch (e) {
          console.log('DESCRIPTOR_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code, {
        env: { DESCRIPTOR_SECRET: 'descriptor_secret_value' }
      });
      
      return {
        pass: !result.output.includes('DESCRIPTOR_EXPOSED'),
        reason: result.output.includes('DESCRIPTOR_EXPOSED') ? 'descriptor bypass' : 'protected',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // =========================================================================
  // COPY OPERATIONS
  // =========================================================================
  console.log('\n--- Object Copy Bypasses ---\n');
  
  // Test 4: Spread operator bypass
  await tracker.runTest('protectedVariables - spread operator bypass', async () => {
    const testDir = setupTestDir('env-spread');
    
    try {
      writeMinimalConfig(testDir, {
        environment: {
          protectedVariables: ['SPREAD_SECRET'],
          allowTrustedModulesAccess: false
        }
      });
      
      const code = `
        try {
          const envCopy = {...process.env};
          if (envCopy.SPREAD_SECRET === 'spread_secret_value') {
            console.log('SPREAD_EXPOSED');
          } else if (envCopy.SPREAD_SECRET) {
            console.log('SPREAD_REDACTED:' + envCopy.SPREAD_SECRET);
          } else {
            console.log('SPREAD_UNDEFINED');
          }
        } catch (e) {
          console.log('SPREAD_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code, {
        env: { SPREAD_SECRET: 'spread_secret_value' }
      });
      
      return {
        pass: !result.output.includes('SPREAD_EXPOSED'),
        reason: result.output.includes('SPREAD_EXPOSED') ? 'spread bypass' : 'protected',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 5: Object.assign bypass
  await tracker.runTest('protectedVariables - Object.assign bypass', async () => {
    const testDir = setupTestDir('env-assign');
    
    try {
      writeMinimalConfig(testDir, {
        environment: {
          protectedVariables: ['ASSIGN_SECRET'],
          allowTrustedModulesAccess: false
        }
      });
      
      const code = `
        try {
          const envCopy = Object.assign({}, process.env);
          if (envCopy.ASSIGN_SECRET === 'assign_secret_value') {
            console.log('ASSIGN_EXPOSED');
          } else if (envCopy.ASSIGN_SECRET) {
            console.log('ASSIGN_REDACTED:' + envCopy.ASSIGN_SECRET);
          } else {
            console.log('ASSIGN_UNDEFINED');
          }
        } catch (e) {
          console.log('ASSIGN_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code, {
        env: { ASSIGN_SECRET: 'assign_secret_value' }
      });
      
      return {
        pass: !result.output.includes('ASSIGN_EXPOSED'),
        reason: result.output.includes('ASSIGN_EXPOSED') ? 'Object.assign bypass' : 'protected',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // =========================================================================
  // ENUMERATION BYPASSES
  // =========================================================================
  console.log('\n--- Enumeration Bypasses ---\n');
  
  // Test 6: for...in enumeration
  await tracker.runTest('protectedVariables - for...in enumeration', async () => {
    const testDir = setupTestDir('env-forin');
    
    try {
      writeMinimalConfig(testDir, {
        environment: {
          protectedVariables: ['FORIN_SECRET'],
          allowTrustedModulesAccess: false
        }
      });
      
      const code = `
        try {
          let found = false;
          let value = null;
          for (const key in process.env) {
            if (key === 'FORIN_SECRET') {
              found = true;
              value = process.env[key];
            }
          }
          if (value === 'forin_secret_value') {
            console.log('FORIN_EXPOSED');
          } else if (found) {
            console.log('FORIN_FOUND_REDACTED');
          } else {
            console.log('FORIN_NOT_FOUND');
          }
        } catch (e) {
          console.log('FORIN_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code, {
        env: { FORIN_SECRET: 'forin_secret_value' }
      });
      
      return {
        pass: !result.output.includes('FORIN_EXPOSED'),
        reason: result.output.includes('FORIN_EXPOSED') ? 'for...in bypass' : 'protected',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 7: Object.entries bypass
  await tracker.runTest('protectedVariables - Object.entries bypass', async () => {
    const testDir = setupTestDir('env-entries');
    
    try {
      writeMinimalConfig(testDir, {
        environment: {
          protectedVariables: ['ENTRIES_SECRET'],
          allowTrustedModulesAccess: false
        }
      });
      
      const code = `
        try {
          const entries = Object.entries(process.env);
          const found = entries.find(([k, v]) => k === 'ENTRIES_SECRET');
          if (found && found[1] === 'entries_secret_value') {
            console.log('ENTRIES_EXPOSED');
          } else if (found) {
            console.log('ENTRIES_REDACTED');
          } else {
            console.log('ENTRIES_NOT_FOUND');
          }
        } catch (e) {
          console.log('ENTRIES_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code, {
        env: { ENTRIES_SECRET: 'entries_secret_value' }
      });
      
      return {
        pass: !result.output.includes('ENTRIES_EXPOSED'),
        reason: result.output.includes('ENTRIES_EXPOSED') ? 'Object.entries bypass' : 'protected',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 8: Object.values bypass
  await tracker.runTest('protectedVariables - Object.values bypass', async () => {
    const testDir = setupTestDir('env-values');
    
    try {
      writeMinimalConfig(testDir, {
        environment: {
          protectedVariables: ['VALUES_SECRET'],
          allowTrustedModulesAccess: false
        }
      });
      
      const code = `
        try {
          const values = Object.values(process.env);
          const found = values.includes('values_secret_value');
          if (found) {
            console.log('VALUES_EXPOSED');
          } else {
            console.log('VALUES_NOT_FOUND');
          }
        } catch (e) {
          console.log('VALUES_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code, {
        env: { VALUES_SECRET: 'values_secret_value' }
      });
      
      return {
        pass: !result.output.includes('VALUES_EXPOSED'),
        reason: result.output.includes('VALUES_EXPOSED') ? 'Object.values bypass' : 'protected',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // =========================================================================
  // INSPECTION BYPASSES
  // =========================================================================
  console.log('\n--- Inspection Bypasses ---\n');
  
  // Test 9: util.inspect bypass
  await tracker.runTest('protectedVariables - util.inspect bypass', async () => {
    const testDir = setupTestDir('env-inspect');
    
    try {
      writeMinimalConfig(testDir, {
        environment: {
          protectedVariables: ['INSPECT_SECRET'],
          allowTrustedModulesAccess: false
        }
      });
      
      const code = `
        const util = require('util');
        try {
          const inspected = util.inspect(process.env, { depth: null, showHidden: true });
          if (inspected.includes('inspect_secret_value')) {
            console.log('INSPECT_EXPOSED');
          } else if (inspected.includes('INSPECT_SECRET')) {
            console.log('INSPECT_KEY_VISIBLE');
          } else {
            console.log('INSPECT_PROTECTED');
          }
        } catch (e) {
          console.log('INSPECT_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code, {
        env: { INSPECT_SECRET: 'inspect_secret_value' }
      });
      
      return {
        pass: !result.output.includes('INSPECT_EXPOSED'),
        reason: result.output.includes('INSPECT_EXPOSED') ? 'util.inspect bypass' : 'protected',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 10: console.dir bypass
  await tracker.runTest('protectedVariables - console.dir bypass', async () => {
    const testDir = setupTestDir('env-consoledir');
    
    try {
      writeMinimalConfig(testDir, {
        environment: {
          protectedVariables: ['CONSOLEDIR_SECRET'],
          allowTrustedModulesAccess: false
        }
      });
      
      const code = `
        // Capture console output
        let output = '';
        const originalDir = console.dir;
        console.dir = (obj) => { output = JSON.stringify(obj); };
        
        try {
          console.dir(process.env);
          if (output.includes('consoledir_secret_value')) {
            console.log('CONSOLEDIR_EXPOSED');
          } else {
            console.log('CONSOLEDIR_PROTECTED');
          }
        } catch (e) {
          console.log('CONSOLEDIR_BLOCKED:' + e.message);
        }
        console.dir = originalDir;
      `;
      
      const result = await runWithFirewall(testDir, code, {
        env: { CONSOLEDIR_SECRET: 'consoledir_secret_value' }
      });
      
      return {
        pass: !result.output.includes('CONSOLEDIR_EXPOSED'),
        reason: result.output.includes('CONSOLEDIR_EXPOSED') ? 'console.dir bypass' : 'protected',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // =========================================================================
  // ALTERNATIVE PROCESS INFO
  // =========================================================================
  console.log('\n--- Alternative Process Info ---\n');
  
  // Test 11: process.config leak
  await tracker.runTest('information leak - process.config', async () => {
    const testDir = setupTestDir('env-config');
    
    try {
      writeMinimalConfig(testDir, {
        environment: {
          protectedVariables: ['CONFIG_SECRET'],
          allowTrustedModulesAccess: false
        }
      });
      
      const code = `
        try {
          // process.config contains build configuration
          // Shouldn't expose runtime secrets but check anyway
          const configStr = JSON.stringify(process.config);
          if (configStr.includes('config_secret_value')) {
            console.log('CONFIG_EXPOSED');
          } else {
            console.log('CONFIG_SAFE');
          }
        } catch (e) {
          console.log('CONFIG_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code, {
        env: { CONFIG_SECRET: 'config_secret_value' }
      });
      
      return {
        pass: !result.output.includes('CONFIG_EXPOSED'),
        reason: 'process.config checked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  return tracker.getSummary();
}

module.exports = { runAdvancedEnvironmentTests };

// Allow direct execution
if (require.main === module) {
  runAdvancedEnvironmentTests().then(summary => {
    console.log('\nAdvanced Environment Tests Summary:');
    console.log(`  Passed: ${summary.passed}`);
    console.log(`  Failed: ${summary.failed}`);
    console.log(`  Skipped: ${summary.skipped}`);
    process.exit(summary.failed > 0 ? 1 : 0);
  });
}
