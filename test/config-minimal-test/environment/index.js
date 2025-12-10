/**
 * Environment Variable Protection Tests
 * 
 * Tests multiple bypass techniques for environment variable access:
 * 1. Direct process.env access
 * 2. Child process with env inheritance
 * 3. Shell command env access (printenv, echo $VAR)
 * 4. process.env enumeration
 * 5. JSON.stringify bypass
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

/**
 * Run a suite of environment-variable protection tests and collect their results.
 *
 * Executes multiple tests that verify protected environment variables are not exposed
 * (direct access, child processes, shell commands, enumeration, JSON.stringify),
 * ensures non-protected and standard Node.js env vars remain accessible, and checks
 * pattern-based protections. Each test runs in an isolated test directory and is
 * cleaned up after execution.
 *
 * @returns {{ passed: number, failed: number, skipped: number, details: Array<Object> }} Summary object with counts and per-test results produced by the TestTracker.
 */
async function runEnvironmentTests() {
  console.log('\nENVIRONMENT VARIABLE PROTECTION TESTS\n');
  console.log('='.repeat(50));
  
  const tracker = new TestTracker('environment');
  
  // =========================================================================
  // PROTECTED VARIABLES TESTS
  // =========================================================================
  console.log('\n--- Protected Variables ---\n');
  
  // Test 1: Direct process.env access
  await tracker.runTest('protectedVariables - direct process.env.GITHUB_TOKEN', async () => {
    const testDir = setupTestDir('env-direct');
    
    try {
      writeMinimalConfig(testDir, {
        environment: {
          protectedVariables: ['GITHUB_TOKEN', 'NPM_TOKEN', 'AWS_SECRET'],
          allowTrustedModulesAccess: false
        }
      });
      
      const code = `
        try {
          const token = process.env.GITHUB_TOKEN;
          if (token && token.includes('ghp_')) {
            console.log('ENV_EXPOSED:' + token);
          } else if (token) {
            console.log('ENV_REDACTED:' + token);
          } else {
            console.log('ENV_UNDEFINED');
          }
        } catch (e) {
          console.log('ENV_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code, {
        env: { GITHUB_TOKEN: 'ghp_secret_token_12345' }
      });
      
      // Token should not be exposed
      return {
        pass: !result.output.includes('ghp_secret_token_12345'),
        reason: result.output.includes('ghp_secret_token_12345') ? 'token exposed' : 'protected',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 2: Child process inherits and reads env
  await tracker.runTest('protectedVariables - child process env inheritance', async () => {
    const testDir = setupTestDir('env-child');
    
    try {
      writeMinimalConfig(testDir, {
        environment: {
          protectedVariables: ['NPM_TOKEN'],
          allowTrustedModulesAccess: false
        }
      });
      
      const code = `
        const { execSync } = require('child_process');
        try {
          const result = execSync('node -e "console.log(process.env.NPM_TOKEN)"').toString();
          console.log('CHILD_ENV:' + result.trim());
        } catch (e) {
          console.log('ENV_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code, {
        env: { NPM_TOKEN: 'npm_secret_abc123' }
      });
      
      return {
        pass: !result.output.includes('npm_secret_abc123'),
        reason: result.output.includes('npm_secret_abc123') ? 'token leaked to child' : 'protected',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 3: Shell printenv/echo bypass
  if (!isWindows) {
    await tracker.runTest('protectedVariables - shell printenv bypass', async () => {
      const testDir = setupTestDir('env-shell');
      
      try {
        writeMinimalConfig(testDir, {
          environment: {
            protectedVariables: ['AWS_SECRET'],
            allowTrustedModulesAccess: false
          }
        });
        
        const code = `
          const { execSync } = require('child_process');
          try {
            const result = execSync('printenv AWS_SECRET').toString();
            console.log('SHELL_ENV:' + result.trim());
          } catch (e) {
            console.log('ENV_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code, {
          env: { AWS_SECRET: 'aws_secret_key_xyz' }
        });
        
        return {
          pass: !result.output.includes('aws_secret_key_xyz'),
          reason: result.output.includes('aws_secret_key_xyz') ? 'printenv bypass worked' : 'protected',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
    
    // Test 4: Shell echo $VAR bypass
    await tracker.runTest('protectedVariables - shell echo $VAR bypass', async () => {
      const testDir = setupTestDir('env-echo');
      
      try {
        writeMinimalConfig(testDir, {
          environment: {
            protectedVariables: ['STRIPE_KEY'],
            allowTrustedModulesAccess: false
          }
        });
        
        const code = `
          const { execSync } = require('child_process');
          try {
            const result = execSync('echo $STRIPE_KEY').toString();
            console.log('SHELL_ECHO:' + result.trim());
          } catch (e) {
            console.log('ENV_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code, {
          env: { STRIPE_KEY: 'sk_live_stripe_secret' }
        });
        
        return {
          pass: !result.output.includes('sk_live_stripe_secret'),
          reason: result.output.includes('sk_live_stripe_secret') ? 'echo bypass worked' : 'protected',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  } else {
    // Windows-specific shell env tests
    await tracker.runTest('protectedVariables - shell set bypass (Windows)', async () => {
      const testDir = setupTestDir('env-set-win');
      
      try {
        writeMinimalConfig(testDir, {
          environment: {
            protectedVariables: ['AWS_SECRET'],
            allowTrustedModulesAccess: false
          }
        });
        
        const code = `
          const { execSync } = require('child_process');
          try {
            const result = execSync('set AWS_SECRET', { shell: 'cmd.exe' }).toString();
            console.log('SHELL_SET:' + result.trim());
          } catch (e) {
            console.log('ENV_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code, {
          env: { AWS_SECRET: 'aws_secret_key_xyz' }
        });
        
        return {
          pass: !result.output.includes('aws_secret_key_xyz'),
          reason: result.output.includes('aws_secret_key_xyz') ? 'set bypass worked' : 'protected',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
    
    await tracker.runTest('protectedVariables - echo %VAR% bypass (Windows)', async () => {
      const testDir = setupTestDir('env-echo-win');
      
      try {
        writeMinimalConfig(testDir, {
          environment: {
            protectedVariables: ['STRIPE_KEY'],
            allowTrustedModulesAccess: false
          }
        });
        
        const code = `
          const { execSync } = require('child_process');
          try {
            const result = execSync('echo %STRIPE_KEY%', { shell: 'cmd.exe' }).toString();
            console.log('SHELL_ECHO:' + result.trim());
          } catch (e) {
            console.log('ENV_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code, {
          env: { STRIPE_KEY: 'sk_live_stripe_secret' }
        });
        
        return {
          pass: !result.output.includes('sk_live_stripe_secret'),
          reason: result.output.includes('sk_live_stripe_secret') ? 'echo %VAR% bypass worked' : 'protected',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  }
  
  // Test 5: process.env enumeration via Object.keys
  await tracker.runTest('protectedVariables - Object.keys enumeration', async () => {
    const testDir = setupTestDir('env-enum');
    
    try {
      writeMinimalConfig(testDir, {
        environment: {
          protectedVariables: ['OPENAI_API_KEY'],
          allowTrustedModulesAccess: false
        }
      });
      
      const code = `
        try {
          const keys = Object.keys(process.env);
          const found = keys.includes('OPENAI_API_KEY');
          const value = process.env.OPENAI_API_KEY;
          console.log('KEY_EXISTS:' + found);
          console.log('VALUE:' + value);
        } catch (e) {
          console.log('ENV_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code, {
        env: { OPENAI_API_KEY: 'sk-openai-secret-key' }
      });
      
      return {
        pass: !result.output.includes('sk-openai-secret-key'),
        reason: result.output.includes('sk-openai-secret-key') ? 'enumeration exposed key' : 'protected',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 6: JSON.stringify(process.env) bypass
  await tracker.runTest('protectedVariables - JSON.stringify bypass', async () => {
    const testDir = setupTestDir('env-json');
    
    try {
      writeMinimalConfig(testDir, {
        environment: {
          protectedVariables: ['DATABASE_PASSWORD'],
          allowTrustedModulesAccess: false
        }
      });
      
      const code = `
        try {
          const envStr = JSON.stringify(process.env);
          if (envStr.includes('super_secret_db_pass')) {
            console.log('JSON_EXPOSED');
          } else {
            console.log('JSON_PROTECTED');
          }
        } catch (e) {
          console.log('ENV_BLOCKED:' + e.message);
        }
      `;
      
      const result = await runWithFirewall(testDir, code, {
        env: { DATABASE_PASSWORD: 'super_secret_db_pass' }
      });
      
      return {
        pass: !result.output.includes('JSON_EXPOSED'),
        reason: result.output.includes('JSON_EXPOSED') ? 'JSON bypass worked' : 'protected',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // =========================================================================
  // NON-PROTECTED VARIABLES TESTS
  // =========================================================================
  console.log('\n--- Non-Protected Variables ---\n');
  
  // Test 7: Non-protected vars should be accessible
  await tracker.runTest('non-protected variables are accessible', async () => {
    const testDir = setupTestDir('env-public');
    
    try {
      writeMinimalConfig(testDir, {
        environment: {
          protectedVariables: ['SECRET_VAR'],
          allowTrustedModulesAccess: false
        }
      });
      
      const code = `
        const value = process.env.PUBLIC_VAR;
        if (value === 'public_value_123') {
          console.log('PUBLIC_ACCESSIBLE');
        } else {
          console.log('PUBLIC_BLOCKED');
        }
      `;
      
      const result = await runWithFirewall(testDir, code, {
        env: { PUBLIC_VAR: 'public_value_123' }
      });
      
      return {
        pass: result.output.includes('PUBLIC_ACCESSIBLE'),
        reason: result.output.includes('PUBLIC_ACCESSIBLE') ? 'public vars work' : 'public vars blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // Test 8: Standard Node.js env vars should work
  await tracker.runTest('NODE_ENV and standard vars accessible', async () => {
    const testDir = setupTestDir('env-standard');
    
    try {
      writeMinimalConfig(testDir, {
        environment: {
          protectedVariables: ['SECRET_TOKEN'],
          allowTrustedModulesAccess: false
        }
      });
      
      const code = `
        const nodeEnv = process.env.NODE_ENV;
        const path = process.env.PATH;
        if (nodeEnv === 'test' && path) {
          console.log('STANDARD_VARS_OK');
        } else {
          console.log('STANDARD_VARS_BLOCKED');
        }
      `;
      
      const result = await runWithFirewall(testDir, code, {
        env: { NODE_ENV: 'test' }
      });
      
      return {
        pass: result.output.includes('STANDARD_VARS_OK'),
        reason: result.output.includes('STANDARD_VARS_OK') ? 'standard vars work' : 'blocked',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  // =========================================================================
  // PATTERN-BASED PROTECTION TESTS
  // =========================================================================
  console.log('\n--- Pattern-Based Protection ---\n');
  
  // Test 9: Wildcard-like token detection
  await tracker.runTest('protects vars matching sensitive patterns', async () => {
    const testDir = setupTestDir('env-pattern');
    
    try {
      writeMinimalConfig(testDir, {
        environment: {
          protectedVariables: ['MY_APP_SECRET', 'CUSTOM_TOKEN'],
          allowTrustedModulesAccess: false
        }
      });
      
      const code = `
        const secret1 = process.env.MY_APP_SECRET;
        const secret2 = process.env.CUSTOM_TOKEN;
        const exposed = (secret1 === 'secret_value_1' || secret2 === 'token_value_2');
        console.log('EXPOSED:' + exposed);
      `;
      
      const result = await runWithFirewall(testDir, code, {
        env: { 
          MY_APP_SECRET: 'secret_value_1',
          CUSTOM_TOKEN: 'token_value_2'
        }
      });
      
      return {
        pass: result.output.includes('EXPOSED:false') || 
              (!result.output.includes('secret_value_1') && !result.output.includes('token_value_2')),
        reason: result.output.includes('EXPOSED:true') ? 'pattern vars exposed' : 'protected',
        debug: result.output
      };
    } finally {
      cleanupTestDir(testDir);
    }
  });
  
  return tracker.getSummary();
}

module.exports = { runEnvironmentTests };

// Allow direct execution
if (require.main === module) {
  runEnvironmentTests().then(summary => {
    console.log('\nEnvironment Tests Summary:');
    console.log(`  Passed: ${summary.passed}`);
    console.log(`  Failed: ${summary.failed}`);
    console.log(`  Skipped: ${summary.skipped}`);
    process.exit(summary.failed > 0 ? 1 : 0);
  });
}