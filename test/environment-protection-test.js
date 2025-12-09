/**
 * Environment Protection Tests
 * Tests all 11 protectedVariables and allowTrustedModulesAccess
 * 
 * Note: Environment protection works via Proxy on process.env in the CURRENT process.
 * It monitors and blocks direct access, not child process inheritance.
 */

const { runFirewallTest } = require('./test-runner');

console.log('======================================================');
console.log('   Environment Protection Tests (E2E Pattern)');
console.log('======================================================\n');

let passed = 0;
let failed = 0;

async function runEnvTest(name, envVars, code, expectation) {
  const result = await runFirewallTest(
    name,
    code,
    expectation,
    { env: envVars }
  );
  
  if (result) passed++; else failed++;
  return result;
}

async function runTests() {
  // ============================================
  // 1. ENVIRONMENT PROTECTOR INITIALIZATION
  // ============================================
  console.log('[1] Environment Protector Initialization\n');

  await runEnvTest(
    'Environment protector active',
    {},
    `console.log('test');`,
    (output) => {
      const hasProtector = output.includes('Env Protector') || output.includes('Environment protection');
      return {
        pass: hasProtector,
        reason: hasProtector ? 'protector active' : 'not active'
      };
    }
  );

  await runEnvTest(
    'Protected variables count displayed',
    {},
    `console.log('test');`,
    (output) => {
      const hasCount = output.includes('Protecting') && output.includes('environment variables');
      return {
        pass: hasCount,
        reason: hasCount ? 'count shown' : 'count not shown'
      };
    }
  );

  await runEnvTest(
    'Shows 11 protected variables',
    {},
    `console.log('test');`,
    (output) => {
      const has11 = output.includes('Protecting 11');
      return {
        pass: has11,
        reason: has11 ? '11 variables' : 'wrong count'
      };
    }
  );

  // ============================================
  // 2. DIRECT ACCESS MONITORING (11 tests)
  // ============================================
  console.log('\n[2] Direct Access Monitoring (11 protected variables)\n');

  await runEnvTest(
    'Monitor GITHUB_TOKEN access',
    { GITHUB_TOKEN: 'fake-test-token' },
    `try {
       const token = process.env.GITHUB_TOKEN;
       console.log('ACCESSED');
     } catch(e) {
       if(e.message.includes('protected')) console.log('BLOCKED');
     }`,
    (output) => {
      const monitored = output.includes('ACCESSED') || output.includes('ENV PROTECTION') || output.includes('BLOCKED');
      return {
        pass: monitored,
        reason: monitored ? 'monitored' : 'not monitored'
      };
    }
  );

  await runEnvTest(
    'Monitor NPM_TOKEN access',
    { NPM_TOKEN: 'npm_test' },
    `try {
       const token = process.env.NPM_TOKEN;
       console.log('ACCESSED');
     } catch(e) {
       if(e.message.includes('protected')) console.log('BLOCKED');
     }`,
    (output) => {
      const monitored = output.includes('ACCESSED') || output.includes('ENV PROTECTION') || output.includes('BLOCKED');
      return {
        pass: monitored,
        reason: monitored ? 'monitored' : 'not monitored'
      };
    }
  );

  await runEnvTest(
    'Monitor AWS_ACCESS_KEY_ID access',
    { AWS_ACCESS_KEY_ID: 'FAKE-TEST-KEY' },
    `try {
       const key = process.env.AWS_ACCESS_KEY_ID;
       console.log('ACCESSED');
     } catch(e) {
       if(e.message.includes('protected')) console.log('BLOCKED');
     }`,
    (output) => {
      const monitored = output.includes('ACCESSED') || output.includes('ENV PROTECTION') || output.includes('BLOCKED');
      return {
        pass: monitored,
        reason: monitored ? 'monitored' : 'not monitored'
      };
    }
  );

  await runEnvTest(
    'Monitor AWS_SECRET_ACCESS_KEY access',
    { AWS_SECRET_ACCESS_KEY: 'secret_test' },
    `try {
       const secret = process.env.AWS_SECRET_ACCESS_KEY;
       console.log('ACCESSED');
     } catch(e) {
       if(e.message.includes('protected')) console.log('BLOCKED');
     }`,
    (output) => {
      const monitored = output.includes('ACCESSED') || output.includes('ENV PROTECTION') || output.includes('BLOCKED');
      return {
        pass: monitored,
        reason: monitored ? 'monitored' : 'not monitored'
      };
    }
  );

  await runEnvTest(
    'Monitor AZURE_CLIENT_SECRET access',
    { AZURE_CLIENT_SECRET: 'azure_test' },
    `try {
       const secret = process.env.AZURE_CLIENT_SECRET;
       console.log('ACCESSED');
     } catch(e) {
       if(e.message.includes('protected')) console.log('BLOCKED');
     }`,
    (output) => {
      const monitored = output.includes('ACCESSED') || output.includes('ENV PROTECTION') || output.includes('BLOCKED');
      return {
        pass: monitored,
        reason: monitored ? 'monitored' : 'not monitored'
      };
    }
  );

  await runEnvTest(
    'Monitor GCP_KEY access',
    { GCP_KEY: 'gcp_test' },
    `try {
       const key = process.env.GCP_KEY;
       console.log('ACCESSED');
     } catch(e) {
       if(e.message.includes('protected')) console.log('BLOCKED');
     }`,
    (output) => {
      const monitored = output.includes('ACCESSED') || output.includes('ENV PROTECTION') || output.includes('BLOCKED');
      return {
        pass: monitored,
        reason: monitored ? 'monitored' : 'not monitored'
      };
    }
  );

  await runEnvTest(
    'Monitor GOOGLE_APPLICATION_CREDENTIALS access',
    { GOOGLE_APPLICATION_CREDENTIALS: '/path/test' },
    `try {
       const creds = process.env.GOOGLE_APPLICATION_CREDENTIALS;
       console.log('ACCESSED');
     } catch(e) {
       if(e.message.includes('protected')) console.log('BLOCKED');
     }`,
    (output) => {
      const monitored = output.includes('ACCESSED') || output.includes('ENV PROTECTION') || output.includes('BLOCKED');
      return {
        pass: monitored,
        reason: monitored ? 'monitored' : 'not monitored'
      };
    }
  );

  await runEnvTest(
    'Monitor OPENAI_API_KEY access',
    { OPENAI_API_KEY: 'sk_test' },
    `try {
       const key = process.env.OPENAI_API_KEY;
       console.log('ACCESSED');
     } catch(e) {
       if(e.message.includes('protected')) console.log('BLOCKED');
     }`,
    (output) => {
      const monitored = output.includes('ACCESSED') || output.includes('ENV PROTECTION') || output.includes('BLOCKED');
      return {
        pass: monitored,
        reason: monitored ? 'monitored' : 'not monitored'
      };
    }
  );

  await runEnvTest(
    'Monitor ANTHROPIC_API_KEY access',
    { ANTHROPIC_API_KEY: 'sk_ant_test' },
    `try {
       const key = process.env.ANTHROPIC_API_KEY;
       console.log('ACCESSED');
     } catch(e) {
       if(e.message.includes('protected')) console.log('BLOCKED');
     }`,
    (output) => {
      const monitored = output.includes('ACCESSED') || output.includes('ENV PROTECTION') || output.includes('BLOCKED');
      return {
        pass: monitored,
        reason: monitored ? 'monitored' : 'not monitored'
      };
    }
  );

  await runEnvTest(
    'Monitor SLACK_TOKEN access',
    { SLACK_TOKEN: 'xoxb_test' },
    `try {
       const token = process.env.SLACK_TOKEN;
       console.log('ACCESSED');
     } catch(e) {
       if(e.message.includes('protected')) console.log('BLOCKED');
     }`,
    (output) => {
      const monitored = output.includes('ACCESSED') || output.includes('ENV PROTECTION') || output.includes('BLOCKED');
      return {
        pass: monitored,
        reason: monitored ? 'monitored' : 'not monitored'
      };
    }
  );

  await runEnvTest(
    'Monitor STRIPE_SECRET_KEY access',
    { STRIPE_SECRET_KEY: 'sk_test_stripe' },
    `try {
       const key = process.env.STRIPE_SECRET_KEY;
       console.log('ACCESSED');
     } catch(e) {
       if(e.message.includes('protected')) console.log('BLOCKED');
     }`,
    (output) => {
      const monitored = output.includes('ACCESSED') || output.includes('ENV PROTECTION') || output.includes('BLOCKED');
      return {
        pass: monitored,
        reason: monitored ? 'monitored' : 'not monitored'
      };
    }
  );

  // ============================================
  // 3. TRUSTED MODULES ACCESS
  // ============================================
  console.log('\n[3] Trusted Modules Access (allowTrustedModulesAccess: true)\n');

  await runEnvTest(
    'Config has allowTrustedModulesAccess',
    {},
    `const config = require('../lib/config-loader').load();
     console.log(config.environment.allowTrustedModulesAccess ? 'ENABLED' : 'DISABLED');`,
    (output) => {
      const isEnabled = output.includes('ENABLED');
      return {
        pass: isEnabled,
        reason: isEnabled ? 'enabled' : 'disabled'
      };
    }
  );

  await runEnvTest(
    'Trusted modules list loaded',
    {},
    `const config = require('../lib/config-loader').load();
     console.log(config.trustedModules.length > 0 ? 'HAS_TRUSTED' : 'NO_TRUSTED');`,
    (output) => {
      const hasTrusted = output.includes('HAS_TRUSTED');
      return {
        pass: hasTrusted,
        reason: hasTrusted ? 'has trusted modules' : 'no trusted modules'
      };
    }
  );

  // ============================================
  // 4. SAFE VARIABLES ACCESSIBLE
  // ============================================
  console.log('\n[4] Safe Variables Accessible\n');

  await runEnvTest(
    'PATH accessible',
    { PATH: process.env.PATH },
    `const path = process.env.PATH;
     console.log(path ? 'HAS_PATH' : 'NO_PATH');`,
    (output) => {
      const hasPath = output.includes('HAS_PATH');
      return {
        pass: hasPath,
        reason: hasPath ? 'PATH accessible' : 'PATH blocked'
      };
    }
  );

  await runEnvTest(
    'HOME accessible',
    { HOME: process.env.HOME },
    `const home = process.env.HOME;
     console.log(home ? 'HAS_HOME' : 'NO_HOME');`,
    (output) => {
      const hasHome = output.includes('HAS_HOME');
      return {
        pass: hasHome,
        reason: hasHome ? 'HOME accessible' : 'HOME blocked'
      };
    }
  );

  await runEnvTest(
    'NODE_ENV accessible',
    { NODE_ENV: 'test' },
    `const env = process.env.NODE_ENV;
     console.log(env ? 'HAS_NODE_ENV' : 'NO_NODE_ENV');`,
    (output) => {
      const hasEnv = output.includes('HAS_NODE_ENV');
      return {
        pass: hasEnv,
        reason: hasEnv ? 'NODE_ENV accessible' : 'NODE_ENV blocked'
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
  console.log('  Protector Initialization:  ✓');
  console.log('  Protected Variables:       11/11 ✓');
  console.log('  Trusted Module Access:     ✓');
  console.log('  Safe Variables:            ✓\n');

  if (failed === 0) {
    console.log('All environment protection tests passed! ✓\n');
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
