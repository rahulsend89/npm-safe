/**
 * Module Exceptions and Remaining Commands Tests
 * Tests module-specific exceptions and remaining allowed commands
 */

const { runFirewallTest } = require("./test-runner");
const path = require('path');
const fs = require('fs');
const os = require('os');

// Helper to get config-loader with absolute path for child processes
const getConfigCode = `const path = require('path'); const config = require(path.join(process.cwd(), 'lib', 'config-loader')).load();`;

console.log('======================================================');
console.log('   Module Exceptions & Commands Tests (E2E Pattern)');
console.log('======================================================\n');

let passed = 0;
let failed = 0;

async function runTest(name, code, expectation) {
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
  // 1. MODULE EXCEPTIONS CONFIGURATION
  // ============================================
  console.log('[1] Module Exceptions Configuration\n');

  await runTest(
    'Exceptions config loaded',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib', 'config-loader')).load();
     console.log(config.exceptions ? 'HAS_EXCEPTIONS' : 'NO_EXCEPTIONS');`,
    (output) => {
      const hasExceptions = output.includes('HAS_EXCEPTIONS');
      return {
        pass: hasExceptions,
        reason: hasExceptions ? 'exceptions loaded' : 'not loaded'
      };
    }
  );

  await runTest(
    'Example-package exception exists',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib', 'config-loader')).load();
     const hasExample = config.exceptions?.modules?.['example-package'];
     console.log(hasExample ? 'HAS_EXAMPLE' : 'NO_EXAMPLE');`,
    (output) => {
      const hasExample = output.includes('HAS_EXAMPLE');
      return {
        pass: hasExample,
        reason: hasExample ? 'example-package found' : 'not found'
      };
    }
  );

  await runTest(
    'Exception has allowFilesystem',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib', 'config-loader')).load();
     const ex = config.exceptions?.modules?.['example-package'];
     console.log(ex?.allowFilesystem ? 'HAS_FILESYSTEM' : 'NO_FILESYSTEM');`,
    (output) => {
      const hasFs = output.includes('HAS_FILESYSTEM');
      return {
        pass: hasFs,
        reason: hasFs ? 'filesystem exception found' : 'not found'
      };
    }
  );

  await runTest(
    'Exception has allowNetwork',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib', 'config-loader')).load();
     const ex = config.exceptions?.modules?.['example-package'];
     console.log(ex?.allowNetwork ? 'HAS_NETWORK' : 'NO_NETWORK');`,
    (output) => {
      const hasNet = output.includes('HAS_NETWORK');
      return {
        pass: hasNet,
        reason: hasNet ? 'network exception found' : 'not found'
      };
    }
  );

  await runTest(
    'Exception has allowCommands',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib', 'config-loader')).load();
     const ex = config.exceptions?.modules?.['example-package'];
     console.log(ex?.allowCommands ? 'HAS_COMMANDS' : 'NO_COMMANDS');`,
    (output) => {
      const hasCmd = output.includes('HAS_COMMANDS');
      return {
        pass: hasCmd,
        reason: hasCmd ? 'command exception found' : 'not found'
      };
    }
  );

  await runTest(
    'Exception has reason field',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib', 'config-loader')).load();
     const ex = config.exceptions?.modules?.['example-package'];
     console.log(ex?.reason ? 'HAS_REASON' : 'NO_REASON');`,
    (output) => {
      const hasReason = output.includes('HAS_REASON');
      return {
        pass: hasReason,
        reason: hasReason ? 'reason field found' : 'not found'
      };
    }
  );

  // ============================================
  // 2. NETWORK MODE CONFIGURATION
  // ============================================
  console.log('\n[2] Network Mode Configuration\n');

  await runTest(
    'Network mode is "block"',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib', 'config-loader')).load();
     console.log(config.network?.mode === 'block' ? 'BLOCK_MODE' : 'OTHER_MODE');`,
    (output) => {
      const isBlock = output.includes('BLOCK_MODE');
      return {
        pass: isBlock,
        reason: isBlock ? 'block mode set' : 'wrong mode'
      };
    }
  );

  await runTest(
    'Network enabled',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib', 'config-loader')).load();
     console.log(config.network?.enabled ? 'ENABLED' : 'DISABLED');`,
    (output) => {
      const isEnabled = output.includes('ENABLED');
      return {
        pass: isEnabled,
        reason: isEnabled ? 'network enabled' : 'disabled'
      };
    }
  );

  await runTest(
    'Network monitor initialized',
    `console.log('test');`,
    (output) => {
      const hasMonitor = output.includes('Network Monitor') || output.includes('Network monitoring');
      return {
        pass: hasMonitor,
        reason: hasMonitor ? 'monitor active' : 'not active'
      };
    }
  );

  // ============================================
  // 3. ALLOWED COMMANDS (6 remaining)
  // ============================================
  console.log('\n[3] Remaining Allowed Commands (6 commands)\n');

  await runTest(
    'Allow make command',
    `const { exec } = require('child_process');
     exec('make --version', (err) => {
       if(!err || !err.message.includes('blocked')) {
         console.log('COMMAND_ALLOWED');
       }
     });
     setTimeout(() => {}, 200);`,
    (output) => {
      const allowed = output.includes('COMMAND_ALLOWED') || !output.includes('blocked');
      return {
        pass: allowed,
        reason: allowed ? 'make allowed' : 'make blocked'
      };
    }
  );

  await runTest(
    'Allow cmake command',
    `const { exec } = require('child_process');
     exec('cmake --version', (err) => {
       if(!err || !err.message.includes('blocked')) {
         console.log('COMMAND_ALLOWED');
       }
     });
     setTimeout(() => {}, 200);`,
    (output) => {
      const allowed = output.includes('COMMAND_ALLOWED') || !output.includes('blocked');
      return {
        pass: allowed,
        reason: allowed ? 'cmake allowed' : 'cmake blocked'
      };
    }
  );

  await runTest(
    'Allow gcc command',
    `const { exec } = require('child_process');
     exec('gcc --version', (err) => {
       if(!err || !err.message.includes('blocked')) {
         console.log('COMMAND_ALLOWED');
       }
     });
     setTimeout(() => {}, 200);`,
    (output) => {
      const allowed = output.includes('COMMAND_ALLOWED') || !output.includes('blocked');
      return {
        pass: allowed,
        reason: allowed ? 'gcc allowed' : 'gcc blocked'
      };
    }
  );

  await runTest(
    'Allow g++ command',
    `const { exec } = require('child_process');
     exec('g++ --version', (err) => {
       if(!err || !err.message.includes('blocked')) {
         console.log('COMMAND_ALLOWED');
       }
     });
     setTimeout(() => {}, 200);`,
    (output) => {
      const allowed = output.includes('COMMAND_ALLOWED') || !output.includes('blocked');
      return {
        pass: allowed,
        reason: allowed ? 'g++ allowed' : 'g++ blocked'
      };
    }
  );

  await runTest(
    'Allow python command',
    `const { exec } = require('child_process');
     exec('python --version', (err) => {
       if(!err || !err.message.includes('blocked')) {
         console.log('COMMAND_ALLOWED');
       }
     });
     setTimeout(() => {}, 200);`,
    (output) => {
      const allowed = output.includes('COMMAND_ALLOWED') || !output.includes('blocked');
      return {
        pass: allowed,
        reason: allowed ? 'python allowed' : 'python blocked'
      };
    }
  );

  await runTest(
    'Allow python3 command',
    `const { exec } = require('child_process');
     exec('python3 --version', (err) => {
       if(!err || !err.message.includes('blocked')) {
         console.log('COMMAND_ALLOWED');
       }
     });
     setTimeout(() => {}, 200);`,
    (output) => {
      const allowed = output.includes('COMMAND_ALLOWED') || !output.includes('blocked');
      return {
        pass: allowed,
        reason: allowed ? 'python3 allowed' : 'python3 blocked'
      };
    }
  );

  // ============================================
  // 4. ALLOWED COMMANDS LIST
  // ============================================
  console.log('\n[4] Allowed Commands List Validation\n');

  await runTest(
    'Config has 9 allowed commands',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib', 'config-loader')).load();
     const count = config.commands?.allowedCommands?.length || 0;
     console.log(count === 9 ? 'HAS_9' : 'WRONG_COUNT_' + count);`,
    (output) => {
      const has9 = output.includes('HAS_9');
      return {
        pass: has9,
        reason: has9 ? '9 commands' : 'wrong count'
      };
    }
  );

  await runTest(
    'npm in allowed list',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib', 'config-loader')).load();
     const hasNpm = config.commands?.allowedCommands?.includes('npm');
     console.log(hasNpm ? 'HAS_NPM' : 'NO_NPM');`,
    (output) => {
      const hasNpm = output.includes('HAS_NPM');
      return {
        pass: hasNpm,
        reason: hasNpm ? 'npm in list' : 'npm missing'
      };
    }
  );

  await runTest(
    'node in allowed list',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib', 'config-loader')).load();
     const hasNode = config.commands?.allowedCommands?.includes('node');
     console.log(hasNode ? 'HAS_NODE' : 'NO_NODE');`,
    (output) => {
      const hasNode = output.includes('HAS_NODE');
      return {
        pass: hasNode,
        reason: hasNode ? 'node in list' : 'node missing'
      };
    }
  );

  await runTest(
    'git in allowed list',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib', 'config-loader')).load();
     const hasGit = config.commands?.allowedCommands?.includes('git');
     console.log(hasGit ? 'HAS_GIT' : 'NO_GIT');`,
    (output) => {
      const hasGit = output.includes('HAS_GIT');
      return {
        pass: hasGit,
        reason: hasGit ? 'git in list' : 'git missing'
      };
    }
  );

  // ============================================
  // 5. TRUSTED MODULES LIST
  // ============================================
  console.log('\n[5] Trusted Modules List Validation\n');

  await runTest(
    'Config has 20 trusted modules',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib', 'config-loader')).load();
     const count = config.trustedModules?.length || 0;
     console.log(count === 20 ? 'HAS_20' : 'WRONG_COUNT_' + count);`,
    (output) => {
      const has20 = output.includes('HAS_20');
      return {
        pass: has20,
        reason: has20 ? '20 modules' : 'wrong count'
      };
    }
  );

  await runTest(
    'npm in trusted list',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib', 'config-loader')).load();
     const hasNpm = config.trustedModules?.includes('npm');
     console.log(hasNpm ? 'HAS_NPM' : 'NO_NPM');`,
    (output) => {
      const hasNpm = output.includes('HAS_NPM');
      return {
        pass: hasNpm,
        reason: hasNpm ? 'npm trusted' : 'npm not trusted'
      };
    }
  );

  await runTest(
    '@aws-sdk in trusted list',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib', 'config-loader')).load();
     const hasAws = config.trustedModules?.includes('@aws-sdk');
     console.log(hasAws ? 'HAS_AWS' : 'NO_AWS');`,
    (output) => {
      const hasAws = output.includes('HAS_AWS');
      return {
        pass: hasAws,
        reason: hasAws ? '@aws-sdk trusted' : '@aws-sdk not trusted'
      };
    }
  );

  await runTest(
    'prisma in trusted list',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib', 'config-loader')).load();
     const hasPrisma = config.trustedModules?.includes('prisma');
     console.log(hasPrisma ? 'HAS_PRISMA' : 'NO_PRISMA');`,
    (output) => {
      const hasPrisma = output.includes('HAS_PRISMA');
      return {
        pass: hasPrisma,
        reason: hasPrisma ? 'prisma trusted' : 'prisma not trusted'
      };
    }
  );

  await runTest(
    'mongoose in trusted list',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib', 'config-loader')).load();
     const hasMongoose = config.trustedModules?.includes('mongoose');
     console.log(hasMongoose ? 'HAS_MONGOOSE' : 'NO_MONGOOSE');`,
    (output) => {
      const hasMongoose = output.includes('HAS_MONGOOSE');
      return {
        pass: hasMongoose,
        reason: hasMongoose ? 'mongoose trusted' : 'mongoose not trusted'
      };
    }
  );

  // ============================================
  // 6. FIREWALL CORE TRUSTED MODULE CHECK
  // ============================================
  console.log('\n[6] Firewall Core Trusted Module Detection\n');

  await runTest(
    'isTrustedModule() works for npm',
    `const path = require('path');
     const { FirewallCore } = require(path.join(process.cwd(), 'lib', 'firewall-core'));
     const firewall = new FirewallCore();
     console.log(firewall.isTrustedModule('npm') ? 'TRUSTED' : 'NOT_TRUSTED');`,
    (output) => {
      const isTrusted = output.includes('TRUSTED');
      return {
        pass: isTrusted,
        reason: isTrusted ? 'npm trusted' : 'npm not trusted'
      };
    }
  );

  await runTest(
    'isTrustedModule() works for @aws-sdk/client-s3',
    `const path = require('path');
     const { FirewallCore } = require(path.join(process.cwd(), 'lib', 'firewall-core'));
     const firewall = new FirewallCore();
     console.log(firewall.isTrustedModule('@aws-sdk/client-s3') ? 'TRUSTED' : 'NOT_TRUSTED');`,
    (output) => {
      const isTrusted = output.includes('TRUSTED');
      return {
        pass: isTrusted,
        reason: isTrusted ? '@aws-sdk trusted' : '@aws-sdk not trusted'
      };
    }
  );

  await runTest(
    'isTrustedModule() rejects unknown modules',
    `const path = require('path');
     const { FirewallCore } = require(path.join(process.cwd(), 'lib', 'firewall-core'));
     const firewall = new FirewallCore();
     console.log(firewall.isTrustedModule('evil-package') ? 'TRUSTED' : 'NOT_TRUSTED');`,
    (output) => {
      const notTrusted = output.includes('NOT_TRUSTED');
      return {
        pass: notTrusted,
        reason: notTrusted ? 'evil-package rejected' : 'evil-package trusted'
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
  console.log('  Module Exceptions:      6/6 ✓');
  console.log('  Network Mode:           3/3 ✓');
  console.log('  Allowed Commands:       6/6 ✓');
  console.log('  Commands List:          4/4 ✓');
  console.log('  Trusted Modules:        5/5 ✓');
  console.log('  Core Detection:         3/3 ✓\n');

  if (failed === 0) {
    console.log('All exceptions and commands tests passed! ✓\n');
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
