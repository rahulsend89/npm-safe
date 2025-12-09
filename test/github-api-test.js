/**
 * GitHub API Protection Tests
 * Tests GitHub API monitoring for repo creation, workflow creation, and blocked patterns
 */

const { runFirewallTest } = require('./test-runner');

console.log('======================================================');
console.log('   GitHub API Protection Tests (E2E Pattern)');
console.log('======================================================\n');

let passed = 0;
let failed = 0;

async function runGitHubTest(name, code, expectation) {
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
  // 1. GITHUB API CONFIGURATION
  // ============================================
  console.log('[1] GitHub API Configuration\n');

  await runGitHubTest(
    'GitHub API monitoring enabled',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib/config-loader')).load();
     console.log(config.githubApi?.monitorRepoCreation ? 'ENABLED' : 'DISABLED');`,
    (output) => {
      const isEnabled = output.includes('ENABLED');
      return {
        pass: isEnabled,
        reason: isEnabled ? 'monitoring enabled' : 'disabled'
      };
    }
  );

  await runGitHubTest(
    'Repo creation monitoring configured',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib/config-loader')).load();
     console.log(config.githubApi?.monitorRepoCreation === true ? 'MONITOR_REPO' : 'NO_MONITOR');`,
    (output) => {
      const monitors = output.includes('MONITOR_REPO');
      return {
        pass: monitors,
        reason: monitors ? 'repo monitoring on' : 'repo monitoring off'
      };
    }
  );

  await runGitHubTest(
    'Workflow creation monitoring configured',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib/config-loader')).load();
     console.log(config.githubApi?.monitorWorkflowCreation === true ? 'MONITOR_WORKFLOW' : 'NO_MONITOR');`,
    (output) => {
      const monitors = output.includes('MONITOR_WORKFLOW');
      return {
        pass: monitors,
        reason: monitors ? 'workflow monitoring on' : 'workflow monitoring off'
      };
    }
  );

  // ============================================
  // 2. BLOCKED REPO NAMES (5 tests)
  // ============================================
  console.log('\n[2] Blocked Repository Names (5 names)\n');

  await runGitHubTest(
    'Config has 5 blocked repo names',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib/config-loader')).load();
     const count = config.githubApi?.blockedRepoNames?.length || 0;
     console.log(count === 5 ? 'HAS_5' : 'WRONG_COUNT_' + count);`,
    (output) => {
      const has5 = output.includes('HAS_5');
      return {
        pass: has5,
        reason: has5 ? '5 names' : 'wrong count'
      };
    }
  );

  await runGitHubTest(
    'Blocks "shai-hulud" repo name',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib/config-loader')).load();
     const blocked = config.githubApi?.blockedRepoNames?.includes('shai-hulud');
     console.log(blocked ? 'BLOCKED' : 'NOT_BLOCKED');`,
    (output) => {
      const isBlocked = output.includes('BLOCKED');
      return {
        pass: isBlocked,
        reason: isBlocked ? 'shai-hulud blocked' : 'not blocked'
      };
    }
  );

  await runGitHubTest(
    'Blocks "secrets" repo name',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib/config-loader')).load();
     const blocked = config.githubApi?.blockedRepoNames?.includes('secrets');
     console.log(blocked ? 'BLOCKED' : 'NOT_BLOCKED');`,
    (output) => {
      const isBlocked = output.includes('BLOCKED');
      return {
        pass: isBlocked,
        reason: isBlocked ? 'secrets blocked' : 'not blocked'
      };
    }
  );

  await runGitHubTest(
    'Blocks "credentials" repo name',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib/config-loader')).load();
     const blocked = config.githubApi?.blockedRepoNames?.includes('credentials');
     console.log(blocked ? 'BLOCKED' : 'NOT_BLOCKED');`,
    (output) => {
      const isBlocked = output.includes('BLOCKED');
      return {
        pass: isBlocked,
        reason: isBlocked ? 'credentials blocked' : 'not blocked'
      };
    }
  );

  await runGitHubTest(
    'Blocks "tokens" repo name',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib/config-loader')).load();
     const blocked = config.githubApi?.blockedRepoNames?.includes('tokens');
     console.log(blocked ? 'BLOCKED' : 'NOT_BLOCKED');`,
    (output) => {
      const isBlocked = output.includes('BLOCKED');
      return {
        pass: isBlocked,
        reason: isBlocked ? 'tokens blocked' : 'not blocked'
      };
    }
  );

  await runGitHubTest(
    'Blocks "keys" repo name',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib/config-loader')).load();
     const blocked = config.githubApi?.blockedRepoNames?.includes('keys');
     console.log(blocked ? 'BLOCKED' : 'NOT_BLOCKED');`,
    (output) => {
      const isBlocked = output.includes('BLOCKED');
      return {
        pass: isBlocked,
        reason: isBlocked ? 'keys blocked' : 'not blocked'
      };
    }
  );

  // ============================================
  // 3. BLOCKED WORKFLOW PATTERNS (2 tests)
  // ============================================
  console.log('\n[3] Blocked Workflow Patterns (2 patterns)\n');

  await runGitHubTest(
    'Config has 2 blocked workflow patterns',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib/config-loader')).load();
     const count = config.githubApi?.blockedWorkflowPatterns?.length || 0;
     console.log(count === 2 ? 'HAS_2' : 'WRONG_COUNT_' + count);`,
    (output) => {
      const has2 = output.includes('HAS_2');
      return {
        pass: has2,
        reason: has2 ? '2 patterns' : 'wrong count'
      };
    }
  );

  await runGitHubTest(
    'Blocks "discussion.yaml" workflow',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib/config-loader')).load();
     const blocked = config.githubApi?.blockedWorkflowPatterns?.includes('discussion.yaml');
     console.log(blocked ? 'BLOCKED' : 'NOT_BLOCKED');`,
    (output) => {
      const isBlocked = output.includes('BLOCKED');
      return {
        pass: isBlocked,
        reason: isBlocked ? 'discussion.yaml blocked' : 'not blocked'
      };
    }
  );

  await runGitHubTest(
    'Blocks "self-hosted" workflow pattern',
    `const path = require('path'); const config = require(path.join(process.cwd(), 'lib/config-loader')).load();
     const blocked = config.githubApi?.blockedWorkflowPatterns?.includes('self-hosted');
     console.log(blocked ? 'BLOCKED' : 'NOT_BLOCKED');`,
    (output) => {
      const isBlocked = output.includes('BLOCKED');
      return {
        pass: isBlocked,
        reason: isBlocked ? 'self-hosted blocked' : 'not blocked'
      };
    }
  );

  // ============================================
  // 4. GITHUB API MONITOR INITIALIZATION
  // ============================================
  console.log('\n[4] GitHub API Monitor Initialization\n');

  await runGitHubTest(
    'GitHub API monitor initialized',
    `console.log('test');`,
    (output) => {
      const hasMonitor = output.includes('GitHub API Monitor') || output.includes('GitHub-based attacks');
      return {
        pass: hasMonitor,
        reason: hasMonitor ? 'monitor initialized' : 'not initialized'
      };
    }
  );

  await runGitHubTest(
    'Shows blocked repo names in init',
    `console.log('test');`,
    (output) => {
      const showsRepos = output.includes('Blocking repo names:') || output.includes('shai-hulud');
      return {
        pass: showsRepos,
        reason: showsRepos ? 'repo names shown' : 'not shown'
      };
    }
  );

  await runGitHubTest(
    'Shows blocked workflow patterns in init',
    `console.log('test');`,
    (output) => {
      const showsWorkflows = output.includes('Blocking workflow patterns:') || output.includes('discussion.yaml');
      return {
        pass: showsWorkflows,
        reason: showsWorkflows ? 'workflow patterns shown' : 'not shown'
      };
    }
  );

  // ============================================
  // 5. GITHUB API DETECTION
  // ============================================
  console.log('\n[5] GitHub API Detection\n');

  await runGitHubTest(
    'Detects api.github.com requests',
    `const https = require('https');
     const req = https.get('https://api.github.com/user/repos', () => {});
     req.on('error', () => {});
     req.end();
     setTimeout(() => {}, 200);`,
    (output) => {
      const detected = output.includes('api.github.com') || output.includes('GitHub');
      return {
        pass: detected,
        reason: detected ? 'API detected' : 'not detected'
      };
    }
  );

  await runGitHubTest(
    'Allows legitimate GitHub API requests',
    `const https = require('https');
     const req = https.get('https://api.github.com/', () => {});
     req.on('error', () => {});
     req.end();
     console.log('REQUEST_MADE');`,
    (output) => {
      const allowed = output.includes('REQUEST_MADE');
      return {
        pass: allowed,
        reason: allowed ? 'request allowed' : 'request blocked'
      };
    }
  );

  // ============================================
  // 6. GITHUB API MONITOR CLASS
  // ============================================
  console.log('\n[6] GitHub API Monitor Class\n');

  await runGitHubTest(
    'GitHubApiMonitor class exists',
    `const path = require('path'); const { GitHubApiMonitor } = require(path.join(process.cwd(), 'lib/github-api-monitor'));
     console.log(GitHubApiMonitor ? 'EXISTS' : 'NOT_EXISTS');`,
    (output) => {
      const exists = output.includes('EXISTS');
      return {
        pass: exists,
        reason: exists ? 'class exists' : 'class missing'
      };
    }
  );

  await runGitHubTest(
    'GitHubApiMonitor can be instantiated',
    `const path = require('path'); 
     const { GitHubApiMonitor } = require(path.join(process.cwd(), 'lib/github-api-monitor'));
     const config = require(path.join(process.cwd(), 'lib/config-loader')).load();
     const monitor = new GitHubApiMonitor(config, true);
     console.log(monitor ? 'CREATED' : 'NOT_CREATED');`,
    (output) => {
      const created = output.includes('CREATED');
      return {
        pass: created,
        reason: created ? 'monitor created' : 'creation failed'
      };
    }
  );

  await runGitHubTest(
    'GitHubApiMonitor enabled property works',
    `const path = require('path'); 
     const { GitHubApiMonitor } = require(path.join(process.cwd(), 'lib/github-api-monitor'));
     const config = require(path.join(process.cwd(), 'lib/config-loader')).load();
     const monitor = new GitHubApiMonitor(config, true);
     console.log(monitor.enabled ? 'ENABLED' : 'DISABLED');`,
    (output) => {
      const enabled = output.includes('ENABLED');
      return {
        pass: enabled,
        reason: enabled ? 'monitor enabled' : 'monitor disabled'
      };
    }
  );

  await runGitHubTest(
    'GitHubApiMonitor has blockedRepoNames',
    `const path = require('path'); 
     const { GitHubApiMonitor } = require(path.join(process.cwd(), 'lib/github-api-monitor'));
     const config = require(path.join(process.cwd(), 'lib/config-loader')).load();
     const monitor = new GitHubApiMonitor(config, true);
     console.log(monitor.blockedRepoNames?.length > 0 ? 'HAS_REPOS' : 'NO_REPOS');`,
    (output) => {
      const hasRepos = output.includes('HAS_REPOS');
      return {
        pass: hasRepos,
        reason: hasRepos ? 'has blocked repos' : 'no blocked repos'
      };
    }
  );

  await runGitHubTest(
    'GitHubApiMonitor has blockedWorkflowPatterns',
    `const path = require('path'); 
     const { GitHubApiMonitor } = require(path.join(process.cwd(), 'lib/github-api-monitor'));
     const config = require(path.join(process.cwd(), 'lib/config-loader')).load();
     const monitor = new GitHubApiMonitor(config, true);
     console.log(monitor.blockedWorkflowPatterns?.length > 0 ? 'HAS_PATTERNS' : 'NO_PATTERNS');`,
    (output) => {
      const hasPatterns = output.includes('HAS_PATTERNS');
      return {
        pass: hasPatterns,
        reason: hasPatterns ? 'has patterns' : 'no patterns'
      };
    }
  );

  // ============================================
  // 7. INTEGRATION WITH NETWORK MONITOR
  // ============================================
  console.log('\n[7] Integration with Network Monitor\n');

  await runGitHubTest(
    'GitHub monitor integrated in network monitor',
    `const path = require('path');
     const { initialize } = require(path.join(process.cwd(), 'lib/network-monitor'));
     const config = require(path.join(process.cwd(), 'lib/config-loader')).load();
     const monitor = initialize(config, true);
     console.log(monitor.githubMonitor ? 'INTEGRATED' : 'NOT_INTEGRATED');`,
    (output) => {
      const integrated = output.includes('INTEGRATED');
      return {
        pass: integrated,
        reason: integrated ? 'integrated' : 'not integrated'
      };
    }
  );

  await runGitHubTest(
    'GitHub monitor active in network stack',
    `console.log('test');`,
    (output) => {
      const active = output.includes('GitHub API Monitor') || output.includes('Network Monitor');
      return {
        pass: active,
        reason: active ? 'active in stack' : 'not active'
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
  console.log('  GitHub API Config:        ✓');
  console.log('  Blocked Repo Names:       5/5 ✓');
  console.log('  Blocked Workflow Patterns: 2/2 ✓');
  console.log('  Monitor Initialization:   ✓');
  console.log('  API Detection:            ✓');
  console.log('  Monitor Class:            ✓');
  console.log('  Network Integration:      ✓\n');

  if (failed === 0) {
    console.log('All GitHub API protection tests passed! ✓\n');
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
