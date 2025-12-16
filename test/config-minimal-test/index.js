/**
 * Configuration-Based Minimal Tests - Main Runner
 * 
 * Runs all test suites and aggregates results.
 * 
 * Test Categories:
 * - Filesystem: blockedReadPaths, blockedWritePaths, allowedPaths, blockedExtensions
 * - Environment: protectedVariables, pattern-based protection
 * - Network: blockedDomains, suspiciousPorts, credentialPatterns
 * - Commands: blockedPatterns, allowedCommands
 * 
 * Each category tests multiple bypass techniques:
 * - Direct API access (fs, http, process.env)
 * - Child process execution (execSync, spawn)
 * - Shell command bypass (cat, curl, echo)
 * - Pipe bypass attempts (cmd1 | cmd2)
 * - Script execution (.sh, .py files)
 * 
 * Cross-platform: Works on Linux, macOS, and Windows
 * 
 * Usage:
 *   node test/config-minimal-test/index.js
 *   npm run test:config-minimal
 */

const path = require('path');
const fs = require('fs');
const os = require('os');

const { isWindows, isMac, isLinux, getTestTempBase, cleanupTestDir, projectRoot } = require('./utils');
const { runFilesystemTests } = require('./filesystem');
const { runFilesystemAdvancedTests } = require('./filesystem/advanced-bypass');
const { runEnvironmentTests } = require('./environment');
const { runEnvironmentAdvancedTests } = require('./environment/advanced-bypass');
const { runNetworkTests } = require('./network');
const { runCommandTests } = require('./commands');
const { runEsmBypassTests } = require('./esm-bypass');
const { runAdvancedBypassTests } = require('./advanced-bypass');

// Advanced bypass tests
const { runAdvancedFilesystemTests } = require('./filesystem/advanced-bypass');
const { runAdvancedEnvironmentTests } = require('./environment/advanced-bypass');

// Header
console.log('\n' + '╔' + '═'.repeat(58) + '╗');
console.log('║' + ' '.repeat(10) + 'CONFIGURATION-BASED SECURITY TESTS' + ' '.repeat(13) + '║');
console.log('╚' + '═'.repeat(58) + '╝');
console.log('\nTest Information:');
console.log(`   Platform: ${os.platform()} (${isWindows ? 'Windows' : isMac ? 'macOS' : 'Linux'})`);
console.log(`   Node.js: ${process.version}`);
console.log(`   Project: ${projectRoot}`);
console.log(`   Temp Dir: ${getTestTempBase()}`);

/**
 * Print section header
 */
function printSectionHeader(title, emoji) {
  console.log('\n' + '─'.repeat(60));
  console.log(`${emoji} ${title}`);
  console.log('─'.repeat(60));
}

/**
 * Print summary table
 */
function printSummaryTable(summaries) {
  const totalPassed = summaries.reduce((acc, s) => acc + s.passed, 0);
  const totalFailed = summaries.reduce((acc, s) => acc + s.failed, 0);
  const totalSkipped = summaries.reduce((acc, s) => acc + s.skipped, 0);
  const totalTests = totalPassed + totalFailed + totalSkipped;
  
  console.log('\n' + '╔' + '═'.repeat(58) + '╗');
  console.log('║' + ' '.repeat(20) + 'TEST SUMMARY' + ' '.repeat(26) + '║');
  console.log('╠' + '═'.repeat(58) + '╣');
  
  // Header row
  console.log('║ ' + 'Category'.padEnd(20) + '│ ' + 'Passed'.padEnd(8) + '│ ' + 'Failed'.padEnd(8) + '│ ' + 'Skipped'.padEnd(8) + '│ ' + 'Total'.padEnd(6) + '║');
  console.log('╟' + '─'.repeat(21) + '┼' + '─'.repeat(9) + '┼' + '─'.repeat(9) + '┼' + '─'.repeat(9) + '┼' + '─'.repeat(7) + '╢');
  
  // Category rows
  for (const summary of summaries) {
    const passStr = summary.passed > 0 ? `✓${summary.passed}` : '0';
    const failStr = summary.failed > 0 ? `✗${summary.failed}` : '0';
    const skipStr = summary.skipped > 0 ? `-${summary.skipped}` : '0';
    const total = summary.passed + summary.failed + summary.skipped;
    
    console.log('║ ' + 
      summary.category.padEnd(20) + '│ ' + 
      passStr.padEnd(8) + '│ ' + 
      failStr.padEnd(8) + '│ ' + 
      skipStr.padEnd(8) + '│ ' + 
      String(total).padEnd(6) + '║');
  }
  
  // Total row
  console.log('╟' + '─'.repeat(21) + '┼' + '─'.repeat(9) + '┼' + '─'.repeat(9) + '┼' + '─'.repeat(9) + '┼' + '─'.repeat(7) + '╢');
  const passStr = totalPassed > 0 ? `✓${totalPassed}` : '0';
  const failStr = totalFailed > 0 ? `✗${totalFailed}` : '0';
  const skipStr = totalSkipped > 0 ? `-${totalSkipped}` : '0';
  console.log('║ ' + 
    'TOTAL'.padEnd(20) + '│ ' + 
    passStr.padEnd(8) + '│ ' + 
    failStr.padEnd(8) + '│ ' + 
    skipStr.padEnd(8) + '│ ' + 
    String(totalTests).padEnd(6) + '║');
  
  console.log('╚' + '═'.repeat(58) + '╝');
  
  // Final result
  console.log('\n' + '═'.repeat(60));
  if (totalFailed === 0) {
    console.log('ALL TESTS PASSED!');
    if (totalSkipped > 0) {
      console.log(`   (${totalSkipped} tests skipped due to platform)`);
    }
  } else {
    console.log(`${totalFailed} TESTS FAILED`);
    console.log('   Review output above for details.');
  }
  console.log('═'.repeat(60) + '\n');
  
  return { totalPassed, totalFailed, totalSkipped, totalTests };
}

/**
 * Main test runner
 */
async function main() {
  const summaries = [];
  
  try {
    // Clean up any leftover test directories
    const testBase = getTestTempBase();
    cleanupTestDir(testBase);
    fs.mkdirSync(testBase, { recursive: true });
    
    // Run all test suites
    printSectionHeader('FILESYSTEM PROTECTION', '[FS]');
    summaries.push(await runFilesystemTests());
    
    printSectionHeader('ADVANCED FILESYSTEM BYPASSES', '[FS+]');
    summaries.push(await runAdvancedFilesystemTests());
    
    printSectionHeader('ENVIRONMENT VARIABLE PROTECTION', '[ENV]');
    summaries.push(await runEnvironmentTests());
    
    printSectionHeader('ADVANCED ENVIRONMENT BYPASSES', '[ENV+]');
    summaries.push(await runAdvancedEnvironmentTests());
    
    printSectionHeader('NETWORK PROTECTION', '[NET]');
    summaries.push(await runNetworkTests());
    
    printSectionHeader('COMMAND EXECUTION PROTECTION', '[CMD]');
    summaries.push(await runCommandTests());
    
    printSectionHeader('ESM BUILT-IN BYPASS TESTS', '[ESM]');
    summaries.push(await runEsmBypassTests());
    
    printSectionHeader('ADVANCED BYPASS TECHNIQUES', '[ADV]');
    summaries.push(await runAdvancedBypassTests());
    
    // Final cleanup
    cleanupTestDir(testBase);
    
    // Print summary
    const { totalFailed } = printSummaryTable(summaries);
    
    process.exit(totalFailed > 0 ? 1 : 0);
    
  } catch (e) {
    console.error('\nTest suite error:', e);
    process.exit(1);
  }
}

// Run tests
main();
