/**
 * Config Coverage Test Suite Runner
 * Runs all comprehensive config coverage tests
 */

const { runFilesystemCoverageTests } = require('./filesystem-coverage');
const { runNetworkCoverageTests } = require('./network-coverage');
const { runEnvironmentCoverageTests } = require('./environment-coverage');
const { runCommandsCoverageTests } = require('./commands-coverage');

async function runConfigCoverageTests() {
  const summaries = [];
  
  console.log('\n╔════════════════════════════════════════════════════════════╗');
  console.log('║         COMPREHENSIVE CONFIG COVERAGE TESTS                ║');
  console.log('║  Testing EVERY config option (blocked & allowed)           ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  
  try {
    summaries.push(await runFilesystemCoverageTests());
    summaries.push(await runNetworkCoverageTests());
    summaries.push(await runEnvironmentCoverageTests());
    summaries.push(await runCommandsCoverageTests());
    
    // Print summary
    console.log('\n╔════════════════════════════════════════════════════════════╗');
    console.log('║              CONFIG COVERAGE TEST SUMMARY                  ║');
    console.log('╠════════════════════════════════════════════════════════════╣');
    
    let totalPassed = 0;
    let totalFailed = 0;
    let totalSkipped = 0;
    
    for (const summary of summaries) {
      const passStr = summary.passed > 0 ? `✓${summary.passed}` : '0';
      const failStr = summary.failed > 0 ? `✗${summary.failed}` : '0';
      const skipStr = summary.skipped > 0 ? `-${summary.skipped}` : '0';
      const total = summary.passed + summary.failed + summary.skipped;
      
      console.log(`║ ${summary.category.padEnd(20)} │ P:${passStr.padEnd(5)} F:${failStr.padEnd(5)} S:${skipStr.padEnd(5)} T:${String(total).padEnd(4)} ║`);
      
      totalPassed += summary.passed;
      totalFailed += summary.failed;
      totalSkipped += summary.skipped;
    }
    
    console.log('╠════════════════════════════════════════════════════════════╣');
    console.log(`║ TOTAL: ${totalPassed} passed, ${totalFailed} failed, ${totalSkipped} skipped`.padEnd(59) + '║');
    console.log('╚════════════════════════════════════════════════════════════╝\n');
    
    if (totalFailed > 0) {
      console.log('❌ Some config coverage tests failed. Review output above.\n');
      process.exit(1);
    } else {
      console.log('✅ All config coverage tests passed!\n');
      process.exit(0);
    }
    
  } catch (error) {
    console.error('\n❌ Config coverage test suite error:', error);
    process.exit(1);
  }
}

module.exports = { runConfigCoverageTests };

// Run if executed directly
if (require.main === module) {
  runConfigCoverageTests();
}
