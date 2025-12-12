#!/usr/bin/env node

/**
 * Comprehensive Attack Suite
 * Simulates complete supply chain attack like Shai-Hulud
 * Runs ALL attack vectors in sequence
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('\n');
console.log('');
console.log('    COMPREHENSIVE SUPPLY CHAIN ATTACK SIMULATION ');
console.log('');
console.log('');
console.log('This test simulates a real supply chain attack like Shai-Hulud');
console.log('Testing all firewall protection layers...');
console.log('\n');

const results = {
  timestamp: new Date().toISOString(),
  testSuites: [],
  overall: {
    totalAttacks: 0,
    blocked: 0,
    successful: 0,
    protectionRate: 0
  }
};

// Run test suite
function runTestSuite(name, script) {
  console.log(`\n${''.repeat(60)}`);
  console.log(`Running: ${name}`);
  console.log(''.repeat(60));
  
  try {
    const output = execSync(`node ${script}`, { 
      encoding: 'utf8',
      stdio: 'pipe'
    });
    console.log(output);
    
    // Try to parse report
    const reportFile = script.replace('test-', '').replace('.js', '-report.json');
    if (fs.existsSync(reportFile)) {
      const report = JSON.parse(fs.readFileSync(reportFile, 'utf8'));
      results.testSuites.push({
        name,
        attacks: report.attacks
      });
      
      const successful = report.attacks.filter(a => a.success).length;
      const blocked = report.attacks.filter(a => !a.success).length;
      
      results.overall.totalAttacks += report.attacks.length;
      results.overall.blocked += blocked;
      results.overall.successful += successful;
    }
  } catch (e) {
    console.error(`Error running ${name}:`, e.message);
    console.log('Output:', e.stdout?.toString());
  }
}

// Run all test suites
console.log('Starting comprehensive security test...\n');

runTestSuite('File-Based Attacks', 'test-file-attacks.js');
runTestSuite('Network-Based Attacks', 'test-network-attacks.js');
runTestSuite('Command Execution Attacks', 'test-command-attacks.js');

// Calculate overall protection rate
if (results.overall.totalAttacks > 0) {
  results.overall.protectionRate = Math.round(
    (results.overall.blocked / results.overall.totalAttacks) * 100
  );
}

// Generate comprehensive report
console.log('\n\n');
console.log('');
console.log('     FIREWALL SECURITY ASSESSMENT REPORT');
console.log('\n');

console.log('📊 OVERALL STATISTICS');
console.log(''.repeat(60));
console.log(`Total Attack Vectors Tested:    ${results.overall.totalAttacks}`);
console.log(`Attacks Blocked:                ${results.overall.blocked} `);
console.log(`Attacks Succeeded:              ${results.overall.successful} `);
console.log(`Overall Protection Rate:        ${results.overall.protectionRate}%`);
console.log('');

// Protection level assessment
let grade, recommendation;
if (results.overall.protectionRate >= 90) {
  grade = 'A - EXCELLENT';
  recommendation = 'Firewall provides excellent protection against supply chain attacks.';
} else if (results.overall.protectionRate >= 75) {
  grade = 'B - GOOD';
  recommendation = 'Firewall provides good protection. Consider tuning rules for edge cases.';
} else if (results.overall.protectionRate >= 60) {
  grade = 'C - MODERATE';
  recommendation = 'Firewall provides moderate protection. Significant gaps exist that should be addressed.';
} else {
  grade = 'D - INSUFFICIENT';
  recommendation = 'Firewall has major gaps. Immediate action required to improve security posture.';
}

console.log(` SECURITY GRADE: ${grade}`);
console.log(`📝 RECOMMENDATION: ${recommendation}`);
console.log('');

// Detailed breakdown by category
console.log('DETAILED BREAKDOWN BY ATTACK CATEGORY');
console.log(''.repeat(60));

results.testSuites.forEach(suite => {
  const successful = suite.attacks.filter(a => a.success).length;
  const blocked = suite.attacks.filter(a => !a.success).length;
  const rate = Math.round((blocked / suite.attacks.length) * 100);
  
  console.log(`\n${suite.name}:`);
  console.log(`  Total:      ${suite.attacks.length}`);
  console.log(`  Blocked:    ${blocked} `);
  console.log(`  Succeeded:  ${successful} `);
  console.log(`  Rate:       ${rate}%`);
  
  if (successful > 0) {
    console.log(`  \n  Vulnerabilities:`);
    suite.attacks.filter(a => a.success).forEach(attack => {
      console.log(`     - ${attack.attack}`);
    });
  }
});

console.log('\n');
console.log(' CRITICAL FINDINGS');
console.log(''.repeat(60));

const criticalAttacks = [];
results.testSuites.forEach(suite => {
  suite.attacks.filter(a => a.success).forEach(attack => {
    if (['SSH_KEY_THEFT', 'AWS_CREDENTIALS_THEFT', 'NPM_TOKEN_THEFT', 
         'SSH_KEY_EXFIL', 'GITHUB_REPO_CREATE', 'BACKDOOR_SCRIPT_CREATE',
         'NETCAT_REVERSE_SHELL'].includes(attack.attack)) {
      criticalAttacks.push(attack);
    }
  });
});

if (criticalAttacks.length > 0) {
  console.log('⛔ CRITICAL VULNERABILITIES DETECTED:');
  criticalAttacks.forEach(attack => {
    console.log(`   - ${attack.attack}`);
    if (attack.file) console.log(`     File: ${attack.file}`);
    if (attack.command) console.log(`     Command: ${attack.command}`);
  });
} else {
  console.log(' No critical vulnerabilities detected');
}

console.log('\n');
console.log(' RECOMMENDATIONS');
console.log(''.repeat(60));

const recommendations = [];

if (results.overall.successful > 0) {
  recommendations.push('• Review and tighten firewall rules for failed protections');
  recommendations.push('• Consider adding exceptions for legitimate packages that were blocked');
  recommendations.push('• Enable strict mode for maximum protection in production');
  recommendations.push('• Review behavior reports regularly for anomaly detection');
}

if (results.overall.protectionRate < 100) {
  recommendations.push('• Implement additional native-level protections for unblocked attacks');
  recommendations.push('• Consider layered security with additional tools (Socket.dev, Snyk)');
  recommendations.push('• Enable network monitoring for all external connections');
}

if (recommendations.length > 0) {
  recommendations.forEach(rec => console.log(rec));
} else {
  console.log(' Firewall configuration is optimal for current threat landscape');
}

console.log('\n');
console.log('📄 DETAILED REPORTS');
console.log(''.repeat(60));
console.log('• attack-report.json - File attack details');
console.log('• network-attack-report.json - Network attack details');
console.log('• command-attack-report.json - Command execution details');
console.log('• comprehensive-report.json - Complete assessment');
console.log('');

// Save comprehensive report
try {
  fs.writeFileSync(
    'comprehensive-report.json', 
    JSON.stringify(results, null, 2)
  );
  console.log(' Comprehensive report saved successfully\n');
} catch (e) {
  console.error(' Failed to save comprehensive report:', e.message);
}

console.log('');
console.log('   Test Suite Completed');
console.log('\n');

// Exit with appropriate code
if (results.overall.successful > 0) {
  console.log('Warning: Some attacks succeeded. Review reports above.\n');
  process.exit(1);
} else {
  console.log(' All attacks blocked successfully!\n');
  process.exit(0);
}
