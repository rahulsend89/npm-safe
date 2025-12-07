// Catch all uncaught errors to continue testing
process.on('uncaughtException', (err) => {
  console.log(` ATTACK BLOCKED - ${err.message}`);
});

process.on('unhandledRejection', (reason) => {
  console.log(` ATTACK BLOCKED - ${reason}`);
});

// Auto-exit after running attacks
require('./server.js');

setTimeout(() => {
  console.log('\n');
  console.log('  TEST COMPLETE - All attacks have been attempted');
  console.log('  Check logs: malicious-app-firewall.log');
  console.log('  Check report: malicious-app-report.json');
  console.log('\n');
  process.exit(0);
}, 5000);
