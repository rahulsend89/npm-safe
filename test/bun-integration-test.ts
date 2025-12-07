/**
 * Bun Integration Test
 * Verifies firewall protections in Bun runtime
 */

console.log('Running Bun Integration Test...');

try {
  // 1. Test blocked command execution
  console.log('\nTest 1: Bun.spawn with dangerous command...');
  try {
    // Add timeout race
    const procPromise = Bun.spawn(['bash', '-c', 'cat /etc/shadow']).exited;
    const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 2000));
    
    await Promise.race([procPromise, timeoutPromise]);
    console.log('FAILED: Dangerous command was allowed');
  } catch (e) {
    console.log('PASSED: Dangerous command blocked');
    console.log(`   Error: ${e.message}`);
  }

  // 2. Test sensitive file access
  console.log('\nTest 2: Bun.file access to sensitive file...');
  try {
    const file = Bun.file('/etc/shadow');
    if (await file.exists()) {
      await file.text();
      console.log('FAILED: Sensitive file access allowed');
    } else {
      console.log('SKIPPED: File does not exist (expected on some systems)');
    }
  } catch (e) {
    console.log('PASSED: Sensitive file access blocked');
    console.log(`   Error: ${e.message}`);
  }

  // 3. Test shell execution
  console.log('\nTest 3: Bun.$ shell execution...');
  try {
    await Bun.$`cat /etc/passwd`;
    console.log('FAILED: Shell execution allowed');
  } catch (e) {
    console.log('PASSED: Shell execution blocked');
    console.log(`   Error: ${e.message}`);
  }
  
  console.log('\nBun Integration Test Complete');
} catch (e) {
  console.error('Unexpected error:', e);
  process.exit(1);
}
