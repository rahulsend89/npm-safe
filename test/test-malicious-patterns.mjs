/**
 * Test malicious pattern detection in ESM load hook
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('Testing malicious pattern detection in ESM load hook...\n');

// Test 1: Create a malicious module with base64 eval
const maliciousCode = `
export function evil() {
  eval(atob('Y29uc29sZS5sb2coImV2aWwiKQ=='));
}
`;

// Write test file
import { writeFileSync, unlinkSync, mkdirSync, rmSync } from 'fs';

// Simulate node_modules structure
const testDir = join(__dirname, 'temp-malicious-test', 'node_modules', 'evil-package');
const testFile = join(testDir, 'index.mjs');

try {
  mkdirSync(testDir, { recursive: true });
  writeFileSync(testFile, maliciousCode);
  
  console.log('✓ Created test malicious module');
  
  // Try to load it with firewall enabled
  const testProcess = spawn('node', [
    '--import', join(__dirname, '../lib/init.mjs'),
    '-e', `import('${testFile}').then(() => console.log('LOADED')).catch(e => console.log('BLOCKED:', e.message))`
  ], {
    env: { ...process.env, NODE_FIREWALL: '1' },
    cwd: __dirname
  });
  
  let output = '';
  testProcess.stdout.on('data', (data) => {
    output += data.toString();
  });
  
  testProcess.stderr.on('data', (data) => {
    output += data.toString();
  });
  
  testProcess.on('close', (code) => {
    if (output.includes('BLOCKED') || output.includes('Malicious code detected')) {
      console.log('✓ Malicious pattern was detected and blocked');
    } else if (output.includes('LOADED')) {
      console.log('✗ WARNING: Malicious code was NOT blocked!');
      console.log('Output:', output);
    } else {
      console.log('? Test result unclear');
      console.log('Output:', output);
    }
    
    // Cleanup
    try {
      const cleanupDir = join(__dirname, 'temp-malicious-test');
      rmSync(cleanupDir, { recursive: true, force: true });
      console.log('✓ Cleaned up test files');
    } catch (e) {
      console.log('Cleanup error:', e.message);
    }
  });
  
} catch (e) {
  console.error('Test error:', e.message);
  try {
    rmSync(testDir, { recursive: true, force: true });
  } catch {}
}
