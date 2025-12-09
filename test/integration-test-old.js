/**
 * Integration Test: Complete firewall functionality
 * Tests all major components with the current Node.js version
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const [major, minor] = process.versions.node.split('.').map(Number);

console.log('======================================================');
console.log('   Firewall Integration Test');
console.log('======================================================');
console.log('Node.js version:', process.version);
console.log('');

let testsPassed = 0;
let testsFailed = 0;

function test(name, fn) {
  process.stdout.write(`Testing ${name}... `);
  try {
    fn();
    console.log('✓');
    testsPassed++;
  } catch (e) {
    console.log('✗');
    console.error('  Error:', e.message);
    testsFailed++;
  }
}

function testAsync(name, fn) {
  return new Promise((resolve) => {
    process.stdout.write(`Testing ${name}... `);
    fn()
      .then(() => {
        console.log('✓');
        testsPassed++;
        resolve();
      })
      .catch((e) => {
        console.log('✗');
        console.error('  Error:', e.message);
        testsFailed++;
        resolve();
      });
  });
}

function runCommand(cmd, args, env = {}) {
  return new Promise((resolve, reject) => {
    const proc = spawn(cmd, args, {
      env: { ...process.env, ...env },
      stdio: 'pipe'
    });
    
    let stdout = '';
    let stderr = '';
    
    proc.stdout.on('data', (data) => { stdout += data; });
    proc.stderr.on('data', (data) => { stderr += data; });
    
    proc.on('close', (code) => {
      if (code === 0) {
        resolve({ stdout, stderr });
      } else {
        reject(new Error(`Exit code ${code}: ${stderr || stdout}`));
      }
    });
    
    proc.on('error', reject);
  });
}

// Synchronous tests
test('Version detection', () => {
  const supportsImport = major > 20 || (major === 20 && minor >= 6);
  const supportsLoader = major > 16 || (major === 16 && minor >= 12);
  
  if (major >= 20 && minor >= 6 && !supportsImport) {
    throw new Error('Should support --import');
  }
  if (major >= 16 && minor >= 12 && major < 20 && !supportsLoader) {
    throw new Error('Should support --loader');
  }
});

test('Config loader exists', () => {
  const configPath = path.join(__dirname, '..', 'lib', 'config-loader.js');
  if (!fs.existsSync(configPath)) {
    throw new Error('config-loader.js not found');
  }
});

test('Config loading', () => {
  const config = require('../lib/config-loader.js');
  const loaded = config.load();
  if (!loaded || typeof loaded !== 'object') {
    throw new Error('Config loading failed');
  }
});

test('Firewall core exists', () => {
  const corePath = path.join(__dirname, '..', 'lib', 'firewall-core.js');
  if (!fs.existsSync(corePath)) {
    throw new Error('firewall-core.js not found');
  }
});

test('FS interceptor exists', () => {
  const fsPath = path.join(__dirname, '..', 'lib', 'fs-interceptor-v2.js');
  if (!fs.existsSync(fsPath)) {
    throw new Error('fs-interceptor-v2.js not found');
  }
});

test('Child process interceptor exists', () => {
  const cpPath = path.join(__dirname, '..', 'lib', 'child-process-interceptor.js');
  if (!fs.existsSync(cpPath)) {
    throw new Error('child-process-interceptor.js not found');
  }
});

// Async tests
(async () => {
  console.log('');
  console.log('Running async tests...');
  console.log('');
  
  // Test firewall initialization
  await testAsync('Firewall initialization', () => 
    runCommand('node', ['-e', 'const fw = require("./lib/firewall-core.js"); console.log("OK")'], {
      NODE_FIREWALL: '1'
    })
  );
  
  // Test FS interceptor loading
  await testAsync('FS interceptor loading', () =>
    runCommand('node', ['-r', './lib/fs-interceptor-v2.js', '-e', 'console.log("OK")'], {
      NODE_FIREWALL: '1'
    })
  );
  
  // Test child process interceptor loading
  await testAsync('Child process interceptor', () =>
    runCommand('node', ['-r', './lib/child-process-interceptor.js', '-e', 'console.log("OK")'], {
      NODE_FIREWALL: '1'
    })
  );
  
  // Test ESM loader if supported
  if (major > 20 || (major === 20 && minor >= 6)) {
    await testAsync('ESM hooks (--import)', () =>
      runCommand('node', ['--import', './lib/init.mjs', '-e', 'console.log("OK")'])
    );
  } else if (major > 16 || (major === 16 && minor >= 12)) {
    const loaderFlag = (major >= 19 || (major === 18 && minor >= 19)) ? '--loader' : '--experimental-loader';
    await testAsync(`ESM hooks (${loaderFlag})`, () =>
      runCommand('node', [loaderFlag, './lib/legacy-loader.mjs', '-e', 'console.log("OK")'], {
        NODE_FIREWALL: '1'
      })
    );
  }
  
  // Test npm-safe wrapper
  await testAsync('npm-safe wrapper', () =>
    runCommand('node', ['./bin/npm-safe', '--version'])
  );
  
  // Final summary
  console.log('');
  console.log('======================================================');
  console.log('Summary:');
  console.log(`  Passed: ${testsPassed}`);
  console.log(`  Failed: ${testsFailed}`);
  console.log('======================================================');
  
  if (testsFailed > 0) {
    console.log('');
    console.error('Some tests failed!');
    process.exit(1);
  } else {
    console.log('');
    console.log('All tests passed! ✓');
    process.exit(0);
  }
})();
