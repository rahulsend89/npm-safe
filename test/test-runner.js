/**
 * Universal Test Runner
 * Consolidates all test execution logic with proper Node.js version detection,
 * cross-platform support, and real-world firewall initialization
 */

const { spawn } = require('child_process');
const path = require('path');
const os = require('os');

// Detect Node.js version
const nodeVersion = process.version;
const nodeMajor = parseInt(nodeVersion.split('.')[0].substring(1));
const nodeMinor = parseInt(nodeVersion.split('.')[1]);
const platform = os.platform();
const isWindows = platform === 'win32';

// Determine which loader API to use (matches install-helper.js logic)
const supportsImport = nodeMajor > 20 || (nodeMajor === 20 && nodeMinor >= 6);
const loaderFlag = supportsImport ? '--import' : '--loader';

// Get absolute paths (cross-platform)
const projectRoot = path.resolve(__dirname, '..');
const loaderPath = supportsImport 
  ? path.join(projectRoot, 'lib', 'init.mjs')
  : path.join(projectRoot, 'lib', 'legacy-loader.mjs');

// Convert to file:// URL for --loader (required on Windows and some Node versions)
const loaderUrl = isWindows || !supportsImport
  ? `file:///${loaderPath.replace(/\\/g, '/')}`
  : loaderPath;

console.log(`[Test Runner] Platform: ${platform}`);
console.log(`[Test Runner] Node.js: ${nodeVersion} (v${nodeMajor}.${nodeMinor})`);
console.log(`[Test Runner] Loader: ${loaderFlag}`);
console.log(`[Test Runner] Loader Path: ${loaderPath}`);
console.log(`[Test Runner] Supports Import: ${supportsImport}\n`);

/**
 * Universal test runner that simulates real npm-safe usage
 * @param {string} name - Test name
 * @param {string} code - Code to execute
 * @param {function} expectation - Function that validates output
 * @param {object} options - Additional options
 * @returns {Promise<boolean>}
 */
function runFirewallTest(name, code, expectation, options = {}) {
  return new Promise((resolve) => {
    process.stdout.write(`Testing ${name}... `);
    
    // Build command arguments (simulates real npm-safe usage)
    const args = [
      loaderFlag,
      loaderUrl
    ];
    
    // CRITICAL: Preload CommonJS interceptors for Node.js 18 (matches npm-safe behavior)
    // The --loader API only intercepts ESM imports. Requiring from loader context doesn't
    // reliably initialize interceptors in main process, so -r flags are REQUIRED
    if (!supportsImport) {
      const interceptorPath = path.join(projectRoot, 'lib', 'fs-interceptor-v2.js');
      args.push('-r', interceptorPath);
      const childProcessInterceptorPath = path.join(projectRoot, 'lib', 'child-process-interceptor.js');
      args.push('-r', childProcessInterceptorPath);
    }
    
    args.push('-e', code);

    const proc = spawn('node', args, {
      env: { 
        ...process.env, 
        NODE_FIREWALL: '1',
        ...(options.env || {})
      },
      cwd: options.cwd || projectRoot,
      timeout: options.timeout || 3000,
      shell: isWindows // Use shell on Windows for better compatibility
    });

    let output = '';
    let stderr = '';
    let resolved = false;
    
    proc.stdout.on('data', (data) => { output += data.toString(); });
    proc.stderr.on('data', (data) => { 
      stderr += data.toString();
      output += data.toString();
    });

    const finishTest = (exitCode) => {
      if (resolved) return;
      resolved = true;
      
      try {
        const result = expectation(output, exitCode, stderr);
        
        if (result.pass) {
          console.log('✓');
          resolve(true);
        } else {
          console.log(`✗ (${result.reason})`);
          if (options.debug && result.debug) {
            console.log(`  Debug: ${result.debug.substring(0, 150)}`);
          }
          resolve(false);
        }
      } catch (e) {
        console.log(`✗ (expectation error: ${e.message})`);
        resolve(false);
      }
    };

    proc.on('close', (code) => finishTest(code));
    proc.on('exit', (code) => finishTest(code));
    proc.on('error', (err) => {
      if (!resolved) {
        console.log(`✗ (spawn error: ${err.message})`);
        resolved = true;
        resolve(false);
      }
    });

    setTimeout(() => {
      if (!resolved) {
        proc.kill('SIGKILL');
        finishTest(-1);
      }
    }, options.timeout || 3000);
  });
}

/**
 * Synchronous test for non-firewall tests
 */
function runTest(name, fn) {
  process.stdout.write(`Testing ${name}... `);
  try {
    fn();
    console.log('✓');
    return true;
  } catch (e) {
    console.log('✗');
    console.error(`  Error: ${e.message}`);
    return false;
  }
}

/**
 * Async test for non-firewall tests
 */
async function runAsyncTest(name, fn) {
  process.stdout.write(`Testing ${name}... `);
  try {
    await fn();
    console.log('✓');
    return true;
  } catch (e) {
    console.log('✗');
    console.error(`  Error: ${e.message}`);
    return false;
  }
}

/**
 * Get platform-specific path
 */
function getPlatformPath(unixPath) {
  if (isWindows) {
    // Convert Unix paths to Windows paths
    return unixPath.replace(/\//g, '\\');
  }
  return unixPath;
}

/**
 * Get platform-specific home directory
 */
function getHomeDir() {
  return os.homedir();
}

/**
 * Check if path exists (cross-platform)
 */
function pathExists(filePath) {
  const fs = require('fs');
  try {
    return fs.existsSync(filePath);
  } catch {
    return false;
  }
}

/**
 * Create temporary config file for testing
 */
function createTempConfig(config) {
  const fs = require('fs');
  const tempPath = path.join(os.tmpdir(), `firewall-test-${Date.now()}.json`);
  fs.writeFileSync(tempPath, JSON.stringify(config, null, 2));
  return tempPath;
}

/**
 * Clean up temporary config file
 */
function cleanupTempConfig(configPath) {
  const fs = require('fs');
  try {
    if (fs.existsSync(configPath)) {
      fs.unlinkSync(configPath);
    }
  } catch (e) {
    // Ignore cleanup errors
  }
}

module.exports = {
  // Main test runner
  runFirewallTest,
  
  // Sync/async test helpers
  runTest,
  runAsyncTest,
  
  // Platform info
  platform,
  isWindows,
  nodeMajor,
  nodeMinor,
  nodeVersion,
  supportsImport,
  loaderFlag,
  loaderPath,
  
  // Path helpers
  getPlatformPath,
  getHomeDir,
  pathExists,
  projectRoot,
  
  // Config helpers
  createTempConfig,
  cleanupTempConfig
};
