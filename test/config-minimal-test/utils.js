/**
 * Shared Utilities for Config-Based Tests
 * 
 * Cross-platform utilities for testing firewall configuration.
 */

const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawn } = require('child_process');

// Platform detection
const platform = os.platform();
const isWindows = platform === 'win32';
const isMac = platform === 'darwin';
const isLinux = platform === 'linux';

// Get project root
const projectRoot = path.resolve(__dirname, '../..');

/**
 * Get platform-appropriate temp directory for tests
 */
function getTestTempBase() {
  if (isWindows) {
    return path.join(os.tmpdir(), 'node-firewall-test');
  } else {
    return '/tmp/node-firewall-test';
  }
}

/**
 * Create test directory structure
 */
function setupTestDir(testName) {
  const testBase = getTestTempBase();
  const testDir = path.join(testBase, testName);
  fs.mkdirSync(testDir, { recursive: true });
  return testDir;
}

/**
 * Clean up test directory
 */
function cleanupTestDir(testDir) {
  try {
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  } catch (e) {
    // Ignore cleanup errors
  }
}

/**
 * Write a minimal firewall config to test directory
 */
function writeMinimalConfig(testDir, config) {
  const configPath = path.join(testDir, '.firewall-config.json');
  const fullConfig = {
    version: '2.0.0',
    mode: {
      enabled: true,
      interactive: false,
      strictMode: false,
      alertOnly: false
    },
    ...config
  };
  fs.writeFileSync(configPath, JSON.stringify(fullConfig, null, 2));
  return configPath;
}

/**
 * Create a test script file
 */
function writeTestScript(testDir, scriptName, code) {
  const scriptPath = path.join(testDir, scriptName);
  fs.writeFileSync(scriptPath, code);
  // Make executable on Unix
  if (!isWindows) {
    try {
      fs.chmodSync(scriptPath, 0o755);
    } catch (e) {}
  }
  return scriptPath;
}

/**
 * Get the shell command prefix for the current platform
 */
function getShellCommand() {
  if (isWindows) {
    return { shell: 'cmd.exe', shellArg: '/c' };
  } else {
    return { shell: '/bin/sh', shellArg: '-c' };
  }
}

/**
 * Get the cat/type command for the current platform
 */
function getCatCommand(filePath) {
  if (isWindows) {
    return `type "${filePath}"`;
  } else {
    return `cat "${filePath}"`;
  }
}

/**
 * Get the echo-to-file command for the current platform
 */
function getEchoToFileCommand(content, filePath) {
  if (isWindows) {
    return `echo ${content} > "${filePath}"`;
  } else {
    return `echo "${content}" > "${filePath}"`;
  }
}

/**
 * Run a script with the firewall enabled
 */
function runWithFirewall(testDir, code, options = {}) {
  return new Promise((resolve) => {
    const nodeMajor = parseInt(process.version.split('.')[0].substring(1));
    const nodeMinor = parseInt(process.version.split('.')[1]);
    const supportsImport = nodeMajor > 20 || (nodeMajor === 20 && nodeMinor >= 6);
    
    const loaderFlag = supportsImport ? '--import' : '--loader';
    const loaderPath = supportsImport 
      ? path.join(projectRoot, 'lib', 'init.mjs')
      : path.join(projectRoot, 'lib', 'legacy-loader.mjs');
    
    const loaderUrl = isWindows || !supportsImport
      ? `file:///${loaderPath.replace(/\\/g, '/')}`
      : loaderPath;
    
    const args = [loaderFlag, loaderUrl];
    
    if (!supportsImport) {
      args.push('-r', path.join(projectRoot, 'lib', 'fs-interceptor-v2.js'));
      args.push('-r', path.join(projectRoot, 'lib', 'child-process-interceptor.js'));
    }
    
    args.push('-e', code);
    
    const proc = spawn('node', args, {
      cwd: testDir,
      env: {
        ...process.env,
        NODE_FIREWALL: '1',
        FIREWALL_CONFIG: path.join(testDir, '.firewall-config.json'),
        FIREWALL_SILENT: options.silent ? '1' : '',
        ...options.env
      },
      timeout: options.timeout || 15000,
      shell: false
    });
    
    let stdout = '';
    let stderr = '';
    
    proc.stdout.on('data', (data) => {
      stdout += data.toString();
    });
    
    proc.stderr.on('data', (data) => {
      stderr += data.toString();
    });
    
    proc.on('close', (code) => {
      resolve({ stdout, stderr, exitCode: code, output: stdout + stderr });
    });
    
    proc.on('error', (err) => {
      resolve({ stdout, stderr, exitCode: -1, error: err.message, output: stdout + stderr });
    });
    
    setTimeout(() => {
      proc.kill('SIGKILL');
    }, options.timeout || 15000);
  });
}

/**
 * Run a script WITHOUT the firewall (baseline test)
 */
function runWithoutFirewall(testDir, code, options = {}) {
  return new Promise((resolve) => {
    const proc = spawn('node', ['-e', code], {
      cwd: testDir,
      env: {
        ...process.env,
        NODE_FIREWALL: '',
        ...options.env
      },
      timeout: options.timeout || 10000,
      shell: false
    });
    
    let stdout = '';
    let stderr = '';
    
    proc.stdout.on('data', (data) => {
      stdout += data.toString();
    });
    
    proc.stderr.on('data', (data) => {
      stderr += data.toString();
    });
    
    proc.on('close', (code) => {
      resolve({ stdout, stderr, exitCode: code, output: stdout + stderr });
    });
    
    proc.on('error', (err) => {
      resolve({ stdout, stderr, exitCode: -1, error: err.message, output: stdout + stderr });
    });
  });
}

/**
 * Check if output indicates blocking
 */
function isBlocked(output) {
  const blockIndicators = [
    'BLOCKED',
    'blocked',
    'DENIED',
    'denied',
    'permission denied',
    'access denied',
    'not allowed',
    'forbidden'
  ];
  return blockIndicators.some(indicator => output.includes(indicator));
}

/**
 * Escape path for use in JavaScript string
 */
function escapePath(filePath) {
  return filePath.replace(/\\/g, '\\\\');
}

/**
 * Test result tracker
 */
class TestTracker {
  constructor(category) {
    this.category = category;
    this.passed = 0;
    this.failed = 0;
    this.skipped = 0;
    this.results = [];
  }
  
  async runTest(name, testFn) {
    process.stdout.write(`  Testing ${name}... `);
    try {
      const result = await testFn();
      if (result.pass) {
        console.log('✓');
        this.passed++;
        this.results.push({ name, status: 'passed' });
        return true;
      } else {
        console.log(`✗ (${result.reason})`);
        if (result.debug && process.env.DEBUG) {
          console.log('    Debug:', result.debug.substring(0, 300));
        }
        this.failed++;
        this.results.push({ name, status: 'failed', reason: result.reason });
        return false;
      }
    } catch (e) {
      console.log(`✗ (exception: ${e.message})`);
      this.failed++;
      this.results.push({ name, status: 'failed', reason: e.message });
      return false;
    }
  }
  
  skip(name, reason) {
    console.log(`  Skipping ${name}... (${reason})`);
    this.skipped++;
    this.results.push({ name, status: 'skipped', reason });
  }
  
  getSummary() {
    return {
      category: this.category,
      passed: this.passed,
      failed: this.failed,
      skipped: this.skipped,
      total: this.passed + this.failed + this.skipped
    };
  }
}

module.exports = {
  // Platform info
  platform,
  isWindows,
  isMac,
  isLinux,
  projectRoot,
  
  // Re-export for convenience
  os: require('os'),
  
  // Directory helpers
  getTestTempBase,
  setupTestDir,
  cleanupTestDir,
  
  // Config helpers
  writeMinimalConfig,
  writeTestScript,
  
  // Command helpers
  getShellCommand,
  getCatCommand,
  getEchoToFileCommand,
  escapePath,
  
  // Runners
  runWithFirewall,
  runWithoutFirewall,
  
  // Result helpers
  isBlocked,
  TestTracker
};
