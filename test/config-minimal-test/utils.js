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
 * Returns the platform-specific base temporary directory path used for tests.
 * On Windows this is a 'node-firewall-test' subdirectory of the OS temp dir; on other platforms it is '/tmp/node-firewall-test'.
 * @returns {string} The base temporary directory path for test files.
 */
function getTestTempBase() {
  if (isWindows) {
    return path.join(os.tmpdir(), 'node-firewall-test');
  } else {
    return '/tmp/node-firewall-test';
  }
}

/**
 * Create and return a platform-specific test directory for the given test name.
 *
 * Ensures the directory exists under the test temp base (creating parents as needed).
 * @param {string} testName - Subdirectory name to create under the test temp base.
 * @returns {string} The full path to the created test directory.
 */
function setupTestDir(testName) {
  const testBase = getTestTempBase();
  const testDir = path.join(testBase, testName);
  fs.mkdirSync(testDir, { recursive: true });
  return testDir;
}

/**
 * Remove a test directory and its contents if it exists.
 *
 * Silently ignores any errors encountered while removing the directory.
 * @param {string} testDir - Path of the directory to remove.
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
 * Create a minimal firewall configuration file in the given test directory.
 *
 * The written config uses sensible defaults (version "2.0.0" and default mode
 * settings) merged with any properties provided in `config`.
 *
 * @param {string} testDir - Directory where the config file will be created.
 * @param {Object} [config] - Optional config properties to merge into defaults.
 * @returns {string} Path to the created '.firewall-config.json' file.
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
 * Write a test script file into the specified test directory.
 *
 * The file is created with the provided code. On non-Windows platforms the
 * file's mode is set to executable (755); permission changes are ignored on error.
 *
 * @param {string} testDir - Directory in which to create the script.
 * @param {string} scriptName - Name of the script file to create.
 * @param {string} code - File contents to write.
 * @returns {string} The full path to the written script file.
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
 * Return platform-specific shell executable and its command argument.
 * @returns {{shell: string, shellArg: string}} An object with `shell` set to the shell executable and `shellArg` set to the argument used to pass a command to that shell.
 */
function getShellCommand() {
  if (isWindows) {
    return { shell: 'cmd.exe', shellArg: '/c' };
  } else {
    return { shell: '/bin/sh', shellArg: '-c' };
  }
}

/**
 * Return a platform-appropriate shell command that outputs a file's contents.
 * @param {string} filePath - Path to the file to be displayed.
 * @returns {string} A command string that prints the contents of the specified file.
 */
function getCatCommand(filePath) {
  if (isWindows) {
    return `type "${filePath}"`;
  } else {
    return `cat "${filePath}"`;
  }
}

/**
 * Build a platform-appropriate shell command that writes the given text to a file.
 *
 * @param {string} content - The text to write into the file (not escaped).
 * @param {string} filePath - The destination file path.
 * @returns {string} A shell command that writes `content` to `filePath` on the current platform.
 */
function getEchoToFileCommand(content, filePath) {
  if (isWindows) {
    return `echo ${content} > "${filePath}"`;
  } else {
    return `echo "${content}" > "${filePath}"`;
  }
}

/**
 * Execute JavaScript code in a separate Node process with the test firewall enabled.
 *
 * @param {string} testDir - Working directory for the spawned Node process.
 * @param {string} code - JavaScript code to execute (passed to `node -e`).
 * @param {Object} [options] - Execution options.
 * @param {boolean} [options.silent=false] - If true, set FIREWALL_SILENT in the child environment.
 * @param {Object} [options.env] - Additional environment variables to merge into the child process environment.
 * @param {number} [options.timeout=15000] - Milliseconds before the child process is forcefully killed.
 * @returns {{ stdout: string, stderr: string, exitCode: number, output: string, error?: string }} An object containing captured `stdout`, `stderr`, the numeric `exitCode`, a combined `output` string, and an optional `error` message when process spawn fails.
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
 * Execute Node.js code in a test directory with the firewall disabled.
 *
 * @param {string} testDir - Working directory where the code will run.
 * @param {string} code - JavaScript source to execute (passed to `node -e`).
 * @param {Object} [options] - Optional execution settings.
 * @param {Object} [options.env] - Additional environment variables to merge into the process env.
 * @param {number} [options.timeout] - Maximum execution time in milliseconds (default: 10000).
 * @returns {{ stdout: string, stderr: string, output: string, exitCode: number, error?: string }} An object containing captured `stdout`, `stderr`, combined `output`, the process `exitCode`, and an optional `error` message when execution failed to start.
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
 * Determine whether a command output contains indicators that an action was blocked.
 * @param {string} output - The text to inspect for blocking indicators.
 * @returns {boolean} `true` if any known blocking phrase (for example: "blocked", "denied", "permission denied", "forbidden") appears in the output, `false` otherwise.
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