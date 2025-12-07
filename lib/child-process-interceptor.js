const Module = require('module');
const fs = require('fs');
const path = require('path');
const { makeImmutable } = require('./immutable-property');

// Store original fs functions before interception
const originalFs = {
  appendFileSync: fs.appendFileSync
};

class ChildProcessFirewall {
  constructor(fsOverride = null) {
    this.fs = fsOverride || originalFs;
    
    // SECURITY: Make enabled immutable
    makeImmutable(this, 'enabled', process.env.NODE_FIREWALL === '1');
    
    this.interactive = process.env.FS_FIREWALL_INTERACTIVE !== 'false' && process.env.FIREWALL_TEST_MODE !== '1';
    this.silent = false; // Never silent for child process interception
    this.logFile = process.env.FS_FIREWALL_LOG || 'fs-firewall.log';
    
    // Queue for sequential prompts
    this.promptQueue = [];
    this.isPrompting = false;
    
    if (!this.enabled) return;
    
    // Increase max listeners to avoid warnings
    if (process.stdin.setMaxListeners) {
      process.stdin.setMaxListeners(100);
    }
    
    console.log('Child Process Firewall activated');
    console.log('Shell command protection enabled');
    
    this.dangerousPatterns = [
      // File downloads
      { pattern: /curl.*(-o|--output|>)/, desc: 'Download to file', severity: 'high' },
      { pattern: /wget/, desc: 'Download file', severity: 'high' },
      
      // Pipe to shell execution (CRITICAL)
      { pattern: /\|\s*(sh|bash|zsh|fish|ksh)/, desc: 'Pipe to shell', severity: 'critical' },
      
      // Shell command execution (CRITICAL)
      { pattern: /bash\s+-c\s+/, desc: 'Bash -c command execution', severity: 'critical' },
      { pattern: /sh\s+-c\s+/, desc: 'Shell -c command execution', severity: 'critical' },
      { pattern: /zsh\s+-c\s+/, desc: 'Zsh -c command execution', severity: 'critical' },
      { pattern: /eval\s+["']/, desc: 'Eval code execution', severity: 'critical' },
      { pattern: /eval\s+\(/, desc: 'Eval code execution', severity: 'critical' },
      
      // File operations via shell
      { pattern: /cat\s+[~/]/, desc: 'Read user file', severity: 'medium' },
      { pattern: />\s*[~/]/, desc: 'Write to file', severity: 'high' },
      { pattern: />>\s*[~/]/, desc: 'Append to file', severity: 'high' },
      
      // Dangerous deletions
      { pattern: /rm\s+(-rf?|--recursive)/, desc: 'Recursive delete', severity: 'critical' },
      { pattern: /rm\s+[~/]/, desc: 'Delete file', severity: 'high' },
      
      // Sensitive file access
      { pattern: /\/(\.ssh|\.aws|\.gnupg|\.kube|\.docker)/, desc: 'Access sensitive directory', severity: 'critical' },
      { pattern: /\/(etc\/)?(passwd|shadow|hosts|sudoers)/, desc: 'Access system file', severity: 'critical' },
      
      // Network operations
      { pattern: /nc\s+/, desc: 'Network connection', severity: 'high' },
      { pattern: /netcat\s+/, desc: 'Network connection', severity: 'high' },
      
      // Archive operations
      { pattern: /tar\s+.*[xc]/, desc: 'Archive operation', severity: 'medium' },
      { pattern: /zip\s+/, desc: 'Create archive', severity: 'medium' },
      { pattern: /unzip\s+/, desc: 'Extract archive', severity: 'medium' },
    ];
    
    // Dangerous spawn commands/args (stricter validation)
    this.dangerousSpawnPatterns = [
      { command: 'bash', args: ['-c'], desc: 'Bash shell execution', severity: 'critical' },
      { command: 'sh', args: ['-c'], desc: 'Shell execution', severity: 'critical' },
      { command: 'zsh', args: ['-c'], desc: 'Zsh execution', severity: 'critical' },
      { command: 'eval', args: null, desc: 'Code evaluation', severity: 'critical' },
      { command: 'curl', args: ['-o', '--output'], desc: 'Download to file', severity: 'high' },
      { command: 'wget', args: null, desc: 'Download file', severity: 'high' },
      { command: 'nc', args: null, desc: 'Netcat connection', severity: 'high' },
      { command: 'netcat', args: null, desc: 'Netcat connection', severity: 'high' },
    ];
    
    this.setupInterception();
  }

  setupInterception() {
    // Get the original child_process module
    const childProcess = require('child_process');
    
    // Store original functions
    this.originals = {
      exec: childProcess.exec,
      execSync: childProcess.execSync,
      spawn: childProcess.spawn,
      spawnSync: childProcess.spawnSync,
      execFile: childProcess.execFile,
      execFileSync: childProcess.execFileSync,
    };
    
    const self = this;
    
    // Replace with wrapped versions
    childProcess.exec = function(...args) {
      return self.wrappedExec.apply(self, args);
    };
    
    childProcess.execSync = function(...args) {
      return self.wrappedExecSync.apply(self, args);
    };
    
    childProcess.spawn = function(...args) {
      return self.wrappedSpawn.apply(self, args);
    };
    
    childProcess.spawnSync = function(...args) {
      return self.wrappedSpawnSync.apply(self, args);
    };
    
    childProcess.execFile = function(...args) {
      return self.wrappedExecFile.apply(self, args);
    };
    
    childProcess.execFileSync = function(...args) {
      return self.wrappedExecFileSync.apply(self, args);
    };
  }

  wrappedExec(command, options, callback) {
    if (typeof options === 'function') {
      callback = options;
      options = undefined;
    }
    
    const result = this.checkCommand('exec', command, getCaller());
    
    // Handle both synchronous and asynchronous returns
    Promise.resolve(result).then(allowed => {
      if (!allowed) {
        const error = new Error('Shell command blocked by firewall');
        error.code = 'EACCES';
        if (callback) {
          return callback(error);
        }
        throw error;
      }
      
      return this.originals.exec.call(this, command, options, callback);
    }).catch(err => {
      if (callback) {
        callback(err);
      } else {
        throw err;
      }
    });
  }
  
  wrappedExecSync(command, options) {
    const allowed = this.checkCommand('execSync', command, getCaller());
    if (!allowed) {
      const error = new Error('Shell command blocked by firewall');
      error.code = 'EACCES';
      throw error;
    }
    
    return this.originals.execSync.call(this, command, options);
  }
  
  wrappedSpawn(command, args, options) {
    const fullCommand = args ? `${command} ${args.join(' ')}` : command;
    const argsArray = args || [];
    
    // Check if this is called by npm's official toolchain or node-gyp
    const stack = new Error().stack;
    const isNpmOperation = stack.includes('@npmcli/arborist') || 
                          stack.includes('@npmcli/run-script') || 
                          stack.includes('@npmcli/promise-spawn') ||
                          stack.includes('node-gyp');
    
    // Check if this is a build tool command (make, cmake, gcc, etc.)
    const isBuildTool = /^(make|cmake|gcc|g\+\+|clang|clang\+\+|python|python3|node|npm)$/.test(command);
    
    // STRICT: Check for dangerous command/argument combinations
    const spawnThreats = this.checkSpawnArguments(command, argsArray);
    
    // For spawn, we need synchronous check since we must return the process object immediately
    // Check for dangerous patterns in full command
    const threats = this.dangerousPatterns.filter(p => p.pattern.test(fullCommand));
    
    // Combine both threat lists
    const allThreats = [...spawnThreats, ...threats];
    const caller = getCaller();
    
    if (allThreats.length === 0) {
      // Command looks safe, allow it
      this.logAccess('ALLOWED', 'spawn', fullCommand, caller, []);
      
      // Mark child processes with parent PID to reduce verbose output
      const opts = options || {};
      if (!opts.env) {
        opts.env = { ...process.env, FIREWALL_PARENT_PID: String(process.pid) };
      } else if (!opts.env.FIREWALL_PARENT_PID) {
        opts.env.FIREWALL_PARENT_PID = String(process.pid);
      }
      
      return this.originals.spawn.call(this, command, args, opts);
    }
    
    // If called by npm's official modules or node-gyp, allow with logging
    if (isNpmOperation) {
      this.logAccess('NPM_OPERATION', 'spawn', fullCommand, caller, allThreats);
      return this.originals.spawn.call(this, command, args, options);
    }
    
    // If it's a build tool, allow with logging
    if (isBuildTool) {
      this.logAccess('BUILD_TOOL', 'spawn', fullCommand, caller, allThreats);
      return this.originals.spawn.call(this, command, args, options);
    }
    
    // Log the request
    this.logAccess('REQUEST', 'spawn', fullCommand, caller, allThreats);
    
    if (!this.interactive) {
      // Non-interactive mode: deny dangerous commands
      this.logAccess('DENIED', 'spawn', fullCommand, caller, allThreats);
      console.error(`\n [SPAWN BLOCKED] ${allThreats.map(t => t.desc).join(', ')}`);
      console.error(`   Command: ${fullCommand}`);
      const error = new Error(`Process spawn blocked by firewall: ${allThreats[0]?.desc || 'dangerous command'}`);
      error.code = 'EACCES';
      throw error;
    }
    
    // Interactive mode: log but allow (can't block synchronously without freezing)
    console.log(`\n[FIREWALL] Detected potentially dangerous spawn command: ${fullCommand}`);
    console.log(`[FIREWALL] Threats: ${allThreats.map(t => t.desc).join(', ')}`);
    console.log(`[FIREWALL] Allowing (interactive blocking not supported for spawn - use FS_FIREWALL_INTERACTIVE=false to block)`);
    
    return this.originals.spawn.call(this, command, args, options);
  }
  
  // Check spawn arguments for dangerous combinations
  checkSpawnArguments(command, args) {
    const threats = [];
    
    // Check each dangerous spawn pattern
    for (const pattern of this.dangerousSpawnPatterns) {
      if (pattern.command === command) {
        // If no specific args to check, command itself is dangerous
        if (pattern.args === null) {
          threats.push({
            pattern: new RegExp(command),
            desc: pattern.desc,
            severity: pattern.severity
          });
          continue;
        }
        
        // Check if any dangerous args are present
        for (const dangerousArg of pattern.args) {
          if (args && args.includes(dangerousArg)) {
            threats.push({
              pattern: new RegExp(`${command}.*${dangerousArg}`),
              desc: `${pattern.desc} (${command} ${dangerousArg})`,
              severity: pattern.severity
            });
            break; // One match is enough for this pattern
          }
        }
      }
    }
    
    return threats;
  }
  
  wrappedSpawnSync(command, args, options) {
    const fullCommand = args ? `${command} ${args.join(' ')}` : command;
    const argsArray = args || [];
    
    // Check spawn arguments strictly
    const spawnThreats = this.checkSpawnArguments(command, argsArray);
    
    // Also check full command pattern
    const allowed = this.checkCommand('spawnSync', fullCommand, getCaller());
    
    // Block if spawn arguments are dangerous OR command pattern is dangerous
    if (!allowed || spawnThreats.length > 0) {
      if (spawnThreats.length > 0) {
        console.error(`\n [SPAWN BLOCKED] ${spawnThreats.map(t => t.desc).join(', ')}`);
        console.error(`   Command: ${fullCommand}`);
      }
      return {
        error: new Error('Process spawn blocked by firewall'),
        status: 1,
        signal: null,
        output: [],
        stdout: Buffer.from(''),
        stderr: Buffer.from('Blocked by firewall\n')
      };
    }
    
    return this.originals.spawnSync.call(this, command, args, options);
  }
  
  wrappedExecFile(file, args, options, callback) {
    if (typeof args === 'function') {
      callback = args;
      args = [];
      options = undefined;
    } else if (typeof options === 'function') {
      callback = options;
      options = undefined;
    }
    
    const fullCommand = args ? `${file} ${args.join(' ')}` : file;
    const allowed = this.checkCommand('execFile', fullCommand, getCaller());
    if (!allowed) {
      const error = new Error('File execution blocked by firewall');
      error.code = 'EACCES';
      if (callback) {
        return callback(error);
      }
      throw error;
    }
    
    return this.originals.execFile.call(this, file, args, options, callback);
  }
  
  wrappedExecFileSync(file, args, options) {
    const fullCommand = args ? `${file} ${args.join(' ')}` : file;
    const allowed = this.checkCommand('execFileSync', fullCommand, getCaller());
    if (!allowed) {
      const error = new Error('File execution blocked by firewall');
      error.code = 'EACCES';
      throw error;
    }
    
    return this.originals.execFileSync.call(this, file, args, options);
  }

  checkCommand(operation, command, caller) {
    // Check for dangerous patterns
    const threats = this.dangerousPatterns.filter(p => p.pattern.test(command));
    
    if (threats.length === 0) {
      // Command looks safe, allow it
      this.logAccess('ALLOWED', operation, command, caller, []);
      return true;
    }
    
    // Log the request
    this.logAccess('REQUEST', operation, command, caller, threats);
    
    if (!this.interactive) {
      this.logAccess('DENIED', operation, command, caller, threats);
      console.error('\n  BLOCKED shell command:', command);
      return false;
    }
    
    // Show interactive prompt
    return this.promptUser(operation, command, threats, caller);
  }

  promptUser(operation, command, threats, caller) {
    return new Promise((resolve) => {
      // Add to queue
      this.promptQueue.push({ operation, command, threats, caller, resolve });
      
      // Process queue if not already prompting
      if (!this.isPrompting) {
        this.processPromptQueue();
      }
    });
  }
  
  async processPromptQueue() {
    if (this.promptQueue.length === 0) {
      this.isPrompting = false;
      return;
    }
    
    this.isPrompting = true;
    const { operation, command, threats, caller, resolve } = this.promptQueue.shift();
    
    // Check if we can actually prompt (stdin must be available and readable)
    // During npm install, stdin might not be a TTY but we can still try to read from it
    const canPrompt = process.stdin && process.stdin.readable !== false;
    
    if (!canPrompt) {
      console.log('\n[FIREWALL] Cannot prompt (stdin not available) - auto-allowing command');
      this.logAccess('ALLOWED_AUTO', operation, command, caller, threats);
      resolve(true);
      this.processPromptQueue();
      return;
    }
    
    const readline = require('readline').createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: true
    });
    
    console.log('\n+');
    console.log('| SHELL COMMAND EXECUTION REQUEST');
    console.log('+');
    console.log('| Operation:    ', operation);
    console.log('| Command:      ', command);
    console.log('| Process ID:   ', process.pid);
    console.log('+');
    console.log('| SECURITY WARNINGS');
    
    threats.forEach(threat => {
      console.log('|   [!]  ', threat.desc);
    });
    
    console.log('+');
    console.log('| CALL STACK');
    const stack = new Error().stack.split('\n').slice(3, 8);
    stack.forEach((line, i) => {
      console.log(`| ${i + 1}. ${line.trim().substring(3)}`);
    });
    console.log('+');
    
    // Use a more robust prompting mechanism
    process.stdout.write('Allow this command? (y/n/always/never) [default: y]: ');
    
    // Set stdin to raw mode to capture input immediately
    if (process.stdin.setRawMode) {
      process.stdin.setRawMode(true);
    }
    process.stdin.resume();
    
    const onData = (chunk) => {
      const input = chunk.toString().trim();
      
      // Clean up
      process.stdin.pause();
      if (process.stdin.setRawMode) {
        process.stdin.setRawMode(false);
      }
      process.stdin.removeListener('data', onData);
      readline.close();
      
      console.log(input || 'y'); // Echo the choice
      
      const choice = input.toLowerCase();
      const allowed = choice === 'y' || choice === 'yes' || choice === 'always' || choice === '' || choice === '\r' || choice === '\n';
      
      this.logAccess(allowed ? 'ALLOWED' : 'DENIED', operation, command, caller, threats);
      
      if (choice === 'always') {
        console.log('Note: "always" functionality not yet implemented');
      } else if (choice === 'never') {
        console.log('Note: "never" functionality not yet implemented');
      }
      
      resolve(allowed);
      
      // Process next in queue
      this.processPromptQueue();
    };
    
    process.stdin.once('data', onData);
  }

  logAccess(action, operation, command, caller, threats) {
    const timestamp = new Date().toISOString();
    const threatDesc = threats.map(t => t.desc).join(', ');
    
    // For NPM_OPERATION and BUILD_TOOL, use compact logging (no stack trace)
    if (action === 'NPM_OPERATION' || action === 'BUILD_TOOL') {
      const logEntry = [
        `[${timestamp}]`,
        `ACTION=${action}`,
        `OP=${operation}`,
        `CMD=${command}`,
        '\n'
      ].join(' | ');
      
      try {
        this.fs.appendFileSync(this.logFile, logEntry);
      } catch (e) {
        console.error('Failed to write to firewall log:', e.message);
      }
      return;
    }
    
    // For other actions, include full stack trace
    const stack = new Error().stack;
    const stackLines = stack.split('\n')
      .slice(2) // Skip Error and logAccess
      .filter(line => !line.includes('node:internal'))
      .slice(0, 15) // Limit to 15 lines
      .map(line => line.trim())
      .join('\n    ');
    
    const logEntry = [
      `[${timestamp}]`,
      `ACTION=${action}`,
      `OP=${operation}`,
      `CMD=${command}`,
      `CALLER=${caller}`,
      threatDesc ? `THREATS=${threatDesc}` : '',
      `\n  STACK TRACE:\n    ${stackLines}`,
      '\n\n'
    ].filter(Boolean).join(' | ');
    
    try {
      this.fs.appendFileSync(this.logFile, logEntry);
    } catch (e) {
      console.error('Failed to write to firewall log:', e.message);
    }
  }
}

function getCaller() {
  const stack = new Error().stack;
  const lines = stack.split('\n');
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.includes('child-process-interceptor')) continue;
    if (line.includes('node:internal')) continue;
    
    const match = line.match(/at\s+(.+?)\s+\((.+?):(\d+):(\d+)\)/);
    if (match) {
      return `${match[1]} (${match[2]}:${match[3]})`;
    }
    
    const fileMatch = line.match(/at\s+(.+?):(\d+):(\d+)/);
    if (fileMatch) {
      return `${fileMatch[1]}:${fileMatch[2]}`;
    }
  }
  
  return 'unknown';
}

// Initialize the firewall singleton
const firewall = new ChildProcessFirewall();

// SECURITY FIX #3: Only export singleton, NOT the class constructor
// This prevents attackers from creating new instances
module.exports = firewall;
// REMOVED: module.exports.ChildProcessFirewall = ChildProcessFirewall;

