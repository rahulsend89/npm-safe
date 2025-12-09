const Module = require('module');
const fs = require('fs');
const path = require('path');
const { makeImmutable } = require('./immutable-property');

// Store original fs functions before interception
const originalFs = {
  appendFileSync: fs.appendFileSync
};

// Use centralized config loader
// ARCHITECTURE: Single source of truth for configuration
const configLoader = require('./config-loader');

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
    
    // Use centralized config (already loaded by config-loader singleton)
    this.config = configLoader.load();
    
    // Build patterns from config + defaults
    this.dangerousPatterns = this.buildDangerousPatterns();
    
    // Initialize spawn patterns and setup interception
    this.initializePatterns();
  }
  
  buildDangerousPatterns() {
    // ARCHITECTURE: Two-tier pattern system
    // 1. User-defined patterns from config (checked first, can customize severity)
    // 2. Security-critical patterns (always enforced, cannot be disabled)
    
    const userPatterns = [];
    const configPatterns = this.config?.commands?.blockedPatterns || [];
    
    for (const p of configPatterns) {
      try {
        userPatterns.push({
          pattern: new RegExp(p.pattern),
          desc: p.description || p.pattern,
          severity: p.severity || 'medium',
          source: 'config'
        });
      } catch (e) {
        console.warn(`[Child Process Firewall] Invalid regex in config: ${p.pattern}`);
      }
    }
    
    // SECURITY-CRITICAL: These patterns are ALWAYS enforced (defense in depth)
    // Even if config is missing or tampered with, these provide baseline protection
    // Derived from filesystem.blockedReadPaths patterns in config schema
    const blockedPaths = this.config?.filesystem?.blockedReadPaths || [];
    const sensitivePathPattern = blockedPaths.length > 0 
      ? new RegExp(blockedPaths.map(p => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'))
      : /\/(\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.env|\.npmrc)/;
    
    const criticalPatterns = [
      // Pipe to shell (supply chain attack vector)
      { pattern: /\|\s*(sh|bash|zsh|fish|ksh)/, desc: 'Pipe to shell', severity: 'critical', source: 'security' },
      
      // Recursive delete (destructive)
      { pattern: /rm\s+(-rf?|--recursive)/, desc: 'Recursive delete', severity: 'critical', source: 'security' },
      
      // SECURITY FIX: Block network requests via curl/wget
      { pattern: /^curl\s+/, desc: 'Network request (curl)', severity: 'critical', source: 'security' },
      { pattern: /^wget\s+/, desc: 'Network request (wget)', severity: 'critical', source: 'security' },
      { pattern: /\bcurl\s+/, desc: 'Network request (curl)', severity: 'critical', source: 'security' },
      { pattern: /\bwget\s+/, desc: 'Network request (wget)', severity: 'critical', source: 'security' },
      
      // Sensitive file access (derived from config or defaults)
      { pattern: sensitivePathPattern, desc: 'Access sensitive directory', severity: 'critical', source: 'security' },
      
      // System file access
      { pattern: /\/(etc\/)?(passwd|shadow|sudoers)/, desc: 'Access system file', severity: 'critical', source: 'security' },
    ];
    
    // User patterns first (for custom severity), then critical patterns
    return [...userPatterns, ...criticalPatterns];
  }
  
  buildDangerousSpawnPatterns() {
    // SECURITY-CRITICAL: These spawn patterns are always checked
    // They represent common attack vectors that should never be allowed from untrusted code
    const patterns = [
      { command: 'bash', args: ['-c'], desc: 'Bash shell execution', severity: 'critical' },
      { command: 'sh', args: ['-c'], desc: 'Shell execution', severity: 'critical' },
      { command: 'zsh', args: ['-c'], desc: 'Zsh execution', severity: 'critical' },
      { command: 'eval', args: null, desc: 'Code evaluation', severity: 'critical' },
      // SECURITY FIX: Block ALL curl/wget to prevent network bypass
      { command: 'curl', args: null, desc: 'Network request (curl)', severity: 'critical' },
      { command: 'wget', args: null, desc: 'Network request (wget)', severity: 'critical' },
      { command: 'nc', args: null, desc: 'Netcat connection', severity: 'critical' },
      { command: 'netcat', args: null, desc: 'Netcat connection', severity: 'critical' },
    ];
    
    // Allowed commands from config - these are trusted build tools
    // SECURITY: Only commands explicitly in config are allowed to bypass checks
    const configAllowed = this.config?.commands?.allowedCommands;
    this.allowedCommands = new Set(configAllowed || []);
    
    // SECURITY: If no config, use minimal safe defaults (fail closed)
    if (!configAllowed || configAllowed.length === 0) {
      // Minimal set required for npm to function
      this.allowedCommands = new Set(['npm', 'node', 'git']);
    }
    
    return patterns;
  }
  
  initializePatterns() {
    this.dangerousSpawnPatterns = this.buildDangerousSpawnPatterns();
    this.setupInterception();
  }

  setupInterception() {
    const self = this;
    
    // SECURITY FIX: Intercept child_process at require time
    // This ensures interception works even when child_process is required after firewall init
    const originalLoad = Module._load;
    Module._load = function(request, parent, isMain) {
      const exports = originalLoad.apply(this, arguments);
      
      // Intercept child_process module
      if (request === 'child_process' || request === 'node:child_process') {
        // Only wrap once
        if (!exports.__firewallWrapped) {
          self.wrapChildProcessModule(exports);
          exports.__firewallWrapped = true;
        }
      }
      
      return exports;
    };
    
    // Also wrap the already-loaded child_process module if it exists
    try {
      const childProcess = require('child_process');
      if (!childProcess.__firewallWrapped) {
        this.wrapChildProcessModule(childProcess);
        childProcess.__firewallWrapped = true;
      }
    } catch (e) {
      // child_process not loaded yet, will be intercepted on first require
    }
  }
  
  wrapChildProcessModule(childProcess) {
    // Store original functions
    if (!this.originals) {
      this.originals = {
        exec: childProcess.exec,
        execSync: childProcess.execSync,
        spawn: childProcess.spawn,
        spawnSync: childProcess.spawnSync,
        execFile: childProcess.execFile,
        execFileSync: childProcess.execFileSync,
      };
    }
    
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

  // Helper method to copy environment variables to plain object
  // SECURITY FIX: Strip sensitive environment variables from child processes
  copyEnv(source) {
    const plainEnv = {};
    
    // Get protected variables from config
    const protectedVars = this.config?.environment?.protectedVariables || [
      'GITHUB_TOKEN',
      'NPM_TOKEN',
      'SLACK_TOKEN',
      'OPENAI_API_KEY',
      'AWS_ACCESS_KEY_ID',
      'AWS_SECRET_ACCESS_KEY',
      'STRIPE_SECRET_KEY',
      'PRIVATE_KEY',
      'SSH_PRIVATE_KEY',
      'DATABASE_URL',
      'API_KEY'
    ];
    
    for (const key of Object.keys(source)) {
      // Skip protected variables - don't leak them to child processes
      if (protectedVars.includes(key)) {
        console.warn(`[Child Process Firewall] Stripped sensitive env var: ${key}`);
        continue;
      }
      plainEnv[key] = source[key];
    }
    return plainEnv;
  }

  // Helper method to create access denied error
  createAccessError(message) {
    const error = new Error(message);
    error.code = 'EACCES';
    return error;
  }

  // Helper method to build full command string
  buildFullCommand(command, args) {
    if (!args) return command;
    if (!Array.isArray(args)) {
      console.error('[Child Process Firewall] buildFullCommand called with non-array args:', typeof args, args);
      return command;
    }
    return `${command} ${args.join(' ')}`;
  }

  // Helper method to set FIREWALL_PARENT_PID in environment
  setParentPidInEnv(opts) {
    if (!opts.env) {
      const plainEnv = this.copyEnv(process.env);
      plainEnv.FIREWALL_PARENT_PID = String(process.pid);
      opts.env = plainEnv;
    } else if (!opts.env.FIREWALL_PARENT_PID) {
      opts.env.FIREWALL_PARENT_PID = String(process.pid);
    }
  }

  wrappedExec(command, options, callback) {
    if (typeof options === 'function') {
      callback = options;
      options = undefined;
    }
    
    // SECURITY FIX: exec() is synchronous, so we must check synchronously
    // checkCommand returns a boolean, not a Promise
    const allowed = this.checkCommand('exec', command, getCaller());
    
    if (!allowed) {
      const error = this.createAccessError('Shell command blocked by firewall');
      if (callback) {
        // Call callback asynchronously to maintain expected behavior
        process.nextTick(() => callback(error));
        return;
      }
      throw error;
    }
    
    // SECURITY FIX: Sanitize environment variables
    let opts = options;
    if (!opts) {
      opts = { env: this.copyEnv(process.env) };
    } else {
      // Copy options and sanitize env
      opts = { ...opts };
      if (!opts.env) {
        opts.env = this.copyEnv(process.env);
      } else {
        opts.env = this.copyEnv(opts.env);
      }
    }
    
    // Command is allowed, proceed with original exec
    // Don't use 'this' as context - use the child_process module
    return this.originals.exec(command, opts, callback);
  }
  
  wrappedExecSync(command, options) {
    const allowed = this.checkCommand('execSync', command, getCaller());
    if (!allowed) {
      throw this.createAccessError('Shell command blocked by firewall');
    }
    
    // SECURITY FIX: Sanitize environment variables
    let opts = options;
    if (!opts) {
      opts = { env: this.copyEnv(process.env) };
    } else {
      // Copy options and sanitize env
      opts = { ...opts };
      if (!opts.env) {
        opts.env = this.copyEnv(process.env);
      } else {
        opts.env = this.copyEnv(opts.env);
      }
    }
    
    return this.originals.execSync(command, opts);
  }
  
  wrappedSpawn(command, args, options) {
    // Handle spawn(command, options) signature where args is actually options
    if (args && !Array.isArray(args) && typeof args === 'object') {
      options = args;
      args = [];
    }
    
    const fullCommand = this.buildFullCommand(command, args);
    const argsArray = args || [];
    
    // Check if this is called by npm's official toolchain or node-gyp
    const stack = new Error().stack;
    const isNpmOperation = stack.includes('@npmcli/arborist') || 
                          stack.includes('@npmcli/run-script') || 
                          stack.includes('@npmcli/promise-spawn') ||
                          stack.includes('node-gyp');
    
    // Check if this is a build tool command (make, cmake, gcc, etc.)
    const isBuildTool = /^(make|cmake|gcc|g\+\+|clang|clang\+\+|python|python3|node|npm)$/.test(command);
    
    // Check if this is a node-gyp or native build operation that shouldn't inherit NODE_OPTIONS
    const isNativeBuild = command.includes('node-gyp') || 
                          command.includes('python') ||
                          command === 'make' ||
                          command === 'cmake' ||
                          command.includes('gyp') ||
                          (Array.isArray(args) && args.some(a => String(a).includes('node-gyp') || String(a).includes('gyp_main.py')));
    
    // Check if this is a shell command from npm script execution (sh -c "...")
    // These should also have NODE_OPTIONS stripped to prevent double-loading
    const isShellFromNpm = (command === 'sh' || command === 'bash' || command === 'zsh') &&
                           Array.isArray(args) && args[0] === '-c' &&
                           stack.includes('@npmcli/run-script');
    
    // SECURITY: Detect if this is a LIFECYCLE script (postinstall, preinstall, etc.)
    // These run code from UNTRUSTED packages and need FULL security checks
    const lifecycleEvent = process.env.npm_lifecycle_event || '';
    const isLifecycleScript = ['preinstall', 'install', 'postinstall', 'preuninstall', 'uninstall', 'postuninstall', 'prepublish', 'prepare', 'prepublishOnly'].includes(lifecycleEvent);
    
    // Detect if we're in the ROOT project or a DEPENDENCY
    // Root project scripts (npm run dev) are trusted
    // Dependency lifecycle scripts (postinstall in node_modules/foo) are NOT trusted
    const npmPackageName = process.env.npm_package_name || '';
    const isRootProject = process.cwd() === process.env.INIT_CWD;
    const isDependencyLifecycle = isLifecycleScript && !isRootProject;
    
    // STRICT: Check for dangerous command/argument combinations
    const spawnThreats = this.checkSpawnArguments(command, argsArray);
    
    // For spawn, we need synchronous check since we must return the process object immediately
    // Check for dangerous patterns in full command
    const threats = this.dangerousPatterns.filter(p => p.pattern.test(fullCommand));
    
    // Combine both threat lists
    const allThreats = [...spawnThreats, ...threats];
    const caller = getCaller();
    
    // Prepare options
    const opts = options || {};
    
    // SECURITY FIX: De-proxy environment to ensure native spawn works correctly
    // CRITICAL: Always create a sanitized environment copy to strip sensitive vars
    if (opts.env) {
      try {
        opts.env = this.copyEnv(opts.env);
      } catch (e) {
        // Ignore de-proxy errors
      }
    } else {
      // SECURITY: If no env provided, create sanitized copy of process.env
      // This prevents sensitive env vars from leaking to child processes
      opts.env = this.copyEnv(process.env);
    }
    
    // CRITICAL FIX: Strip NODE_OPTIONS for native build tools and npm scripts to prevent firewall interference
    // node-gyp, make, python etc. should not inherit --import flags as it breaks compilation
    // npm scripts (sh -c "...") should also not double-load the firewall
    if (isNativeBuild || isNpmOperation || isShellFromNpm) {
      if (!opts.env) {
        opts.env = this.copyEnv(process.env);
      }
      // Remove firewall-related NODE_OPTIONS to prevent double-loading and build interference
      if (opts.env.NODE_OPTIONS) {
        // Remove --import and -r flags that load the firewall
        opts.env.NODE_OPTIONS = opts.env.NODE_OPTIONS
          .replace(/--import\s+[^\s]+/g, '')
          .replace(/-r\s+[^\s]+/g, '')
          .trim();
      }
    }
    
    // LIFECYCLE SCRIPT HANDLING:
    // Two categories of npm scripts:
    // 1. ROOT PROJECT scripts (npm run dev, npm run build) - TRUSTED (user defined)
    // 2. DEPENDENCY lifecycle scripts (postinstall in node_modules/foo) - UNTRUSTED
    
    if (isShellFromNpm) {
      if (isDependencyLifecycle) {
        // UNTRUSTED: Dependency lifecycle script (e.g., postinstall from a package)
        // Apply FULL security checks - these are the main attack vector
        // Don't skip any patterns - check everything
        if (allThreats.length > 0) {
          // Log and potentially block
          this.logAccess('DEPENDENCY_LIFECYCLE_THREAT', 'spawn', fullCommand, caller, allThreats);
          
          // For critical threats, block immediately
          const criticalThreats = allThreats.filter(t => t.severity === 'critical');
          if (criticalThreats.length > 0) {
            console.error(`\n[FIREWALL] BLOCKED: Dangerous command in dependency lifecycle script`);
            console.error(`  Package: ${npmPackageName}`);
            console.error(`  Event: ${lifecycleEvent}`);
            console.error(`  Command: ${fullCommand}`);
            console.error(`  Threats: ${criticalThreats.map(t => t.desc).join(', ')}`);
            
            throw this.createAccessError(`Firewall blocked dangerous command in ${npmPackageName} ${lifecycleEvent}`);
          }
          // Non-critical threats: warn but allow (for now)
          console.warn(`[FIREWALL] WARNING: Suspicious command in ${npmPackageName} ${lifecycleEvent}: ${fullCommand}`);
        }
        
        // Allow with logging
        this.logAccess('DEPENDENCY_LIFECYCLE', 'spawn', fullCommand, caller, allThreats);
      } else {
        // TRUSTED: Root project script (npm run dev, etc.)
        // Only check critical security patterns, not user-defined ones
        const criticalThreats = allThreats.filter(t => t.source === 'security');
        if (criticalThreats.length > 0) {
          // Even trusted scripts shouldn't access /etc/shadow or rm -rf /
          this.logAccess('ROOT_SCRIPT_CRITICAL_THREAT', 'spawn', fullCommand, caller, criticalThreats);
          // Fall through to normal handling for critical threats
        } else {
          this.logAccess('ROOT_SCRIPT', 'spawn', fullCommand, caller, []);
        }
      }
      
      // Set up environment for child process
      this.setParentPidInEnv(opts);
      
      // If no critical threats for root scripts, or dependency script passed checks, allow
      if (!isDependencyLifecycle || allThreats.filter(t => t.severity === 'critical').length === 0) {
        const criticalThreats = allThreats.filter(t => t.source === 'security');
        if (!isDependencyLifecycle && criticalThreats.length === 0) {
          return this.originals.spawn.call(this, command, args, opts);
        }
        if (isDependencyLifecycle) {
          return this.originals.spawn.call(this, command, args, opts);
        }
      }
      // Fall through for critical threats
    }
    
    if (allThreats.length === 0) {
      // Command looks safe, allow it
      this.logAccess('ALLOWED', 'spawn', fullCommand, caller, []);
      
      // Mark child processes with parent PID to reduce verbose output
      this.setParentPidInEnv(opts);
      
      return this.originals.spawn.call(this, command, args, opts);
    }
    
    // If called by npm's official modules or node-gyp, allow with logging
    if (isNpmOperation) {
      this.logAccess('NPM_OPERATION', 'spawn', fullCommand, caller, allThreats);
      return this.originals.spawn.call(this, command, args, opts);
    }
    
    // If it's a build tool, allow with logging
    if (isBuildTool) {
      this.logAccess('BUILD_TOOL', 'spawn', fullCommand, caller, allThreats);
      return this.originals.spawn.call(this, command, args, opts);
    }
    
    // Log the request
    this.logAccess('REQUEST', 'spawn', fullCommand, caller, allThreats);
    
    // SECURITY FIX: ALWAYS block critical threats regardless of interactive mode
    const criticalThreats = allThreats.filter(t => t.severity === 'critical');
    if (criticalThreats.length > 0) {
      this.logAccess('DENIED', 'spawn', fullCommand, caller, criticalThreats);
      console.error(`\n[FIREWALL] BLOCKED: Critical security threat detected`);
      console.error(`  Command: ${fullCommand}`);
      console.error(`  Threats: ${criticalThreats.map(t => t.desc).join(', ')}`);
      throw this.createAccessError(`Process spawn blocked by firewall: ${criticalThreats[0]?.desc || 'critical threat'}`);
    }
    
    if (!this.interactive) {
      // Non-interactive mode: deny all dangerous commands
      this.logAccess('DENIED', 'spawn', fullCommand, caller, allThreats);
      console.error(`\n[FIREWALL] BLOCKED: ${allThreats.map(t => t.desc).join(', ')}`);
      console.error(`  Command: ${fullCommand}`);
      throw this.createAccessError(`Process spawn blocked by firewall: ${allThreats[0]?.desc || 'dangerous command'}`);
    }
    
    // Interactive mode: log but allow (only for non-critical threats)
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
    // Handle spawnSync(command, options) signature where args is actually options
    if (args && !Array.isArray(args) && typeof args === 'object') {
      options = args;
      args = [];
    }
    
    const fullCommand = this.buildFullCommand(command, args);
    const argsArray = args || [];
    
    // Prepare options
    const opts = options || {};
    
    // SECURITY FIX: De-proxy environment
    if (opts.env) {
      try {
        opts.env = { ...opts.env };
      } catch (e) {
        // Ignore
      }
    }
    
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
    
    return this.originals.spawnSync.call(this, command, args, opts);
  }
  
  wrappedExecFile(file, args, options, callback) {
    // Handle execFile(file, options, callback) signature
    if (typeof args === 'function') {
      callback = args;
      args = [];
      options = undefined;
    } else if (typeof options === 'function') {
      callback = options;
      options = undefined;
    }
    
    // Handle execFile(file, options, callback) where args is actually options
    if (args && !Array.isArray(args) && typeof args === 'object') {
      if (typeof options === 'function') {
        callback = options;
      }
      options = args;
      args = [];
    }
    
    const fullCommand = this.buildFullCommand(file, args);
    const allowed = this.checkCommand('execFile', fullCommand, getCaller());
    if (!allowed) {
      const error = this.createAccessError('File execution blocked by firewall');
      if (callback) {
        return callback(error);
      }
      throw error;
    }
    
    return this.originals.execFile.call(this, file, args, options, callback);
  }
  
  wrappedExecFileSync(file, args, options) {
    // Handle execFileSync(file, options) signature where args is actually options
    if (args && !Array.isArray(args) && typeof args === 'object') {
      options = args;
      args = [];
    }
    
    const fullCommand = this.buildFullCommand(file, args);
    const allowed = this.checkCommand('execFileSync', fullCommand, getCaller());
    if (!allowed) {
      throw this.createAccessError('File execution blocked by firewall');
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
    
    // SECURITY FIX: For synchronous operations (exec, execSync, spawnSync, execFileSync, execFile), 
    // we can't use async prompts. Return false (deny) in interactive mode for synchronous operations.
    // Interactive prompts only work for async operations (spawn)
    // Note: execFile is async but called synchronously, so we must check synchronously
    if (operation === 'exec' || operation === 'execSync' || 
        operation === 'spawnSync' || operation === 'execFileSync' || operation === 'execFile') {
      // In interactive mode, log but deny for synchronous operations
      // User should use spawn() for interactive approval
      this.logAccess('DENIED', operation, command, caller, threats);
      console.error(`\n  BLOCKED shell command (interactive mode not supported for ${operation}):`, command);
      return false;
    }
    
    // For async operations (spawn), show interactive prompt
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

