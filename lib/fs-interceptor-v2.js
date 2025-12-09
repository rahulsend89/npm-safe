/**
 * Filesystem Interceptor v2.0
 * Integrated with firewall-core for unified configuration and behavior monitoring
 */

const fs = require('fs');
const path = require('path');
const { makeImmutable } = require('./immutable-property');

// SECURITY: Fortress hardening is DISABLED by default
// To enable fortress protections, set NODE_FIREWALL_FORTRESS=1
// Fortress provides additional protection but can interfere with some applications
if (process.env.NODE_FIREWALL === '1' && process.env.NODE_FIREWALL_FORTRESS === '1') {
  try {
    // Initialize fortress immediately - do not wait for event loop
    // This prevents race conditions where malicious code runs before protection
    const { getInstance: getFortress } = require('./firewall-hardening-fortress');
    const fortress = getFortress({
      blockWorkers: true,
      blockNativeAddons: true,
      blockSharedArrayBuffer: true,
      strictMode: process.env.NODE_FIREWALL_STRICT === '1'
    });
    fortress.initialize();
    console.log('[FS Interceptor] Fortress hardening initialized synchronously');
  } catch (e) {
    console.error('[FS Interceptor] Fortress initialization failed:', e.message);
  }
}

// Store original fs functions before modification
const originalFs = { ...fs };
['readFileSync', 'writeFileSync', 'appendFileSync', 'existsSync', 'statSync', 'readdirSync',
 'unlinkSync', 'mkdirSync', 'rmdirSync', 'rmSync', 'renameSync', 'copyFileSync', 'openSync', 'opendirSync', 'readSync', 'writeSync',
 'readFile', 'writeFile', 'appendFile', 'unlink', 'mkdir', 'rmdir', 'rm', 'rename', 'copyFile', 'open', 'opendir', 'read', 'write'
].forEach(method => {
  if (fs[method]) originalFs[method] = fs[method].bind(fs);
});

class FileSystemInterceptor {
  constructor() {
    this.firewall = null;
    
    // Determine if should be enabled
    let shouldEnable = process.env.NODE_FIREWALL === '1';
    
    // Detect if we're in a build process (node-gyp, make, etc.)
    if (shouldEnable) {
      const isBuildProcess = this.detectBuildProcess();
      if (isBuildProcess) {
        // Disable firewall for native builds to avoid interfering with Makefiles
        shouldEnable = false;
      }
    }
    
    // SECURITY: Make enabled immutable
    makeImmutable(this, 'enabled', shouldEnable);
    
    if (!this.enabled) return;
    
    // SECURITY FIX: Initialize firewall synchronously to prevent race conditions
    // Firewall must be ready before any file operations can occur
    try {
      // We need to require here to handle circular deps if not injected
      const { getInstance } = require('./firewall-core');
      this.firewall = getInstance();
      
      // SECURITY: Ensure firewall is fully initialized
      if (!this.firewall.initialized) {
        this.firewall.initialize();
      }
    } catch (e) {
      // CRITICAL: If firewall can't initialize, we're in an insecure state
      // Log error but don't silently fail - this is a security issue
      console.error('[FS Interceptor] CRITICAL: Failed to initialize firewall:', e.message);
      console.error('[FS Interceptor] Stack:', e.stack);
      // Set firewall to null so checks will fail closed
      this.firewall = null;
    }
    
    this.projectDir = this.findProjectRoot(process.cwd());
    console.log(`[FS Interceptor] Active | Project: ${this.projectDir}`);
    
    // Performance: Cache package lookups
    this.packageCache = new Map();
    this.packageCacheTTL = 5000; // 5 second TTL
    
    this.setupInterception();
  }
  
  detectBuildProcess() {
    // ENHANCED: Check actual parent process, not just argv (prevents spoofing)
    try {
      const ppid = process.ppid;
      if (ppid) {
        // Try to get parent process name (platform-specific)
        const { execSync } = require('child_process');
        let parentCmd = '';
        
        if (process.platform === 'win32') {
          // Windows: use wmic (faster than PowerShell, still available on most systems)
          // PowerShell can hang or be slow to start
          // Note: wmic is deprecated on Windows 11+, but we catch errors gracefully
          try {
            parentCmd = execSync(
              `wmic process where processid=${ppid} get name /format:value`,
              { encoding: 'utf8', windowsHide: true, timeout: 1000, stdio: ['pipe', 'pipe', 'ignore'] }
            ).toString().trim();
            // Extract just the name from "Name=xxx"
            const match = parentCmd.match(/Name=(.+)/i);
            if (match) parentCmd = match[1].trim();
          } catch (e) {
            // Silently fail and rely on environment variable checks
            // wmic may not be available on Windows 11+ or in restricted environments
          }
        } else {
          // Unix/Linux/Mac: use ps
          parentCmd = execSync(`ps -p ${ppid} -o comm=`, { encoding: 'utf8', timeout: 1000 }).toString().trim();
        }
        
        const trustedBuilders = ['node-gyp', 'prebuild', 'cmake', 'make', 'gcc', 'g++', 'clang'];
        if (trustedBuilders.some(builder => parentCmd.includes(builder))) {
          return true;
        }
      }
    } catch (e) {
      // Process detection might fail on some systems, fallback to other checks
    }
    
    // Secondary check: environment variables (more reliable than argv)
    const lifecycleEvent = process.env.npm_lifecycle_event;
    if (lifecycleEvent === 'install' || lifecycleEvent === 'rebuild') {
      const script = process.env.npm_lifecycle_script || '';
      // Only trust if script actually contains build tools, not just mentions them
      if (script.match(/\b(node-gyp|prebuild|cmake|make)\b/)) {
        return true;
      }
    }
    
    // Tertiary check: argv (least reliable, only as fallback)
    const argv = process.argv;
    const directBuildTools = ['node-gyp', 'prebuild', 'node-pre-gyp', 'cmake'];
    if (argv.length > 1 && directBuildTools.includes(argv[1])) {
      // argv[1] is the actual script being run (not just a string in args)
      return true;
    }
    
    return false; // Fail-closed: deny if unsure
  }
  
  findProjectRoot(startDir) {
    let currentDir = startDir;
    const root = path.parse(currentDir).root;
    
    while (currentDir !== root) {
      const pkgPath = path.join(currentDir, 'package.json');
      if (originalFs.existsSync(pkgPath)) {
        return currentDir;
      }
      const parentDir = path.dirname(currentDir);
      if (parentDir === currentDir) break;
      currentDir = parentDir;
    }
    
    return startDir;
  }
  
  // Helper method to create access denied error
  createAccessError(message) {
    const error = new Error(message);
    error.code = 'EACCES';
    return error;
  }

  setupInterception() {
    // Intercept sync read operations
    fs.readFileSync = this.wrapSync('readFileSync', 'READ');
    fs.statSync = this.wrapSync('statSync', 'READ');
    fs.readdirSync = this.wrapSync('readdirSync', 'READ');
    fs.existsSync = this.wrapSync('existsSync', 'READ');
    fs.openSync = this.wrapSync('openSync', 'READ'); // Opening a file is effectively a read intent (or write)
    fs.opendirSync = this.wrapSync('opendirSync', 'READ');
    fs.readSync = this.wrapSync('readSync', 'READ');

    // Intercept sync write operations
    fs.writeFileSync = this.wrapSync('writeFileSync', 'WRITE');
    fs.appendFileSync = this.wrapSync('appendFileSync', 'WRITE');
    fs.unlinkSync = this.wrapSync('unlinkSync', 'DELETE');
    fs.mkdirSync = this.wrapSync('mkdirSync', 'CREATE');
    fs.rmdirSync = this.wrapSync('rmdirSync', 'DELETE');
    fs.rmSync = this.wrapSync('rmSync', 'DELETE');
    fs.renameSync = this.wrapSync('renameSync', 'WRITE');
    fs.copyFileSync = this.wrapSync('copyFileSync', 'WRITE');
    fs.writeSync = this.wrapSync('writeSync', 'WRITE');
    
    // Intercept async operations
    fs.readFile = this.wrapAsync('readFile', 'READ');
    fs.writeFile = this.wrapAsync('writeFile', 'WRITE');
    fs.appendFile = this.wrapAsync('appendFile', 'WRITE');
    fs.unlink = this.wrapAsync('unlink', 'DELETE');
    fs.mkdir = this.wrapAsync('mkdir', 'CREATE');
    fs.rmdir = this.wrapAsync('rmdir', 'DELETE');
    fs.rm = this.wrapAsync('rm', 'DELETE');
    fs.rename = this.wrapAsync('rename', 'WRITE');
    fs.copyFile = this.wrapAsync('copyFile', 'WRITE');
    fs.open = this.wrapAsync('open', 'READ');
    fs.opendir = this.wrapAsync('opendir', 'READ');
    fs.read = this.wrapAsync('read', 'READ');
    fs.write = this.wrapAsync('write', 'WRITE');
    
    // Intercept promises API using Proxy (works with Node.js v22+ read-only properties)
    if (fs.promises) {
      const originalPromises = fs.promises;
      const self = this;
      
      // Operation mapping for promise methods
      const operationMap = {
        readFile: 'READ',
        writeFile: 'WRITE',
        appendFile: 'WRITE',
        unlink: 'DELETE',
        mkdir: 'CREATE',
        rmdir: 'DELETE',
        rm: 'DELETE',
        rename: 'WRITE',
        copyFile: 'WRITE',
        stat: 'READ',
        lstat: 'READ',
        access: 'READ',
        readdir: 'READ',
        open: 'READ',
        opendir: 'READ'
      };
      
      // Create proxy to intercept all promise methods
      const promisesProxy = new Proxy(originalPromises, {
        get(target, prop) {
          const original = target[prop];
          if (typeof original !== 'function') return original;
          
          const operation = operationMap[prop];
          if (!operation) return original;
          
          // Return wrapped async function
          return async function(...args) {
            const filePath = self.extractPath(args[0]);
            
            if (!self.shouldIntercept(filePath, prop)) {
              return original.apply(target, args);
            }
            
            const check = self.checkAccess(operation, filePath);
            
            if (!check.allowed) {
              // Check if alert-only mode is enabled
              if (self.firewall?.config?.mode?.alertOnly) {
                console.warn(`[Firewall] ALERT: Would block ${operation} on ${filePath} (reason: ${check.reason})`);
                return original.apply(target, args);
              }
              
              self.handleBlocked(operation, filePath, check);
              throw self.createAccessError(`Firewall: ${check.reason} - ${filePath}`);
            }
            
            return original.apply(target, args);
          };
        }
      });
      
      // Replace fs.promises with proxy (works even if property is read-only)
      try {
        Object.defineProperty(fs, 'promises', {
          get: () => promisesProxy,
          set: () => {
            console.error('[FS Interceptor] Cannot override fs.promises');
            return false;
          },
          configurable: false
        });
        console.log('[FS Interceptor] fs.promises protected via proxy');
      } catch (e) {
        console.warn('[FS Interceptor] Could not fully protect fs.promises:', e.message);
      }
    }
  }
  
  wrapSync(method, operation) {
    const self = this;
    const original = originalFs[method];
    
    return function(...args) {
      const filePath = self.extractPath(args[0], method);
      
      if (!self.shouldIntercept(filePath, method)) {
        return original.apply(fs, args);
      }
      
      // Extract content for write operations to check for shebangs
      let content = null;
      if ((operation === 'WRITE' || operation === 'CREATE') && args[1]) {
        content = args[1];
      }
      
      const check = self.checkAccess(operation, filePath, content);
      
      if (!check.allowed) {
        // Check if alert-only mode is enabled
        if (self.firewall?.config?.mode?.alertOnly) {
          console.warn(`[Firewall] ALERT: Would block ${operation} on ${filePath} (reason: ${check.reason})`);
          return original.apply(fs, args);
        }
        
        self.handleBlocked(operation, filePath, check);
        throw self.createAccessError(`Firewall: ${check.reason} - ${filePath}`);
      }
      
      return original.apply(fs, args);
    };
  }
  
  wrapAsync(method, operation) {
    const self = this;
    const original = originalFs[method];
    
    return function(...args) {
      const callback = args[args.length - 1];
      const filePath = self.extractPath(args[0], method);
      
      if (!self.shouldIntercept(filePath, method)) {
        return original.apply(fs, args);
      }
      
      const check = self.checkAccess(operation, filePath);
      
      if (!check.allowed) {
        // Check if alert-only mode is enabled
        if (self.firewall?.config?.mode?.alertOnly) {
          console.warn(`[Firewall] ALERT: Would block ${operation} on ${filePath} (reason: ${check.reason})`);
          return original.apply(fs, args);
        }
        
        self.handleBlocked(operation, filePath, check);
        const error = self.createAccessError(`Firewall: ${check.reason} - ${filePath}`);
        
        if (typeof callback === 'function') {
          process.nextTick(() => callback(error));
          return;
        }
        throw error;
      }
      
      return original.apply(fs, args);
    };
  }
  
  wrapPromise(method, operation) {
    const self = this;
    
    return async function(...args) {
      const filePath = self.extractPath(args[0]);
      
      if (!self.shouldIntercept(filePath)) {
        return method.apply(this, args);
      }
      
      const check = self.checkAccess(operation, filePath);
      
      if (!check.allowed) {
        // Check if alert-only mode is enabled
        if (self.firewall?.config?.mode?.alertOnly) {
          console.warn(`[Firewall] ALERT: Would block ${operation} on ${filePath} (reason: ${check.reason})`);
          return method.apply(this, args);
        }
        
        self.handleBlocked(operation, filePath, check);
        throw self.createAccessError(`Firewall: ${check.reason} - ${filePath}`);
      }
      
      return method.apply(this, args);
    };
  }
  
  extractPath(pathArg, method) {
    if (!pathArg) return '';
    
    // Skip file descriptors (numbers) - they're already open files
    if (typeof pathArg === 'number') {
      return '';
    }
    
    // Handle different argument types
    if (typeof pathArg === 'string') {
      return path.resolve(pathArg);
    }
    if (Buffer.isBuffer(pathArg)) {
      return path.resolve(pathArg.toString());
    }
    if (typeof pathArg === 'object' && pathArg.toString) {
      return path.resolve(pathArg.toString());
    }
    
    return String(pathArg);
  }
  
  shouldIntercept(filePath, method) {
    // Don't intercept our own log files
    if (filePath.includes('fs-firewall') || filePath.includes('firewall-report')) {
      return false;
    }
    
    // Don't intercept node internals
    if (filePath.includes('node:') || filePath.includes('<builtin>')) {
      return false;
    }
    
    // PERFORMANCE: Check if we're in install mode - relax non-critical checks
    // Check multiple sources: npm-safe sets FIREWALL_INSTALL_MODE, npm sets npm_command
    const isInstallMode = process.env.FIREWALL_INSTALL_MODE === '1' ||
                          process.env.npm_command === 'install' || 
                          process.env.npm_command === 'ci' ||
                          process.env.npm_lifecycle_event === 'install';
    
    // ALWAYS intercept sensitive patterns (highest priority) - even during install
    if (this.isSensitivePattern(filePath, isInstallMode)) {
      return true;
    }
    
    // Auto-allow npm cache and package manager directories
    if (filePath.includes('/.npm/') || 
        filePath.includes('/.yarn/') || 
        filePath.includes('/.pnpm/') ||
        filePath.includes('/node_modules/') ||
        filePath.includes('/.cache/') ||
        filePath.includes('/.nvm/') ||
        filePath.includes('/var/folders/')) {  // macOS temp (used by npm)
      return false;
    }
    
    // INSTALL MODE OPTIMIZATION: Allow more paths during npm install
    if (isInstallMode) {
      // Allow package-lock.json, yarn.lock, etc.
      if (filePath.endsWith('package-lock.json') ||
          filePath.endsWith('yarn.lock') ||
          filePath.endsWith('pnpm-lock.yaml') ||
          filePath.endsWith('package.json') ||
          filePath.endsWith('.npmrc')) {  // npm needs to read .npmrc for auth
        return false;
      }
    }
    
    // Auto-allow project directory (only if not sensitive)
    if (this.projectDir && filePath.startsWith(this.projectDir)) {
      return false;
    }
    
    return true;
  }
  
  isSensitivePattern(filePath, isInstallMode = false) {
    // CRITICAL: These are ALWAYS blocked - even during install
    // These represent credential/key storage that should never be accessed by packages
    const criticalSensitive = [
      '/.ssh/',      // SSH keys
      '/.aws/',      // AWS credentials
      '/.gnupg/',    // GPG keys
      '/.kube/',     // Kubernetes config
      '/.docker/',   // Docker config (may have registry creds)
      '/.git/hooks/', // Git hooks (code execution on git operations)
      '/etc/shadow', // System passwords
      '/etc/passwd', // System users
    ];
    
    if (criticalSensitive.some(pattern => filePath.includes(pattern))) {
      return true;
    }
    
    // CONDITIONAL: These are blocked except when npm legitimately needs them
    if (!isInstallMode) {
      const conditionalSensitive = [
        '/.env',           // Environment files (app should use dotenv)
        '/.gitconfig',     // Git config
        '/.github/workflows/', // CI workflows
      ];
      
      if (conditionalSensitive.some(pattern => filePath.includes(pattern))) {
        return true;
      }
    }
    
    // NOTE: /.npmrc is NOT in sensitive list - npm needs it for authentication
    // The EnvProtector handles protecting tokens read from .npmrc
    
    return false;
  }
  
  isExecutableFile(filePath, content = null) {
    // Check 1: File has execute permissions
    try {
      const stats = originalFs.statSync(filePath);
      if (stats.mode & 0o111) {
        return true;
      }
    } catch (e) {
      // File might not exist yet (write operation)
    }
    
    // Check 2: File has shebang (script header)
    if (content) {
      const contentStr = Buffer.isBuffer(content) 
        ? content.toString('utf8', 0, 100) 
        : String(content).substring(0, 100);
      if (contentStr.startsWith('#!')) {
        return true;
      }
    }
    
    // Check 3: Common executable extensions
    const executableExts = ['.sh', '.bash', '.zsh', '.fish', '.command', '.exe', '.bat', '.cmd', '.ps1', '.py', '.rb', '.pl'];
    if (executableExts.some(ext => filePath.endsWith(ext))) {
      return true;
    }
    
    return false;
  }
  
  checkAccess(operation, filePath, content = null) {
    if (!this.firewall) {
      return { allowed: true, reason: 'firewall_not_ready' };
    }
    
    // Extract package name from call stack
    const packageName = this.getCallingPackage();
    
    // Check if trusted module
    if (packageName && this.firewall.isTrustedModule(packageName)) {
      return { allowed: true, reason: 'trusted_module', package: packageName };
    }
    
    // ENHANCED: Block executable file writes (not just by extension)
    if ((operation === 'WRITE' || operation === 'CREATE') && this.isExecutableFile(filePath, content)) {
      return {
        allowed: false,
        reason: 'executable_file_blocked',
        severity: 'critical',
        message: 'Writing executable files is blocked by firewall'
      };
    }
    
    // Check blocked extensions for WRITE/CREATE operations
    if (operation === 'WRITE' || operation === 'CREATE') {
      const config = this.firewall.getConfig();
      const blockedExt = config?.filesystem?.blockedExtensions || ['.sh', '.bash', '.command'];
      
      for (const ext of blockedExt) {
        if (filePath.endsWith(ext)) {
          return { 
            allowed: false, 
            reason: 'blocked_extension', 
            extension: ext,
            severity: 'high'
          };
        }
      }
    }
    
    // Use firewall core to check
    return this.firewall.checkFileAccess(operation, filePath, packageName);
  }
  
  getCallingPackage() {
    try {
      const stack = new Error().stack;
      
      // Check cache first (performance optimization)
      const cacheKey = stack.split('\n')[2]; // Use first relevant stack frame as key
      const now = Date.now();
      const cached = this.packageCache.get(cacheKey);
      if (cached && (now - cached.timestamp) < this.packageCacheTTL) {
        return cached.package;
      }
      
      // Parse stack trace
      const match = stack.match(/node_modules[/\\]((?:@[^/\\]+[/\\])?[^/\\]+)/);
      const packageName = match ? match[1] : null;
      
      // Cache result
      this.packageCache.set(cacheKey, { package: packageName, timestamp: now });
      
      // Limit cache size
      if (this.packageCache.size > 100) {
        const firstKey = this.packageCache.keys().next().value;
        this.packageCache.delete(firstKey);
      }
      
      return packageName;
    } catch (e) {
      return null;
    }
  }
  
  handleBlocked(operation, filePath, check) {
    console.error('\n╔╗');
    console.error('   FILESYSTEM ACCESS BLOCKED                      ');
    console.error('╚╝');
    console.error(`Operation:  ${operation}`);
    console.error(`Path:       ${filePath}`);
    console.error(`Reason:     ${check.reason}`);
    console.error(`Severity:   ${check.severity || 'high'}`);
    
    if (check.pattern) {
      console.error(`Pattern:    ${check.pattern}`);
    }
    
    const packageName = this.getCallingPackage();
    if (packageName) {
      console.error(`Package:    ${packageName}`);
      console.error('\nTo allow this, add an exception:');
      console.error(`  Edit .firewall-config.json and add to exceptions.modules["${packageName}"]`);
    }
    
    console.error('\n');
    
    // Log to file
    this.logBlocked(operation, filePath, check, packageName);
  }
  
  logBlocked(operation, filePath, check, packageName) {
    try {
      const logEntry = {
        timestamp: new Date().toISOString(),
        type: 'FILESYSTEM_BLOCKED',
        operation,
        path: filePath,
        reason: check.reason,
        severity: check.severity,
        package: packageName,
        callStack: new Error().stack.split('\n').slice(2, 7)
      };
      
      const logFile = this.firewall?.getConfig().reporting?.logFile || 'fs-firewall.log';
      const logLine = `[${logEntry.timestamp}] BLOCKED | ${JSON.stringify(logEntry)}\n`;
      originalFs.appendFileSync(logFile, logLine);
    } catch (e) {
      // Silent fail
    }
  }
}

// Initialize if enabled
if (process.env.NODE_FIREWALL === '1') {
  new FileSystemInterceptor();
}

module.exports = { FileSystemInterceptor };
module.exports.FileSystemInterceptor = FileSystemInterceptor;
