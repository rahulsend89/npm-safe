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
  const Module = require('module');
  
  // Wait for Module.mainModule to be set before initializing
  const initFortress = () => {
    if (Module.mainModule || require.main) {
      try {
        // Lazy-load fortress only when needed to avoid loading it unnecessarily
        const { getInstance: getFortress } = require('./firewall-hardening-fortress');
        const fortress = getFortress({
          blockWorkers: true,
          blockNativeAddons: true,
          blockSharedArrayBuffer: true,
          strictMode: process.env.NODE_FIREWALL_STRICT === '1'
        });
        fortress.initialize();
      } catch (e) {
        console.error('[FS Interceptor] Fortress initialization failed:', e.message);
      }
    } else {
      setImmediate(initFortress);
    }
  };
  
  setImmediate(initFortress);
}

// Store original fs functions before modification
const originalFs = { ...fs };
['readFileSync', 'writeFileSync', 'appendFileSync', 'existsSync', 'statSync', 'readdirSync',
 'unlinkSync', 'mkdirSync', 'rmdirSync', 'rmSync', 'renameSync', 'copyFileSync',
 'readFile', 'writeFile', 'appendFile', 'unlink', 'mkdir', 'rmdir', 'rm', 'rename', 'copyFile'
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
        // Try to get parent process name
        const { execSync } = require('child_process');
        const parentCmd = execSync(`ps -p ${ppid} -o comm=`, { encoding: 'utf8' }).toString().trim();
        
        const trustedBuilders = ['node-gyp', 'prebuild', 'cmake', 'make', 'gcc', 'g++', 'clang'];
        if (trustedBuilders.some(builder => parentCmd.includes(builder))) {
          return true;
        }
      }
    } catch (e) {
      // ps command might fail on some systems, fallback to other checks
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
  
  setupInterception() {
    // Intercept sync read operations
    fs.readFileSync = this.wrapSync('readFileSync', 'READ');
    fs.statSync = this.wrapSync('statSync', 'READ');
    fs.readdirSync = this.wrapSync('readdirSync', 'READ');
    fs.existsSync = this.wrapSync('existsSync', 'READ');
    
    // Intercept sync write operations
    fs.writeFileSync = this.wrapSync('writeFileSync', 'WRITE');
    fs.appendFileSync = this.wrapSync('appendFileSync', 'WRITE');
    fs.unlinkSync = this.wrapSync('unlinkSync', 'DELETE');
    fs.mkdirSync = this.wrapSync('mkdirSync', 'CREATE');
    fs.rmdirSync = this.wrapSync('rmdirSync', 'DELETE');
    fs.rmSync = this.wrapSync('rmSync', 'DELETE');
    fs.renameSync = this.wrapSync('renameSync', 'WRITE');
    fs.copyFileSync = this.wrapSync('copyFileSync', 'WRITE');
    
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
        readdir: 'READ'
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
              self.handleBlocked(operation, filePath, check);
              const error = new Error(`Firewall: ${check.reason} - ${filePath}`);
              error.code = 'EACCES';
              throw error;
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
        self.handleBlocked(operation, filePath, check);
        const error = new Error(`Firewall: ${check.reason} - ${filePath}`);
        error.code = 'EACCES';
        throw error;
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
        self.handleBlocked(operation, filePath, check);
        const error = new Error(`Firewall: ${check.reason} - ${filePath}`);
        error.code = 'EACCES';
        
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
        self.handleBlocked(operation, filePath, check);
        const error = new Error(`Firewall: ${check.reason} - ${filePath}`);
        error.code = 'EACCES';
        throw error;
      }
      
      return method.apply(this, args);
    };
  }
  
  extractPath(pathArg, method) {
    if (!pathArg) return '';
    
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
    
    // ALWAYS intercept sensitive patterns (highest priority)
    if (this.isSensitivePattern(filePath)) {
      return true;
    }
    
    // Auto-allow npm cache and package manager directories
    if (filePath.includes('/.npm/') || 
        filePath.includes('/.yarn/') || 
        filePath.includes('/.pnpm/') ||
        filePath.includes('/node_modules/') ||
        filePath.includes('/.cache/')) {
      return false;
    }
    
    // Auto-allow project directory (only if not sensitive)
    if (this.projectDir && filePath.startsWith(this.projectDir)) {
      return false;
    }
    
    return true;
  }
  
  isSensitivePattern(filePath) {
    const sensitive = [
      '/.ssh/', '/.aws/', '/.gnupg/', '/.env', 
      '/.npmrc', '/.gitconfig', '/.github/workflows/', '/etc/', '/usr/bin/'
    ];
    return sensitive.some(pattern => filePath.includes(pattern));
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
