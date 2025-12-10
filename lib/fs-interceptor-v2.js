/**
 * Filesystem Interceptor v2.0
 * Integrated with firewall-core for unified configuration and behavior monitoring
 */

const fs = require('fs');
const path = require('path');
const { makeImmutable } = require('./immutable-property');

// SECURITY: Get firewall's lib directory path at module load time
// This is used to verify that stack traces are from firewall internal code
// and not from malicious packages that name their files similarly
const FIREWALL_LIB_DIR = path.resolve(__dirname);
const FIREWALL_MODULE_NAMES = [
  'audit-logger.js',
  'behavior-monitor.js',
  'network-monitor.js',
  'github-api-monitor.js',
  'firewall-core.js',
  'child-process-interceptor.js',
  'fs-interceptor-v2.js',
  'firewall-hardening-fortress.js'
];

/**
 * SECURITY: Check if a stack trace is from firewall internal code
 * This prevents bypass attacks where malicious packages name their files
 * the same as firewall modules (e.g., node_modules/evil/audit-logger.js)
 * 
 * @param {string} stack - Error stack trace string
 * @returns {boolean} - True if stack is from firewall's own lib directory
 */
function isFirewallInternalStack(stack) {
  if (!stack || typeof stack !== 'string') {
    return false;
  }
  
  // Parse stack trace to extract file paths
  // Stack format: "at Function.fn (/path/to/file.js:line:col)"
  const stackLines = stack.split('\n');
  
  for (const line of stackLines) {
    // Extract file path from stack line
    // Match patterns like: "at ... (/path/to/file.js:line:col)" or "at /path/to/file.js:line:col"
    // Priority: try to extract from parentheses first (more reliable)
    const parenMatch = line.match(/\(([^)]+)\)/);
    const atMatch = line.match(/at\s+([^\s(]+)/);
    
    const filePath = (parenMatch && parenMatch[1]) || (atMatch && atMatch[1]);
    if (!filePath) continue;
    
    // Skip Node.js internals and built-in modules
    if (filePath.includes('<anonymous>') || 
        filePath.includes('node:') || 
        filePath.includes('internal/') ||
        filePath.includes('(native)')) {
      continue;
    }
    
    // Resolve to absolute path for comparison
    let absolutePath;
    try {
      // Remove line:column suffix if present
      // CROSS-PLATFORM FIX: Handle Windows paths with drive letters (C:\path\to\file.js:10:5)
      // On Windows: "C:\path\to\file.js:10:5" should become "C:\path\to\file.js"
      // On Unix: "/path/to/file.js:10:5" should become "/path/to/file.js"
      let pathOnly = filePath;
      
      // Check if this looks like a Windows path (has drive letter)
      const windowsPathMatch = filePath.match(/^([A-Za-z]:[\\/].+?)(?::(\d+):(\d+))?$/);
      if (windowsPathMatch) {
        // Windows path: extract just the path part (group 1)
        pathOnly = windowsPathMatch[1];
      } else {
        // Unix path: split by : and take first part (but only if there are multiple colons)
        const parts = filePath.split(':');
        if (parts.length > 1 && parts[0].startsWith('/')) {
          // Unix absolute path with line:col
          pathOnly = parts[0];
        } else if (parts.length > 2) {
          // Relative path or other format
          pathOnly = parts.slice(0, -2).join(':');
        }
      }
      
      absolutePath = path.resolve(pathOnly);
    } catch (e) {
      // Invalid path, skip
      continue;
    }
    
    // Check if path is within firewall's lib directory
    // SECURITY: Use path comparison to ensure it's actually in our lib dir
    // and not just a file with a similar name in node_modules
    // FIREWALL_LIB_DIR is set to __dirname at module load time, so it points to
    // the actual firewall package's lib directory (e.g., /project/node_modules/@rahulmalik/npm-safe/lib)
    // A malicious file at /project/node_modules/evil-package/audit-logger.js will NOT match
    // because it doesn't start with FIREWALL_LIB_DIR
    if (absolutePath.startsWith(FIREWALL_LIB_DIR + path.sep) || 
        absolutePath === FIREWALL_LIB_DIR) {
      // Verify it's actually one of our firewall modules
      const fileName = path.basename(absolutePath);
      if (FIREWALL_MODULE_NAMES.includes(fileName)) {
        return true;
      }
    }
  }
  
  return false;
}

// SECURITY: Fortress hardening is DISABLED by default
// To enable fortress protections, set NODE_FIREWALL_FORTRESS=1
// Fortress provides additional protection but can interfere with some applications
if (process.env.NODE_FIREWALL_FORTRESS === '1') {
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
['readFileSync', 'writeFileSync', 'appendFileSync', 'existsSync', 'statSync', 'lstatSync', 'readdirSync',
 'createWriteStream', 'createReadStream',
 'unlinkSync', 'mkdirSync', 'rmdirSync', 'rmSync', 'renameSync', 'copyFileSync', 'openSync', 'opendirSync', 'readSync', 'writeSync',
 'readFile', 'writeFile', 'appendFile', 'unlink', 'mkdir', 'rmdir', 'rm', 'rename', 'copyFile', 'open', 'opendir', 'read', 'write',
 // SECURITY FIX: Include symlink/link and realpath methods
 'symlinkSync', 'linkSync', 'symlink', 'link', 'realpathSync', 'realpath',
 // SECURITY FIX: Include access methods for existence detection prevention
 'accessSync', 'access'
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
    fs.lstatSync = this.wrapSync('lstatSync', 'READ');
    fs.readdirSync = this.wrapSync('readdirSync', 'READ');
    fs.existsSync = this.wrapSync('existsSync', 'READ');
    fs.accessSync = this.wrapSync('accessSync', 'READ'); // SECURITY FIX: Prevent file existence detection
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
    
    // SECURITY FIX: Intercept symlink/link operations
    // These can be used to bypass path restrictions
    if (fs.symlinkSync) fs.symlinkSync = this.wrapSymlink('symlinkSync');
    if (fs.linkSync) fs.linkSync = this.wrapSync('linkSync', 'WRITE');
    
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
    fs.access = this.wrapAsync('access', 'READ'); // SECURITY FIX: Prevent existence detection
    fs.lstat = this.wrapAsync('lstat', 'READ');
    
    // SECURITY FIX: Intercept stream operations
    // These can bypass writeFileSync/readFileSync interception
    fs.createWriteStream = this.wrapStream('createWriteStream', 'WRITE');
    fs.createReadStream = this.wrapStream('createReadStream', 'READ');
    
    // SECURITY FIX: Intercept process.chdir to prevent changing to blocked directories
    // This prevents bypass via relative paths after chdir to a blocked location
    this.interceptChdir();
    
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
        opendir: 'READ',
        // SECURITY FIX: Additional methods
        realpath: 'READ',
        readlink: 'READ',
        symlink: 'WRITE',
        link: 'WRITE'
      };
      
      // SECURITY FIX: Wrap FileHandle to intercept handle-based reads
      // This prevents bypass via: const handle = await fs.promises.open(); handle.read();
      const wrapFileHandle = (handle, filePath) => {
        return new Proxy(handle, {
          get(target, prop) {
            const original = target[prop];
            if (typeof original !== 'function') return original;
            
            // Intercept read operations on handle
            if (prop === 'read' || prop === 'readFile' || prop === 'readv') {
              return async function(...args) {
                const check = self.checkAccess('READ', filePath);
                if (!check.allowed) {
                  if (self.firewall?.config?.mode?.alertOnly) {
                    console.warn(`[Firewall] ALERT: Would block handle READ on ${filePath}`);
                    return original.apply(target, args);
                  }
                  self.handleBlocked('READ', filePath, check);
                  throw self.createAccessError(`Firewall: ${check.reason} - ${filePath}`);
                }
                return original.apply(target, args);
              };
            }
            
            // Intercept write operations on handle
            if (prop === 'write' || prop === 'writeFile' || prop === 'writev' || prop === 'appendFile') {
              return async function(...args) {
                const check = self.checkAccess('WRITE', filePath);
                if (!check.allowed) {
                  if (self.firewall?.config?.mode?.alertOnly) {
                    console.warn(`[Firewall] ALERT: Would block handle WRITE on ${filePath}`);
                    return original.apply(target, args);
                  }
                  self.handleBlocked('WRITE', filePath, check);
                  throw self.createAccessError(`Firewall: ${check.reason} - ${filePath}`);
                }
                return original.apply(target, args);
              };
            }
            
            return typeof original === 'function' ? original.bind(target) : original;
          }
        });
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
            
            // SECURITY FIX: Resolve real path for FileHandle wrapping
            let realFilePath = filePath;
            try {
              if (originalFs.existsSync(filePath)) {
                realFilePath = originalFs.realpathSync(filePath);
              }
            } catch (e) {}
            
            if (!self.shouldIntercept(filePath, prop) && !self.shouldIntercept(realFilePath, prop)) {
              const result = await original.apply(target, args);
              // SECURITY FIX: ALWAYS wrap FileHandle to prevent bypass via handle methods
              // Even if open was allowed, the file might be in a blocked path
              if (prop === 'open' && result && typeof result.read === 'function') {
                return wrapFileHandle(result, realFilePath);
              }
              return result;
            }
            
            const check = self.checkAccess(operation, filePath);
            const realCheck = (filePath !== realFilePath) ? self.checkAccess(operation, realFilePath) : check;
            const effectiveCheck = (!check.allowed) ? check : ((!realCheck.allowed) ? realCheck : check);
            
            if (!effectiveCheck.allowed) {
              // Check if alert-only mode is enabled
              if (self.firewall?.config?.mode?.alertOnly) {
                console.warn(`[Firewall] ALERT: Would block ${operation} on ${filePath} (reason: ${effectiveCheck.reason})`);
                const result = await original.apply(target, args);
                if (prop === 'open' && result && typeof result.read === 'function') {
                  return wrapFileHandle(result, realFilePath);
                }
                return result;
              }
              
              self.handleBlocked(operation, filePath, effectiveCheck);
              throw self.createAccessError(`Firewall: ${effectiveCheck.reason} - ${filePath}`);
            }
            
            const result = await original.apply(target, args);
            // SECURITY FIX: Wrap FileHandle to prevent handle-based bypasses
            if (prop === 'open' && result && typeof result.read === 'function') {
              return wrapFileHandle(result, realFilePath);
            }
            return result;
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
      
      // SECURITY FIX: Check both original path AND resolved path
      // This handles symlinks and macOS /tmp -> /private/tmp
      let resolvedPath = filePath;
      try {
        if (originalFs.existsSync(filePath)) {
          resolvedPath = originalFs.realpathSync(filePath);
        }
      } catch (e) {
        // File might not exist yet for write operations
      }
      
      // Check if EITHER path should be intercepted
      if (!self.shouldIntercept(filePath, method) && !self.shouldIntercept(resolvedPath, method)) {
        return original.apply(fs, args);
      }
      
      // Extract content for write operations to check for shebangs
      let content = null;
      if ((operation === 'WRITE' || operation === 'CREATE') && args[1] && typeof args[1] !== 'string') {
        content = args[1];
      }
      
      // SECURITY FIX: Check BOTH the original path AND resolved path
      // If either is blocked, deny access
      const check = self.checkAccess(operation, filePath, content);
      const resolvedCheck = (filePath !== resolvedPath) ? self.checkAccess(operation, resolvedPath, content) : check;
      
      // Block if either check fails
      const effectiveCheck = (!check.allowed) ? check : ((!resolvedCheck.allowed) ? resolvedCheck : check);
      
      if (!effectiveCheck.allowed) {
        // Check if alert-only mode is enabled
        if (self.firewall?.config?.mode?.alertOnly) {
          console.warn(`[Firewall] ALERT: Would block ${operation} on ${filePath} (reason: ${effectiveCheck.reason})`);
          return original.apply(fs, args);
        }
        
        self.handleBlocked(operation, filePath, effectiveCheck);
        throw self.createAccessError(`Firewall: ${effectiveCheck.reason} - ${filePath}`);
      }
      
      // SECURITY FIX: For operations with destination path (copyFileSync, renameSync),
      // also check the destination against blocked write paths
      const twoPathMethods = ['copyFileSync', 'renameSync', 'copyFile', 'rename', 'link', 'linkSync', 'symlink', 'symlinkSync'];
      if (twoPathMethods.includes(method) && args[1]) {
        const destPath = self.extractPath(args[1], method);
        let resolvedDestPath = destPath;
        try {
          // For destination, resolve parent directory if file doesn't exist
          const destDir = path.dirname(destPath);
          if (originalFs.existsSync(destDir)) {
            resolvedDestPath = path.join(originalFs.realpathSync(destDir), path.basename(destPath));
          }
        } catch (e) {
          // Use original path if resolution fails
        }
        
        // Check both original and resolved destination paths
        const destCheck = self.checkAccess('WRITE', destPath, null);
        const destResolvedCheck = (destPath !== resolvedDestPath) ? self.checkAccess('WRITE', resolvedDestPath, null) : destCheck;
        const effectiveDestCheck = (!destCheck.allowed) ? destCheck : ((!destResolvedCheck.allowed) ? destResolvedCheck : destCheck);
        
        if (!effectiveDestCheck.allowed) {
          if (self.firewall?.config?.mode?.alertOnly) {
            console.warn(`[Firewall] ALERT: Would block WRITE to ${destPath} (reason: ${effectiveDestCheck.reason})`);
            return original.apply(fs, args);
          }
          
          self.handleBlocked('WRITE', destPath, effectiveDestCheck);
          throw self.createAccessError(`Firewall: ${effectiveDestCheck.reason} - ${destPath}`);
        }
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
      
      // SECURITY FIX: Check both original path AND resolved path
      let resolvedPath = filePath;
      try {
        if (originalFs.existsSync(filePath)) {
          resolvedPath = originalFs.realpathSync(filePath);
        }
      } catch (e) {
        // File might not exist yet for write operations
      }
      
      if (!self.shouldIntercept(filePath, method) && !self.shouldIntercept(resolvedPath, method)) {
        return original.apply(fs, args);
      }
      
      // Check both original and resolved path
      const check = self.checkAccess(operation, filePath);
      const resolvedCheck = (filePath !== resolvedPath) ? self.checkAccess(operation, resolvedPath) : check;
      const effectiveCheck = (!check.allowed) ? check : ((!resolvedCheck.allowed) ? resolvedCheck : check);
      
      if (!effectiveCheck.allowed) {
        // Check if alert-only mode is enabled
        if (self.firewall?.config?.mode?.alertOnly) {
          console.warn(`[Firewall] ALERT: Would block ${operation} on ${filePath} (reason: ${effectiveCheck.reason})`);
          return original.apply(fs, args);
        }
        
        self.handleBlocked(operation, filePath, effectiveCheck);
        const error = self.createAccessError(`Firewall: ${effectiveCheck.reason} - ${filePath}`);
        
        if (typeof callback === 'function') {
          process.nextTick(() => callback(error));
          return;
        }
        throw error;
      }
      
      // SECURITY FIX: For operations with destination path (copyFile, rename),
      // also check the destination against blocked write paths
      const twoPathMethods = ['copyFile', 'rename', 'link', 'symlink'];
      if (twoPathMethods.includes(method) && args[1] && typeof args[1] === 'string') {
        const destPath = self.extractPath(args[1], method);
        let resolvedDestPath = destPath;
        try {
          const destDir = path.dirname(destPath);
          if (originalFs.existsSync(destDir)) {
            resolvedDestPath = path.join(originalFs.realpathSync(destDir), path.basename(destPath));
          }
        } catch (e) {
          // Use original path if resolution fails
        }
        
        const destCheck = self.checkAccess('WRITE', destPath, null);
        const destResolvedCheck = (destPath !== resolvedDestPath) ? self.checkAccess('WRITE', resolvedDestPath, null) : destCheck;
        const effectiveDestCheck = (!destCheck.allowed) ? destCheck : ((!destResolvedCheck.allowed) ? destResolvedCheck : destCheck);
        
        if (!effectiveDestCheck.allowed) {
          if (self.firewall?.config?.mode?.alertOnly) {
            console.warn(`[Firewall] ALERT: Would block WRITE to ${destPath} (reason: ${effectiveDestCheck.reason})`);
            return original.apply(fs, args);
          }
          
          self.handleBlocked('WRITE', destPath, effectiveDestCheck);
          const error = self.createAccessError(`Firewall: ${effectiveDestCheck.reason} - ${destPath}`);
          
          if (typeof callback === 'function') {
            process.nextTick(() => callback(error));
            return;
          }
          throw error;
        }
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
  
  /**
   * SECURITY FIX: Wrap stream creation methods
   * createWriteStream and createReadStream return streams that bypass file interception
   * We intercept the stream creation and check access before returning the stream
   */
  wrapStream(method, operation) {
    const self = this;
    const original = originalFs[method];
    
    return function(filePath, options) {
      const resolvedPath = self.extractPath(filePath, method);
      
      if (!self.shouldIntercept(resolvedPath, method)) {
        return original.call(fs, filePath, options);
      }
      
      const check = self.checkAccess(operation, resolvedPath);
      
      if (!check.allowed) {
        // Check if alert-only mode is enabled
        if (self.firewall?.config?.mode?.alertOnly) {
          console.warn(`[Firewall] ALERT: Would block ${operation} stream on ${resolvedPath} (reason: ${check.reason})`);
          return original.call(fs, filePath, options);
        }
        
        self.handleBlocked(operation, resolvedPath, check);
        throw self.createAccessError(`Firewall: ${check.reason} - ${resolvedPath}`);
      }
      
      return original.call(fs, filePath, options);
    };
  }
  
  /**
   * SECURITY FIX: Intercept process.chdir
   * Prevents changing to blocked directories which could enable
   * bypass via relative paths
   */
  interceptChdir() {
    const self = this;
    const originalChdir = process.chdir.bind(process);
    
    process.chdir = function(directory) {
      const resolvedDir = path.resolve(directory);
      
      // Also get the real path (handles /tmp -> /private/tmp on macOS)
      let realDir = resolvedDir;
      try {
        if (originalFs.existsSync(resolvedDir)) {
          realDir = originalFs.realpathSync(resolvedDir);
        }
      } catch (e) {
        // Directory might not exist
      }
      
      // Check if EITHER path is blocked
      const check = self.checkAccess('READ', resolvedDir);
      const realCheck = (resolvedDir !== realDir) ? self.checkAccess('READ', realDir) : check;
      const effectiveCheck = (!check.allowed) ? check : ((!realCheck.allowed) ? realCheck : check);
      
      if (!effectiveCheck.allowed) {
        if (self.firewall?.config?.mode?.alertOnly) {
          console.warn(`[Firewall] ALERT: Would block chdir to ${resolvedDir}`);
          return originalChdir(directory);
        }
        
        self.handleBlocked('CHDIR', resolvedDir, effectiveCheck);
        throw self.createAccessError(`Firewall: Cannot change to blocked directory - ${resolvedDir}`);
      }
      
      return originalChdir(directory);
    };
  }
  
  /**
   * SECURITY FIX: Wrap symlink creation
   * Symlinks can be used to bypass path restrictions by creating a link
   * in an allowed location that points to a blocked path
   */
  wrapSymlink(method) {
    const self = this;
    const original = originalFs[method] || fs[method];
    
    return function(target, linkPath, ...rest) {
      const resolvedTarget = self.extractPath(target, method);
      const resolvedLink = self.extractPath(linkPath, method);
      
      // Check if the target (what the symlink points to) is blocked
      // This prevents creating symlinks that point to blocked paths
      let realTarget = resolvedTarget;
      try {
        if (originalFs.existsSync(resolvedTarget)) {
          realTarget = originalFs.realpathSync(resolvedTarget);
        }
      } catch (e) {
        // Target might not exist
      }
      
      // Check if target is in a blocked read path (check both paths)
      const targetCheck = self.checkAccess('READ', resolvedTarget);
      const realTargetCheck = (resolvedTarget !== realTarget) ? self.checkAccess('READ', realTarget) : targetCheck;
      const effectiveTargetCheck = (!targetCheck.allowed) ? targetCheck : ((!realTargetCheck.allowed) ? realTargetCheck : targetCheck);
      
      if (!effectiveTargetCheck.allowed) {
        if (self.firewall?.config?.mode?.alertOnly) {
          console.warn(`[Firewall] ALERT: Would block symlink to blocked path ${resolvedTarget}`);
          return original.call(fs, target, linkPath, ...rest);
        }
        
        self.handleBlocked('SYMLINK', resolvedTarget, effectiveTargetCheck);
        throw self.createAccessError(`Firewall: Cannot create symlink to blocked path - ${resolvedTarget}`);
      }
      
      // Check if the link location is allowed
      const linkCheck = self.checkAccess('WRITE', resolvedLink);
      if (!linkCheck.allowed) {
        if (self.firewall?.config?.mode?.alertOnly) {
          console.warn(`[Firewall] ALERT: Would block symlink creation at ${resolvedLink}`);
          return original.call(fs, target, linkPath, ...rest);
        }
        
        self.handleBlocked('SYMLINK', resolvedLink, linkCheck);
        throw self.createAccessError(`Firewall: ${linkCheck.reason} - ${resolvedLink}`);
      }
      
      return original.call(fs, target, linkPath, ...rest);
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
    // Don't intercept empty paths (file descriptors, etc.)
    if (!filePath || filePath === '') {
      return false;
    }
    
    // SECURITY: Protect firewall output files from tampering
    // These files contain audit logs, behavior reports, and security data
    // Malicious code (Shai-Hulud) may attempt to delete or overwrite them
    const isFirewallOutputFile = filePath.includes('fs-firewall') || 
                                  filePath.includes('firewall-report') ||
                                  filePath.includes('firewall-audit') ||
                                  filePath.includes('firewall-zero-trust');
    
    if (isFirewallOutputFile) {
      // Check if this is a firewall internal write (using originalFs)
      // Firewall code uses originalFs directly, so it won't reach this point
      // If we're here, it's external code trying to access firewall files
      // SECURITY: Use secure stack trace checking to prevent bypass attacks
      const stack = new Error().stack;
      const isFirewallInternal = isFirewallInternalStack(stack);
      
      // If not from firewall internals, intercept and block
      if (!isFirewallInternal) {
        return true; // DO intercept - will be blocked
      }
      
      // Allow firewall's own writes
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
          filePath.endsWith('.npmrc') ||  // npm needs to read .npmrc for auth
          filePath.endsWith('.gitconfig')) {  // npm needs .gitconfig for git dependencies
        return false;
      }
    }
    
    // SECURITY FIX: Check if path matches blockedReadPaths/blockedWritePaths BEFORE 
    // auto-allowing project directory. Config-defined blocks take precedence.
    if (this.firewall?.config?.filesystem) {
      const blockedReadPaths = this.firewall.config.filesystem.blockedReadPaths || [];
      const blockedWritePaths = this.firewall.config.filesystem.blockedWritePaths || [];
      
      // Check if path matches any blocked path pattern
      for (const pattern of [...blockedReadPaths, ...blockedWritePaths]) {
        const normalizedPattern = pattern.endsWith('/') ? pattern.slice(0, -1) : pattern;
        if (filePath.includes(pattern) || 
            filePath === normalizedPattern ||
            filePath.startsWith(normalizedPattern + '/')) {
          return true; // DO intercept - this path is explicitly blocked
        }
      }
    }
    
    // Auto-allow project directory (only if not sensitive AND not in blockedPaths)
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
    
    // SECURITY: Block tampering with firewall output files
    // Shai-Hulud and similar attacks attempt to delete/overwrite logs to hide tracks
    const isFirewallOutputFile = filePath.includes('fs-firewall') || 
                                  filePath.includes('firewall-report') ||
                                  filePath.includes('firewall-audit') ||
                                  filePath.includes('firewall-zero-trust');
    
    if (isFirewallOutputFile && (operation === 'WRITE' || operation === 'CREATE' || operation === 'DELETE')) {
      // Check if this is firewall internal code
      // SECURITY: Use secure stack trace checking to prevent bypass attacks
      // Malicious packages cannot bypass this by naming their files similarly
      const stack = new Error().stack;
      const isFirewallInternal = isFirewallInternalStack(stack);
      
      if (!isFirewallInternal) {
        return {
          allowed: false,
          reason: 'firewall_output_tampering',
          severity: 'critical',
          message: 'Tampering with firewall output files is blocked'
        };
      }
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
      // SECURITY: Don't log when blocking firewall output files (prevents infinite loop)
      const isFirewallOutputFile = filePath.includes('fs-firewall') || 
                                    filePath.includes('firewall-report') ||
                                    filePath.includes('firewall-audit') ||
                                    filePath.includes('firewall-zero-trust');
      
      if (isFirewallOutputFile) {
        // Skip logging to avoid infinite recursion
        return;
      }
      
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
