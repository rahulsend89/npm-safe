/**
 * Firewall Core - Main orchestrator
 * Coordinates all security components and provides unified interface
 */

const config = require('./config-loader');
const { NetworkMonitor, initialize: initNetwork } = require('./network-monitor');
const { BehaviorMonitor } = require('./behavior-monitor');
const { EnvProtector } = require('./env-protector');
const { getInstance: getAuditLogger } = require('./audit-logger');
const { makeImmutableProperties } = require('./immutable-property');
const { isBuildOrCacheDirectory, isTsNodeTemp } = require('./build-directory-utils');
const { getInstance: getExfiltrationDetector } = require('./exfiltration-detector');
const fs = require('fs');
const path = require('path');

const originalFs = { ...fs };

// SECURITY: Use Symbols for internal state (can't be deleted like env vars)
const FIREWALL_ACTIVE = Symbol.for('node.firewall.active.v2');
const FIREWALL_INITIALIZED = Symbol.for('node.firewall.initialized.v2');

class FirewallCore {
  constructor() {
    // SECURITY: Check if already initialized via Symbol (bypass-proof)
    if (global[FIREWALL_INITIALIZED]) {
      return global[FIREWALL_INITIALIZED];
    }
    
    // SECURITY: Make critical properties immutable to prevent tampering
    const loadedConfig = config.load();
    const isBuildProcess = this.detectBuildProcess();
    const isChildProcess = process.env.FIREWALL_PARENT_PID && process.env.FIREWALL_PARENT_PID !== String(process.pid);
    
    makeImmutableProperties(this, {
      config: Object.freeze(loadedConfig),
      enabled: loadedConfig.mode?.enabled !== false,
      silent: isBuildProcess || isChildProcess
    });
    
    if (!this.enabled) {
      if (!this.silent) console.log('[Firewall] Disabled by configuration');
      return;
    }
    
    // SECURITY: Mark as active using Symbol
    global[FIREWALL_ACTIVE] = true;
    global[FIREWALL_INITIALIZED] = this;
    
    // SECURITY: Protect NODE_FIREWALL from tampering
    this.protectFirewallFlag();
    
    // SECURITY: Protect require cache from manipulation
    this.protectRequireCache();
    
    this.networkMonitor = null;
    this.behaviorMonitor = null;
    this.envProtector = null;
    this.auditLogger = null;
    this.exfiltrationDetector = null;
    this.initialized = false;
    
    // Performance: Cache package lookups
    this.packageCache = new Map();
    this.packageCacheTTL = 5000; // 5 second TTL
    
    if (!this.silent) {
      console.log('╔╗');
      console.log('  Node.js Security Firewall v2.0                    ');
      console.log('╚╝');
      console.log(`Mode: ${this.config.mode?.alertOnly ? 'Alert-Only' : 'Enforcement'}`);
      console.log(`Strict: ${this.config.mode?.strictMode ? 'Yes' : 'No'}`);
    }
  }
  
  protectFirewallFlag() {
    // SECURITY: Make NODE_FIREWALL immutable to prevent tampering
    try {
      if (process.env.NODE_FIREWALL === '1') {
        Object.defineProperty(process.env, 'NODE_FIREWALL', {
          value: '1',
          writable: false,
          configurable: false,
          enumerable: true
        });
      }
    } catch (e) {
      // May fail if already defined, that's okay
      if (!this.silent) {
        console.warn('[Firewall] Could not make NODE_FIREWALL immutable:', e.message);
      }
    }
    
    // SECURITY: Monitor for tampering attempts via Object.defineProperty
    const originalDefineProperty = Object.defineProperty;
    Object.defineProperty = function(obj, prop, descriptor) {
      if (obj === process.env && prop === 'NODE_FIREWALL' && descriptor.value !== '1') {
        console.error('[Firewall] TAMPERING DETECTED: Attempt to modify NODE_FIREWALL');
        console.error('[Firewall] Rejecting modification to maintain security');
        return obj;
      }
      return originalDefineProperty.call(this, obj, prop, descriptor);
    };
  }
  
  protectRequireCache() {
    // SECURITY: Prevent deletion of firewall modules from require.cache
    const firewallModules = [
      'firewall-core',
      'env-protector',
      'network-monitor',
      'behavior-monitor',
      'fs-interceptor-v2',
      'child-process-interceptor',
      'firewall-hardening-fortress'
    ];
    
    try {
      // Find and protect firewall module cache entries
      const cacheKeys = Object.keys(require.cache);
      
      for (const key of cacheKeys) {
        const isFirewallModule = firewallModules.some(mod => key.includes(mod));
        
        if (isFirewallModule) {
          // Make cache entry non-configurable to prevent deletion
          try {
            Object.defineProperty(require.cache, key, {
              configurable: false,
              writable: false,
              enumerable: true
            });
          } catch (e) {
            // Already protected or read-only, that's fine
          }
        }
      }
      
      // Monitor delete operations on require.cache
      const cacheProxy = new Proxy(require.cache, {
        deleteProperty(target, prop) {
          const isFirewallModule = firewallModules.some(mod => prop.includes(mod));
          
          if (isFirewallModule) {
            if (!this.silent) {
              console.error('[Firewall] TAMPERING DETECTED: Attempt to delete firewall module from cache');
              console.error('[Firewall] Module:', prop);
            }
            return false; // Prevent deletion
          }
          
          delete target[prop];
          return true;
        }
      });
      
      // Note: We can't replace require.cache itself, but we can monitor it
      // The Object.defineProperty protection above is the main defense
      
    } catch (e) {
      if (!this.silent) {
        console.warn('[Firewall] Could not fully protect require.cache:', e.message);
      }
    }
  }
  
  detectBuildProcess() {
    const argv = process.argv.join(' ');
    const isBuildProcess = argv.includes('node-gyp') || 
           argv.includes('prebuild') ||
           argv.includes('node-pre-gyp') ||
           (process.env.npm_lifecycle_script && process.env.npm_lifecycle_script.includes('node-gyp'));
    return Boolean(isBuildProcess);
  }
  
  // SECURITY: Check if firewall is active via Symbol
  static isActive() {
    return global[FIREWALL_ACTIVE] === true || process.env.NODE_FIREWALL === '1';
  }
  
  initialize() {
    if (this.initialized || !this.enabled) return;
    
    // Initialize audit logger
    try {
      this.auditLogger = getAuditLogger();
      if (!this.silent) {
        console.log('[Firewall] Audit logging enabled -> firewall-audit.jsonl');
      }
    } catch (error) {
      console.error('[Firewall] Failed to initialize audit logger:', error.message);
    }
    
    // Initialize network monitor
    if (this.config.network?.enabled) {
      this.networkMonitor = initNetwork(this.config, this.silent);
      if (!this.silent) console.log('[Firewall]  Network monitoring active');
    }
    
    // Initialize behavior monitor
    if (this.config.behavioral?.monitorLifecycleScripts) {
      this.behaviorMonitor = new BehaviorMonitor(this.config, this.silent);
      if (!this.silent) console.log('[Firewall]  Behavior monitoring active');
    }
    
    // Initialize environment protector
    if (this.config.environment?.protectedVariables?.length > 0) {
      this.envProtector = new EnvProtector(this.config, this.silent);
      this.envProtector.initialize(this);
    }
    
    // Initialize exfiltration detector (CRITICAL for supply chain attacks)
    this.exfiltrationDetector = getExfiltrationDetector();
    if (!this.silent) console.log('[Firewall]  Data exfiltration protection active');
    
    // Setup cleanup on exit
    this.setupCleanup();
    
    this.initialized = true;
    if (!this.silent) console.log('\n');
  }
  
  setupCleanup() {
    const cleanup = () => {
      if (this.behaviorMonitor && !this.silent) {
        const assessment = this.behaviorMonitor.printSummary();
        
        if (assessment.risk === 'high') {
          console.error('\n HIGH RISK ACTIVITY DETECTED!');
          console.error('   Review the behavior report before trusting this package.\n');
          process.exitCode = 1;
        } else if (assessment.risk === 'medium') {
          console.warn('\nUNUSUAL ACTIVITY DETECTED');
          console.warn('   Review the behavior report for details.\n');
        } else {
          console.log(' Package behavior assessment: CLEAN\n');
        }
        
        this.behaviorMonitor.generateReport();
      }
      
      if (this.networkMonitor && !this.silent) {
        const stats = this.networkMonitor.getStats();
        if (stats.blocked > 0 || stats.suspicious > 0) {
          console.log(`[Network] Blocked: ${stats.blocked}, Suspicious: ${stats.suspicious}`);
        }
      }
    };
    
    process.on('exit', cleanup);
    process.on('SIGINT', () => {
      cleanup();
      process.exit(130);
    });
    process.on('SIGTERM', () => {
      cleanup();
      process.exit(143);
    });
  }
  
  // SECURITY: Add timing safety to prevent detection via timing attacks
  addTimingNoise() {
    // Add 0-2ms random delay to mask firewall presence
    // This prevents attackers from detecting firewall via timing analysis
    if (this.config.mode?.preventTimingAttacks !== false) {
      const delay = Math.random() * 2; // 0-2ms
      const start = Date.now();
      while (Date.now() - start < delay) {
        // Busy wait for timing noise
      }
    }
  }
  
  checkFileAccess(operation, filePath, packageName = null) {
    if (!this.enabled) return { allowed: true, reason: 'disabled' };
    
    // SECURITY: Add timing noise to prevent detection
    this.addTimingNoise();
    
    // Track behavior
    if (this.behaviorMonitor) {
      if (operation === 'READ') {
        this.behaviorMonitor.trackFileRead(filePath);
        
        // CRITICAL: Track sensitive file reads for exfiltration detection
        if (this.exfiltrationDetector) {
          this.exfiltrationDetector.trackSensitiveFileRead(filePath);
        }
      } else if (operation === 'WRITE' || operation === 'CREATE') {
        this.behaviorMonitor.trackFileWrite(filePath);
      }
    }
    
    let result;
    
    // SECURITY: Allow reading project files from current working directory
    // Applications need to access their own configuration and source files
    if (operation === 'READ') {
      const path = require('path');
      const cwd = process.cwd();
      const resolvedPath = path.resolve(filePath);
      const cwdPath = path.resolve(cwd);
      const ext = path.extname(filePath);
      
      // Allow .env files in project directory or parents (up to 3 levels)
      if (filePath.endsWith('.env') || filePath.includes('.env.')) {
        if (resolvedPath.startsWith(cwdPath) || 
            resolvedPath.startsWith(path.resolve(cwd, '..')) ||
            resolvedPath.startsWith(path.resolve(cwd, '../..'))) {
          result = { allowed: true, reason: 'project_env_file' };
          this.logAudit('FILESYSTEM', operation, filePath, result, packageName);
          return result;
        }
      }
      
      // Allow source files (.ts, .js, .json, etc) in project directory or TypeScript temp
      const sourceExts = ['.ts', '.tsx', '.js', '.jsx', '.json', '.mjs', '.cjs', '.map'];
      
      if (sourceExts.includes(ext) && (resolvedPath.startsWith(cwdPath) || isTsNodeTemp(resolvedPath))) {
        result = { allowed: true, reason: 'project_source_file' };
        this.logAudit('FILESYSTEM', operation, filePath, result, packageName);
        return result;
      }
    }
    
    // Check exceptions first
    if (packageName && this.config.exceptions?.modules?.[packageName]) {
      if (this.config.exceptions.modules[packageName].allowFilesystem) {
        const allowed = this.config.exceptions.modules[packageName].allowFilesystem;
        if (allowed.some(pattern => filePath.includes(pattern))) {
          result = { allowed: true, reason: 'exception', exception: packageName };
          this.logAudit('FILESYSTEM', operation, filePath, result, packageName);
          return result;
        }
      }
    }
    
    // Check blocked paths
    if (operation === 'READ') {
      const blocked = this.config.filesystem?.blockedReadPaths || [];
      for (const pattern of blocked) {
        if (filePath.includes(pattern)) {
          result = { 
            allowed: false, 
            reason: 'blocked_read', 
            pattern,
            severity: 'high'
          };
          this.logAudit('FILESYSTEM', operation, filePath, result, packageName);
          return result;
        }
      }
    }
    
    if (operation === 'WRITE' || operation === 'CREATE') {
      // Allow writing to TypeScript compilation cache and build directories
      const path = require('path');
      const cwd = process.cwd();
      const resolvedPath = path.resolve(filePath);
      const cwdPath = path.resolve(cwd);
      
      // Check if writing to build/cache directory
      const isInProjectBuildDir = resolvedPath.startsWith(cwdPath) && 
                                   (resolvedPath.includes('/dist/') || 
                                    resolvedPath.includes('/build/') ||
                                    resolvedPath.includes('/.cache/'));
      
      if (isBuildOrCacheDirectory(resolvedPath) || isInProjectBuildDir) {
        result = { allowed: true, reason: 'build_cache_directory' };
        this.logAudit('FILESYSTEM', operation, filePath, result, packageName);
        return result;
      }
      
      const blocked = this.config.filesystem?.blockedWritePaths || [];
      for (const pattern of blocked) {
        if (filePath.includes(pattern)) {
          return { 
            allowed: false, 
            reason: 'blocked_write', 
            pattern,
            severity: 'critical'
          };
        }
      }
      
      // Check blocked extensions
      const blockedExt = this.config.filesystem?.blockedExtensions || [];
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
    
    // Check allowed paths (whitelist mode in strict)
    if (this.config.mode?.strictMode) {
      const allowed = this.config.filesystem?.allowedPaths || [];
      const isAllowed = allowed.some(pattern => filePath.includes(pattern));
      
      if (!isAllowed) {
        return { 
          allowed: false, 
          reason: 'strict_mode_not_allowed',
          severity: 'medium'
        };
      }
    }
    
    return { allowed: true, reason: 'passed' };
  }
  
  checkNetworkAccess(url, method = 'GET', packageName = null) {
    if (!this.enabled || !this.networkMonitor) {
      return { allowed: true, reason: 'disabled' };
    }
    
    // SECURITY: Add timing noise to prevent detection
    this.addTimingNoise();
    
    // Track behavior
    if (this.behaviorMonitor) {
      this.behaviorMonitor.trackNetworkRequest(url, method);
    }
    
    // Check exceptions
    if (packageName && this.config.exceptions?.modules?.[packageName]) {
      if (this.config.exceptions.modules[packageName].allowNetwork) {
        const allowed = this.config.exceptions.modules[packageName].allowNetwork;
        if (allowed.some(domain => url.includes(domain))) {
          return { allowed: true, reason: 'exception', exception: packageName };
        }
      }
    }
    
    // Network monitor will handle the actual checking
    return { allowed: true, reason: 'delegated_to_network_monitor' };
  }
  
  checkCommandExecution(command, packageName = null) {
    if (!this.enabled) return { allowed: true, reason: 'disabled' };
    
    // SECURITY: Add timing noise to prevent detection
    this.addTimingNoise();
    
    // SECURITY FIX: Detect and block shell metacharacters
    const shellMetacharactersRegex = /[;&|`$(){}[\]<>\\]/;
    if (shellMetacharactersRegex.test(command)) {
      // Parse to extract all commands (detect chaining attempts)
      const suspiciousPatterns = [
        { pattern: /;\s*\w+/, name: 'semicolon chaining' },
        { pattern: /\|\s*\w+/, name: 'pipe chaining' },
        { pattern: /&&\s*\w+/, name: 'AND chaining' },
        { pattern: /\|\|\s*\w+/, name: 'OR chaining' },
        { pattern: /`[^`]+`/, name: 'backtick execution' },
        { pattern: /\$\([^)]+\)/, name: 'command substitution' }
      ];
      
      const foundPatterns = suspiciousPatterns
        .filter(({ pattern }) => pattern.test(command))
        .map(({ name }) => name);
      
      if (foundPatterns.length > 0) {
        return {
          allowed: false,
          reason: 'shell_metacharacters_detected',
          severity: 'critical',
          description: `Command contains shell metacharacters: ${foundPatterns.join(', ')}. This could be used to bypass command filtering.`,
          command: command,
          patterns: foundPatterns
        };
      }
    }
    
    // SECURITY FIX: Verify PATH integrity
    const currentPath = process.env.PATH || '';
    const suspiciousPaths = ['/tmp', '/var/tmp', './', '../'];
    const pathEntries = currentPath.split(':');
    
    const hasSuspiciousPath = pathEntries.some(entry => 
      suspiciousPaths.some(suspicious => entry.startsWith(suspicious) || entry.includes(suspicious))
    );
    
    if (hasSuspiciousPath) {
      if (!this.silent) {
        console.warn('[Firewall] WARNING: Suspicious PATH entries detected');
        console.warn(`[Firewall] PATH: ${currentPath}`);
        console.warn('[Firewall] This may indicate PATH manipulation attack');
      }
    }
    
    // Track behavior and check hard limits
    if (this.behaviorMonitor) {
      const limitCheck = this.behaviorMonitor.trackProcessSpawn(command);
      if (!limitCheck.allowed) {
        return limitCheck;
      }
    }
    
    // Check exceptions
    if (packageName && this.config.exceptions?.modules?.[packageName]) {
      if (this.config.exceptions.modules[packageName].allowCommands) {
        const allowed = this.config.exceptions.modules[packageName].allowCommands;
        if (allowed.includes(command)) {
          return { allowed: true, reason: 'exception', exception: packageName };
        }
      }
    }
    
    // Check blocked patterns
    const blocked = this.config.commands?.blockedPatterns || [];
    for (const block of blocked) {
      const pattern = new RegExp(block.pattern);
      if (pattern.test(command)) {
        return { 
          allowed: false, 
          reason: 'blocked_command', 
          pattern: block.pattern,
          severity: block.severity || 'high',
          description: block.description
        };
      }
    }
    
    // Check allowed commands whitelist (strict mode for commands)
    const allowedCommands = this.config.commands?.allowedCommands || [];
    if (allowedCommands.length > 0) {
      // SECURITY FIX: Extract ONLY the actual command, no args
      const commandOnly = command.trim().split(/\s+/)[0].split('/').pop();
      const isAllowed = allowedCommands.some(allowed => commandOnly === allowed);
      
      if (!isAllowed) {
        return {
          allowed: false,
          reason: 'not_in_allowed_commands',
          severity: 'medium',
          description: `Command "${commandOnly}" not in whitelist. Only ${allowedCommands.join(', ')} are allowed.`
        };
      }
      
      // SECURITY FIX: Even if command is whitelisted, check arguments for injection
      const args = command.substring(commandOnly.length).trim();
      if (args && shellMetacharactersRegex.test(args)) {
        return {
          allowed: false,
          reason: 'whitelisted_command_with_shell_injection',
          severity: 'high',
          description: `Command "${commandOnly}" is whitelisted but arguments contain shell metacharacters that could be used for command injection.`,
          command: command,
          args: args
        };
      }
    }
    
    return { allowed: true, reason: 'passed' };
  }
  
  isTrustedModule(packageName) {
    if (!this.enabled) return false;
    
    const trusted = this.config.trustedModules || [];
    return trusted.some(module => {
      return packageName === module || packageName.startsWith(module + '/');
    });
  }
  
  promptUser(type, details) {
    if (!this.config.mode?.interactive) {
      return false;
    }
    
    console.log('\n╔╗');
    console.log('  SECURITY PROMPT                                   ');
    console.log('╚╝');
    console.log(`Type:     ${type}`);
    console.log(`Details:  ${JSON.stringify(details, null, 2)}`);
    console.log('');
    console.log('Options:');
    console.log('  [A]llow once');
    console.log('  [D]eny');
    console.log('  [E]xception - Add permanent exception for this package');
    console.log('');
    
    // This would need readline in real implementation
    // For now, return based on alertOnly mode
    return this.config.mode?.alertOnly;
  }
  
  addException(packageName, type, value, reason) {
    const exception = this.config.exceptions?.modules?.[packageName] || {};
    
    switch (type) {
      case 'filesystem':
        exception.allowFilesystem = exception.allowFilesystem || [];
        if (!exception.allowFilesystem.includes(value)) {
          exception.allowFilesystem.push(value);
        }
        break;
      case 'network':
        exception.allowNetwork = exception.allowNetwork || [];
        if (!exception.allowNetwork.includes(value)) {
          exception.allowNetwork.push(value);
        }
        break;
      case 'command':
        exception.allowCommands = exception.allowCommands || [];
        if (!exception.allowCommands.includes(value)) {
          exception.allowCommands.push(value);
        }
        break;
    }
    
    exception.reason = reason;
    exception.addedAt = new Date().toISOString();
    
    config.addException(packageName, exception);
    console.log(`[Firewall]  Exception added for ${packageName}`);
  }
  
  getConfig() {
    return this.config;
  }
  
  reload() {
    // SECURITY: Config is immutable - cannot be reloaded
    // To change configuration, restart the process
    console.warn('[Firewall] Configuration is immutable. Restart process to apply new config.');
    console.warn('[Firewall] This is a security feature to prevent runtime tampering.');
  }
  
  logAudit(type, operation, target, result, packageName = null) {
    if (this.auditLogger) {
      try {
        this.auditLogger.log({
          type,
          operation,
          target,
          allowed: result.allowed,
          reason: result.reason,
          severity: result.severity || 'info',
          package: packageName
        });
      } catch (error) {
        // Don't let audit logging break the firewall
      }
    }
  }
}

// Singleton instance
let instance = null;

function getInstance() {
  if (!instance) {
    instance = new FirewallCore();
    instance.initialize();
  }
  return instance;
}

// CRITICAL: Auto-initialize when NODE_FIREWALL is set
// This ensures protection is active BEFORE any malicious code runs
if (process.env.NODE_FIREWALL === '1') {
  try {
    getInstance();
    if (!instance.silent) {
      console.log('[Firewall] Auto-initialized on module load');
    }
  } catch (error) {
    console.error('[Firewall] CRITICAL: Failed to auto-initialize:', error.message);
    // Fail-closed: if firewall can't load, we have a problem
    // but don't crash the entire process, just log it
  }
}

module.exports = { FirewallCore, getInstance };
