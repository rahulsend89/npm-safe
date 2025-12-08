/**
 * Bun Runtime Interceptor
 * Intercepts Bun-specific APIs (Bun.spawn, Bun.file, etc.)
 */

const config = require('./config-loader');
const { BehaviorMonitor } = require('./behavior-monitor');
const { getInstance: getAuditLogger } = require('./audit-logger');

// Check if we're running in Bun
const isBun = typeof Bun !== 'undefined';

class BunInterceptor {
  constructor() {
    this.config = config.load();
    this.enabled = this.config.mode?.enabled !== false;
    this.behaviorMonitor = null;
    this.auditLogger = null;
    
    if (!this.enabled) {
      return;
    }
    
    // Initialize monitors
    this.behaviorMonitor = new BehaviorMonitor(this.config);
    this.auditLogger = getAuditLogger();
  }
  
  // Helper method to check if in alert-only mode
  isAlertOnlyMode() {
    return this.config.mode?.alertOnly;
  }

  // Helper method to handle blocked operations (log and throw/warn based on mode)
  handleBlocked(error, auditLogData) {
    this.auditLogger.log(auditLogData);
    
    if (this.isAlertOnlyMode()) {
      console.warn(error.message);
    } else {
      throw error;
    }
  }

  initialize() {
    if (!this.enabled || !isBun) return;
    
    this.interceptBunSpawn();
    this.interceptBunFile();
    this.interceptBunWrite();
    this.interceptBunShell();
    
    if (!this.config.mode?.silent) {
      console.log('[Bun Interceptor] Bun runtime protections active');
    }
  }
  
  /**
   * Intercept Bun.spawn - process spawning
   */
  interceptBunSpawn() {
    if (!Bun.spawn) return;
    
    const originalSpawn = Bun.spawn;
    const self = this;
    
    Bun.spawn = function(command, options) {
      // Check if command is blocked
      const blockedPatterns = self.config.commands?.blockedPatterns || [];
      const cmd = Array.isArray(command) ? command.join(' ') : String(command);
      
      for (const pattern of blockedPatterns) {
        const regex = new RegExp(pattern);
        if (regex.test(cmd)) {
          const error = new Error(`[Bun Firewall] Blocked command: ${cmd}`);
          self.handleBlocked(error, {
            type: 'COMMAND',
            operation: 'spawn',
            target: cmd,
            allowed: false,
            reason: 'blocked_pattern',
            severity: 'critical'
          });
        }
      }
      
      // Track in behavior monitor
      if (self.behaviorMonitor) {
        const result = self.behaviorMonitor.trackProcessSpawn(cmd);
        if (!result.allowed && !self.config.mode?.alertOnly) {
          throw new Error(`[Bun Firewall] Process spawn blocked: ${result.reason}`);
        }
      }
      
      return originalSpawn.call(this, command, options);
    };
  }
  
  /**
   * Intercept Bun.file - file access
   */
  interceptBunFile() {
    if (!Bun.file) return;
    
    const originalFile = Bun.file;
    const self = this;
    
    Bun.file = function(path, options) {
      const filePath = String(path);
      
      // Check blocked read paths
      const blockedPaths = self.config.filesystem?.blockedReadPaths || [];
      for (const blockedPath of blockedPaths) {
        if (filePath.includes(blockedPath)) {
          const error = new Error(`[Bun Firewall] Blocked file access: ${filePath}`);
          self.handleBlocked(error, {
            type: 'FILESYSTEM',
            operation: 'read',
            target: filePath,
            allowed: false,
            reason: 'blocked_path',
            severity: 'critical'
          });
        }
      }
      
      // Track in behavior monitor
      if (self.behaviorMonitor) {
        self.behaviorMonitor.trackFileRead(filePath);
      }
      
      return originalFile.call(this, path, options);
    };
  }
  
  /**
   * Intercept Bun.write - file writing
   */
  interceptBunWrite() {
    if (!Bun.write) return;
    
    const originalWrite = Bun.write;
    const self = this;
    
    Bun.write = async function(destination, data, options) {
      const filePath = String(destination);
      
      // Check if writing to sensitive locations
      const sensitivePaths = [
        '/etc/',
        '/usr/bin/',
        '/usr/local/bin/',
        '/.ssh/',
        '/.aws/'
      ];
      
      for (const sensitivePath of sensitivePaths) {
        if (filePath.includes(sensitivePath)) {
          const error = new Error(`[Bun Firewall] Blocked write to sensitive path: ${filePath}`);
          self.handleBlocked(error, {
            type: 'FILESYSTEM',
            operation: 'write',
            target: filePath,
            allowed: false,
            reason: 'sensitive_path',
            severity: 'critical'
          });
        }
      }
      
      // Track in behavior monitor
      if (self.behaviorMonitor) {
        const result = self.behaviorMonitor.trackFileWrite(filePath);
        if (!result.allowed && !self.config.mode?.alertOnly) {
          throw new Error(`[Bun Firewall] File write blocked: ${result.reason}`);
        }
      }
      
      return originalWrite.call(this, destination, data, options);
    };
  }
  
  /**
   * Intercept Bun.$ - shell command execution
   */
  interceptBunShell() {
    if (!Bun.$) return;
    
    const originalShell = Bun.$;
    const self = this;
    
    // Bun.$ returns a template tag function
    Bun.$ = function(strings, ...values) {
      const command = strings.reduce((acc, str, i) => {
        return acc + str + (values[i] || '');
      }, '');
      
      // Check blocked patterns
      const blockedPatterns = self.config.commands?.blockedPatterns || [];
      for (const pattern of blockedPatterns) {
        const regex = new RegExp(pattern);
        if (regex.test(command)) {
          const error = new Error(`[Bun Firewall] Blocked shell command: ${command}`);
          self.handleBlocked(error, {
            type: 'COMMAND',
            operation: 'shell',
            target: command,
            allowed: false,
            reason: 'blocked_pattern',
            severity: 'critical'
          });
        }
      }
      
      // Track in behavior monitor
      if (self.behaviorMonitor) {
        self.behaviorMonitor.trackProcessSpawn(command);
      }
      
      return originalShell(strings, ...values);
    };
  }
}

let interceptor = null;

function initialize() {
  if (!isBun) {
    return;
  }
  
  if (!interceptor) {
    interceptor = new BunInterceptor();
    interceptor.initialize();
  }
  
  return interceptor;
}

module.exports = {
  initialize,
  BunInterceptor,
  isBun
};
