/**
 * Environment Variable Protector
 * Monitors and protects sensitive environment variables from unauthorized access
 */

const { makeImmutableProperties } = require('./immutable-property');

class EnvProtector {
  constructor(config, silent = false) {
    // SECURITY: Make critical properties immutable
    const frozenConfig = Object.freeze(config || {});
    makeImmutableProperties(this, {
      config: frozenConfig,
      enabled: frozenConfig.environment?.protectedVariables?.length > 0,
      silent: silent
    });
    this.protectedVars = this.config.environment?.protectedVariables || [];
    this.allowTrustedModules = this.config.environment?.allowTrustedModulesAccess !== false;
    this.accessLog = [];
    this.initialized = false;
    
    if (this.enabled && !this.silent) {
      console.log(`[Env Protector] Protecting ${this.protectedVars.length} environment variables`);
    }
  }
  
  initialize(firewall) {
    if (this.initialized || !this.enabled) return;
    
    this.firewall = firewall;
    this.setupProtection();
    this.initialized = true;
    
    if (!this.silent) {
      console.log('[Env Protector]  Environment protection active');
    }
  }
  
  setupProtection() {
    const self = this;
    const originalEnv = process.env;
    
    // SECURITY: Create a frozen copy to prevent direct access bypasses
    const frozenEnvCopy = Object.create(null);
    Object.keys(originalEnv).forEach(key => {
      frozenEnvCopy[key] = originalEnv[key];
    });
    
    // SECURITY FIX: Custom inspect symbol to prevent util.inspect bypass
    const inspectSymbol = Symbol.for('nodejs.util.inspect.custom');
    
    const envProxy = new Proxy(originalEnv, {
      get(target, prop) {
        // SECURITY FIX: Handle util.inspect custom symbol
        // When util.inspect is called, return a filtered version that hides protected vars
        if (prop === inspectSymbol || prop === 'inspect') {
          return function(depth, options) {
            const filtered = {};
            for (const key in target) {
              if (self.isProtected(key)) {
                const packageName = self.getCallingPackage();
                const check = self.checkAccess(key, packageName);
                if (!check.allowed) {
                  // Don't include protected vars in inspection output
                  filtered[key] = '[PROTECTED]';
                  continue;
                }
              }
              filtered[key] = target[key];
            }
            return filtered;
          };
        }
        
        // SECURITY FIX: Handle toJSON for JSON.stringify
        if (prop === 'toJSON') {
          return function() {
            const filtered = {};
            for (const key in target) {
              if (self.isProtected(key)) {
                const packageName = self.getCallingPackage();
                const check = self.checkAccess(key, packageName);
                if (!check.allowed) {
                  filtered[key] = '[PROTECTED]';
                  continue;
                }
              }
              filtered[key] = target[key];
            }
            return filtered;
          };
        }
        
        if (typeof prop === 'string' && self.isProtected(prop)) {
          const packageName = self.getCallingPackage();
          const check = self.checkAccess(prop, packageName);
          
          if (!check.allowed) {
            self.logAccess(prop, packageName, 'READ', check);
            
            if (!self.config.mode?.alertOnly) {
              // SECURITY FIX: Return '[PROTECTED]' instead of throwing
              // This prevents util.inspect and similar from exposing the value
              // While still indicating the variable exists
              return '[PROTECTED]';
            } else {
              console.warn(`[ENV PROTECTION] Access to protected variable '${prop}' by ${packageName || 'unknown'}`);
            }
          }
          
          self.logAccess(prop, packageName, 'READ', check);
        }
        
        return target[prop];
      },
      
      set(target, prop, value) {
        if (typeof prop === 'string' && self.isProtected(prop)) {
          const packageName = self.getCallingPackage();
          const check = self.checkAccess(prop, packageName);
          
          if (!check.allowed) {
            self.logAccess(prop, packageName, 'WRITE', check);
            
            if (!self.config.mode?.alertOnly) {
              throw new Error(`Modification of protected environment variable '${prop}' is blocked`);
            } else {
              console.warn(`[ENV PROTECTION] Modification of protected variable '${prop}' by ${packageName || 'unknown'}`);
            }
          }
          
          self.logAccess(prop, packageName, 'WRITE', check);
        }
        
        target[prop] = value;
        return true;
      },
      
      deleteProperty(target, prop) {
        if (typeof prop === 'string' && self.isProtected(prop)) {
          const packageName = self.getCallingPackage();
          
          if (!self.config.mode?.alertOnly) {
            throw new Error(`Deletion of protected environment variable '${prop}' is blocked`);
          } else {
            console.warn(`[ENV PROTECTION] Deletion attempt of protected variable '${prop}' by ${packageName || 'unknown'}`);
          }
          
          self.logAccess(prop, packageName, 'DELETE', { allowed: false, reason: 'deletion_blocked' });
          return false;
        }
        
        delete target[prop];
        return true;
      },
      
      // SECURITY FIX: Prevent Object.getOwnPropertyDescriptor bypass
      getOwnPropertyDescriptor(target, prop) {
        // CRITICAL: Must return descriptor that matches target's configurability (Proxy invariant)
        const targetDesc = Object.getOwnPropertyDescriptor(target, prop);
        
        if (typeof prop === 'string' && self.isProtected(prop)) {
          const packageName = self.getCallingPackage();
          const check = self.checkAccess(prop, packageName);
          
          if (!check.allowed) {
            self.logAccess(prop, packageName, 'DESCRIPTOR_ACCESS', check);
            
            if (!self.config.mode?.alertOnly) {
              // SECURITY FIX: Return undefined if property doesn't exist
              // For existing properties, return descriptor but with undefined value
              // This maintains Proxy invariants while hiding the value
              if (!targetDesc) {
                return undefined;
              }
              
              // Return descriptor with same configurability as target (Proxy invariant requirement)
              // But with undefined value to hide the actual value
              return {
                value: undefined,
                writable: targetDesc.writable,
                enumerable: false, // Make non-enumerable to hide from Object.keys()
                configurable: targetDesc.configurable
              };
            }
          }
        }
        
        return targetDesc;
      },
      
      // SECURITY FIX: Control enumeration to prevent key discovery
      // This traps Object.keys(), Object.getOwnPropertyNames(), and Reflect.ownKeys()
      ownKeys(target) {
        const keys = Reflect.ownKeys(target);
        
        // Filter out protected keys for unauthorized callers
        const filteredKeys = keys.filter(key => {
          if (typeof key === 'string' && self.isProtected(key)) {
            const packageName = self.getCallingPackage();
            const check = self.checkAccess(key, packageName);
            return check.allowed;
          }
          return true;
        });
        
        // Note: Reflect.ownKeys() will call this trap, so we're protected
        return filteredKeys;
      },
      
      // SECURITY FIX: Control 'in' operator
      has(target, prop) {
        if (typeof prop === 'string' && self.isProtected(prop)) {
          const packageName = self.getCallingPackage();
          const check = self.checkAccess(prop, packageName);
          
          if (!check.allowed && !self.config.mode?.alertOnly) {
            return false; // Hide protected vars from unauthorized callers
          }
        }
        
        return prop in target;
      }
    });
    
    try {
      // SECURITY: First delete any existing property
      delete process.env;
      
      Object.defineProperty(process, 'env', {
        get() { return envProxy; },
        set() { 
          console.error('[Env Protector] TAMPERING DETECTED: Attempt to reassign process.env');
          return false; 
        },
        configurable: false,  // Cannot be reconfigured
        enumerable: true
      });
      
      // SECURITY NOTE: We used to call Object.preventExtensions(process) here
      // but it caused "Cannot define property mainModule" errors in Node.js v22+
      // The env proxy protection is sufficient without making process non-extensible
      
    } catch (e) {
      if (!this.silent) {
        console.warn('[Env Protector] Could not fully protect process.env:', e.message);
        console.warn('[Env Protector] Protection may be partially active');
      }
    }
    
    // SECURITY FIX: Intercept util.inspect to prevent it from bypassing the proxy
    // util.inspect uses internal mechanisms that can bypass Proxy get traps
    try {
      const util = require('util');
      const originalInspect = util.inspect;
      
      util.inspect = function(obj, ...args) {
        // Only filter if inspecting process.env
        if (obj === process.env || obj === envProxy) {
          const filtered = {};
          for (const key in obj) {
            if (self.isProtected(key)) {
              const packageName = self.getCallingPackage();
              const check = self.checkAccess(key, packageName);
              if (!check.allowed) {
                filtered[key] = '[PROTECTED]';
                continue;
              }
            }
            filtered[key] = obj[key];
          }
          return originalInspect(filtered, ...args);
        }
        return originalInspect(obj, ...args);
      };
      
      // Copy static properties
      Object.keys(originalInspect).forEach(key => {
        util.inspect[key] = originalInspect[key];
      });
      
      // Make immutable
      Object.freeze(util.inspect);
    } catch (e) {
      // Silently fail - util.inspect protection is a nice-to-have
    }
  }
  
  isProtected(varName) {
    return this.protectedVars.some(pattern => {
      if (pattern.includes('*')) {
        const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$', 'i');
        return regex.test(varName);
      }
      return varName.toUpperCase() === pattern.toUpperCase();
    });
  }
  
  checkAccess(varName, packageName) {
    // SECURITY FIX: When in strict mode OR when explicitly blocking untrusted access,
    // don't allow access even without package context.
    // This prevents bypasses where code runs without module context.
    const isStrictMode = this.config.mode?.strictMode === true;
    const blockWithoutContext = this.config.environment?.blockWithoutContext !== false;
    
    if (!packageName) {
      // Check if we're being called from user's main code or from untrusted code
      // In strict mode, always require package context
      if (isStrictMode) {
        return { 
          allowed: false, 
          reason: 'strict_mode_no_context',
          variable: varName,
          severity: 'medium'
        };
      }
      
      // If allowTrustedModulesAccess is false, block even without context
      // This is for maximum security configurations
      if (!this.allowTrustedModules && blockWithoutContext) {
        return { 
          allowed: false, 
          reason: 'untrusted_no_context',
          variable: varName,
          severity: 'medium'
        };
      }
      
      return { allowed: true, reason: 'no_package_context' };
    }
    
    const isTrusted = this.firewall?.isTrustedModule(packageName);
    if (this.allowTrustedModules && isTrusted) {
      return { allowed: true, reason: 'trusted_module', package: packageName };
    }
    
    if (this.config.exceptions?.modules?.[packageName]?.allowEnvironment) {
      const allowedVars = this.config.exceptions.modules[packageName].allowEnvironment;
      if (allowedVars.includes(varName) || allowedVars.includes('*')) {
        return { allowed: true, reason: 'exception', package: packageName };
      }
    }
    
    return { 
      allowed: false, 
      reason: 'protected_variable',
      variable: varName,
      package: packageName,
      severity: 'high'
    };
  }
  
  getCallingPackage() {
    try {
      const stack = new Error().stack;
      // Match all node_modules references
      const matches = stack.match(/node_modules[/\\]((?:@[^/\\]+[/\\])?[^/\\]+)/g);
      if (!matches) return null;
      
      // Extract package names
      const packages = matches.map(match => {
        const m = match.match(/node_modules[/\\]((?:@[^/\\]+[/\\])?[^/\\]+)/);
        return m ? m[1] : null;
      }).filter(Boolean);
      
      // Filter out infrastructure packages that wrap execution
      const infrastructurePackages = [
        'source-map-support',
        'ts-node',
        'ts-node-dev',
        '@babel/core',
        '@babel/register'
      ];
      
      // Find first non-infrastructure package (reverse order for deepest first)
      for (let i = packages.length - 1; i >= 0; i--) {
        const pkg = packages[i];
        if (!infrastructurePackages.includes(pkg)) {
          return pkg;
        }
      }
      
      // Fallback to last package if all are infrastructure
      return packages[packages.length - 1] || null;
    } catch (e) {
      return null;
    }
  }
  
  logAccess(varName, packageName, operation, check) {
    const entry = {
      timestamp: new Date().toISOString(),
      variable: varName,
      package: packageName || 'unknown',
      operation,
      allowed: check.allowed,
      reason: check.reason
    };
    
    // SECURITY FIX: Limit access log size to prevent memory leaks
    const MAX_ACCESS_LOG = 500;
    
    this.accessLog.push(entry);
    
    if (this.accessLog.length > MAX_ACCESS_LOG) {
      // Remove oldest entries (FIFO)
      this.accessLog.shift();
    }
    
    const shouldAlert = this.config.reporting?.alertOnSuspicious !== false;
    if (!check.allowed && !this.silent && shouldAlert) {
      console.warn(`[ENV PROTECTION] ${operation} blocked: ${varName} by ${packageName || 'unknown'}`);
    }
  }
  
  getStats() {
    return {
      totalAccesses: this.accessLog.length,
      blocked: this.accessLog.filter(e => !e.allowed).length,
      recentAccesses: this.accessLog.slice(-10)
    };
  }
}

module.exports = { EnvProtector };
