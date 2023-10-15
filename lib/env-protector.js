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
    
    const envProxy = new Proxy(originalEnv, {
      get(target, prop) {
        if (typeof prop === 'string' && self.isProtected(prop)) {
          const packageName = self.getCallingPackage();
          const check = self.checkAccess(prop, packageName);
          
          if (!check.allowed) {
            self.logAccess(prop, packageName, 'READ', check);
            
            if (!self.config.mode?.alertOnly) {
              throw new Error(`Access to protected environment variable '${prop}' is blocked`);
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
              // Return undefined if property doesn't exist, otherwise mask the value
              if (!targetDesc) {
                return undefined;
              }
              
              // Return descriptor with same configurability as target (Proxy invariant requirement)
              return {
                value: undefined,
                writable: targetDesc.writable,
                enumerable: targetDesc.enumerable,
                configurable: targetDesc.configurable
              };
            }
          }
        }
        
        return targetDesc;
      },
      
      // SECURITY FIX: Control enumeration to prevent key discovery
      ownKeys(target) {
        const keys = Reflect.ownKeys(target);
        
        // Filter out protected keys for unauthorized callers
        return keys.filter(key => {
          if (typeof key === 'string' && self.isProtected(key)) {
            const packageName = self.getCallingPackage();
            const check = self.checkAccess(key, packageName);
            return check.allowed;
          }
          return true;
        });
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
    if (!packageName) {
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
    
    this.accessLog.push(entry);
    
    if (this.accessLog.length > 100) {
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
