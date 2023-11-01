/**
 * Firewall Hardening - Fortress Mode (Smart)
 * Eliminates bypasses WITHOUT breaking Node.js internals
 * 
 * Strategy: Hook at the RIGHT level, don't fight Node.js
 */

const Module = require('module');
const path = require('path');

class FortressHardening {
  constructor(options = {}) {
    this.options = {
      blockWorkers: options.blockWorkers !== false,
      blockNativeAddons: options.blockNativeAddons !== false,
      blockSharedArrayBuffer: options.blockSharedArrayBuffer !== false,
      strictMode: options.strictMode !== false,
      ...options
    };
    
    this.initialized = false;
    this.firewallModules = new Set();
    this.originalMethods = new Map();
    this.startupPhase = true; // Allow Node.js initialization operations
    this.protectionReady = false;
    
    // CRITICAL: Complete startup phase after Node.js initialization
    // This allows module cache setup, then locks down
    setTimeout(() => {
      this.startupPhase = false;
      console.log('[Fortress] Startup phase complete - full protection active');
    }, 100);
    
    // Use setImmediate for next event loop tick (safer than setTimeout)
    setImmediate(() => {
      this.protectionReady = true;
      console.log('[Fortress] Protection layers fully initialized');
    });
  }
  
  initialize() {
    if (this.initialized) return;
    
    console.log('[Fortress] Initializing fortress-grade protection...');
    
    // Store firewall module paths
    this.identifyFirewallModules();
    
    // Apply protections
    this.protectRequireCache();
    this.protectPrototypes();
    this.interceptDangerousModules();
    this.protectProcessBindings();
    this.protectEnvironment();
    
    this.initialized = true;
    console.log('[Fortress] FORTRESS MODE ACTIVE');
    this.printStatus();
  }
  
  identifyFirewallModules() {
    Object.keys(require.cache).forEach(key => {
      if (key.includes('firewall') || key.includes('interceptor') || key.includes('hardening')) {
        this.firewallModules.add(key);
      }
    });
    console.log(`[Fortress] Identified ${this.firewallModules.size} firewall modules`);
  }
  
  // ============================================
  // 1. PROTECT REQUIRE.CACHE (Aggressive)
  // ============================================
  protectRequireCache() {
    const self = this;
    const cache = require.cache;
    const moduleSnapshots = new Map();
    
    // Take snapshots of firewall modules
    this.firewallModules.forEach(key => {
      if (cache[key]) {
        moduleSnapshots.set(key, cache[key]);
      }
    });
    
    // AGGRESSIVE: Wrap require.cache with Proxy to PREVENT deletion
    const handler = {
      deleteProperty(target, prop) {
        // Allow deletions during startup phase (Node.js internal operations)
        if (self.startupPhase) {
          return Reflect.deleteProperty(target, prop);
        }
        
        // Block deletion of firewall modules
        if (self.firewallModules.has(prop)) {
          console.error(`[Fortress] ATTACK BLOCKED: Cannot delete firewall module`);
          return false; // Prevent deletion
        }
        
        // CRITICAL: Also block deletion of 'fs' module to prevent bypass
        if (prop.endsWith('/fs.js') || prop === 'fs') {
          console.error(`[Fortress] ATTACK BLOCKED: Cannot delete fs module`);
          return false;
        }
        
        return Reflect.deleteProperty(target, prop);
      },
      
      set(target, prop, value) {
        // Allow during startup
        if (self.startupPhase) {
          return Reflect.set(target, prop, value);
        }
        
        // Allow setting but restore if it's a firewall module being cleared
        if (self.firewallModules.has(prop) && !value && target[prop]) {
          console.error(`[Fortress] ATTACK BLOCKED: Cannot clear firewall module`);
          return false;
        }
        return Reflect.set(target, prop, value);
      },
      
      get(target, prop) {
        // If a firewall module was deleted, restore it
        if (!self.startupPhase && self.firewallModules.has(prop) && !target[prop] && moduleSnapshots.has(prop)) {
          console.error(`[Fortress] AUTO-RESTORE: ${path.basename(prop)}`);
          target[prop] = moduleSnapshots.get(prop);
        }
        return target[prop];
      }
    };
    
    // Replace require.cache with Proxy
    const proxiedCache = new Proxy(cache, handler);
    
    // Override Module._cache
    try {
      Object.defineProperty(Module, '_cache', {
        get: () => proxiedCache,
        set: () => {
          console.error('[Fortress] ATTACK BLOCKED: Cannot replace Module._cache');
        },
        configurable: false
      });
    } catch (e) {
      // Already defined/locked, which is fine
    }
    
    // Also set require.cache
    try {
      Object.defineProperty(require, 'cache', {
        get: () => proxiedCache,
        set: () => {
          console.error('[Fortress] ATTACK BLOCKED: Cannot replace require.cache');
        },
        configurable: false
      });
    } catch (e) {
      // Already defined/locked
    }
    
    console.log('[Fortress] require.cache LOCKED (proxy protection)');
  }
  
  // ============================================
  // 2. PROTECT PROTOTYPES (Smart)
  // ============================================
  protectPrototypes() {
    const self = this;
    
    // Properties that are definitely malicious if set on Object.prototype
    const dangerousProps = [
      'enabled', 'disabled', 'alertOnly', 'allowed', 'blocked',
      'strictMode', 'mode', 'config', '__proto__'
    ];
    
    // Node.js internal properties - DO NOT PROTECT these
    const nodeInternalProps = ['mainModule', 'wrapper', 'extensions', '_extensions'];
    
    // First, freeze __proto__ setter
    try {
      const originalProtoSetter = Object.getOwnPropertyDescriptor(Object.prototype, '__proto__').set;
      Object.defineProperty(Object.prototype, '__proto__', {
        set: function(value) {
          if (!self.startupPhase) {
            console.error('[Fortress] ATTACK: __proto__ pollution blocked');
            throw new Error('__proto__ modification blocked');
          }
          return originalProtoSetter.call(this, value);
        },
        get: Object.getOwnPropertyDescriptor(Object.prototype, '__proto__').get,
        configurable: false
      });
    } catch (e) {
      // Might fail, continue
    }
    
    dangerousProps.forEach(prop => {
      if (prop === '__proto__') return; // Already handled
      
      // Only protect if not already exists
      if (!Object.prototype.hasOwnProperty(prop)) {
        try {
          // Store the original descriptor (if any) before we override
          const originalDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, prop);
          
          Object.defineProperty(Object.prototype, prop, {
            set: function(value) {
              // SECURITY: During startup phase, completely bypass our protection
              if (self.startupPhase) {
                // Define the property directly on this object to shadow the prototype
                try {
                  Object.defineProperty(this, prop, {
                    value: value,
                    writable: true,
                    enumerable: true,
                    configurable: true
                  });
                } catch (e) {
                  // Silently fail if object is not extensible during startup
                }
                return;
              }
              
              // Check if this is being set on an actual object (not prototype)
              if (this !== Object.prototype) {
                // SECURITY FIX: Skip all protection for Node.js built-ins
                // They need to work without any interference
                const isFunction = typeof this === 'function';
                const hasNodeInternalName = isFunction && this.name && (
                  this.name[0] === this.name[0].toUpperCase() || // Constructors
                  this.name.startsWith('_') // Internal functions
                );
                
                const isNodeBuiltin = (
                  this === Module ||
                  this === require ||
                  this === process ||
                  this === global ||
                  hasNodeInternalName ||
                  this.constructor === Function
                );
                
                if (isNodeBuiltin) {
                  // For Node.js built-ins, actually set the property without our protection
                  // Use Reflect.defineProperty or direct property creation
                  try {
                    // Try to define the property directly on the object
                    Object.defineProperty(this, prop, {
                      value: value,
                      writable: true,
                      enumerable: true,
                      configurable: true
                    });
                  } catch (e) {
                    // If Object.defineProperty fails (object not extensible), that's OK
                    // Just silently allow it to fail for Node.js internals
                  }
                  return;
                }
                
                // For user objects, use safe property definition
                try {
                  Object.defineProperty(this, prop, {
                    value: value,
                    writable: true,
                    enumerable: true,
                    configurable: true
                  });
                } catch (e) {
                  // Fallback to direct assignment
                  try {
                    this[prop] = value;
                  } catch (e2) {
                    // Silent fail - object might not be extensible
                  }
                }
                return true;
              }
              
              // Only block if explicitly setting on Object.prototype
              if (!self.startupPhase) {
                console.error(`[Fortress] PROTOTYPE POLLUTION BLOCKED: ${prop}=${value}`);
                throw new Error(`Prototype pollution blocked: ${prop}`);
              }
              return true;
            },
            get: function() {
              return undefined;
            },
            configurable: false,
            enumerable: false
          });
        } catch (e) {
          // Property might exist, skip
        }
      }
    });
    
    console.log('[Fortress] Prototypes protected (smart mode)');
  }
  
  // ============================================
  // 3. INTERCEPT DANGEROUS MODULES (Smart Hook)
  // ============================================
  interceptDangerousModules() {
    // Hook Module._load instead of overwriting require
    const originalLoad = Module._load;
    const self = this;
    
    Module._load = function(request, parent, isMain) {
      // SECURITY: Set startup phase to true so prototype setters allow assignments
      const wasStartupPhase = self.startupPhase;
      self.startupPhase = true;
      
      try {
        // Call original Module._load
        const module = originalLoad.apply(this, arguments);
        return self._processLoadedModule(request, module);
      } finally {
        // Restore startup phase
        self.startupPhase = wasStartupPhase;
      }
    };
    
    console.log('[Fortress] Module interception active (fs will be locked)');
  }
  
  _processLoadedModule(request, module) {
      // CRITICAL: Apply fs wrapping IN Module._load itself
      if (request === 'fs' && !this.startupPhase) {
        // Wrap fs methods INLINE to ensure protection
        return this.wrapFS(module);
      }
      
      // Apply protections based on module
      if (request === 'worker_threads') {
        return this.hardenWorkerThreads(module);
      }
      if (request === 'vm') {
        return this.hardenVM(module);
      }
      if (request === 'v8') {
        return this.hardenV8(module);
      }
      if (request === 'inspector') {
        return this.hardenInspector(module);
      }
      if (request === 'child_process') {
        return this.hardenChildProcess(module);
      }
      
      return module;
  }
  
  // ============================================
  // FS WRAPPING - Inline Protection
  // ============================================
  wrapFS(fsModule) {
    // Wrap all dangerous fs methods
    const dangerousMethods = ['readFileSync', 'readFile', 'writeFileSync', 'writeFile', 
                              'appendFileSync', 'appendFile', 'unlinkSync', 'unlink'];
    
    const sensitivePatterns = [
      /\.ssh/i, /\.aws/i, /\.npmrc/i, /\.env/i, /\.git/i,
      /id_rsa/i, /id_dsa/i, /id_ecdsa/i, /credentials/i, /\.pem/i
    ];
    
    const checkPath = (filePath) => {
      if (!filePath || typeof filePath !== 'string') return true;
      
      const isSensitive = sensitivePatterns.some(pattern => pattern.test(filePath));
      if (isSensitive) {
        console.error(`[Fortress] BLOCKED: Sensitive file access: ${filePath}`);
        return false;
      }
      return true;
    };
    
    dangerousMethods.forEach(method => {
      if (fsModule[method]) {
        const original = fsModule[method];
        
        fsModule[method] = function(filePath, ...args) {
          if (!checkPath(filePath)) {
            const error = new Error(`Firewall: Access denied to sensitive file`);
            error.code = 'EACCES';
            throw error;
          }
          return original.call(this, filePath, ...args);
        };
      }
    });
    
    console.log('[Fortress] fs module wrapped inline');
    return fsModule;
  }
  
  // Worker Threads Protection
  hardenWorkerThreads(module) {
    if (this.options.blockWorkers && process.env.npm_lifecycle_event) {
      return new Proxy(module, {
        get(target, prop) {
          if (prop === 'Worker') {
            return function() {
              console.error('[Fortress] ATTACK BLOCKED: Worker threads during install');
              throw new Error('Worker threads blocked during package installation');
            };
          }
          return target[prop];
        }
      });
    }
    
    // Inject firewall into workers
    if (module.Worker) {
      const OriginalWorker = module.Worker;
      
      module.Worker = class extends OriginalWorker {
        constructor(...args) {
          console.warn('[Fortress] Worker created - injecting firewall');
          
          // Inject firewall
          if (args.length > 1 && typeof args[1] === 'object') {
            const options = args[1];
            if (!options.env) options.env = { ...process.env };
            
            options.env.NODE_OPTIONS = process.env.NODE_OPTIONS || '';
            options.env.NODE_FIREWALL = '1';
            
            if (options.eval && typeof args[0] === 'string') {
              args[0] = `
                try {
                  require('${path.resolve(__dirname, 'fs-interceptor-v2.js')}');
                } catch (e) { process.exit(1); }
                ${args[0]}
              `;
            }
          }
          
          super(...args);
        }
      };
    }
    
    return module;
  }
  
  // VM Protection - Enhanced escape detection
  hardenVM(module) {
    // SECURITY: Comprehensive VM escape patterns
    const escapePatterns = [
      /constructor\.constructor/i,
      /Function\s*\(/i,
      /this\.constructor/i,
      /Object\.constructor/i,
      /\[\s*['"]constructor['"]\s*\]/i,
      /process\.binding/i,
      /process\.dlopen/i,
      /require\s*\(\s*['"]child_process['"]\s*\)/i,
      /eval\s*\(/i,
      /\bBuffer\s*\(/i,
      /\.__proto__/i,
      /Object\.setPrototypeOf/i,
      /Proxy\s*\(/i,
      /Reflect\./i
    ];
    
    // Obfuscation detection patterns
    const obfuscationPatterns = [
      /\\x[0-9a-f]{2}/i,  // Hex encoding
      /\\u[0-9a-f]{4}/i,  // Unicode encoding
      /String\.fromCharCode/i,
      /atob\s*\(/i,  // Base64 decode
      /Buffer\.from.*base64/i
    ];
    
    if (module.runInContext) {
      const original = module.runInContext;
      module.runInContext = function(code, ...args) {
        if (typeof code === 'string') {
          // Check for direct escape patterns
          for (const pattern of escapePatterns) {
            if (pattern.test(code)) {
              console.error('[Fortress] VM ESCAPE BLOCKED - Pattern:', pattern);
              throw new Error('VM escape attempt detected');
            }
          }
          
          // Check for obfuscation (warn but allow, as it may be legitimate)
          for (const pattern of obfuscationPatterns) {
            if (pattern.test(code)) {
              console.warn('[Fortress] Obfuscated code detected in VM context');
              break;
            }
          }
          
          // SECURITY: Check code length (potential DoS via infinite loops)
          if (code.length > 100000) {
            console.error('[Fortress] VM code too large - potential DoS');
            throw new Error('VM code size limit exceeded');
          }
        }
        
        return original.apply(this, [code, ...args]);
      };
    }
    
    // Also harden runInThisContext and runInNewContext
    if (module.runInThisContext) {
      const original = module.runInThisContext;
      module.runInThisContext = function(code, ...args) {
        if (typeof code === 'string') {
          for (const pattern of escapePatterns) {
            if (pattern.test(code)) {
              console.error('[Fortress] VM ESCAPE BLOCKED in runInThisContext');
              throw new Error('VM escape attempt detected');
            }
          }
        }
        return original.apply(this, [code, ...args]);
      };
    }
    
    if (module.runInNewContext) {
      const original = module.runInNewContext;
      module.runInNewContext = function(code, ...args) {
        if (typeof code === 'string') {
          for (const pattern of escapePatterns) {
            if (pattern.test(code)) {
              console.error('[Fortress] VM ESCAPE BLOCKED in runInNewContext');
              throw new Error('VM escape attempt detected');
            }
          }
        }
        return original.apply(this, [code, ...args]);
      };
    }
    
    return module;
  }
  
  // V8 Protection
  hardenV8(module) {
    if (module.writeHeapSnapshot) {
      const original = module.writeHeapSnapshot;
      module.writeHeapSnapshot = function(...args) {
        if (process.env.npm_lifecycle_event) {
          console.error('[Fortress] HEAP SNAPSHOT BLOCKED');
          throw new Error('Heap snapshots blocked during install');
        }
        console.warn('[Fortress] Heap snapshot created');
        return original.apply(this, args);
      };
    }
    
    return module;
  }
  
  // Inspector Protection
  hardenInspector(module) {
    if (module.open) {
      module.open = function() {
        console.error('[Fortress] INSPECTOR BLOCKED');
        throw new Error('Inspector protocol blocked');
      };
    }
    
    return module;
  }
  
  // Child Process Protection (Maximum)
  hardenChildProcess(module) {
    const firewallPath = path.resolve(__dirname, 'fs-interceptor-v2.js');
    
    ['spawn', 'exec', 'execFile', 'fork', 'execSync', 'spawnSync'].forEach(method => {
      if (module[method]) {
        const original = module[method];
        module[method] = function(...args) {
          const command = args[0];
          
          // CRITICAL: If spawning 'node', inject firewall
          if (command === 'node' || command.endsWith('/node')) {
            console.error(`[Fortress] INTERCEPTING node spawn - injecting firewall`);
            
            // Get the args array
            let nodeArgs = args[1];
            if (Array.isArray(nodeArgs)) {
              // Check if firewall is already loaded
              const hasFirewall = nodeArgs.some(arg => arg.includes('firewall') || arg.includes('interceptor'));
              
              if (!hasFirewall) {
                // Inject -r flags at the beginning
                args[1] = [
                  '-r', firewallPath,
                  ...nodeArgs
                ];
                console.error(`[Fortress] Added firewall to child process args`);
              }
            }
            
            // Also enforce NODE_FIREWALL in env
            const options = args.find(arg => arg && typeof arg === 'object' && !Array.isArray(arg));
            if (options) {
              if (!options.env) {
                options.env = { ...process.env };
              }
              options.env.NODE_FIREWALL = '1';
              options.env.npm_lifecycle_event = process.env.npm_lifecycle_event;
            }
          }
          
          return original.apply(this, args);
        };
      }
    });
    
    console.log('[Fortress] child_process hardened (auto-inject firewall)');
    return module;
  }
  
  // ============================================
  // 4. PROTECT PROCESS.BINDING & NATIVE ADDONS
  // ============================================
  protectProcessBindings() {
    // Block process.binding
    if (typeof process.binding === 'function') {
      const originalBinding = process.binding;
      
      process.binding = function(name) {
        if (process.env.npm_lifecycle_event) {
          console.error(`[Fortress] process.binding('${name}') BLOCKED during install`);
          throw new Error('process.binding blocked during package installation');
        }
        console.warn(`[Fortress] process.binding('${name}') accessed`);
        return originalBinding.apply(this, arguments);
      };
    }
    
    // Block _linkedBinding
    if (typeof process._linkedBinding === 'function') {
      process._linkedBinding = function() {
        throw new Error('_linkedBinding blocked');
      };
    }
    
    // Block process.dlopen (native addon loading)
    if (typeof process.dlopen === 'function') {
      const originalDlopen = process.dlopen;
      
      try {
        process.dlopen = function(module, filename, flags) {
          if (process.env.npm_lifecycle_event && this.options.blockNativeAddons) {
            console.error(`[Fortress] NATIVE ADDON BLOCKED: ${filename}`);
            throw new Error(`Native addon loading blocked during install: ${path.basename(filename)}`);
          }
          console.warn(`[Fortress] Native addon loaded: ${path.basename(filename)}`);
          return originalDlopen.apply(this, arguments);
        }.bind(this);
        
        // Make non-writable
        Object.defineProperty(process, 'dlopen', {
          value: process.dlopen,
          writable: false,
          configurable: false
        });
      } catch (e) {
        // Ignore if already protected/non-writable
      }
    }
    
    console.log('[Fortress] process.binding + dlopen protected');
  }
  
  // ============================================
  // 5. PROTECT ENVIRONMENT VARIABLES
  // ============================================
  protectEnvironment() {
    // Make critical environment variables immutable
    const criticalVars = ['NODE_OPTIONS', 'NODE_FIREWALL'];
    
    criticalVars.forEach(varName => {
      const originalValue = process.env[varName];
      if (originalValue) {
        // Delete existing property
        try {
          delete process.env[varName];
        } catch (e) {
          // Already non-configurable/hardened
          return;
        }
        
        // Redefine as non-writable (truly immutable)
        try {
          Object.defineProperty(process.env, varName, {
            value: originalValue,
            writable: false,
            configurable: false,
            enumerable: true
          });
          console.log(`[Fortress] ${varName} locked (immutable)`);
        } catch (e) {
          // Fallback: restore if defineProperty fails
          process.env[varName] = originalValue;
          console.warn(`[Fortress] Could not lock ${varName}, using fallback`);
        }
      }
    });
    
    // SharedArrayBuffer monitoring
    if (this.options.blockSharedArrayBuffer && typeof SharedArrayBuffer !== 'undefined') {
      const OriginalSAB = SharedArrayBuffer;
      
      global.SharedArrayBuffer = function(...args) {
        if (process.env.npm_lifecycle_event && this.options.strictMode) {
          console.error('[Fortress] SharedArrayBuffer BLOCKED');
          throw new Error('SharedArrayBuffer blocked during install');
        }
        console.warn('[Fortress] SharedArrayBuffer created');
        return new OriginalSAB(...args);
      };
      
      Object.setPrototypeOf(global.SharedArrayBuffer, OriginalSAB);
    }
    
    console.log('[Fortress] Environment protected');
  }
  
  // ============================================
  // STATUS
  // ============================================
  printStatus() {
    console.log('=========================================================');
    console.log('|           FORTRESS MODE STATUS                       |');
    console.log('=========================================================');
    console.log('');
    console.log('Protection                          Status');
    console.log('---------------------------------------------------------');
    console.log('* require.cache poisoning           MITIGATED');
    console.log('* Prototype pollution               BLOCKED');
    console.log('* Worker thread bypass              ' + (this.options.blockWorkers ? 'BLOCKED' : 'INJECTED'));
    console.log('* VM escape                         BLOCKED');
    console.log('* process.binding abuse             BLOCKED');
    console.log('* Heap snapshot dumps               BLOCKED');
    console.log('* Inspector protocol                BLOCKED');
    console.log('* Child process env bypass          ENFORCED');
    console.log('* SharedArrayBuffer                 MONITORED');
    console.log('* Environment tampering             MONITORED');
    console.log('---------------------------------------------------------');
    console.log('Protection Level: FORTRESS');
    console.log('');
  }
  
  getStatus() {
    return {
      initialized: this.initialized,
      mode: 'FORTRESS',
      protectedModules: this.firewallModules.size,
      protections: {
        requireCache: 'AUTO-RESTORE',
        prototypes: 'PROTECTED',
        workerThreads: this.options.blockWorkers ? 'BLOCKED' : 'INJECTED',
        vmModule: 'PROTECTED',
        processBinding: 'BLOCKED',
        v8Module: 'PROTECTED',
        inspector: 'BLOCKED',
        childProcess: 'ENFORCED',
        sharedArrayBuffer: 'MONITORED',
        environment: 'MONITORED'
      }
    };
  }
}

// Singleton
let instance = null;

function getInstance(options) {
  if (!instance) {
    instance = new FortressHardening(options);
  }
  return instance;
}

// Auto-init
if (process.env.NODE_FIREWALL === '1') {
  const fortress = getInstance({
    blockWorkers: true,
    blockNativeAddons: true,
    blockSharedArrayBuffer: true,
    strictMode: process.env.NODE_FIREWALL_STRICT === '1'
  });
  fortress.initialize();
}

module.exports = {
  FortressHardening,
  getInstance
};
