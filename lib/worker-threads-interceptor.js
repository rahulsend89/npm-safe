/**
 * Worker Threads Interceptor
 * Ensures worker threads inherit firewall protection
 */

const Module = require('module');
const path = require('path');
const { pathToFileURL } = require('url');

class WorkerThreadsInterceptor {
  constructor() {
    this.enabled = process.env.NODE_FIREWALL === '1';
    this.initialized = false;
  }

  setupInterception() {
    if (!this.enabled || this.initialized) return;

    // Hook Module._load to intercept worker_threads
    const originalLoad = Module._load;
    const self = this;

    Module._load = function(request, parent, isMain) {
      const module = originalLoad.apply(this, arguments);

      // Intercept worker_threads module (both 'worker_threads' and 'node:worker_threads')
      if ((request === 'worker_threads' || request === 'node:worker_threads') && module && module.Worker) {
        return self.wrapWorkerThreads(module);
      }

      return module;
    };

    this.initialized = true;
    console.log('[Firewall] Worker threads interception active');
  }

  wrapWorkerThreads(module) {
    const OriginalWorker = module.Worker;
    const firewallPath = path.resolve(__dirname, 'firewall-core.js');

    // Wrap Worker constructor to inject firewall
    module.Worker = class FirewallWorker extends OriginalWorker {
      constructor(filename, options = {}) {
        // Inject firewall environment and loader flags
        if (!options.env) {
          options.env = { ...process.env };
        }

        // Ensure NODE_FIREWALL is set
        options.env.NODE_FIREWALL = '1';
        options.env.FIREWALL_CONFIG = process.env.FIREWALL_CONFIG || '';

        // For eval workers, prepend firewall initialization
        if (options.eval && typeof filename === 'string') {
          // Inject firewall require at the start of eval code
          // Use JSON.stringify to properly escape path (handles Windows backslashes)
          const firewallInit = `
            // Firewall initialization for worker thread
            if (process.env.NODE_FIREWALL === '1') {
              try {
                require(${JSON.stringify(firewallPath)});
              } catch (e) {
                console.error('[Firewall] Failed to initialize in worker:', e.message);
              }
            }
          `;
          
          filename = firewallInit + '\n' + filename;
        } else {
          // For file-based workers, inject via execArgv
          if (!options.execArgv) {
            options.execArgv = [];
          }

          // Get current loader flags from process.execArgv
          const loaderFlag = process.execArgv.find(arg => arg.startsWith('--import=') || arg.startsWith('--loader='));
          
          if (loaderFlag && !options.execArgv.includes(loaderFlag)) {
            options.execArgv.push(loaderFlag);
          } else if (!loaderFlag) {
            // If no loader flag in execArgv, construct one from the init module
            // Convert to file URL for cross-platform compatibility (handles Windows backslashes)
            const initPath = path.resolve(__dirname, 'init.mjs');
            const initFileURL = pathToFileURL(initPath).href;
            const importFlag = `--import=${initFileURL}`;
            
            if (!options.execArgv.includes(importFlag)) {
              options.execArgv.push(importFlag);
            }
          }
        }

        super(filename, options);
      }
    };

    // Preserve static properties
    Object.setPrototypeOf(module.Worker, OriginalWorker);
    Object.getOwnPropertyNames(OriginalWorker).forEach(prop => {
      if (prop !== 'prototype' && prop !== 'length' && prop !== 'name') {
        try {
          module.Worker[prop] = OriginalWorker[prop];
        } catch (e) {
          // Ignore non-configurable properties
        }
      }
    });

    return module;
  }
}

// Singleton instance
let instance = null;

function getInstance() {
  if (!instance) {
    instance = new WorkerThreadsInterceptor();
  }
  return instance;
}

module.exports = {
  WorkerThreadsInterceptor,
  getInstance
};
