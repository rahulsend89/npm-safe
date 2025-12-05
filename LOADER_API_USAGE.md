# Using Node.js Loader API for Firewall Interception

## Current Implementation

The codebase currently uses the `-r` (require) flag to preload firewall modules:

```bash
node -r ./index.js script.js
```

This approach:
- ✅ Works with CommonJS modules
- ✅ Simple to implement
- ✅ Synchronous initialization
- ❌ Only works for CommonJS
- ❌ Loads after some Node.js internals
- ❌ Cannot intercept ESM modules

## Node.js Loader API Overview

The Loader API allows you to intercept and transform modules during the loading phase, before they execute. This provides **earlier interception** than `-r` flag.

### Important Notes

1. **Deprecation**: The `--loader` flag was deprecated in Node.js 20.6.0 and removed in Node.js 21+
2. **Replacement**: Use `--import` flag or `register()` API for newer Node.js versions
3. **ESM Only**: Loaders work with ES modules (`.mjs` files or `"type": "module"` in package.json)
4. **CommonJS Limitation**: Loaders cannot directly intercept CommonJS `require()` calls

## Implementation Options

### Option 1: ESM Loader (Recommended for ESM projects)

Create an ESM loader that initializes the firewall before any modules load:

**File: `lib/esm-loader.mjs`**

```javascript
/**
 * ESM Loader for Firewall
 * Intercepts module loading to initialize firewall before any code executes
 */

// Initialize firewall synchronously before any modules load
let firewallInitialized = false;

function initializeFirewall() {
  if (firewallInitialized) return;
  
  // Enable firewall
  process.env.NODE_FIREWALL = '1';
  
  // Initialize firewall core synchronously
  // Note: This requires converting firewall-core to ESM or using dynamic import
  try {
    // For now, we'll use a synchronous initialization approach
    const { createRequire } = await import('module');
    const require = createRequire(import.meta.url);
    
    const firewallCore = require('../lib/firewall-core');
    const firewall = firewallCore.getInstance();
    firewall.initialize();
    
    // Initialize interceptors
    require('../lib/fs-interceptor-v2');
    require('../lib/child-process-interceptor');
    
    firewallInitialized = true;
    console.log('[Firewall Loader] Initialized');
  } catch (error) {
    console.error('[Firewall Loader] CRITICAL: Failed to initialize:', error);
    process.exit(1);
  }
}

// Initialize immediately when loader is loaded
initializeFirewall();

/**
 * ESM Loader Hook: resolve
 * Called for each module import to resolve the module specifier
 */
export async function resolve(specifier, context, nextResolve) {
  // Ensure firewall is initialized before resolving any modules
  if (!firewallInitialized) {
    await initializeFirewall();
  }
  
  // Call the next resolve hook in the chain
  return nextResolve(specifier, context);
}

/**
 * ESM Loader Hook: load
 * Called to load the module source
 */
export async function load(url, context, nextLoad) {
  // Ensure firewall is initialized
  if (!firewallInitialized) {
    await initializeFirewall();
  }
  
  // Call the next load hook in the chain
  return nextLoad(url, context);
}
```

**Usage:**

```bash
# Node.js 18.x and earlier
node --loader ./lib/esm-loader.mjs script.mjs

# Node.js 20.6.0+ (using --import)
node --import ./lib/esm-loader.mjs script.mjs

# Or register programmatically
node --import ./lib/register-loader.mjs script.mjs
```

### Option 2: Hybrid Approach (CommonJS + ESM)

Create a loader that works with both CommonJS and ESM by intercepting at the module level:

**File: `lib/hybrid-loader.mjs`**

```javascript
/**
 * Hybrid Loader - Works with both CommonJS and ESM
 * Uses Module._extensions to intercept CommonJS requires
 */

import { register } from 'node:module';
import { pathToFileURL } from 'node:url';

// Initialize firewall before any modules load
function initializeFirewall() {
  if (global.__FIREWALL_INITIALIZED__) return;
  
  process.env.NODE_FIREWALL = '1';
  
  // Use createRequire to load CommonJS modules from ESM context
  const { createRequire } = await import('module');
  const require = createRequire(import.meta.url);
  
  try {
    const firewallCore = require('../lib/firewall-core');
    const firewall = firewallCore.getInstance();
    firewall.initialize();
    
    require('../lib/fs-interceptor-v2');
    require('../lib/child-process-interceptor');
    
    global.__FIREWALL_INITIALIZED__ = true;
  } catch (error) {
    console.error('[Firewall Loader] Initialization failed:', error);
    throw error;
  }
}

// Intercept CommonJS requires via Module._extensions
const Module = await import('module');
const originalExtension = Module._extensions['.js'];

Module._extensions['.js'] = function(module, filename) {
  if (!global.__FIREWALL_INITIALIZED__) {
    initializeFirewall();
  }
  return originalExtension.call(this, module, filename);
};

// ESM loader hooks
export async function resolve(specifier, context, nextResolve) {
  if (!global.__FIREWALL_INITIALIZED__) {
    await initializeFirewall();
  }
  return nextResolve(specifier, context);
}

export async function load(url, context, nextLoad) {
  if (!global.__FIREWALL_INITIALIZED__) {
    await initializeFirewall();
  }
  return nextLoad(url, context);
}
```

### Option 3: Register API (Node.js 20.6.0+)

Use the newer `register()` API for better compatibility:

**File: `lib/register-loader.mjs`**

```javascript
/**
 * Firewall Loader using register() API
 * Compatible with Node.js 20.6.0+
 */

import { register } from 'node:module';
import { pathToFileURL } from 'node:url';

// Initialize firewall
let initialized = false;

async function initializeFirewall() {
  if (initialized) return;
  
  process.env.NODE_FIREWALL = '1';
  
  const { createRequire } = await import('module');
  const require = createRequire(import.meta.url);
  
  const firewallCore = require('../lib/firewall-core');
  const firewall = firewallCore.getInstance();
  firewall.initialize();
  
  require('../lib/fs-interceptor-v2');
  require('../lib/child-process-interceptor');
  
  initialized = true;
}

// Register the loader
register(pathToFileURL('./lib/esm-loader.mjs'), {
  data: { initializeFirewall },
  importAttributes: ['firewall']
});

// Initialize immediately
await initializeFirewall();
```

## Benefits of Using Loader API

1. **Earlier Interception**: Firewall initializes before any user code executes
2. **ESM Support**: Can intercept ES module imports
3. **Module Transformation**: Can modify module source before execution
4. **Better Security**: Closes race condition windows

## Limitations

1. **ESM Only**: Loaders primarily work with ES modules
2. **CommonJS Challenge**: Intercepting CommonJS requires additional work
3. **Node.js Version**: Different APIs for different Node.js versions
4. **Complexity**: More complex than `-r` flag approach

## Recommended Implementation Strategy

For this codebase, I recommend:

### Step 1: Create ESM Loader Wrapper

Create `lib/esm-loader.mjs` that:
- Initializes firewall synchronously
- Works with both `--loader` (Node.js < 20.6) and `--import` (Node.js 20.6+)
- Provides hooks for module interception

### Step 2: Update Bin Scripts

Modify `bin/node-firewall` to support both approaches:

```javascript
#!/usr/bin/env node

const { spawn } = require('child_process');
const path = require('path');

const args = process.argv.slice(2);
const nodeVersion = process.version.match(/^v(\d+)\./)?.[1];

// Use loader for ESM, -r for CommonJS
const useLoader = args.some(arg => arg.endsWith('.mjs') || 
  process.env.NODE_FIREWALL_USE_LOADER === '1');

if (useLoader && parseInt(nodeVersion) >= 18) {
  const loaderPath = path.join(__dirname, '..', 'lib', 'esm-loader.mjs');
  const loaderFlag = parseInt(nodeVersion) >= 20 ? '--import' : '--loader';
  const nodeArgs = [loaderFlag, loaderPath, ...args];
  
  spawn(process.execPath, nodeArgs, { stdio: 'inherit' });
} else {
  // Fallback to -r flag for CommonJS
  const firewallLib = path.join(__dirname, '..', 'index.js');
  const nodeArgs = ['-r', firewallLib, ...args];
  
  spawn(process.execPath, nodeArgs, { stdio: 'inherit' });
}
```

### Step 3: Documentation

Update README to explain:
- When to use `--loader` vs `-r`
- How to use with ESM projects
- Node.js version compatibility

## Example Usage

### With ESM Modules

```bash
# Using loader
node --import ./lib/esm-loader.mjs app.mjs

# Or via wrapper
./bin/node-firewall app.mjs
```

### With CommonJS (Current Approach)

```bash
# Using -r flag (current)
node -r ./index.js app.js

# Or via wrapper
./bin/node-firewall app.js
```

## Testing the Loader

Create a test ESM file:

**File: `test-loader.mjs`**

```javascript
// This should be intercepted by the loader
import fs from 'fs';

console.log('Testing firewall loader...');

// Try to access a file - should be intercepted
fs.readFileSync('/etc/passwd', 'utf8');
```

Run with loader:

```bash
node --import ./lib/esm-loader.mjs test-loader.mjs
```

## Migration Path

1. **Phase 1**: Create ESM loader alongside existing `-r` approach
2. **Phase 2**: Update documentation and examples
3. **Phase 3**: Make loader the default for ESM projects
4. **Phase 4**: Keep `-r` as fallback for CommonJS-only projects

## Code Review Recommendations

As mentioned in `CODE_REVIEW.md`:
- Use `--loader` API for earlier interception (✅ addressed)
- Fix initialization race conditions (✅ loader initializes first)
- Support both CommonJS and ESM (✅ hybrid approach)

## References

- [Node.js ESM Loaders](https://nodejs.org/api/esm.html#loaders)
- [Node.js register() API](https://nodejs.org/api/module.html#moduleregisterspecifier-parenturl-options)
- [Loader Hooks Specification](https://nodejs.org/api/esm.html#loaders)
