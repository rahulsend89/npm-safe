# Security Audit & Roadmap

**Date:** Dec 5, 2025
**Auditor:** Principal Security Engineer
**Version:** 2.1.0

## Executive Summary

The `node-firewall` project has reached a mature state with robust defenses against common supply chain attacks. Recent architectural improvements (centralized config, fail-closed hooks, native build stripping) have significantly improved stability and security.

However, **critical vulnerabilities** remain regarding low-level file access and runtime compatibility. This report outlines these issues and provides a strategic roadmap for Bun compatibility.

---

## 1. Security Vulnerabilities & Fixes

### 1.1 [CRITICAL] File System Bypass via File Descriptors (Fixed)
**Issue:** Previous versions intercepted path-based `fs` methods (e.g., `readFileSync`) but missed descriptor-based methods (`read`, `write`) and `open`. An attacker could use `fs.openSync` to get a file descriptor for a sensitive file and then read it using `fs.readSync`, bypassing path checks.
**Status:** **FIXED**.
**Fix:** Added interception for:
- `fs.open`, `fs.openSync`
- `fs.opendir`, `fs.opendirSync`
- `fs.read`, `fs.readSync`
- `fs.write`, `fs.writeSync`
- `fs.promises.open`, `fs.promises.opendir`

### 1.2 [HIGH] `npm install` Lifecycle Scripts
**Issue:** Running `npm install` executes `postinstall` scripts from untrusted packages. Disabling the firewall during install (to avoid build failures) opens a major security hole.
**Status:** **FIXED**.
**Implementation:**

1. **Two-tier script handling:**
   - **ROOT PROJECT scripts** (`npm run dev`, `npm run build`): TRUSTED - user defined in their own `package.json`. Only critical security patterns checked (sensitive file access, `rm -rf`).
   - **DEPENDENCY lifecycle scripts** (`postinstall` in `node_modules/foo`): UNTRUSTED - full security checks applied.

2. **Detection mechanism:**
   ```javascript
   const lifecycleEvent = process.env.npm_lifecycle_event;
   const isRootProject = process.cwd() === process.env.INIT_CWD;
   const isDependencyLifecycle = isLifecycleScript && !isRootProject;
   ```

3. **Security enforcement:**
   - Dependency lifecycle scripts with **critical threats** are **BLOCKED** immediately
   - Dependency lifecycle scripts with non-critical threats generate **WARNINGS**
   - Root project scripts are allowed (user's own code)

4. **NODE_OPTIONS stripping:**
   - Build tools (`node-gyp`, `make`, `python`) have `NODE_OPTIONS` stripped to prevent compilation failures
   - npm script shells (`sh -c`) have `NODE_OPTIONS` stripped to prevent double-loading
   - Security checks still apply after stripping

---

## 2. Bun Compatibility Strategy

Bun is a different runtime that does not support Node's `child_process` internals or `NODE_OPTIONS` in the same way.

### 2.1 Challenges
1.  **No `NODE_OPTIONS`**: Bun ignores this env var.
2.  **Different APIs**: Bun uses `Bun.file`, `Bun.write`, `Bun.spawn` which bypass Node's `fs` and `child_process` modules.
3.  **ESM Native**: Bun treats everything as ESM.

### 2.2 Implementation Plan
To support Bun, we need a dedicated entry point and configuration.

**Step 1: Create `lib/bun-firewall.ts`**
This will be a Bun-specific plugin/preload script.

```typescript
// lib/bun-firewall.ts
import { plugin } from "bun";

// Intercept Bun.file
const originalFile = Bun.file;
Bun.file = (path) => {
  // Check path against config
  checkPath(path, 'READ');
  return originalFile(path);
};

// Intercept Bun.write
const originalWrite = Bun.write;
Bun.write = (destination, input) => {
  checkPath(destination, 'WRITE');
  return originalWrite(destination, input);
};

// Intercept Bun.spawn
const originalSpawn = Bun.spawn;
Bun.spawn = (cmd, options) => {
  checkCommand(cmd);
  return originalSpawn(cmd, options);
};
```

**Step 2: Configuration (`bunfig.toml`)**
Users must configure Bun to preload the firewall.

```toml
# bunfig.toml
preload = ["./node_modules/node-firewall/lib/bun-firewall.ts"]
```

**Step 3: `bun-safe` Wrapper**
Create a `bin/bun-safe` wrapper similar to `npm-safe` that sets up the environment (though `bunfig.toml` is preferred).

---

## 3. "npm-safe install" Optimization

The user requested skipping checks for `npm-safe install`.

**Recommendation:** **REJECT**.
Skipping checks during install is unsafe. `postinstall` scripts are the #1 vector for supply chain attacks.

**Optimization Alternative:**
Instead of disabling checks, we:
1.  **Identify Context**: `firewall-core.js` detects `isPackageManager`.
2.  **Trust Package Manager**: We already skip `EnvProtector` for the main npm process to prevent `cross-env` issues.
3.  **Relax Specific Rules**: We auto-allow writes to `node_modules`, `/.npm/`, `/.cache/`.
4.  **Performance**: Use `module.register` (ESM hooks) which is faster than legacy `require` interception.

**Conclusion**: The current setup (stripping `NODE_OPTIONS` for build tools + allowing `node_modules` writes) is the correct balance of security and functionality. Disabling it further would be negligent.

### 1.3 [OPTIMIZATION] `npm-safe install` Performance
**Issue:** Behavior monitor was too noisy during install, flagging legitimate file writes as suspicious.
**Status:** **FIXED**.
**Implementation:**

1. **Install mode detection via `FIREWALL_INSTALL_MODE` env var:**
   - Set by `npm-safe` wrapper when command is `install`, `i`, `ci`, or `add`
   - Propagates to all child processes

2. **Relaxed thresholds during install:**
   ```javascript
   const installMultiplier = {
     fileReads: 100,    // 100x more reads during install
     fileWrites: 100,   // 100x more writes during install
     networkRequests: 10,
     processSpawns: 20
   };
   ```

3. **Fast path for common install operations:**
   - `node_modules/`, `/.npm/`, `/.cache/` writes: ALLOWED without checks
   - `package-lock.json`, `yarn.lock`, `package.json`: ALLOWED
   - `.npmrc` reads: ALLOWED (needed for auth)

4. **Critical paths still blocked:**
   - `/.ssh/`, `/.aws/`, `/.gnupg/`: ALWAYS BLOCKED
   - `/etc/shadow`, `/etc/passwd`: ALWAYS BLOCKED

5. **Log Deduplication:**
   - Threshold alerts and hard limit errors are logged **once per metric** per process.
   - Prevents log flooding while still alerting on the first violation.
   - Full audit log still records the first violation event.

---

## 4. Architecture Review

The code has moved to a **Fail-Closed** architecture:
- **Config Loading**: Centralized in `config-loader.js`.
- **Pattern Matching**: Critical patterns are hardcoded/derived and enforced *even if config fails*.
- **ESM Hooks**: Independent, strict-default implementation.

**Rating:** 8.5/10 (Significant Improvement)
**Remaining Work:** Full Bun support implementation.
