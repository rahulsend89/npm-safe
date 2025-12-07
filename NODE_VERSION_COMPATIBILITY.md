# Node.js Version Compatibility

This document outlines the compatibility and feature support across different Node.js versions.

## Compatibility Matrix

| Node.js Version | Loader API | ESM Protection | CJS Protection | Status |
|----------------|------------|----------------|----------------|---------|
| 20.6.0+        | `--import` (stable) | ✅ Full | ✅ Full | **Recommended** |
| 18.19.0 - 20.5.x | `--loader` (experimental) | ✅ Full | ✅ Full | Supported |
| 16.12.0 - 18.18.x | `--experimental-loader` | ✅ Full | ✅ Full | Supported |
| 16.0.0 - 16.11.x | None | ⚠️ Limited | ✅ Full | Limited Support |
| < 16.0.0       | None | ❌ None | ✅ Full | Not Supported |

## Feature Breakdown by Version

### Node.js 20.6.0+ (Recommended)

**Loader API:** `--import` with `module.register()`

**Features:**
- ✅ Full ESM module interception
- ✅ Full CJS module interception
- ✅ Network monitoring
- ✅ File system protection
- ✅ Child process interception
- ✅ Behavior monitoring
- ✅ Stable, non-experimental API

**Example:**
```bash
node --import ./lib/init.mjs your-app.js
```

**Advantages:**
- Stable API (no experimental warnings)
- Better performance
- Official support from Node.js team
- `module.register()` allows dynamic hook registration

---

### Node.js 18.19.0 - 20.5.x

**Loader API:** `--loader` (experimental)

**Features:**
- ✅ Full ESM module interception
- ✅ Full CJS module interception
- ✅ Network monitoring
- ✅ File system protection
- ✅ Child process interception
- ✅ Behavior monitoring
- ⚠️ Experimental API (warnings in console)

**Example:**
```bash
node --loader ./lib/legacy-loader.mjs --require ./lib/fs-interceptor-v2.js your-app.js
```

**Limitations:**
- Experimental warnings in console
- API may change in future versions
- Slightly different hook signature

---

### Node.js 16.12.0 - 18.18.x

**Loader API:** `--experimental-loader`

**Features:**
- ✅ Full ESM module interception
- ✅ Full CJS module interception
- ✅ Network monitoring
- ✅ File system protection
- ✅ Child process interception
- ✅ Behavior monitoring
- ⚠️ Experimental API (warnings in console)

**Example:**
```bash
node --experimental-loader ./lib/legacy-loader.mjs --require ./lib/fs-interceptor-v2.js your-app.js
```

**Limitations:**
- Experimental warnings in console
- Older hook format (includes `getFormat`)
- API may change in future versions

---

### Node.js 16.0.0 - 16.11.x (Limited Support)

**Loader API:** None available

**Features:**
- ❌ No ESM module interception
- ✅ Full CJS module interception
- ✅ Network monitoring (for CJS)
- ✅ File system protection (for CJS)
- ✅ Child process interception (for CJS)
- ⚠️ Behavior monitoring (CJS only)

**Example:**
```bash
node --require ./lib/fs-interceptor-v2.js --require ./lib/child-process-interceptor.js your-app.js
```

**Limitations:**
- **No ESM protection** - ESM modules bypass firewall
- Only works for CommonJS (require-based) code
- Not recommended for production

**Warning:** When using Node.js < 16.12, you'll see:
```
⚠️  Warning: Node.js version < 16.12 detected
   ESM module protection is limited. Consider upgrading to Node.js 16.12+
```

---

## Automatic Detection

The `npm-safe` wrapper automatically detects your Node.js version and uses the appropriate loader:

```javascript
// From bin/npm-safe
const [major, minor] = process.versions.node.split('.').map(Number);
const supportsImport = major > 20 || (major === 20 && minor >= 6);
const supportsLoader = major > 16 || (major === 16 && minor >= 12);

if (supportsImport) {
  // Use --import (Node.js 20.6+)
  process.env.NODE_OPTIONS += ` --import ${INIT_ESM}`;
} else if (supportsLoader) {
  // Use --loader or --experimental-loader (Node.js 16.12 - 20.5)
  const loaderFlag = (major >= 19 || (major === 18 && minor >= 19)) 
    ? '--loader' 
    : '--experimental-loader';
  process.env.NODE_OPTIONS += ` ${loaderFlag} ${LEGACY_LOADER} -r ${FS_INTERCEPTOR} -r ${CHILD_PROCESS_INTERCEPTOR}`;
} else {
  // Fallback to require hooks only (Node.js < 16.12)
  process.env.NODE_OPTIONS += ` -r ${FS_INTERCEPTOR} -r ${CHILD_PROCESS_INTERCEPTOR}`;
}
```

## Testing Your Version

Check which loader API your Node.js version uses:

```bash
npm-safe --version
```

The banner will show:
```
╔════════════════════════════════════════════════════╗
║  🛡️  npm-safe: Protected npm execution             ║
╚════════════════════════════════════════════════════╝
```

And the firewall will log:
- Node.js 20.6+: `[Firewall] ESM hooks registered via module.register()`
- Node.js 16.12-20.5: `[Firewall Legacy Loader] ESM hooks registered (--loader API)`
- Node.js < 16.12: Warning about limited ESM protection

## Migration Guide

### Upgrading from Node.js 16.x to 18.x+

No changes required! The firewall automatically detects and adapts.

### Upgrading from Node.js 18.x to 20.6+

No changes required! The firewall automatically switches from `--loader` to `--import`.

### Still on Node.js < 16.12?

**Strongly recommended:** Upgrade to Node.js 18.x LTS or 20.x LTS for:
- Full ESM protection
- Better performance
- Active security updates

**If you must stay on old Node.js:**
- Avoid ESM modules in your project
- Use CommonJS exclusively
- Be aware that ESM dependencies may bypass firewall

## Technical Details

### Why Different APIs?

**`--import` (Node.js 20.6+):**
- Stable, officially supported API
- Uses `module.register()` for dynamic registration
- No experimental warnings
- Better performance

**`--loader` / `--experimental-loader` (Node.js 16.12 - 20.5):**
- Older experimental API
- Requires separate loader file
- Different hook signatures
- Produces experimental warnings

**`-r` / `--require` (All versions):**
- Works for CommonJS only
- Cannot intercept ESM imports
- Limited to synchronous hooks

### Hook Differences

**Modern API (--import):**
```javascript
module.register('./hooks.mjs', {
  parentURL: import.meta.url,
  data: { config }
});
```

**Legacy API (--loader):**
```javascript
export async function resolve(specifier, context, nextResolve) {
  // Custom resolution logic
  return nextResolve(specifier, context);
}

export async function load(url, context, nextLoad) {
  // Custom loading logic
  return nextLoad(url, context);
}
```

## Troubleshooting

### "ExperimentalWarning: --experimental-loader"

**Cause:** You're using Node.js 16.12 - 18.18.x  
**Solution:** Upgrade to Node.js 20.6+ to eliminate warnings, or suppress with:
```bash
NODE_NO_WARNINGS=1 npm-safe install
```

### "ESM module protection is limited"

**Cause:** You're using Node.js < 16.12  
**Solution:** Upgrade to Node.js 16.12+ for ESM support

### Loader not found

**Cause:** Corrupt installation  
**Solution:** Reinstall:
```bash
npm install -g @rahulmalik/npm-safe@latest
```

## Recommendations

1. **Production:** Use Node.js 20.x LTS (latest)
2. **Development:** Use Node.js 20.x or 18.x LTS
3. **Legacy systems:** Minimum Node.js 16.12.0
4. **Avoid:** Node.js < 16.12 (limited protection)

## Support Policy

- **Node.js 20.6+:** Full support, recommended
- **Node.js 18.19+:** Full support with experimental warnings
- **Node.js 16.12+:** Full support with experimental warnings
- **Node.js 16.0-16.11:** Limited support (CJS only)
- **Node.js < 16.0:** Not supported

---

**Last Updated:** December 5, 2025  
**Version:** 2.0.1
