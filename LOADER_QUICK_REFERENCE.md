# Loader API Quick Reference

## Current vs Loader Approach

### Current Approach (`-r` flag)
```bash
node -r ./index.js script.js
```
- ✅ Simple
- ✅ Works with CommonJS
- ❌ Only loads after some Node.js internals
- ❌ Cannot intercept ESM modules

### Loader Approach (`--loader` / `--import`)
```bash
# Node.js 18.x
node --loader ./lib/esm-loader.mjs script.mjs

# Node.js 20.6+
node --import ./lib/esm-loader.mjs script.mjs
```
- ✅ Earlier interception (before modules load)
- ✅ Works with ES modules
- ✅ Can transform module source
- ❌ More complex
- ❌ Primarily for ESM (CommonJS needs workarounds)

## When to Use Each

| Scenario | Recommended Approach |
|----------|---------------------|
| CommonJS project | `-r` flag (current) |
| ESM project | `--loader` / `--import` |
| Mixed CJS/ESM | `--loader` with CommonJS bridge |
| Need earliest interception | `--loader` |
| Simple setup | `-r` flag |

## Implementation Files

1. **`lib/esm-loader.mjs`** - ESM loader implementation
2. **`LOADER_API_USAGE.md`** - Detailed documentation
3. **`example-loader-usage.mjs`** - Usage example

## Key Benefits

1. **Earlier Interception**: Firewall initializes before any user modules
2. **ESM Support**: Can protect ES module imports
3. **Race Condition Fix**: Eliminates initialization race conditions
4. **Module Transformation**: Can modify source before execution (future)

## Code Locations

- **Loader Implementation**: `lib/esm-loader.mjs`
- **Current Initialization**: `index.js` (uses `-r` flag)
- **Firewall Core**: `lib/firewall-core.js`
- **Interceptors**: `lib/fs-interceptor-v2.js`, `lib/child-process-interceptor.js`

## Testing

```bash
# Test with ESM loader
node --import ./lib/esm-loader.mjs example-loader-usage.mjs

# Test with current -r approach (CommonJS)
node -r ./index.js test-script.js
```

## Node.js Version Compatibility

| Node.js Version | Loader Flag | Status |
|----------------|-------------|--------|
| < 18.0 | `--loader` | Not supported |
| 18.0 - 20.5 | `--loader` | ✅ Supported |
| 20.6+ | `--import` | ✅ Supported (recommended) |
| 21+ | `--import` | ✅ Supported (only option) |

## Migration Checklist

- [ ] Create ESM loader (`lib/esm-loader.mjs`) ✅
- [ ] Test with ESM projects
- [ ] Update documentation
- [ ] Update bin scripts to support loader
- [ ] Add examples
- [ ] Test with different Node.js versions

## Next Steps

1. Test the loader with real ESM projects
2. Update `bin/node-firewall` to auto-detect and use loader for `.mjs` files
3. Add loader support to `bin/npm-safe`
4. Create hybrid loader for mixed CJS/ESM projects
