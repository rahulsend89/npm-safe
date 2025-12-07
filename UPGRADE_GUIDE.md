# Upgrade Guide

## Version 2.0.1 - Essential Fix (December 5, 2025)

### 🚨 Why You Should Upgrade

Version 2.0.1 fixes a critical issue where the behavior monitor would generate **thousands of duplicate log entries** during `npm install`, making it difficult to identify genuine security threats.

### What's Fixed

1. **Excessive Logging**: Previous versions logged every single file write violation, even after the limit was exceeded. This could result in 5000+ duplicate log entries.

2. **Smart Filtering**: Safe directory operations (node_modules, .cache, .npm) no longer count against behavioral limits, so your `maxFileWrites: 50` now correctly applies to *unusual* writes only.

3. **Install Mode Detection**: The `FIREWALL_INSTALL_MODE` environment variable now properly propagates to all child processes, ensuring install optimizations work correctly.

### Upgrade Instructions

#### Global Installation
```bash
npm install -g @rahulmalik/npm-safe@latest
```

#### Project-Level Installation
```bash
npm install --save-dev @rahulmalik/npm-safe@latest
```

### Verification

After upgrading, verify the version:

```bash
npm-safe --version
# Should show: 2.0.1
```

Or check during execution - the firewall banner will show:
```
╔╗
  Node.js Security Firewall v2.0.1
╚╝
```

### Breaking Changes

**None.** Version 2.0.1 is fully backward compatible with 2.0.0. No configuration changes are required.

### What Happens If You Don't Upgrade?

If you're using v2.0.0:
- `npm install` will generate excessive logs (thousands of lines)
- Genuine security threats may be buried in noise
- Behavior monitoring will be less effective

The firewall will still **protect** you, but the user experience will be degraded.

### Automatic Notification

If you're running an older version, the firewall will automatically display an upgrade notification:

```
╔════════════════════════════════════════════════════╗
║  ⚠️  UPGRADE AVAILABLE - ESSENTIAL FIX             ║
╚════════════════════════════════════════════════════╝
Current version: 2.0.0
Latest version:  2.0.1

🚨 Version 2.0.1 includes critical fixes:
   • Fixed excessive logging during npm install
   • Improved behavior monitoring deduplication
   • Better install mode detection

Upgrade now:
   npm install -g @rahulmalik/npm-safe@latest
```

### Support

If you encounter any issues during the upgrade:

1. Check the [CHANGELOG.md](./CHANGELOG.md) for detailed changes
2. Review the [SECURITY_AUDIT.md](./SECURITY_AUDIT.md) for technical details
3. Open an issue on [GitHub](https://github.com/rahulsend89/npm-safe/issues)

### Migration Checklist

- [ ] Upgrade to 2.0.1
- [ ] Verify version with `npm-safe --version`
- [ ] Run `npm-safe install` to test (should be quiet)
- [ ] Run `npm-safe run dev` to test (should work smoothly)
- [ ] Check that `.firewall-config.json` is still respected
- [ ] Verify critical security checks still work (try accessing SSH keys)

### Rollback (If Needed)

If you need to rollback to 2.0.0 for any reason:

```bash
npm install -g @rahulmalik/npm-safe@2.0.0
```

However, we strongly recommend staying on 2.0.1 for the improved user experience.
