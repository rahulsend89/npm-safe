# Release Notes - Version 2.0.1

**Release Date:** December 5, 2025  
**Type:** Essential Bug Fix  
**Upgrade Priority:** HIGH

## Overview

Version 2.0.1 is an essential bug fix release that addresses critical logging issues in version 2.0.0. All users are strongly encouraged to upgrade immediately.

## Critical Fixes

### 1. Excessive Logging During npm install
**Problem:** Version 2.0.0 would generate thousands of duplicate log entries during `npm install`, making it nearly impossible to identify genuine security threats.

**Example of the issue:**
```
436. HARD_LIMIT_EXCEEDED: {"metric":"fileWrites","value":5435,"limit":5000}
437. HARD_LIMIT_EXCEEDED: {"metric":"fileWrites","value":5436,"limit":5000}
438. HARD_LIMIT_EXCEEDED: {"metric":"fileWrites","value":5437,"limit":5000}
... (5000+ more lines)
```

**Solution:** Implemented log deduplication - alerts are now shown once per metric, with subsequent violations blocked silently.

### 2. Smart Directory Filtering
**Problem:** The behavior monitor counted all file writes, including legitimate package manager operations in `node_modules`, `.cache`, etc.

**Solution:** Safe directory operations are now filtered out. Your `maxFileWrites: 50` limit now correctly applies to *unusual* writes only (e.g., modifying source code, system files).

### 3. Install Mode Detection
**Problem:** Install mode optimizations weren't propagating correctly to child processes.

**Solution:** Added `FIREWALL_INSTALL_MODE` environment variable that properly propagates through the entire process tree.

## Technical Details

### Files Modified
- `lib/behavior-monitor.js`: Added `isSafeDirectory()`, log deduplication with `Set`
- `lib/firewall-core.js`: Added version display and upgrade notification
- `bin/npm-safe`: Added `FIREWALL_INSTALL_MODE` environment variable
- `lib/fs-interceptor-v2.js`: Enhanced install mode detection

### New Features
- Automatic upgrade notification for users on older versions
- Version display in firewall banner
- Comprehensive changelog and upgrade guide

### Behavioral Changes
- **Before:** Every file write violation was logged and recorded
- **After:** First violation is logged, subsequent violations are blocked silently
- **Impact:** Cleaner logs, easier to spot genuine threats

### Performance Impact
- Slightly improved performance during `npm install` due to reduced logging overhead
- No measurable impact on runtime performance

## Upgrade Instructions

### Global Installation
```bash
npm install -g @rahulmalik/npm-safe@latest
```

### Project Installation
```bash
npm install --save-dev @rahulmalik/npm-safe@latest
```

### Verification
```bash
npm-safe --version
# Should output: 2.0.1
```

## Backward Compatibility

 **Fully backward compatible** with version 2.0.0  
 No configuration changes required  
 No breaking changes  
 Existing `.firewall-config.json` files work without modification

## Testing

Tested scenarios:
-  `npm-safe install` - Clean output, no log spam
-  `npm-safe run dev` - Smooth operation
-  Critical security checks - Still blocking sensitive file access
-  Behavior monitoring - Correctly tracking unusual operations
-  Install mode detection - Working across all child processes

## Known Issues

None at this time.

## Upgrade Notification

Users on version 2.0.0 will see this notification:

```
╔════════════════════════════════════════════════════╗
║     UPGRADE AVAILABLE - ESSENTIAL FIX             ║
╚════════════════════════════════════════════════════╝
Current version: 2.0.0
Latest version:  2.0.1

 Version 2.0.1 includes critical fixes:
   • Fixed excessive logging during npm install
   • Improved behavior monitoring deduplication
   • Better install mode detection

Upgrade now:
   npm install -g @rahulmalik/npm-safe@latest
```

## Support

- **Documentation:** See [UPGRADE_GUIDE.md](./UPGRADE_GUIDE.md)
- **Changelog:** See [CHANGELOG.md](./CHANGELOG.md)
- **Security:** See [SECURITY_AUDIT.md](./SECURITY_AUDIT.md)
- **Issues:** https://github.com/rahulsend89/npm-safe/issues

## Credits

Special thanks to the community for reporting the excessive logging issue and helping test the fix.

## Next Steps

After upgrading:
1. Run `npm-safe install` to verify clean operation
2. Run your development server with `npm-safe run dev`
3. Verify that critical security checks still work
4. Review the CHANGELOG.md for detailed changes

---

**Maintainer:** Rahul Malik (rahul.send89@gmail.com)  
**License:** MIT  
**Repository:** https://github.com/rahulsend89/npm-safe
