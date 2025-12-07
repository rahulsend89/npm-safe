# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.1] - 2025-12-05 - ESSENTIAL FIX

###  Critical Fixes
- **[CRITICAL]** Fixed excessive logging during `npm install` that could generate thousands of duplicate log entries
- **[HIGH]** Behavior monitor now properly deduplicates threshold and limit violations
- **[HIGH]** Install mode detection now works correctly across all child processes via `FIREWALL_INSTALL_MODE` env var

###  Improvements
- Smart filtering: Safe directory operations (node_modules, .cache, .npm) no longer count against behavioral limits
- Threshold alerts now show once per metric instead of flooding logs
- Hard limit violations are recorded once and enforced silently on subsequent violations
- Install mode automatically applies 100x multipliers to behavioral limits during `npm install`

###  Behavioral Monitoring
- `maxFileWrites: 50` now correctly applies to *unusual* writes only (not node_modules)
- `alertThresholds` are respected but intelligently filtered
- Critical security checks (SSH keys, AWS credentials) remain fully active during all operations

###  Technical Details
- Added `isSafeDirectory()` method to filter out noise from legitimate package manager operations
- Implemented per-metric alert tracking with `Set` to prevent duplicate logs
- Moved `recordSuspicious()` inside deduplication block in `checkHardLimit()`

###  Backward Compatibility
- **[NEW]** Added support for `--loader` API (Node.js 16.12 - 20.5.x)
- **[NEW]** Added support for `--experimental-loader` API (Node.js 16.12 - 18.18.x)
- **[NEW]** Automatic version detection and appropriate loader selection
- **[NEW]** Legacy loader implementation (`lib/legacy-loader.mjs`) for older Node.js versions
- Now supports Node.js 16.12.0+ with full ESM protection (previously only 20.6.0+)
- See [NODE_VERSION_COMPATIBILITY.md](./NODE_VERSION_COMPATIBILITY.md) for details

###  Upgrade Notice
**If you're using v2.0.0, please upgrade immediately.** The previous version could generate excessive logs during package installation, making it difficult to identify genuine security threats.

**Upgrade command:**
```bash
npm install -g @rahulmalik/npm-safe@latest
```

###  Migration Notes
No configuration changes required. The fix is fully backward compatible with existing `.firewall-config.json` files.

---

## [2.0.0] - 2025-12-04

###  Major Release
- Complete rewrite with ESM hooks support (Node.js 20.6+)
- Fail-closed architecture for maximum security
- Centralized configuration loading
- File descriptor bypass protection
- Two-tier lifecycle script handling (root vs dependency)
- GitHub API attack protection
- Data exfiltration detection

###  Security Features
- Blocks file descriptor-based bypasses (`fs.open`, `fs.read`)
- Protects against supply chain attacks during `npm install`
- Monitors and blocks suspicious network requests
- Detects credential exfiltration attempts
- Environment variable protection

###  New Components
- `npm-safe` wrapper for protected npm execution
- `firewall-config` CLI tool for configuration management
- Comprehensive audit logging
- Behavior monitoring and reporting

---

## [1.x.x] - Legacy Versions
See git history for older versions.
