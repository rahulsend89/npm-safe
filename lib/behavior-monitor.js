/**
 * Behavior Monitor
 * Tracks package behavior and detects anomalies during npm install and runtime
 */

const fs = require('fs');
const path = require('path');
const { makeImmutableProperties } = require('./immutable-property');
const { isBuildOrCacheDirectory, isProjectSourceFile } = require('./build-directory-utils');

// Store original fs methods for security
const originalFs = {
  appendFileSync: fs.appendFileSync,
  writeFileSync: fs.writeFileSync,
  existsSync: fs.existsSync,
  readFileSync: fs.readFileSync
};

// SECURITY: Use Symbol-based global counters to prevent tampering
const METRICS_SYMBOL = Symbol.for('node.firewall.behavior.metrics.v1');
const CHILD_METRICS_SYMBOL = Symbol.for('node.firewall.behavior.child_metrics.v1');

// SECURITY FIX #4: Initialize global metrics if not already set
// Make the Symbol property non-configurable to prevent reassignment
// but keep the object mutable so counters can increment
if (!global[METRICS_SYMBOL]) {
  const metricsObject = {
    fileReads: 0,
    fileWrites: 0,
    networkRequests: 0,
    processSpawns: 0
  };
  
  Object.defineProperty(global, METRICS_SYMBOL, {
    value: metricsObject,
    writable: false,  // Property itself can't be reassigned
    enumerable: false,  // Hidden from Object.keys()
    configurable: false  // Can't be deleted or redefined
  });
  
  // Seal the object to prevent property additions/deletions
  // but allow counter increments
  Object.seal(metricsObject);
}

if (!global[CHILD_METRICS_SYMBOL]) {
  const childArray = [];
  
  Object.defineProperty(global, CHILD_METRICS_SYMBOL, {
    value: childArray,
    writable: false,
    enumerable: false,
    configurable: false
  });
  
  // Don't seal - array needs to be able to grow as processes are added
  // The property itself is protected, which is sufficient
}

class BehaviorMonitor {
  // Safe JSON stringify helper to prevent corruption
  static safeStringify(obj, maxLength = null) {
    try {
      const str = JSON.stringify(obj);
      return maxLength ? str.substring(0, maxLength) : str;
    } catch (e) {
      return '[Non-serializable]';
    }
  }
  
  constructor(config, silent = false, fsOverride = null) {
    // SECURITY: Make critical properties immutable
    const frozenConfig = Object.freeze(config || {});
    makeImmutableProperties(this, {
      config: frozenConfig,
      enabled: frozenConfig.behavioral?.monitorLifecycleScripts !== false,
      silent: silent
    });
    
    // Allow fs override for testing, but default to secure originalFs
    this.fs = fsOverride || originalFs;
    
    // SECURITY: Use global Symbol-based metrics instead of instance metrics
    // This prevents tampering via require.cache manipulation
    this._globalMetrics = global[METRICS_SYMBOL];
    
    // Local suspicious operations tracking
    this.suspiciousOperations = [];
    
    // Create a getter for metrics that includes suspiciousOperations
    Object.defineProperty(this, 'metrics', {
      get() {
        return {
          ...this._globalMetrics,
          suspiciousOperations: this.suspiciousOperations
        };
      },
      enumerable: true,
      configurable: false
    });
    
    // Register this process in child tracking
    this.processId = process.pid;
    if (!global[CHILD_METRICS_SYMBOL].includes(this.processId)) {
      global[CHILD_METRICS_SYMBOL].push(this.processId);
    }
    
    this.currentPackage = this.detectCurrentPackage();
    this.behaviorLog = [];
    
    if (this.enabled && !this.silent) {
      console.log(`[Behavior Monitor] Tracking: ${this.currentPackage || 'unknown package'}`);
    }
  }
  
  detectCurrentPackage() {
    try {
      // Check if we're in npm lifecycle script (most explicit)
      if (process.env.npm_package_name) {
        return process.env.npm_package_name;
      }
      
      // Try to find package.json in call stack (heuristic)
      const stack = new Error().stack;
      const match = stack.match(/node_modules[/\\]((?:@[^/\\]+[/\\])?[^/\\]+)/);
      if (match) return match[1];
      
      // Check current directory (fallback)
      const pkgPath = path.join(process.cwd(), 'package.json');
      if (this.fs.existsSync(pkgPath)) {
        const pkg = JSON.parse(this.fs.readFileSync(pkgPath, 'utf8'));
        return pkg.name;
      }
    } catch (e) {
      // Ignore
    }
    return null;
  }
  
  trackFileRead(filePath) {
    // Skip counting project source files (.ts, .js, .json) in current directory
    // These are legitimate application files, not suspicious behavior
    if (isProjectSourceFile(filePath, process.cwd())) {
      return { allowed: true, reason: 'project_source_file' };
    }
    
    // SECURITY: Increment global counter atomically
    global[METRICS_SYMBOL].fileReads++;
    this.checkThreshold('fileReads', filePath);
    return this.checkHardLimit('fileReads', 'fileRead', filePath);
  }
  
  trackFileWrite(filePath) {
    // Skip counting writes to build/cache directories
    // These are legitimate TypeScript compilation outputs
    if (isBuildOrCacheDirectory(filePath)) {
      return { allowed: true, reason: 'build_cache_write' };
    }
    
    // SECURITY: Increment global counter atomically
    global[METRICS_SYMBOL].fileWrites++;
    this.checkThreshold('fileWrites', filePath);
    
    // Check for suspicious writes
    if (this.isSuspiciousWrite(filePath)) {
      this.recordSuspicious('SUSPICIOUS_FILE_WRITE', filePath);
    }
    
    return this.checkHardLimit('fileWrites', 'fileWrite', filePath);
  }
  
  trackNetworkRequest(url, method = 'GET') {
    // SECURITY: Increment global counter atomically
    global[METRICS_SYMBOL].networkRequests++;
    this.checkThreshold('networkRequests', url);
    
    // Check for suspicious destinations
    if (this.isSuspiciousUrl(url)) {
      this.recordSuspicious('SUSPICIOUS_NETWORK_REQUEST', { url, method });
    }
    
    return this.checkHardLimit('networkRequests', 'networkRequest', url);
  }
  
  trackProcessSpawn(command, args = []) {
    // SECURITY: Increment global counter atomically
    global[METRICS_SYMBOL].processSpawns++;
    this.checkThreshold('processSpawns', command);
    
    const fullCommand = args.length ? `${command} ${args.join(' ')}` : command;
    
    // Check for suspicious commands
    if (this.isSuspiciousCommand(fullCommand)) {
      this.recordSuspicious('SUSPICIOUS_COMMAND', fullCommand);
    }
    
    return this.checkHardLimit('processSpawns', 'processSpawn', fullCommand);
  }
  
  checkThreshold(metric, context) {
    const thresholds = this.config.behavioral?.alertThresholds || {};
    const threshold = thresholds[metric];
    
    if (threshold && this.metrics[metric] >= threshold) {
      const shouldAlert = this.config.reporting?.alertOnSuspicious !== false;
      
      if (!this.silent && shouldAlert) {
        console.warn(`\n[BEHAVIOR ALERT] Unusual activity detected`);
        console.warn(`   Package: ${this.currentPackage || 'unknown'}`);
        console.warn(`   Metric: ${metric} = ${this.metrics[metric]} (threshold: ${threshold})`);
        console.warn(`   Context: ${BehaviorMonitor.safeStringify(context, 100)}`);
      }
      
      this.recordSuspicious('THRESHOLD_EXCEEDED', { metric, value: this.metrics[metric], context });
    }
  }
  
  checkHardLimit(metric, operationType, context) {
    const maxLimits = {
      networkRequests: this.config.behavioral?.maxNetworkRequests,
      fileWrites: this.config.behavioral?.maxFileWrites,
      processSpawns: this.config.behavioral?.maxProcessSpawns
    };
    
    const limit = maxLimits[metric];
    
    if (limit && this.metrics[metric] > limit) {
      const shouldAlert = this.config.reporting?.alertOnSuspicious !== false;
      
      if (!this.silent && shouldAlert) {
        console.error(`\n[HARD LIMIT EXCEEDED] ${metric} limit reached`);
        console.error(`   Package: ${this.currentPackage || 'unknown'}`);
        console.error(`   Metric: ${metric} = ${this.metrics[metric]} (limit: ${limit})`);
        console.error(`   Context: ${BehaviorMonitor.safeStringify(context, 100)}`);
      }
      
      this.recordSuspicious('HARD_LIMIT_EXCEEDED', { 
        metric, 
        value: this.metrics[metric], 
        limit,
        context 
      });
      
      return { 
        allowed: false, 
        reason: 'hard_limit_exceeded',
        metric,
        limit,
        current: this.metrics[metric],
        severity: 'critical'
      };
    }
    
    return { allowed: true, reason: 'within_limits' };
  }
  
  isSuspiciousWrite(filePath) {
    const suspicious = [
      /\.ssh[/\\]/,
      /\.aws[/\\]/,
      /\.github[/\\]workflows[/\\]/,
      /\.(sh|bash|zsh|command)$/,
      /LaunchAgents[/\\]/,
      /LaunchDaemons[/\\]/,
      /\/etc\//,
      /\/usr\/(local\/)?bin\//  // Matches both /usr/bin/ and /usr/local/bin/
    ];
    
    return suspicious.some(pattern => pattern.test(filePath));
  }
  
  isSuspiciousUrl(url) {
    const suspicious = [
      /pastebin\.com/,
      /paste\.ee/,
      /transfer\.sh/,
      /temp\.sh/,
      /ngrok\.io/,
      /\.ru\//,
      /\.cn\//,
      /discord(app)?\.com\/api\/webhooks/,  // Discord webhooks for exfiltration
      /api\.telegram\.org\/bot/,  // Telegram bot API for exfiltration
      /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/  // Raw IP addresses
    ];
    
    return suspicious.some(pattern => pattern.test(url));
  }
  
  isSuspiciousCommand(command) {
    const suspicious = [
      /\|\s*(sh|bash|zsh)/,  // Pipe to shell execution
      /curl.*-X POST/,
      /wget.*-O/,
      /bash\s+-c.*(curl|wget|nc)/,  // bash -c with download/network
      /eval\s+/,  // eval command
      /rm\s+-rf\s+[~/]/,
      /cat\s+.*\.(ssh|aws|gnupg)/,
      /nc\s+/,
      /bash\s+-c.*eval/,
      /python.*-c.*exec/,
      /chmod\s+\+x/
    ];
    
    return suspicious.some(pattern => pattern.test(command));
  }
  
  recordSuspicious(type, details) {
    const entry = {
      timestamp: new Date().toISOString(),
      package: this.currentPackage,
      type,
      details,
      callStack: new Error().stack.split('\n').slice(2, 7)  // Get relevant stack frames
    };
    
    this.suspiciousOperations.push(entry);
    this.behaviorLog.push(entry);
    
    // Log to file
    this.logBehavior(entry);
    
    const shouldAlert = this.config.reporting?.alertOnSuspicious !== false;
    if (!this.silent && shouldAlert && type.startsWith('SUSPICIOUS_')) {
      console.warn(`[SUSPICIOUS] ${type}: ${BehaviorMonitor.safeStringify(details, 80)}`);
    }
  }
  
  logBehavior(entry) {
    try {
      const logFile = this.config.reporting?.logFile || 'fs-firewall.log';
      const detailsStr = BehaviorMonitor.safeStringify(entry.details);
      const logLine = `[${entry.timestamp}] BEHAVIOR | ${entry.type} | ${detailsStr}\n`;
      this.fs.appendFileSync(logFile, logLine);
    } catch (e) {
      // Silent fail
    }
  }
  
  generateReport() {
    const report = {
      timestamp: new Date().toISOString(),
      package: this.currentPackage,
      metrics: this.metrics,
      suspicious: this.suspiciousOperations,
      assessment: this.assessBehavior()
    };
    
    // Save report to file
    if (this.config.reporting?.generateReport) {
      try {
        const reportFile = this.config.reporting.reportFile || 'firewall-report.json';
        let existingReports = [];
        
        if (this.fs.existsSync(reportFile)) {
          try {
            const content = this.fs.readFileSync(reportFile, 'utf8');
            existingReports = JSON.parse(content);
            
            // Validate it's an array
            if (!Array.isArray(existingReports)) {
              existingReports = [];
            }
          } catch (parseError) {
            // Corrupted file - start fresh with a backup
            console.warn('[Behavior Monitor] Report file corrupted, creating backup and starting fresh');
            try {
              this.fs.writeFileSync(reportFile + '.corrupted', this.fs.readFileSync(reportFile));
            } catch (backupError) {
              // Ignore backup errors
            }
            existingReports = [];
          }
        }
        
        existingReports.push(report);
        
        // Keep only last 50 reports
        if (existingReports.length > 50) {
          existingReports = existingReports.slice(-50);
        }
        
        // SECURITY: Safely stringify with proper error handling
        try {
          const jsonOutput = JSON.stringify(existingReports, null, 2);
          
          // Validate the output is valid JSON by parsing it back
          JSON.parse(jsonOutput);
          
          // Write atomically
          this.fs.writeFileSync(reportFile, jsonOutput);
        } catch (stringifyError) {
          console.error('[Behavior Monitor] JSON serialization failed:', stringifyError.message);
          console.error('[Behavior Monitor] Report data may contain circular references or non-serializable values');
          
          // Try writing a minimal safe report as fallback
          try {
            const safeReport = {
              timestamp: new Date().toISOString(),
              package: this.currentPackage,
              error: 'Report generation failed - data serialization error'
            };
            this.fs.writeFileSync(reportFile, JSON.stringify([safeReport], null, 2));
          } catch (fallbackError) {
            // Complete failure - log only
          }
        }
      } catch (e) {
        console.error('[Behavior Monitor] Failed to save report:', e.message);
      }
    }
    
    return report;
  }
  
  assessBehavior() {
    const suspiciousCount = this.suspiciousOperations.length;
    
    // Clean: no suspicious operations and low activity
    if (suspiciousCount === 0 && this._globalMetrics.networkRequests < 5 && this._globalMetrics.processSpawns < 3) {
      return { status: 'clean', risk: 'clean', message: 'No suspicious behavior detected' };
    }
    
    // High risk: many suspicious operations
    if (suspiciousCount >= 5) {
      return {
        status: 'suspicious',
        risk: 'high',
        message: `${suspiciousCount} suspicious operation(s) detected - HIGH RISK`,
        issues: this.suspiciousOperations.map(op => op.type)
      };
    }
    
    // Medium risk: some suspicious operations
    if (suspiciousCount > 0) {
      return {
        status: 'suspicious',
        risk: 'medium',
        message: `${suspiciousCount} suspicious operation(s) detected`,
        issues: this.suspiciousOperations.map(op => op.type)
      };
    }
    
    // Medium risk: unusual activity levels
    if (this._globalMetrics.networkRequests > 10 || this._globalMetrics.processSpawns > 5) {
      return {
        status: 'unusual',
        risk: 'medium',
        message: 'Unusual activity levels detected'
      };
    }
    
    return { status: 'normal', risk: 'low', message: 'Activity within normal parameters' };
  }
  
  printSummary() {
    const assessment = this.assessBehavior();
    
    // Respect silent mode
    if (!this.silent) {
      console.log('\n');
      console.log('  Package Behavior Summary                           ');
      console.log('');
      console.log(`Package:          ${this.currentPackage || 'unknown'}`);
      console.log(`File Reads:       ${this._globalMetrics.fileReads}`);
      console.log(`File Writes:      ${this._globalMetrics.fileWrites}`);
      console.log(`Network Requests: ${this._globalMetrics.networkRequests}`);
      console.log(`Process Spawns:   ${this._globalMetrics.processSpawns}`);
      console.log(`Suspicious Ops:   ${this.suspiciousOperations.length}`);
      console.log(`\nAssessment:       ${assessment.status.toUpperCase()}`);
      console.log(`Risk Level:       ${assessment.risk.toUpperCase()}`);
      console.log(`Message:          ${assessment.message}`);
      
      if (this.suspiciousOperations.length > 0) {
        console.log('\nSuspicious Operations:');
        this.suspiciousOperations.forEach((op, idx) => {
          const details = op.details ? BehaviorMonitor.safeStringify(op.details, 60) : '';
          console.log(`   ${idx + 1}. ${op.type}${details ? ': ' + details : ''}`);
        });
      }
      
      console.log('\n');
    }
    
    return assessment;
  }
  
  getMetrics() {
    return {
      ...this._globalMetrics,
      suspiciousOperations: this.suspiciousOperations,
      package: this.currentPackage
    };
  }
}

module.exports = { BehaviorMonitor };
