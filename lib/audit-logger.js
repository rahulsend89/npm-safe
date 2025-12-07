/**
 * Centralized Audit Logger
 * Provides comprehensive forensics and attack detection
 */

const fs = require('fs');
const path = require('path');

class AuditLogger {
  constructor(logPath = 'firewall-audit.jsonl') {
    this.logPath = logPath;
    this.buffer = [];
    this.flushInterval = 1000; // Flush every second
    this.maxBufferSize = 100; // Flush at 100 entries
    this.exitHandlersRegistered = false;
    
    // Create write stream
    try {
      this.stream = fs.createWriteStream(this.logPath, { flags: 'a' });
      this.stream.on('error', (err) => {
        console.error('[Audit] Log stream error:', err.message);
      });
    } catch (error) {
      console.error('[Audit] Failed to create log stream:', error.message);
      this.stream = null;
    }
    
    // Auto-flush buffer periodically
    this.flushTimer = setInterval(() => this.flush(), this.flushInterval);
    if (this.flushTimer.unref) {
      this.flushTimer.unref();
    }
    
    // Register exit handlers once (singleton prevents duplicates)
    if (!this.exitHandlersRegistered) {
      // Increase max listeners to avoid warnings from multiple firewall components
      if (process.getMaxListeners() < 20) {
        process.setMaxListeners(20);
      }
      
      const cleanup = () => this.close();
      
      process.once('exit', cleanup);
      process.once('SIGINT', () => {
        this.close();
        process.exit(130);
      });
      process.once('SIGTERM', () => {
        this.close();
        process.exit(143);
      });
      
      this.exitHandlersRegistered = true;
    }
  }
  
  log(event) {
    const entry = {
      timestamp: Date.now(),
      iso: new Date().toISOString(),
      type: event.type, // FILESYSTEM, NETWORK, COMMAND, etc.
      operation: event.operation,
      target: event.target,
      allowed: event.allowed,
      reason: event.reason,
      severity: event.severity || 'info',
      package: event.package || null,
      process: {
        pid: process.pid,
        ppid: process.ppid || null,
        cwd: process.cwd(),
        argv: process.argv.slice(0, 3) // First 3 args only
      }
    };
    
    // Include stack trace for blocked operations (critical for forensics)
    if (!event.allowed && event.severity !== 'low') {
      try {
        const stack = new Error().stack;
        const lines = stack.split('\n').slice(3, 12); // Skip first 3 frames, get next 9
        entry.stackTrace = lines.map(l => l.trim());
      } catch (e) {
        // Stack trace not critical
      }
    }
    
    this.buffer.push(entry);
    
    // Flush immediately for critical events or if buffer is full
    if (event.severity === 'critical' || !event.allowed || this.buffer.length >= this.maxBufferSize) {
      this.flush();
    }
  }
  
  flush() {
    if (!this.stream || this.buffer.length === 0) return;
    
    try {
      const data = this.buffer.map(e => JSON.stringify(e)).join('\n') + '\n';
      this.stream.write(data);
      this.buffer = [];
    } catch (error) {
      console.error('[Audit] Failed to flush logs:', error.message);
    }
  }
  
  close() {
    clearInterval(this.flushTimer);
    this.flush();
    if (this.stream) {
      this.stream.end();
      this.stream = null;
    }
  }
  
  // Query logs for analysis (reads last N entries)
  queryRecent(count = 100, filter = {}) {
    try {
      const content = fs.readFileSync(this.logPath, 'utf8');
      const lines = content.trim().split('\n');
      const recent = lines.slice(-count);
      
      let entries = recent.map(line => {
        try {
          return JSON.parse(line);
        } catch (e) {
          return null;
        }
      }).filter(e => e !== null);
      
      // Apply filters
      if (filter.type) {
        entries = entries.filter(e => e.type === filter.type);
      }
      if (filter.allowed !== undefined) {
        entries = entries.filter(e => e.allowed === filter.allowed);
      }
      if (filter.severity) {
        entries = entries.filter(e => e.severity === filter.severity);
      }
      
      return entries;
    } catch (error) {
      console.error('[Audit] Failed to query logs:', error.message);
      return [];
    }
  }
  
  // Get statistics
  getStats() {
    try {
      const entries = this.queryRecent(1000);
      const stats = {
        total: entries.length,
        blocked: entries.filter(e => !e.allowed).length,
        allowed: entries.filter(e => e.allowed).length,
        byType: {},
        bySeverity: {},
        topPackages: {}
      };
      
      entries.forEach(e => {
        stats.byType[e.type] = (stats.byType[e.type] || 0) + 1;
        stats.bySeverity[e.severity] = (stats.bySeverity[e.severity] || 0) + 1;
        if (e.package) {
          stats.topPackages[e.package] = (stats.topPackages[e.package] || 0) + 1;
        }
      });
      
      return stats;
    } catch (error) {
      return { error: error.message };
    }
  }
}

// Singleton instance
let instance = null;

function getInstance(logPath) {
  if (!instance) {
    instance = new AuditLogger(logPath);
  }
  return instance;
}

module.exports = { AuditLogger, getInstance };
