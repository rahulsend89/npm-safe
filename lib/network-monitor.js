/**
 * Network Traffic Monitor
 * Intercepts http/https requests to detect credential exfiltration and suspicious traffic
 */

const Module = require('module');
const url = require('url');
const path = require('path');
const fs = require('fs');
const { GitHubApiMonitor } = require('./github-api-monitor');
const { makeImmutableProperties } = require('./immutable-property');

// Store original fs methods for security (can't be mocked by malicious code)
const originalFs = {
  appendFileSync: fs.appendFileSync,
  readFileSync: fs.readFileSync,
  existsSync: fs.existsSync
};

class NetworkMonitor {
  constructor(config, silent = false, fsOverride = null) {
    // Set fs first so loadConfig can use it
    this.fs = fsOverride || originalFs;
    
    // SECURITY: Make critical properties immutable
    const loadedConfig = config || this.loadConfig();
    makeImmutableProperties(this, {
      silent: silent,
      config: Object.freeze(loadedConfig),
      enabled: loadedConfig.network?.enabled !== false
    });
    this.stats = {
      requests: 0,
      blocked: 0,
      suspicious: 0
    };
    this.requestLog = [];
    
    // Initialize GitHub API monitor
    this.githubMonitor = new GitHubApiMonitor(this.config, this.silent, fsOverride);
    
    if (!this.enabled) return;
    
    if (!this.silent) console.log('[Network Monitor] Enabled - Monitoring HTTP/HTTPS traffic');
    this.setupInterception();
  }
  
  loadConfig() {
    try {
      const configPath = path.join(process.cwd(), '.firewall-config.json');
      if (this.fs.existsSync(configPath)) {
        return JSON.parse(this.fs.readFileSync(configPath, 'utf8'));
      }
    } catch (e) {
      console.warn('[Network Monitor] Config not found, using defaults');
    }
    
    return {
      network: {
        enabled: true,
        mode: 'monitor',
        allowLocalhost: true,
        blockedDomains: [],
        allowedDomains: [],
        credentialPatterns: []
      },
      mode: { alertOnly: false }
    };
  }
  
  setupInterception() {
    const originalRequire = Module.prototype.require;
    const self = this;
    
    Module.prototype.require = function(id) {
      const module = originalRequire.apply(this, arguments);
      
      // Intercept http and https modules
      if (id === 'http' || id === 'https' || id === 'node:http' || id === 'node:https') {
        return self.wrapHttpModule(module, id);
      }
      
      // Intercept fetch (Node 18+)
      if (id === 'node:fetch' || (global.fetch && module === global.fetch)) {
        return self.wrapFetch(module);
      }
      
      return module;
    };
    
    // Also intercept global fetch if available
    if (global.fetch) {
      global.fetch = this.wrapFetch(global.fetch);
    }
    
    // CRITICAL: Intercept at net.Socket level (catches ALL network libraries)
    // This catches axios, got, undici, node-fetch, etc.
    this.interceptNetSocket();
  }
  
  interceptNetSocket() {
    const net = require('net');
    const self = this;
    const originalConnect = net.Socket.prototype.connect;
    
    net.Socket.prototype.connect = function(...args) {
      // SECURITY FIX: Use Symbol to prevent flag deletion
      const CHECKED_SYMBOL = Symbol.for('node.firewall.socket.checked');
      
      // Skip if already checked (avoid double-checking from http/https)
      if (this[CHECKED_SYMBOL]) {
        return originalConnect.apply(this, args);
      }
      // SECURITY FIX: Use Symbol instead of regular property (can't be deleted)
      this[CHECKED_SYMBOL] = true;
      
      // Extract connection details
      const options = typeof args[0] === 'object' ? args[0] : {};
      const host = options.host || options.hostname || args[1] || 'unknown';
      const port = options.port || args[2] || 0;
      
      const requestInfo = {
        url: `socket://${host}:${port}`,
        method: 'CONNECT',
        headers: {},
        protocol: port === 443 ? 'https' : 'http'
      };
      
      const check = self.checkRequest(requestInfo);
      
      if (!check.allowed) {
        console.error(`\n [NETWORK BLOCKED] ${check.reason}`);
        console.error(`   Socket connection to ${host}:${port}`);
        
        const isMonitorOnly = self.config.network?.mode === 'monitor' || self.config.mode?.alertOnly;
        
        if (!isMonitorOnly) {
          this.destroy(new Error(`Network blocked: ${check.reason}`));
          return this;
        }
      }
      
      self.logRequest(requestInfo, check);
      self.stats.requests++;
      if (!check.allowed) self.stats.blocked++;
      
      return originalConnect.apply(this, args);
    };
    
    if (!this.silent) {
      console.log('[Network Monitor] net.Socket interception active (universal network monitoring)');
    }
  }
  
  wrapHttpModule(httpModule, moduleName) {
    const self = this;
    const originalRequest = httpModule.request;
    const originalGet = httpModule.get;
    
    // Wrap request()
    httpModule.request = function(urlOrOptions, options, callback) {
      const requestInfo = self.parseRequestArgs(urlOrOptions, options);
      
      // Check if allowed
      const check = self.checkRequest(requestInfo);
      
      if (!check.allowed) {
        console.error(`\n [NETWORK BLOCKED] ${check.reason}`);
        console.error(`   ${requestInfo.method} ${requestInfo.url}`);
        
        // Check if in alert-only mode or if network mode is 'monitor'
        const isMonitorOnly = self.config.network?.mode === 'monitor' || self.config.mode?.alertOnly;
        
        if (isMonitorOnly) {
          console.warn('   Alert-only mode: Request proceeding anyway');
        } else {
          const error = new Error(`Network request blocked: ${check.reason}`);
          error.code = 'FIREWALL_BLOCKED';
          throw error;
        }
      }
      
      // Create the request
      const req = originalRequest.apply(this, arguments);
      
      // Wrap write and end to inspect payload
      const originalWrite = req.write.bind(req);
      const originalEnd = req.end.bind(req);
      let requestBody = '';
      
      req.write = function(chunk, encoding, callback) {
        if (chunk) {
          requestBody += chunk.toString();
          
          if (self.containsCredentials(chunk)) {
            console.error('\n [CREDENTIAL EXFILTRATION DETECTED]');
            console.error(`   Destination: ${requestInfo.url}`);
            console.error(`   Payload contains sensitive credentials!`);
            
            self.logThreat('CREDENTIAL_EXFILTRATION', requestInfo, chunk);
            
            const isMonitorOnly = self.config.network?.mode === 'monitor' || self.config.mode?.alertOnly;
            if (!isMonitorOnly) {
              req.destroy();
              return false;
            }
          }
        }
        return originalWrite(chunk, encoding, callback);
      };
      
      req.end = function(chunk, encoding, callback) {
        if (chunk) {
          requestBody += chunk.toString();
          
          if (self.containsCredentials(chunk)) {
            console.error('\n [CREDENTIAL EXFILTRATION DETECTED]');
            console.error(`   Destination: ${requestInfo.url}`);
            
            self.logThreat('CREDENTIAL_EXFILTRATION', requestInfo, chunk);
            
            const isMonitorOnly = self.config.network?.mode === 'monitor' || self.config.mode?.alertOnly;
            if (!isMonitorOnly) {
              req.destroy();
              return;
            }
          }
        }
        
        // Check GitHub API after collecting full request body
        if (self.githubMonitor.enabled) {
          const githubCheck = self.githubMonitor.checkGitHubApiRequest(
            requestInfo.url,
            requestInfo.method,
            requestBody,
            requestInfo.headers
          );
          
          if (!githubCheck.allowed) {
            const isMonitorOnly = self.config.network?.mode === 'monitor' || self.config.mode?.alertOnly;
            if (!isMonitorOnly) {
              req.destroy();
              return;
            }
          }
        }
        
        return originalEnd(chunk, encoding, callback);
      };
      
      self.logRequest(requestInfo, check);
      return req;
    };
    
    // Wrap get() - it's just a convenience method
    httpModule.get = function(urlOrOptions, options, callback) {
      if (typeof options === 'function') {
        callback = options;
        options = {};
      }
      return httpModule.request(urlOrOptions, { ...options, method: 'GET' }, callback);
    };
    
    return httpModule;
  }
  
  wrapFetch(originalFetch) {
    const self = this;
    
    return async function(resource, options = {}) {
      const requestInfo = {
        method: options.method || 'GET',
        url: typeof resource === 'string' ? resource : resource.url,
        headers: options.headers || {}
      };
      
      const check = self.checkRequest(requestInfo);
      
      if (!check.allowed) {
        console.error(`\n [NETWORK BLOCKED] ${check.reason}`);
        console.error(`   ${requestInfo.method} ${requestInfo.url}`);
        
        if (!self.config.mode?.alertOnly) {
          throw new Error(`Network request blocked: ${check.reason}`);
        }
      }
      
      // Check body for credentials
      if (options.body && self.containsCredentials(options.body)) {
        console.error('\n [CREDENTIAL EXFILTRATION DETECTED]');
        console.error(`   Destination: ${requestInfo.url}`);
        
        self.logThreat('CREDENTIAL_EXFILTRATION', requestInfo, options.body);
        
        if (!self.config.mode?.alertOnly) {
          throw new Error('Blocked: Attempt to send credentials over network');
        }
      }
      
      self.logRequest(requestInfo, check);
      return originalFetch.apply(this, arguments);
    };
  }
  
  parseRequestArgs(urlOrOptions, options) {
    let requestUrl, method, headers;
    
    if (typeof urlOrOptions === 'string') {
      requestUrl = urlOrOptions;
      method = options?.method || 'GET';
      headers = options?.headers || {};
    } else {
      // Construct URL from options object
      const protocol = urlOrOptions.protocol || 'https:';
      const hostname = urlOrOptions.hostname || urlOrOptions.host || 'unknown';
      const port = urlOrOptions.port || (protocol === 'https:' ? 443 : 80);
      const path = urlOrOptions.path || '/';
      
      // Build full URL
      requestUrl = `${protocol}//${hostname}${port !== 443 && port !== 80 ? ':' + port : ''}${path}`;
      
      method = urlOrOptions.method || 'GET';
      headers = urlOrOptions.headers || {};
    }
    
    return { url: requestUrl, method, headers };
  }
  
  checkRequest(requestInfo) {
    this.stats.requests++;
    
    try {
      // Handle socket:// URLs properly
      let parsedUrl;
      if (requestInfo.url.startsWith('socket://')) {
        // Extract hostname from socket://host:port
        const socketMatch = requestInfo.url.match(/socket:\/\/([^:]+):?(\d+)?/);
        if (socketMatch) {
          const hostname = socketMatch[1];
          const port = socketMatch[2];
          
          // Allow localhost and unknown hosts (likely localhost connections)
          if (this.config.network?.allowLocalhost && 
              (this.isLocalhost(hostname) || hostname === 'unknown')) {
            return { allowed: true, reason: 'localhost/unknown socket' };
          }
          
          parsedUrl = { hostname, port };
        } else {
          return { allowed: true, reason: 'unparseable socket' };
        }
      } else {
        parsedUrl = new URL(requestInfo.url.startsWith('http') ? requestInfo.url : 'http://' + requestInfo.url);
      }
      
      const hostname = parsedUrl.hostname;
      const port = parsedUrl.port;
      
      // Check localhost (allow if configured)
      if (this.config.network?.allowLocalhost && this.isLocalhost(hostname)) {
        return { allowed: true, reason: 'localhost' };
      }
      
      // Check private networks (allow if configured)
      if (this.config.network?.allowPrivateNetworks && this.isPrivateNetwork(hostname)) {
        return { allowed: true, reason: 'private network' };
      }
      
      // Check blocked domains
      if (this.config.network?.blockedDomains) {
        for (const blocked of this.config.network.blockedDomains) {
          if (hostname.includes(blocked)) {
            this.stats.blocked++;
            return { allowed: false, reason: `Blocked domain: ${blocked}` };
          }
        }
      }
      
      // Check suspicious ports
      if (this.config.network?.suspiciousPorts && port) {
        if (this.config.network.suspiciousPorts.includes(parseInt(port))) {
          this.stats.suspicious++;
          console.warn(`[SUSPICIOUS PORT] ${hostname}:${port}`);
          
          if (!this.config.mode?.alertOnly) {
            return { allowed: false, reason: `Suspicious port: ${port}` };
          }
        }
      }
      
      // Check allowed domains (whitelist mode)
      if (this.config.network?.allowedDomains && this.config.network.allowedDomains.length > 0) {
        const isAllowed = this.config.network.allowedDomains.some(allowed => 
          hostname === allowed || hostname.endsWith('.' + allowed)
        );
        
        if (!isAllowed && !this.isLocalhost(hostname)) {
          this.stats.blocked++;
          return { allowed: false, reason: `Not in allowed domains: ${hostname}` };
        }
      }
      
      return { allowed: true, reason: 'passed checks' };
      
    } catch (e) {
      console.error(`[Network Monitor] Error parsing URL: ${requestInfo.url}`, e.message);
      return { allowed: true, reason: 'parse error' };
    }
  }
  
  isLocalhost(hostname) {
    return hostname === 'localhost' || 
           hostname === '127.0.0.1' || 
           hostname === '::1' ||
           hostname === '0.0.0.0';
  }
  
  isPrivateNetwork(hostname) {
    // Check for private IP ranges
    const privateRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./,
      /^169\.254\./,  // link-local
      /^fc00:/,       // IPv6 private
      /^fd00:/        // IPv6 private
    ];
    
    return privateRanges.some(pattern => pattern.test(hostname));
  }
  
  containsCredentials(data) {
    if (!data) return false;
    
    const str = Buffer.isBuffer(data) ? data.toString() : String(data);
    
    // Use patterns from config
    const patterns = this.config.network?.credentialPatterns || [];
    
    for (const pattern of patterns) {
      if (new RegExp(pattern, 'i').test(str)) {
        return true;
      }
    }
    
    // Additional checks for common credential formats
    if (str.includes('-----BEGIN')) return true; // PEM keys
    if (/AKIA[0-9A-Z]{16}/.test(str)) return true; // AWS access key
    
    // JSON format: "password": "value"
    if (/"password"\s*:\s*"[^"]+"/.test(str)) return true;
    
    // Plain text, YAML, form data: password: value, password=value, password:value
    if (/password\s*[:=]\s*\S+/i.test(str)) return true;
    
    // Token patterns
    if (/token\s*[:=]\s*\S+/i.test(str)) return true;
    if (/"token"\s*:\s*"[^"]+"/.test(str)) return true;
    
    // API key patterns
    if (/api[_-]?key\s*[:=]\s*\S+/i.test(str)) return true;
    if (/"api[_-]?key"\s*:\s*"[^"]+"/.test(str)) return true;
    
    // Secret patterns
    if (/secret\s*[:=]\s*\S+/i.test(str)) return true;
    if (/"secret"\s*:\s*"[^"]+"/.test(str)) return true;
    
    return false;
  }
  
  logRequest(requestInfo, check) {
    const entry = {
      timestamp: new Date().toISOString(),
      method: requestInfo.method,
      url: requestInfo.url,
      allowed: check.allowed,
      reason: check.reason
    };
    
    this.requestLog.push(entry);
    
    // Keep only last 100 requests
    if (this.requestLog.length > 100) {
      this.requestLog.shift();
    }
    
    // Log to file if verbose or blocked
    if (!check.allowed || this.config.reporting?.logLevel === 'verbose') {
      this.appendToLog(entry);
    }
  }
  
  logThreat(type, requestInfo, data) {
    const threat = {
      timestamp: new Date().toISOString(),
      type,
      destination: requestInfo.url,
      method: requestInfo.method,
      dataSize: Buffer.byteLength(String(data)),
      callStack: new Error().stack
    };
    
    this.appendToLog(threat, 'THREAT');
    
    // Generate alert
    if (!this.silent) {
      console.error('\n');
      console.error(' SECURITY THREAT DETECTED');
      console.error('');
      console.error(`Type: ${type}`);
      console.error(`Destination: ${requestInfo.url}`);
      console.error(`Time: ${threat.timestamp}`);
      console.error('\n');
    }
  }
  
  appendToLog(entry, prefix = 'NETWORK') {
    try {
      const logFile = this.config.reporting?.logFile || 'fs-firewall.log';
      const logLine = `[${entry.timestamp}] ${prefix} | ${JSON.stringify(entry)}\n`;
      this.fs.appendFileSync(logFile, logLine);
    } catch (e) {
      // Silent fail
    }
  }
  
  getStats() {
    const stats = {
      ...this.stats,
      recentRequests: this.requestLog.slice(-10)
    };
    
    if (this.githubMonitor.enabled) {
      stats.githubApi = this.githubMonitor.getStats();
    }
    
    return stats;
  }
  
  generateReport() {
    const report = {
      summary: this.stats,
      recentActivity: this.requestLog,
      config: {
        enabled: this.enabled,
        mode: this.config.network?.mode,
        allowLocalhost: this.config.network?.allowLocalhost
      }
    };
    
    if (this.githubMonitor.enabled) {
      report.githubApi = this.githubMonitor.generateReport();
    }
    
    return report;
  }
}

// Singleton instance
let instance = null;

function initialize(config, silent = false, fsOverride = null) {
  if (!instance) {
    instance = new NetworkMonitor(config, silent, fsOverride);
  }
  return instance;
}

function getInstance() {
  return instance || initialize();
}

module.exports = { NetworkMonitor, initialize, getInstance };
