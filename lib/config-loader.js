/**
 * Configuration Loader
 * Centralized configuration management for all firewall components
 */

const fs = require('fs');
const path = require('path');

// Store original fs methods for security (can't be mocked by malicious code)
const originalFs = {
  existsSync: fs.existsSync,
  readFileSync: fs.readFileSync,
  writeFileSync: fs.writeFileSync,
  watch: fs.watch
};

class ConfigLoader {
  constructor(fsOverride = null) {
    this.config = null;
    this.configPath = null;
    this.watchers = [];
    // Allow fs override for testing, but default to secure originalFs
    this.fs = fsOverride || originalFs;
  }
  
  load(customPath = null) {
    // Try custom path first
    if (customPath && this.fs.existsSync(customPath)) {
      this.configPath = customPath;
      return this.readConfig(customPath);
    }
    
    // Try environment variable
    const envPath = process.env.FIREWALL_CONFIG;
    if (envPath && this.fs.existsSync(envPath)) {
      this.configPath = envPath;
      return this.readConfig(envPath);
    }
    
    // Try common locations
    const locations = [
      path.join(process.cwd(), '.firewall-config.json'),
      path.join(process.cwd(), 'firewall-config.json'),
      path.join(require('os').homedir(), '.firewall-config.json'),
      path.join(__dirname, '..', '.firewall-config.json')
    ];
    
    for (const location of locations) {
      if (this.fs.existsSync(location)) {
        this.configPath = location;
        return this.readConfig(location);
      }
    }
    
    console.warn('[Config] No config file found, using defaults');
    this.config = this.getDefaults();
    return this.config;
  }
  
  readConfig(filePath) {
    try {
      const content = this.fs.readFileSync(filePath, 'utf8');
      this.config = JSON.parse(content);
      console.log(`[Config] Loaded from: ${filePath}`);
      return this.config;
    } catch (e) {
      console.error(`[Config] Error reading ${filePath}:`, e.message);
      this.config = this.getDefaults();
      return this.config;
    }
  }
  
  getDefaults() {
    return {
      mode: {
        enabled: true,
        interactive: true,
        strictMode: false,
        alertOnly: false
      },
      filesystem: {
        // Note: Project files are automatically allowed:
        // - .env files (cwd and parent directories)
        // - Source files: .ts, .tsx, .js, .jsx, .json, .mjs, .cjs (in project directory)
        blockedReadPaths: ['/.ssh/', '/.aws/'],
        blockedWritePaths: ['/etc/', '/.ssh/', '/usr/local/bin/'],
        blockedExtensions: ['.sh', '.command'],
        allowedPaths: [
          '/tmp/',           // Temp files
          '/var/folders/',   // macOS temp directory (used by ts-node)
          '/node_modules/',  // Dependencies
          '/.npm/',          // npm cache
          '/.yarn/',         // Yarn cache
          '/.pnpm/',         // pnpm cache
          '/.cache/',        // General cache
          '/.ts-node',       // TypeScript ts-node cache (matches /.ts-node/)
          '/dist/',          // TypeScript build output
          '/build/',         // Build output
          '/.turbo/',        // Turbo cache
          '/.next/'          // Next.js cache
        ]
      },
      network: {
        enabled: true,
        mode: 'monitor',
        allowLocalhost: true,
        allowPrivateNetworks: true,
        blockedDomains: [],
        allowedDomains: [],
        credentialPatterns: ['BEGIN.*PRIVATE KEY', 'aws_access_key_id', 'GITHUB_TOKEN']
      },
      trustedModules: ['npm', 'yarn', 'pnpm', '@npmcli', 'pacote', 'node-gyp', 'aws-sdk', '@aws-sdk', 'firebase', 'dotenv'],
      exceptions: { modules: {} },
      behavioral: {
        monitorLifecycleScripts: true,
        alertThresholds: {
          fileReads: 500,          // Increased for TypeScript projects (ts-node, compilation)
          fileWrites: 100,         // Increased for build outputs
          networkRequests: 50,     // Increased for modern apps
          processSpawns: 10
        }
      },
      reporting: {
        logLevel: 'info',
        logFile: 'fs-firewall.log',
        alertOnSuspicious: true
      }
    };
  }
  
  get(key = null) {
    if (!this.config) {
      this.load();
    }
    
    if (!key) return this.config;
    
    // Support nested keys like 'network.enabled'
    const keys = key.split('.');
    let value = this.config;
    
    for (const k of keys) {
      value = value?.[k];
      if (value === undefined) return undefined;
    }
    
    return value;
  }
  
  set(key, value) {
    if (!this.config) {
      this.load();
    }
    
    const keys = key.split('.');
    let target = this.config;
    
    for (let i = 0; i < keys.length - 1; i++) {
      if (!target[keys[i]]) {
        target[keys[i]] = {};
      }
      target = target[keys[i]];
    }
    
    target[keys[keys.length - 1]] = value;
    return this.save();
  }
  
  save() {
    if (!this.configPath) {
      this.configPath = path.join(process.cwd(), '.firewall-config.json');
    }
    
    try {
      this.fs.writeFileSync(this.configPath, JSON.stringify(this.config, null, 2));
      console.log(`[Config] Saved to: ${this.configPath}`);
      return true;
    } catch (e) {
      console.error('[Config] Failed to save:', e.message);
      return false;
    }
  }
  
  addException(packageName, exception) {
    if (!this.config) {
      this.load();
    }
    
    if (!this.config.exceptions) {
      this.config.exceptions = { modules: {} };
    }
    
    if (!this.config.exceptions.modules) {
      this.config.exceptions.modules = {};
    }
    
    this.config.exceptions.modules[packageName] = exception;
    return this.save();
  }
  
  getException(packageName) {
    if (!this.config) {
      this.load();
    }
    
    return this.config.exceptions?.modules?.[packageName];
  }
  
  hasException(packageName, type, value) {
    const exception = this.getException(packageName);
    if (!exception) return false;
    
    switch (type) {
      case 'filesystem':
        return exception.allowFilesystem?.some(path => value.includes(path));
      case 'network':
        return exception.allowNetwork?.some(domain => value.includes(domain));
      case 'command':
        return exception.allowCommands?.includes(value);
      default:
        return false;
    }
  }
  
  reload() {
    console.log('[Config] Reloading configuration...');
    return this.load(this.configPath);
  }
  
  watch(callback) {
    if (!this.configPath) return;
    
    try {
      const watcher = this.fs.watch(this.configPath, (eventType) => {
        if (eventType === 'change') {
          console.log('[Config] File changed, reloading...');
          this.reload();
          if (callback) callback(this.config);
        }
      });
      
      this.watchers.push(watcher);
      console.log('[Config] Watching for changes...');
    } catch (e) {
      console.error('[Config] Failed to watch file:', e.message);
    }
  }
  
  stopWatching() {
    this.watchers.forEach(watcher => {
      if (watcher && typeof watcher.close === 'function') {
        watcher.close();
      }
    });
    this.watchers = [];
  }
}

// Singleton instance
const instance = new ConfigLoader();

module.exports = instance;
module.exports.ConfigLoader = ConfigLoader;
