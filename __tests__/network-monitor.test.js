const Module = require('module');
const fs = require('fs');
const net = require('net');

jest.mock('fs', () => ({
  existsSync: jest.fn(),
  readFileSync: jest.fn(),
  appendFileSync: jest.fn()
}));

// Mock net module for socket interception
jest.mock('net', () => ({
  Socket: class MockSocket {
    constructor() {
      this.connect = jest.fn();
    }
  }
}));

describe('NetworkMonitor', () => {
  let NetworkMonitor;
  let originalRequire;
  let originalSocketConnect;
  
  beforeEach(() => {
    jest.clearAllMocks();
    jest.resetModules();
    delete require.cache[require.resolve('../lib/network-monitor')];
    originalRequire = Module.prototype.require;
    
    // Save original Socket.prototype.connect
    originalSocketConnect = net.Socket.prototype.connect;
  });
  
  afterEach(() => {
    Module.prototype.require = originalRequire;
    // Restore original Socket.prototype.connect
    if (originalSocketConnect) {
      net.Socket.prototype.connect = originalSocketConnect;
    }
  });

  describe('constructor', () => {
    test('should initialize with config', () => {
      const config = {
        network: { enabled: true, mode: 'monitor' }
      };
      
      const { NetworkMonitor: NM } = require('../lib/network-monitor');
      const monitor = new NM(config, true, fs); // Pass mocked fs
      
      expect(monitor.enabled).toBe(true);
      expect(monitor.silent).toBe(true);
      expect(monitor.stats.requests).toBe(0);
      expect(monitor.stats.blocked).toBe(0);
    });

    test('should be disabled when config disables network monitoring', () => {
      const config = {
        network: { enabled: false }
      };
      
      const { NetworkMonitor: NM } = require('../lib/network-monitor');
      const monitor = new NM(config, true, fs);
      
      expect(monitor.enabled).toBe(false);
    });

    test('should load default config when none provided', () => {
      fs.existsSync.mockReturnValue(false);
      
      const { NetworkMonitor: NM } = require('../lib/network-monitor');
      const monitor = new NM(null, true, fs);
      
      expect(monitor.config).toBeDefined();
      expect(monitor.config.network).toBeDefined();
    });

    test('should log when not silent', () => {
      const consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
      
      const { NetworkMonitor: NM } = require('../lib/network-monitor');
      const monitor = new NM({ network: { enabled: true } }, false, fs);
      
      expect(consoleLogSpy).toHaveBeenCalled();
      consoleLogSpy.mockRestore();
    });
  });

  describe('loadConfig', () => {
    test('should load config from file if exists', () => {
      const mockConfig = { network: { enabled: true } };
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue(JSON.stringify(mockConfig));
      
      const { NetworkMonitor: NM } = require('../lib/network-monitor');
      const monitor = new NM(null, true, fs);
      
      expect(monitor.config).toEqual(mockConfig);
    });

    test('should return defaults when config file not found', () => {
      fs.existsSync.mockReturnValue(false);
      const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      const { NetworkMonitor: NM } = require('../lib/network-monitor');
      const monitor = new NM(null, true, fs);
      
      expect(monitor.config.network).toBeDefined();
      expect(monitor.config.network.enabled).toBe(true);
      consoleWarnSpy.mockRestore();
    });
  });

  describe('setupInterception', () => {
    test('should intercept http module', () => {
      const { NetworkMonitor: NM } = require('../lib/network-monitor');
      const monitor = new NM({ network: { enabled: true } }, true, fs);
      
      const mockHttpModule = {
        request: jest.fn(),
        get: jest.fn()
      };
      
      const wrappedModule = monitor.wrapHttpModule(mockHttpModule, 'http');
      
      expect(wrappedModule.request).toBeDefined();
      expect(wrappedModule.get).toBeDefined();
    });

    test('should intercept fetch if available', () => {
      const originalFetch = jest.fn();
      
      const { NetworkMonitor: NM } = require('../lib/network-monitor');
      const monitor = new NM({ network: { enabled: true } }, true, fs);
      
      const wrappedFetch = monitor.wrapFetch(originalFetch);
      
      expect(wrappedFetch).toBeDefined();
      expect(typeof wrappedFetch).toBe('function');
    });
  });

  describe('checkRequest', () => {
    let monitor;
    
    beforeEach(() => {
      const { NetworkMonitor: NM } = require('../lib/network-monitor');
      monitor = new NM({
        network: {
          enabled: true,
          allowLocalhost: true,
          allowPrivateNetworks: true,
          blockedDomains: ['evil.com']
        }
      }, true, fs);
    });

    test('should allow localhost requests', () => {
      const result = monitor.checkRequest({
        url: 'http://localhost:3000',
        method: 'GET'
      });
      
      expect(result.allowed).toBe(true);
      expect(result.reason).toBe('localhost');
    });

    test('should allow private network requests', () => {
      const result = monitor.checkRequest({
        url: 'http://192.168.1.1',
        method: 'GET'
      });
      
      expect(result.allowed).toBe(true);
      expect(result.reason).toBe('private network');
    });

    test('should block requests to blocked domains', () => {
      const result = monitor.checkRequest({
        url: 'http://evil.com/malware',
        method: 'GET'
      });
      
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Blocked domain');
    });

    test('should check suspicious ports', () => {
      monitor.config.network.suspiciousPorts = [4444];
      const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      const result = monitor.checkRequest({
        url: 'http://example.com:4444',
        method: 'GET'
      });
      
      expect(consoleWarnSpy).toHaveBeenCalled();
      consoleWarnSpy.mockRestore();
    });

    test('should enforce allowed domains whitelist', () => {
      monitor.config.network.allowedDomains = ['trusted.com'];
      
      const result = monitor.checkRequest({
        url: 'http://untrusted.com',
        method: 'GET'
      });
      
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Not in allowed domains');
    });

    test('should handle URL parsing errors', () => {
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      // Use null URL which will cause parsing to fail
      const result = monitor.checkRequest({
        url: null,
        method: 'GET'
      });
      
      expect(result.allowed).toBe(true);
      expect(result.reason).toBe('parse error');
      consoleErrorSpy.mockRestore();
    });
  });

  describe('isLocalhost', () => {
    let monitor;
    
    beforeEach(() => {
      const { NetworkMonitor: NM } = require('../lib/network-monitor');
      monitor = new NM({ network: { enabled: true } }, true, fs);
    });

    test('should identify localhost', () => {
      expect(monitor.isLocalhost('localhost')).toBe(true);
    });

    test('should identify 127.0.0.1', () => {
      expect(monitor.isLocalhost('127.0.0.1')).toBe(true);
    });

    test('should identify ::1', () => {
      expect(monitor.isLocalhost('::1')).toBe(true);
    });

    test('should identify 0.0.0.0', () => {
      expect(monitor.isLocalhost('0.0.0.0')).toBe(true);
    });

    test('should not identify external hosts', () => {
      expect(monitor.isLocalhost('example.com')).toBe(false);
    });
  });

  describe('isPrivateNetwork', () => {
    let monitor;
    
    beforeEach(() => {
      const { NetworkMonitor: NM } = require('../lib/network-monitor');
      monitor = new NM({ network: { enabled: true } }, true, fs);
    });

    test('should identify 10.x.x.x range', () => {
      expect(monitor.isPrivateNetwork('10.0.0.1')).toBe(true);
    });

    test('should identify 192.168.x.x range', () => {
      expect(monitor.isPrivateNetwork('192.168.1.1')).toBe(true);
    });

    test('should identify 172.16-31.x.x range', () => {
      expect(monitor.isPrivateNetwork('172.16.0.1')).toBe(true);
      expect(monitor.isPrivateNetwork('172.20.0.1')).toBe(true);
      expect(monitor.isPrivateNetwork('172.31.0.1')).toBe(true);
    });

    test('should identify link-local 169.254.x.x', () => {
      expect(monitor.isPrivateNetwork('169.254.0.1')).toBe(true);
    });

    test('should not identify public IPs', () => {
      expect(monitor.isPrivateNetwork('8.8.8.8')).toBe(false);
    });
  });

  describe('containsCredentials', () => {
    let monitor;
    
    beforeEach(() => {
      const { NetworkMonitor: NM } = require('../lib/network-monitor');
      monitor = new NM({
        network: {
          enabled: true,
          credentialPatterns: ['SECRET_KEY', 'API_TOKEN']
        }
      }, true, fs);
    });

    test('should detect configured credential patterns', () => {
      const result = monitor.containsCredentials('SECRET_KEY=abc123');
      
      expect(result).toBe(true);
    });

    test('should detect BEGIN private key', () => {
      const result = monitor.containsCredentials('-----BEGIN RSA PRIVATE KEY-----');
      
      expect(result).toBe(true);
    });

    test('should detect AWS access key pattern', () => {
      const result = monitor.containsCredentials('AKIAIOSFODNN7EXAMPLE');
      
      expect(result).toBe(true);
    });

    test('should detect password in JSON', () => {
      const result = monitor.containsCredentials('{"password": "secret123"}');
      
      expect(result).toBe(true);
    });

    test('should not detect in normal data', () => {
      const result = monitor.containsCredentials('normal data without secrets');
      
      expect(result).toBe(false);
    });

    test('should handle null data', () => {
      const result = monitor.containsCredentials(null);
      
      expect(result).toBe(false);
    });

    test('should handle buffer data', () => {
      const buffer = Buffer.from('SECRET_KEY=test');
      const result = monitor.containsCredentials(buffer);
      
      expect(result).toBe(true);
    });
  });

  describe('parseRequestArgs', () => {
    let monitor;
    
    beforeEach(() => {
      const { NetworkMonitor: NM } = require('../lib/network-monitor');
      monitor = new NM({ network: { enabled: true } }, true, fs);
    });

    test('should parse string URL', () => {
      const result = monitor.parseRequestArgs('http://example.com', {});
      
      expect(result.url).toBe('http://example.com');
      expect(result.method).toBe('GET');
    });

    test('should parse options object with hostname', () => {
      const options = {
        hostname: 'example.com',
        path: '/api',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      };
      
      const result = monitor.parseRequestArgs(options, {});
      
      expect(result.url).toContain('example.com');
      expect(result.url).toContain('/api');
      expect(result.method).toBe('POST');
    });

    test('should handle custom port', () => {
      const options = {
        hostname: 'example.com',
        port: 8080,
        path: '/'
      };
      
      const result = monitor.parseRequestArgs(options, {});
      
      expect(result.url).toContain(':8080');
    });

    test('should default to https protocol', () => {
      const options = {
        hostname: 'example.com',
        path: '/'
      };
      
      const result = monitor.parseRequestArgs(options, {});
      
      expect(result.url).toContain('https://');
    });
  });

  describe('wrapHttpModule', () => {
    let monitor;
    
    beforeEach(() => {
      const { NetworkMonitor: NM } = require('../lib/network-monitor');
      monitor = new NM({
        network: {
          enabled: true,
          mode: 'block',
          blockedDomains: ['evil.com']
        },
        mode: { alertOnly: false }
      }, true, fs);
    });

    test('should wrap request method', () => {
      const mockRequest = jest.fn().mockReturnValue({
        write: jest.fn(),
        end: jest.fn()
      });
      
      const httpModule = {
        request: mockRequest,
        get: jest.fn()
      };
      
      const wrapped = monitor.wrapHttpModule(httpModule, 'http');
      
      expect(wrapped.request).not.toBe(mockRequest);
    });

    test('should block disallowed requests in enforcement mode', () => {
      const mockRequest = jest.fn();
      const httpModule = { request: mockRequest, get: jest.fn() };
      const wrapped = monitor.wrapHttpModule(httpModule, 'http');
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      expect(() => {
        wrapped.request('http://evil.com');
      }).toThrow('Network request blocked');
      
      consoleErrorSpy.mockRestore();
    });

    test('should allow requests in monitor mode', () => {
      monitor.config.network.mode = 'monitor';
      const mockReq = {
        write: jest.fn(),
        end: jest.fn()
      };
      const mockRequest = jest.fn().mockReturnValue(mockReq);
      const httpModule = { request: mockRequest, get: jest.fn() };
      const wrapped = monitor.wrapHttpModule(httpModule, 'http');
      const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation();
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      wrapped.request('http://evil.com');
      
      expect(consoleWarnSpy).toHaveBeenCalled();
      consoleWarnSpy.mockRestore();
      consoleErrorSpy.mockRestore();
    });

    test('should detect credentials in request payload', () => {
      const mockReq = {
        write: jest.fn(),
        end: jest.fn(),
        destroy: jest.fn()
      };
      const mockRequest = jest.fn().mockReturnValue(mockReq);
      const httpModule = { request: mockRequest, get: jest.fn() };
      const wrapped = monitor.wrapHttpModule(httpModule, 'http');
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      const req = wrapped.request('http://example.com');
      req.write('password: secret123');
      
      expect(consoleErrorSpy).toHaveBeenCalled();
      consoleErrorSpy.mockRestore();
    });
  });

  describe('wrapFetch', () => {
    let monitor;
    
    beforeEach(() => {
      const { NetworkMonitor: NM } = require('../lib/network-monitor');
      monitor = new NM({
        network: {
          enabled: true,
          blockedDomains: ['evil.com']
        },
        mode: { alertOnly: false }
      }, true, fs);
    });

    test('should wrap fetch function', async () => {
      const originalFetch = jest.fn().mockResolvedValue({ ok: true });
      const wrappedFetch = monitor.wrapFetch(originalFetch);
      
      await wrappedFetch('http://example.com');
      
      expect(originalFetch).toHaveBeenCalled();
    });

    test('should block disallowed fetch requests', async () => {
      const originalFetch = jest.fn();
      const wrappedFetch = monitor.wrapFetch(originalFetch);
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      await expect(wrappedFetch('http://evil.com')).rejects.toThrow('Network request blocked');
      
      consoleErrorSpy.mockRestore();
    });

    test('should detect credentials in fetch body', async () => {
      monitor.config.mode.alertOnly = false;
      const originalFetch = jest.fn();
      const wrappedFetch = monitor.wrapFetch(originalFetch);
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      await expect(
        wrappedFetch('http://example.com', {
          method: 'POST',
          body: 'password: secret'
        })
      ).rejects.toThrow('Blocked: Attempt to send credentials');
      
      consoleErrorSpy.mockRestore();
    });
  });

  describe('logRequest', () => {
    let monitor;
    
    beforeEach(() => {
      const { NetworkMonitor: NM } = require('../lib/network-monitor');
      monitor = new NM({ network: { enabled: true } }, true, fs);
      fs.appendFileSync.mockImplementation(() => {});
    });

    test('should log request to array', () => {
      monitor.logRequest(
        { url: 'http://example.com', method: 'GET' },
        { allowed: true, reason: 'passed' }
      );
      
      expect(monitor.requestLog).toHaveLength(1);
      expect(monitor.requestLog[0]).toHaveProperty('url', 'http://example.com');
    });

    test('should limit log size to 100 entries', () => {
      for (let i = 0; i < 150; i++) {
        monitor.logRequest(
          { url: `http://example.com/${i}`, method: 'GET' },
          { allowed: true, reason: 'passed' }
        );
      }
      
      expect(monitor.requestLog).toHaveLength(100);
    });

    test('should write to file for blocked requests', () => {
      monitor.logRequest(
        { url: 'http://evil.com', method: 'GET' },
        { allowed: false, reason: 'blocked' }
      );
      
      expect(fs.appendFileSync).toHaveBeenCalled();
    });
  });

  describe('logThreat', () => {
    let monitor;
    
    beforeEach(() => {
      const { NetworkMonitor: NM } = require('../lib/network-monitor');
      monitor = new NM({ network: { enabled: true } }, false, fs);
      fs.appendFileSync.mockImplementation(() => {});
    });

    test('should log threat details', () => {
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      monitor.logThreat(
        'CREDENTIAL_EXFILTRATION',
        { url: 'http://evil.com', method: 'POST' },
        'secret data'
      );
      
      expect(fs.appendFileSync).toHaveBeenCalled();
      expect(consoleErrorSpy).toHaveBeenCalled();
      consoleErrorSpy.mockRestore();
    });

    test('should not log to console in silent mode', () => {
      monitor.silent = true;
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      monitor.logThreat(
        'TEST_THREAT',
        { url: 'http://test.com', method: 'GET' },
        'data'
      );
      
      expect(consoleErrorSpy).not.toHaveBeenCalled();
      consoleErrorSpy.mockRestore();
    });
  });

  describe('getStats', () => {
    let monitor;
    
    beforeEach(() => {
      const { NetworkMonitor: NM } = require('../lib/network-monitor');
      monitor = new NM({ network: { enabled: true } }, true, fs);
    });

    test('should return stats with recent requests', () => {
      monitor.stats.requests = 10;
      monitor.stats.blocked = 2;
      monitor.requestLog = [{ url: 'test' }];
      
      const stats = monitor.getStats();
      
      expect(stats.requests).toBe(10);
      expect(stats.blocked).toBe(2);
      expect(stats.recentRequests).toBeDefined();
    });
  });

  describe('generateReport', () => {
    let monitor;
    
    beforeEach(() => {
      const { NetworkMonitor: NM } = require('../lib/network-monitor');
      monitor = new NM({ network: { enabled: true, mode: 'monitor' } }, true, fs);
    });

    test('should generate comprehensive report', () => {
      monitor.stats.requests = 5;
      monitor.requestLog = [{ url: 'test' }];
      
      const report = monitor.generateReport();
      
      expect(report).toHaveProperty('summary');
      expect(report).toHaveProperty('recentActivity');
      expect(report).toHaveProperty('config');
      expect(report.config.enabled).toBe(true);
    });
  });

  describe('appendToLog', () => {
    let monitor;
    
    beforeEach(() => {
      const { NetworkMonitor: NM } = require('../lib/network-monitor');
      monitor = new NM({ network: { enabled: true } }, true, fs);
      fs.appendFileSync.mockImplementation(() => {});
    });

    test('should write log entry to file', () => {
      const entry = {
        timestamp: new Date().toISOString(),
        url: 'http://test.com'
      };
      
      monitor.appendToLog(entry);
      
      expect(fs.appendFileSync).toHaveBeenCalled();
    });

    test('should handle file write errors silently', () => {
      fs.appendFileSync.mockImplementation(() => {
        throw new Error('Write error');
      });
      
      expect(() => {
        monitor.appendToLog({ test: 'data' });
      }).not.toThrow();
    });
  });

  describe('initialize and getInstance', () => {
    test('should create singleton instance', () => {
      const { initialize, getInstance } = require('../lib/network-monitor');
      
      const instance1 = initialize({ network: { enabled: true } }, true, fs);
      const instance2 = getInstance();
      
      expect(instance1).toBe(instance2);
    });

    test('should return existing instance from getInstance', () => {
      jest.resetModules();
      const { initialize, getInstance } = require('../lib/network-monitor');
      
      initialize({ network: { enabled: true } }, true, fs);
      const instance = getInstance();
      
      expect(instance).toBeDefined();
    });
  });
});
