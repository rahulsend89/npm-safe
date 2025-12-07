const fs = require('fs');
const path = require('path');
const os = require('os');

jest.mock('fs', () => ({
  existsSync: jest.fn(),
  readFileSync: jest.fn(),
  writeFileSync: jest.fn(),
  watch: jest.fn()
}));

describe('ConfigLoader', () => {
  let ConfigLoader;
  let configLoader;
  
  beforeEach(() => {
    jest.clearAllMocks();
    jest.resetModules();
    delete require.cache[require.resolve('../lib/config-loader')];
    
    const configLoaderModule = require('../lib/config-loader');
    ConfigLoader = configLoaderModule.ConfigLoader || configLoaderModule;
    // Pass mocked fs to constructor for testing
    configLoader = new ConfigLoader(fs);
  });
  
  afterEach(() => {
    if (configLoader && configLoader.stopWatching) {
      configLoader.stopWatching();
    }
  });

  describe('constructor', () => {
    test('should initialize with null config and path', () => {
      expect(configLoader.config).toBeNull();
      expect(configLoader.configPath).toBeNull();
      expect(configLoader.watchers).toEqual([]);
    });
  });

  describe('load', () => {
    test('should load config from custom path', () => {
      const customPath = '/custom/config.json';
      const mockConfig = { mode: { enabled: true } };
      
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue(JSON.stringify(mockConfig));
      
      const result = configLoader.load(customPath);
      
      expect(fs.existsSync).toHaveBeenCalledWith(customPath);
      expect(fs.readFileSync).toHaveBeenCalledWith(customPath, 'utf8');
      expect(result).toEqual(mockConfig);
      expect(configLoader.configPath).toBe(customPath);
    });

    test('should load config from environment variable', () => {
      const envPath = '/env/config.json';
      const mockConfig = { mode: { enabled: true } };
      
      process.env.FIREWALL_CONFIG = envPath;
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue(JSON.stringify(mockConfig));
      
      const result = configLoader.load();
      
      expect(result).toEqual(mockConfig);
      delete process.env.FIREWALL_CONFIG;
    });

    test('should try common locations when no custom path', () => {
      fs.existsSync.mockImplementation((path) => {
        return path.includes('.firewall-config.json');
      });
      fs.readFileSync.mockReturnValue(JSON.stringify({ test: true }));
      
      const result = configLoader.load();
      
      expect(fs.existsSync).toHaveBeenCalled();
      expect(result).toHaveProperty('test', true);
    });

    test('should return defaults when no config file found', () => {
      fs.existsSync.mockReturnValue(false);
      const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      const result = configLoader.load();
      
      expect(result).toHaveProperty('mode');
      expect(result).toHaveProperty('filesystem');
      expect(result).toHaveProperty('network');
      expect(consoleWarnSpy).toHaveBeenCalled();
      
      consoleWarnSpy.mockRestore();
    });

    test('should handle JSON parse error', () => {
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue('invalid json');
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      const result = configLoader.load('/path/to/config.json');
      
      expect(result).toHaveProperty('mode');
      expect(consoleErrorSpy).toHaveBeenCalled();
      
      consoleErrorSpy.mockRestore();
    });
  });

  describe('readConfig', () => {
    test('should read and parse config file', () => {
      const mockConfig = { test: 'value' };
      fs.readFileSync.mockReturnValue(JSON.stringify(mockConfig));
      const consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
      
      const result = configLoader.readConfig('/path/config.json');
      
      expect(result).toEqual(mockConfig);
      expect(configLoader.config).toEqual(mockConfig);
      expect(consoleLogSpy).toHaveBeenCalled();
      
      consoleLogSpy.mockRestore();
    });

    test('should return defaults on read error', () => {
      fs.readFileSync.mockImplementation(() => {
        throw new Error('Read error');
      });
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      const result = configLoader.readConfig('/path/config.json');
      
      expect(result).toHaveProperty('mode');
      expect(consoleErrorSpy).toHaveBeenCalled();
      
      consoleErrorSpy.mockRestore();
    });
  });

  describe('getDefaults', () => {
    test('should return default configuration', () => {
      const defaults = configLoader.getDefaults();
      
      expect(defaults).toHaveProperty('mode');
      expect(defaults.mode).toHaveProperty('enabled', true);
      expect(defaults).toHaveProperty('filesystem');
      expect(defaults).toHaveProperty('network');
      expect(defaults).toHaveProperty('trustedModules');
      expect(defaults).toHaveProperty('exceptions');
      expect(defaults).toHaveProperty('behavioral');
      expect(defaults).toHaveProperty('reporting');
    });

    test('should return valid default structure', () => {
      const defaults = configLoader.getDefaults();
      
      expect(Array.isArray(defaults.filesystem.blockedReadPaths)).toBe(true);
      expect(Array.isArray(defaults.filesystem.blockedWritePaths)).toBe(true);
      expect(Array.isArray(defaults.trustedModules)).toBe(true);
      expect(typeof defaults.exceptions.modules).toBe('object');
    });
  });

  describe('get', () => {
    test('should return entire config when no key provided', () => {
      const mockConfig = { test: 'value' };
      configLoader.config = mockConfig;
      
      const result = configLoader.get();
      
      expect(result).toEqual(mockConfig);
    });

    test('should return nested value for dot notation key', () => {
      configLoader.config = {
        network: {
          enabled: true,
          mode: 'monitor'
        }
      };
      
      const result = configLoader.get('network.enabled');
      
      expect(result).toBe(true);
    });

    test('should return undefined for non-existent key', () => {
      configLoader.config = { test: 'value' };
      
      const result = configLoader.get('nonexistent.key');
      
      expect(result).toBeUndefined();
    });

    test('should load config if not already loaded', () => {
      fs.existsSync.mockReturnValue(false);
      
      const result = configLoader.get('mode');
      
      expect(configLoader.config).not.toBeNull();
    });
  });

  describe('set', () => {
    test('should set simple key value', () => {
      configLoader.config = {};
      fs.writeFileSync.mockImplementation(() => {});
      
      configLoader.set('testKey', 'testValue');
      
      expect(configLoader.config.testKey).toBe('testValue');
    });

    test('should set nested key value', () => {
      configLoader.config = {};
      fs.writeFileSync.mockImplementation(() => {});
      
      configLoader.set('network.enabled', false);
      
      expect(configLoader.config.network.enabled).toBe(false);
    });

    test('should create intermediate objects for nested keys', () => {
      configLoader.config = {};
      fs.writeFileSync.mockImplementation(() => {});
      
      configLoader.set('deep.nested.value', 'test');
      
      expect(configLoader.config.deep.nested.value).toBe('test');
    });

    test('should call save after setting value', () => {
      configLoader.config = {};
      configLoader.configPath = '/path/config.json';
      fs.writeFileSync.mockImplementation(() => {});
      const consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
      
      const result = configLoader.set('key', 'value');
      
      expect(result).toBe(true);
      expect(fs.writeFileSync).toHaveBeenCalled();
      
      consoleLogSpy.mockRestore();
    });
  });

  describe('save', () => {
    test('should save config to file', () => {
      configLoader.config = { test: 'value' };
      configLoader.configPath = '/path/config.json';
      fs.writeFileSync.mockImplementation(() => {});
      const consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
      
      const result = configLoader.save();
      
      expect(result).toBe(true);
      expect(fs.writeFileSync).toHaveBeenCalledWith(
        '/path/config.json',
        expect.any(String)
      );
      
      consoleLogSpy.mockRestore();
    });

    test('should create config path if not set', () => {
      configLoader.config = { test: 'value' };
      configLoader.configPath = null;
      fs.writeFileSync.mockImplementation(() => {});
      
      configLoader.save();
      
      expect(configLoader.configPath).toContain('.firewall-config.json');
    });

    test('should handle save error', () => {
      configLoader.config = { test: 'value' };
      configLoader.configPath = '/path/config.json';
      fs.writeFileSync.mockImplementation(() => {
        throw new Error('Write error');
      });
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      const result = configLoader.save();
      
      expect(result).toBe(false);
      expect(consoleErrorSpy).toHaveBeenCalled();
      
      consoleErrorSpy.mockRestore();
    });
  });

  describe('addException', () => {
    test('should add exception for package', () => {
      configLoader.config = null;
      fs.existsSync.mockReturnValue(false);
      fs.writeFileSync.mockImplementation(() => {});
      const consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
      
      const exception = { allowFilesystem: ['/tmp'] };
      const result = configLoader.addException('test-package', exception);
      
      expect(configLoader.config.exceptions.modules['test-package']).toEqual(exception);
      expect(result).toBe(true);
      
      consoleLogSpy.mockRestore();
    });

    test('should create exceptions structure if not exists', () => {
      configLoader.config = {};
      fs.writeFileSync.mockImplementation(() => {});
      
      configLoader.addException('pkg', { test: true });
      
      expect(configLoader.config.exceptions).toBeDefined();
      expect(configLoader.config.exceptions.modules).toBeDefined();
    });
  });

  describe('getException', () => {
    test('should return exception for package', () => {
      const exception = { allowFilesystem: ['/tmp'] };
      configLoader.config = {
        exceptions: {
          modules: {
            'test-pkg': exception
          }
        }
      };
      
      const result = configLoader.getException('test-pkg');
      
      expect(result).toEqual(exception);
    });

    test('should return undefined for non-existent exception', () => {
      configLoader.config = {
        exceptions: { modules: {} }
      };
      
      const result = configLoader.getException('nonexistent');
      
      expect(result).toBeUndefined();
    });

    test('should load config if not loaded', () => {
      configLoader.config = null;
      fs.existsSync.mockReturnValue(false);
      
      const result = configLoader.getException('test');
      
      expect(configLoader.config).not.toBeNull();
    });
  });

  describe('hasException', () => {
    beforeEach(() => {
      configLoader.config = {
        exceptions: {
          modules: {
            'test-pkg': {
              allowFilesystem: ['/tmp', '/var'],
              allowNetwork: ['example.com'],
              allowCommands: ['ls', 'cat']
            }
          }
        }
      };
    });

    test('should return true for filesystem exception match', () => {
      const result = configLoader.hasException('test-pkg', 'filesystem', '/tmp/file');
      expect(result).toBe(true);
    });

    test('should return false for filesystem exception non-match', () => {
      const result = configLoader.hasException('test-pkg', 'filesystem', '/home/file');
      expect(result).toBe(false);
    });

    test('should return true for network exception match', () => {
      const result = configLoader.hasException('test-pkg', 'network', 'https://example.com');
      expect(result).toBe(true);
    });

    test('should return false for network exception non-match', () => {
      const result = configLoader.hasException('test-pkg', 'network', 'https://other.com');
      expect(result).toBe(false);
    });

    test('should return true for command exception match', () => {
      const result = configLoader.hasException('test-pkg', 'command', 'ls');
      expect(result).toBe(true);
    });

    test('should return false for command exception non-match', () => {
      const result = configLoader.hasException('test-pkg', 'command', 'rm');
      expect(result).toBe(false);
    });

    test('should return false for non-existent package', () => {
      const result = configLoader.hasException('nonexistent', 'filesystem', '/tmp');
      expect(result).toBe(false);
    });

    test('should return false for unknown type', () => {
      const result = configLoader.hasException('test-pkg', 'unknown', 'value');
      expect(result).toBe(false);
    });
  });

  describe('reload', () => {
    test('should reload config from file', () => {
      const mockConfig = { reloaded: true };
      configLoader.configPath = '/path/config.json';
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue(JSON.stringify(mockConfig));
      const consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
      
      const result = configLoader.reload();
      
      expect(result).toEqual(mockConfig);
      expect(consoleLogSpy).toHaveBeenCalledWith(expect.stringContaining('Reloading'));
      
      consoleLogSpy.mockRestore();
    });
  });

  describe('watch', () => {
    test('should watch config file for changes', () => {
      const mockWatcher = { close: jest.fn() };
      configLoader.configPath = '/path/config.json';
      fs.watch.mockReturnValue(mockWatcher);
      const consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
      
      configLoader.watch();
      
      expect(fs.watch).toHaveBeenCalledWith(
        '/path/config.json',
        expect.any(Function)
      );
      expect(configLoader.watchers).toContain(mockWatcher);
      
      consoleLogSpy.mockRestore();
    });

    test('should not watch if no config path', () => {
      configLoader.configPath = null;
      
      configLoader.watch();
      
      expect(fs.watch).not.toHaveBeenCalled();
    });

    test('should call callback on file change', () => {
      const mockCallback = jest.fn();
      const mockConfig = { changed: true };
      let changeHandler;
      
      configLoader.configPath = '/path/config.json';
      fs.watch.mockImplementation((path, handler) => {
        changeHandler = handler;
        return { close: jest.fn() };
      });
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue(JSON.stringify(mockConfig));
      const consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
      
      configLoader.watch(mockCallback);
      changeHandler('change');
      
      expect(mockCallback).toHaveBeenCalledWith(mockConfig);
      
      consoleLogSpy.mockRestore();
    });

    test('should handle watch error', () => {
      configLoader.configPath = '/path/config.json';
      fs.watch.mockImplementation(() => {
        throw new Error('Watch error');
      });
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      configLoader.watch();
      
      expect(consoleErrorSpy).toHaveBeenCalled();
      
      consoleErrorSpy.mockRestore();
    });
  });

  describe('stopWatching', () => {
    test('should close all watchers', () => {
      const mockWatcher1 = { close: jest.fn() };
      const mockWatcher2 = { close: jest.fn() };
      
      configLoader.watchers = [mockWatcher1, mockWatcher2];
      configLoader.stopWatching();
      
      expect(mockWatcher1.close).toHaveBeenCalled();
      expect(mockWatcher2.close).toHaveBeenCalled();
      expect(configLoader.watchers).toEqual([]);
    });
  });
});
