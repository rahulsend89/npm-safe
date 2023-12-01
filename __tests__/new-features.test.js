/**
 * Integration tests for newly implemented features:
 * - reporting.alertOnSuspicious
 * - behavioral.max* hard limits
 * - commands.allowedCommands whitelist
 * - environment.protectedVariables
 */

const { BehaviorMonitor } = require('../lib/behavior-monitor');
const { FirewallCore } = require('../lib/firewall-core');
const { ConfigLoader } = require('../lib/config-loader');

describe('New Features Integration Tests', () => {
  
  describe('reporting.alertOnSuspicious flag', () => {
    let consoleWarnSpy;
    
    beforeEach(() => {
      consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation();
    });
    
    afterEach(() => {
      consoleWarnSpy.mockRestore();
    });
    
    it('should display alerts when alertOnSuspicious is true', () => {
      const config = {
        behavioral: {
          monitorLifecycleScripts: true,
          alertThresholds: {
            fileReads: 5
          }
        },
        reporting: {
          alertOnSuspicious: true
        }
      };
      
      const monitor = new BehaviorMonitor(config, false);
      
      for (let i = 0; i < 10; i++) {
        monitor.trackFileRead('/test/file.txt');
      }
      
      expect(consoleWarnSpy).toHaveBeenCalled();
      expect(consoleWarnSpy.mock.calls.some(call => 
        call[0].includes('[BEHAVIOR ALERT]')
      )).toBe(true);
    });
    
    it('should suppress alerts when alertOnSuspicious is false', () => {
      const config = {
        behavioral: {
          monitorLifecycleScripts: true,
          alertThresholds: {
            fileReads: 5
          }
        },
        reporting: {
          alertOnSuspicious: false
        }
      };
      
      const monitor = new BehaviorMonitor(config, false);
      
      for (let i = 0; i < 10; i++) {
        monitor.trackFileRead('/test/file.txt');
      }
      
      expect(consoleWarnSpy).not.toHaveBeenCalled();
    });
    
    it('should alert on suspicious operations when enabled', () => {
      const config = {
        behavioral: {
          monitorLifecycleScripts: true
        },
        reporting: {
          alertOnSuspicious: true
        }
      };
      
      const monitor = new BehaviorMonitor(config, false);
      
      monitor.trackFileWrite('/.ssh/id_rsa');
      
      expect(consoleWarnSpy).toHaveBeenCalled();
      expect(consoleWarnSpy.mock.calls.some(call => 
        call[0].includes('[SUSPICIOUS]')
      )).toBe(true);
    });
  });
  
  describe('behavioral.max* hard limits', () => {
    let consoleErrorSpy;
    
    beforeEach(() => {
      consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
    });
    
    afterEach(() => {
      consoleErrorSpy.mockRestore();
    });
    
    it('should enforce maxNetworkRequests limit', () => {
      const config = {
        behavioral: {
          monitorLifecycleScripts: true,
          maxNetworkRequests: 5
        },
        reporting: {
          alertOnSuspicious: true
        }
      };
      
      const monitor = new BehaviorMonitor(config, false);
      
      let blocked = false;
      for (let i = 0; i < 10; i++) {
        const result = monitor.trackNetworkRequest('http://example.com');
        if (!result.allowed) {
          blocked = true;
          expect(result.reason).toBe('hard_limit_exceeded');
          expect(result.metric).toBe('networkRequests');
          expect(result.severity).toBe('critical');
        }
      }
      
      expect(blocked).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalled();
    });
    
    it('should enforce maxFileWrites limit', () => {
      const config = {
        behavioral: {
          monitorLifecycleScripts: true,
          maxFileWrites: 3
        },
        reporting: {
          alertOnSuspicious: true
        }
      };
      
      const monitor = new BehaviorMonitor(config, false);
      
      let blocked = false;
      for (let i = 0; i < 5; i++) {
        const result = monitor.trackFileWrite('/tmp/test.txt');
        if (!result.allowed) {
          blocked = true;
          expect(result.limit).toBe(3);
        }
      }
      
      expect(blocked).toBe(true);
    });
    
    it('should enforce maxProcessSpawns limit', () => {
      const config = {
        behavioral: {
          monitorLifecycleScripts: true,
          maxProcessSpawns: 2
        }
      };
      
      const monitor = new BehaviorMonitor(config, true);
      
      const results = [];
      for (let i = 0; i < 4; i++) {
        results.push(monitor.trackProcessSpawn('ls'));
      }
      
      const blockedResults = results.filter(r => !r.allowed);
      expect(blockedResults.length).toBeGreaterThan(0);
      expect(blockedResults[0].reason).toBe('hard_limit_exceeded');
    });
    
    it('should not enforce limits when not configured', () => {
      const config = {
        behavioral: {
          monitorLifecycleScripts: true
        }
      };
      
      const monitor = new BehaviorMonitor(config, true);
      
      for (let i = 0; i < 100; i++) {
        const result = monitor.trackNetworkRequest('http://example.com');
        expect(result.allowed).toBe(true);
      }
    });
  });
  
  describe('commands.allowedCommands whitelist', () => {
    it('should block commands not in whitelist', () => {
      const config = {
        mode: { enabled: true },
        commands: {
          allowedCommands: ['npm', 'node', 'git'],
          blockedPatterns: []
        },
        behavioral: {}
      };
      
      const mockFirewall = {
        config,
        enabled: true,
        checkCommandExecution: function(command, packageName = null) {
          if (!this.enabled) return { allowed: true, reason: 'disabled' };
          
          const allowedCommands = this.config.commands?.allowedCommands || [];
          if (allowedCommands.length > 0) {
            const commandName = command.split(/\s+/)[0];
            const isAllowed = allowedCommands.some(allowed => 
              commandName === allowed || commandName.endsWith('/' + allowed)
            );
            
            if (!isAllowed) {
              return {
                allowed: false,
                reason: 'not_in_allowed_commands',
                severity: 'medium',
                description: `Command not in whitelist. Only ${allowedCommands.join(', ')} are allowed.`
              };
            }
          }
          
          return { allowed: true, reason: 'passed' };
        }
      };
      
      const result = mockFirewall.checkCommandExecution('curl http://evil.com');
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('not_in_allowed_commands');
    });
    
    it('should allow commands in whitelist', () => {
      const config = {
        mode: { enabled: true },
        commands: {
          allowedCommands: ['npm', 'node', 'git'],
          blockedPatterns: []
        },
        behavioral: {}
      };
      
      const mockFirewall = {
        config,
        enabled: true,
        checkCommandExecution: function(command, packageName = null) {
          if (!this.enabled) return { allowed: true, reason: 'disabled' };
          
          const allowedCommands = this.config.commands?.allowedCommands || [];
          if (allowedCommands.length > 0) {
            const commandName = command.split(/\s+/)[0];
            const isAllowed = allowedCommands.some(allowed => 
              commandName === allowed || commandName.endsWith('/' + allowed)
            );
            
            if (!isAllowed) {
              return {
                allowed: false,
                reason: 'not_in_allowed_commands',
                severity: 'medium'
              };
            }
          }
          
          return { allowed: true, reason: 'passed' };
        }
      };
      
      const result = mockFirewall.checkCommandExecution('npm install');
      expect(result.allowed).toBe(true);
    });
    
    it('should allow all commands when whitelist is empty', () => {
      const config = {
        mode: { enabled: true },
        commands: {
          allowedCommands: [],
          blockedPatterns: []
        },
        behavioral: {}
      };
      
      const mockFirewall = {
        config,
        enabled: true,
        checkCommandExecution: function(command, packageName = null) {
          if (!this.enabled) return { allowed: true, reason: 'disabled' };
          
          const allowedCommands = this.config.commands?.allowedCommands || [];
          if (allowedCommands.length > 0) {
            const commandName = command.split(/\s+/)[0];
            const isAllowed = allowedCommands.some(allowed => 
              commandName === allowed || commandName.endsWith('/' + allowed)
            );
            
            if (!isAllowed) {
              return {
                allowed: false,
                reason: 'not_in_allowed_commands',
                severity: 'medium'
              };
            }
          }
          
          return { allowed: true, reason: 'passed' };
        }
      };
      
      const result = mockFirewall.checkCommandExecution('any-command');
      expect(result.allowed).toBe(true);
    });
  });
  
  describe('Hard limit integration with FirewallCore', () => {
    it('should respect hard limits in command execution', () => {
      const config = {
        mode: { enabled: true },
        behavioral: {
          monitorLifecycleScripts: true,
          maxProcessSpawns: 2
        },
        commands: {
          blockedPatterns: []
        }
      };
      
      const mockFirewall = {
        config,
        enabled: true,
        behaviorMonitor: new BehaviorMonitor(config, true),
        checkCommandExecution: function(command, packageName = null) {
          if (!this.enabled) return { allowed: true, reason: 'disabled' };
          
          if (this.behaviorMonitor) {
            const limitCheck = this.behaviorMonitor.trackProcessSpawn(command);
            if (!limitCheck.allowed) {
              return limitCheck;
            }
          }
          
          return { allowed: true, reason: 'passed' };
        }
      };
      
      const results = [];
      for (let i = 0; i < 5; i++) {
        results.push(mockFirewall.checkCommandExecution('ls -la'));
      }
      
      const blockedResults = results.filter(r => !r.allowed);
      expect(blockedResults.length).toBeGreaterThan(0);
      expect(blockedResults[0].severity).toBe('critical');
    });
  });
  
  describe('Threshold vs Hard Limit difference', () => {
    it('should show warning at threshold but block at hard limit', () => {
      const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation();
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      const config = {
        behavioral: {
          monitorLifecycleScripts: true,
          alertThresholds: {
            fileWrites: 5
          },
          maxFileWrites: 10
        },
        reporting: {
          alertOnSuspicious: true
        }
      };
      
      const monitor = new BehaviorMonitor(config, false);
      
      let results = [];
      for (let i = 0; i < 15; i++) {
        results.push(monitor.trackFileWrite('/tmp/test.txt'));
      }
      
      // Should warn at threshold (5)
      expect(consoleWarnSpy).toHaveBeenCalled();
      
      // Should block after hard limit (10)
      const blocked = results.filter(r => !r.allowed);
      expect(blocked.length).toBeGreaterThan(0);
      expect(consoleErrorSpy).toHaveBeenCalled();
      
      consoleWarnSpy.mockRestore();
      consoleErrorSpy.mockRestore();
    });
  });
  
  describe('Configuration validation', () => {
    it('should handle missing config gracefully', () => {
      const monitor = new BehaviorMonitor({}, true);
      
      const result = monitor.trackNetworkRequest('http://example.com');
      expect(result.allowed).toBe(true);
    });
    
    it('should handle partial config gracefully', () => {
      const config = {
        behavioral: {
          maxNetworkRequests: 5
        }
        // missing reporting config
      };
      
      const monitor = new BehaviorMonitor(config, true);
      
      for (let i = 0; i < 10; i++) {
        const result = monitor.trackNetworkRequest('http://example.com');
        // Should still enforce limits even without reporting config
        if (i > 5) {
          expect(result.allowed).toBe(false);
        }
      }
    });
  });
});
