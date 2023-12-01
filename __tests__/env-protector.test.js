/**
 * Tests for EnvProtector
 * Verifies environment variable protection functionality
 */

const { EnvProtector } = require('../lib/env-protector');

describe('EnvProtector', () => {
  let originalEnv;
  
  beforeEach(() => {
    originalEnv = { ...process.env };
    jest.clearAllMocks();
  });
  
  afterEach(() => {
    process.env = originalEnv;
  });
  
  describe('constructor', () => {
    it('should initialize with config', () => {
      const config = {
        environment: {
          protectedVariables: ['API_KEY', 'SECRET_TOKEN'],
          allowTrustedModulesAccess: true
        }
      };
      
      const protector = new EnvProtector(config, true);
      
      expect(protector.enabled).toBe(true);
      expect(protector.protectedVars).toEqual(['API_KEY', 'SECRET_TOKEN']);
      expect(protector.allowTrustedModules).toBe(true);
    });
    
    it('should be disabled when no protected variables', () => {
      const config = {
        environment: {
          protectedVariables: []
        }
      };
      
      const protector = new EnvProtector(config, true);
      
      expect(protector.enabled).toBe(false);
    });
  });
  
  describe('isProtected', () => {
    it('should match exact variable names', () => {
      const config = {
        environment: {
          protectedVariables: ['API_KEY', 'SECRET_TOKEN']
        }
      };
      
      const protector = new EnvProtector(config, true);
      
      expect(protector.isProtected('API_KEY')).toBe(true);
      expect(protector.isProtected('api_key')).toBe(true); // case insensitive
      expect(protector.isProtected('NORMAL_VAR')).toBe(false);
    });
    
    it('should match wildcard patterns', () => {
      const config = {
        environment: {
          protectedVariables: ['AWS_*', '*_TOKEN']
        }
      };
      
      const protector = new EnvProtector(config, true);
      
      expect(protector.isProtected('AWS_ACCESS_KEY_ID')).toBe(true);
      expect(protector.isProtected('AWS_SECRET_ACCESS_KEY')).toBe(true);
      expect(protector.isProtected('GITHUB_TOKEN')).toBe(true);
      expect(protector.isProtected('NORMAL_VAR')).toBe(false);
    });
  });
  
  describe('checkAccess', () => {
    it('should allow access with no package context', () => {
      const config = {
        environment: {
          protectedVariables: ['API_KEY']
        }
      };
      
      const protector = new EnvProtector(config, true);
      const result = protector.checkAccess('API_KEY', null);
      
      expect(result.allowed).toBe(true);
      expect(result.reason).toBe('no_package_context');
    });
    
    it('should allow trusted modules', () => {
      const config = {
        environment: {
          protectedVariables: ['API_KEY'],
          allowTrustedModulesAccess: true
        }
      };
      
      const mockFirewall = {
        isTrustedModule: jest.fn().mockReturnValue(true)
      };
      
      const protector = new EnvProtector(config, true);
      protector.firewall = mockFirewall;
      
      const result = protector.checkAccess('API_KEY', 'aws-sdk');
      
      expect(result.allowed).toBe(true);
      expect(result.reason).toBe('trusted_module');
      expect(mockFirewall.isTrustedModule).toHaveBeenCalledWith('aws-sdk');
    });
    
    it('should allow exceptions', () => {
      const config = {
        environment: {
          protectedVariables: ['API_KEY']
        },
        exceptions: {
          modules: {
            'my-package': {
              allowEnvironment: ['API_KEY']
            }
          }
        }
      };
      
      const protector = new EnvProtector(config, true);
      const result = protector.checkAccess('API_KEY', 'my-package');
      
      expect(result.allowed).toBe(true);
      expect(result.reason).toBe('exception');
    });
    
    it('should block unauthorized access', () => {
      const config = {
        environment: {
          protectedVariables: ['API_KEY'],
          allowTrustedModulesAccess: false
        }
      };
      
      const protector = new EnvProtector(config, true);
      const result = protector.checkAccess('API_KEY', 'untrusted-package');
      
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('protected_variable');
      expect(result.severity).toBe('high');
    });
  });
  
  describe('logAccess', () => {
    it('should log access attempts', () => {
      const config = {
        environment: {
          protectedVariables: ['API_KEY']
        },
        reporting: {
          alertOnSuspicious: false
        }
      };
      
      const protector = new EnvProtector(config, true);
      const check = { allowed: false, reason: 'protected_variable' };
      
      protector.logAccess('API_KEY', 'evil-package', 'READ', check);
      
      expect(protector.accessLog.length).toBe(1);
      expect(protector.accessLog[0]).toMatchObject({
        variable: 'API_KEY',
        package: 'evil-package',
        operation: 'READ',
        allowed: false
      });
    });
    
    it('should maintain log size limit', () => {
      const config = {
        environment: {
          protectedVariables: ['API_KEY']
        }
      };
      
      const protector = new EnvProtector(config, true);
      const check = { allowed: true, reason: 'test' };
      
      for (let i = 0; i < 150; i++) {
        protector.logAccess('API_KEY', 'package', 'READ', check);
      }
      
      expect(protector.accessLog.length).toBeLessThanOrEqual(100);
    });
  });
  
  describe('getStats', () => {
    it('should return access statistics', () => {
      const config = {
        environment: {
          protectedVariables: ['API_KEY']
        }
      };
      
      const protector = new EnvProtector(config, true);
      
      protector.logAccess('API_KEY', 'pkg1', 'READ', { allowed: true, reason: 'test' });
      protector.logAccess('API_KEY', 'pkg2', 'READ', { allowed: false, reason: 'blocked' });
      protector.logAccess('API_KEY', 'pkg3', 'WRITE', { allowed: false, reason: 'blocked' });
      
      const stats = protector.getStats();
      
      expect(stats.totalAccesses).toBe(3);
      expect(stats.blocked).toBe(2);
      expect(stats.recentAccesses.length).toBe(3);
    });
  });
});
