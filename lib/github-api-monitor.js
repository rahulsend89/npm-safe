/**
 * GitHub API Monitor
 * Protects against Shai-Hulud-style attacks via GitHub API
 * - Monitors repository creation
 * - Monitors workflow creation
 * - Blocks suspicious repo names and workflow patterns
 */

const fs = require('fs');
const path = require('path');
const { makeImmutableProperties } = require('./immutable-property');

const originalFs = {
  appendFileSync: fs.appendFileSync
};

class GitHubApiMonitor {
  constructor(config, silent = false, fsOverride = null) {
    // SECURITY: Make critical properties immutable
    const frozenConfig = Object.freeze(config || {});
    makeImmutableProperties(this, {
      config: frozenConfig,
      enabled: !!(frozenConfig.githubApi?.monitorRepoCreation || frozenConfig.githubApi?.monitorWorkflowCreation),
      silent: silent
    });
    this.fs = fsOverride || originalFs;
    
    this.blockedRepoNames = this.config.githubApi?.blockedRepoNames || [];
    this.blockedWorkflowPatterns = this.config.githubApi?.blockedWorkflowPatterns || [];
    this.monitorRepoCreation = this.config.githubApi?.monitorRepoCreation !== false;
    this.monitorWorkflowCreation = this.config.githubApi?.monitorWorkflowCreation !== false;
    
    this.stats = {
      apiCalls: 0,
      repoCreationAttempts: 0,
      workflowCreationAttempts: 0,
      blocked: 0
    };
    
    this.activityLog = [];
    
    if (this.enabled && !this.silent) {
      console.log('[GitHub API Monitor] Protecting against GitHub-based attacks');
      if (this.monitorRepoCreation) {
        console.log(`[GitHub API Monitor] Blocking repo names: ${this.blockedRepoNames.join(', ')}`);
      }
      if (this.monitorWorkflowCreation) {
        console.log(`[GitHub API Monitor] Blocking workflow patterns: ${this.blockedWorkflowPatterns.join(', ')}`);
      }
    }
  }
  
  checkGitHubApiRequest(url, method, body, headers) {
    if (!this.enabled) {
      return { allowed: true, reason: 'disabled' };
    }
    
    if (!this.isGitHubApi(url)) {
      return { allowed: true, reason: 'not_github_api' };
    }
    
    this.stats.apiCalls++;
    
    const check = this.analyzeRequest(url, method, body, headers);
    
    if (!check.allowed) {
      this.stats.blocked++;
      this.logActivity('BLOCKED', url, method, check);
      
      if (!this.silent) {
        console.error('\n╔╗');
        console.error('   GITHUB API ATTACK DETECTED                     ');
        console.error('╚╝');
        console.error(`Type:     ${check.type}`);
        console.error(`URL:      ${url}`);
        console.error(`Reason:   ${check.reason}`);
        console.error(`Severity: ${check.severity}`);
        if (check.details) {
          console.error(`Details:  ${check.details}`);
        }
        console.error('\n');
      }
    } else {
      this.logActivity('ALLOWED', url, method, check);
    }
    
    return check;
  }
  
  isGitHubApi(url) {
    const githubDomains = [
      'api.github.com',
      'raw.githubusercontent.com'
    ];
    
    try {
      const parsedUrl = new URL(url.startsWith('http') ? url : `https://${url}`);
      const isGithubDomain = githubDomains.some(domain => parsedUrl.hostname.includes(domain));
      const isGithubApiPath = parsedUrl.hostname === 'github.com' && parsedUrl.pathname.startsWith('/api');
      return isGithubDomain || isGithubApiPath;
    } catch (e) {
      return false;
    }
  }
  
  analyzeRequest(url, method, body, headers) {
    try {
      const parsedUrl = new URL(url.startsWith('http') ? url : `https://${url}`);
      const pathname = parsedUrl.pathname;
      
      if (this.monitorRepoCreation && this.isRepoCreationRequest(pathname, method)) {
        return this.checkRepoCreation(body);
      }
      
      if (this.monitorWorkflowCreation && this.isWorkflowCreationRequest(pathname, method)) {
        return this.checkWorkflowCreation(pathname, body);
      }
      
      return { allowed: true, reason: 'normal_api_call' };
      
    } catch (e) {
      return { allowed: true, reason: 'parse_error', error: e.message };
    }
  }
  
  isRepoCreationRequest(pathname, method) {
    if (method !== 'POST') return false;
    
    return pathname === '/user/repos' || /^\/orgs\/[^/]+\/repos$/.test(pathname);
  }
  
  isWorkflowCreationRequest(pathname, method) {
    return (method === 'PUT' || method === 'POST') && (
      pathname.includes('/.github/workflows/') ||
      pathname.match(/\/repos\/[^/]+\/[^/]+\/contents\/\.github\/workflows\//)
    );
  }
  
  checkRepoCreation(body) {
    this.stats.repoCreationAttempts++;
    
    let repoData;
    try {
      repoData = typeof body === 'string' ? JSON.parse(body) : body;
    } catch (e) {
      return { allowed: true, reason: 'cannot_parse_body' };
    }
    
    const repoName = repoData?.name?.toLowerCase();
    
    if (!repoName) {
      return { allowed: true, reason: 'no_repo_name' };
    }
    
    for (const blockedName of this.blockedRepoNames) {
      const pattern = blockedName.toLowerCase();
      if (repoName === pattern || repoName.includes(pattern)) {
        return {
          allowed: false,
          type: 'REPO_CREATION',
          reason: 'blocked_repo_name',
          severity: 'critical',
          details: `Repository name "${repoName}" matches blocked pattern "${blockedName}"`,
          repoName: repoName
        };
      }
    }
    
    return { allowed: true, reason: 'repo_name_allowed', repoName };
  }
  
  checkWorkflowCreation(pathname, body) {
    this.stats.workflowCreationAttempts++;
    
    let workflowContent;
    try {
      const data = typeof body === 'string' ? JSON.parse(body) : body;
      workflowContent = data?.content || data?.message || body;
      
      if (Buffer.isBuffer(workflowContent)) {
        workflowContent = workflowContent.toString('utf8');
      } else if (typeof workflowContent === 'string' && workflowContent.match(/^[A-Za-z0-9+/=]+$/)) {
        workflowContent = Buffer.from(workflowContent, 'base64').toString('utf8');
      }
    } catch (e) {
      workflowContent = String(body);
    }
    
    const workflowPath = pathname.split('/').pop();
    
    for (const pattern of this.blockedWorkflowPatterns) {
      if (workflowPath.includes(pattern)) {
        return {
          allowed: false,
          type: 'WORKFLOW_CREATION',
          reason: 'blocked_workflow_filename',
          severity: 'high',
          details: `Workflow file "${workflowPath}" matches blocked pattern "${pattern}"`,
          workflow: workflowPath
        };
      }
      
      if (typeof workflowContent === 'string' && workflowContent.includes(pattern)) {
        return {
          allowed: false,
          type: 'WORKFLOW_CREATION',
          reason: 'blocked_workflow_content',
          severity: 'high',
          details: `Workflow content contains blocked pattern "${pattern}"`,
          workflow: workflowPath
        };
      }
    }
    
    if (typeof workflowContent === 'string' && this.containsSuspiciousWorkflowContent(workflowContent)) {
      return {
        allowed: false,
        type: 'WORKFLOW_CREATION',
        reason: 'suspicious_workflow_content',
        severity: 'high',
        details: 'Workflow contains suspicious patterns (self-hosted runners, secret exfiltration)',
        workflow: workflowPath
      };
    }
    
    return { allowed: true, reason: 'workflow_allowed', workflow: workflowPath };
  }
  
  containsSuspiciousWorkflowContent(content) {
    const suspiciousPatterns = [
      /runs-on:\s*self-hosted/i,
      /runs-on:\s*\[.*self-hosted.*\]/i,
      /curl.*\$\{\{\s*secrets\./i,
      /wget.*\$\{\{\s*secrets\./i,
      /echo.*\$\{\{\s*secrets\./i,
      /env.*\$\{\{\s*secrets\./i
    ];
    
    return suspiciousPatterns.some(pattern => pattern.test(content));
  }
  
  logActivity(status, url, method, check) {
    const entry = {
      timestamp: new Date().toISOString(),
      status,
      method,
      url,
      type: check.type || 'API_CALL',
      reason: check.reason,
      severity: check.severity
    };
    
    if (check.details) {
      entry.details = check.details;
    }
    
    this.activityLog.push(entry);
    
    if (this.activityLog.length > 100) {
      this.activityLog.shift();
    }
    
    const shouldLog = !check.allowed || this.config.reporting?.logLevel === 'verbose';
    if (shouldLog) {
      try {
        const logFile = this.config.reporting?.logFile || 'fs-firewall.log';
        const logLine = `[${entry.timestamp}] GITHUB_API | ${status} | ${JSON.stringify(entry)}\n`;
        this.fs.appendFileSync(logFile, logLine);
      } catch (e) {
        // Silent fail
      }
    }
  }
  
  getStats() {
    return {
      ...this.stats,
      recentActivity: this.activityLog.slice(-10)
    };
  }
  
  generateReport() {
    return {
      enabled: this.enabled,
      monitoring: {
        repoCreation: this.monitorRepoCreation,
        workflowCreation: this.monitorWorkflowCreation
      },
      blockedPatterns: {
        repoNames: this.blockedRepoNames,
        workflowPatterns: this.blockedWorkflowPatterns
      },
      stats: this.stats,
      recentActivity: this.activityLog
    };
  }
}

module.exports = { GitHubApiMonitor };
