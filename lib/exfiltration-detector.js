/**
 * Data Exfiltration Detector
 * Detects supply chain attacks trying to steal credentials/data
 * 
 * FOCUS: Prevent actual harm (data theft), not false positives (legitimate file reads)
 */

class ExfiltrationDetector {
  constructor() {
    // Track recent sensitive file reads with timestamps
    this.recentSensitiveReads = new Map(); // path -> timestamp
    this.suspiciousCorrelations = [];
    
    // Sensitive file patterns
    this.sensitivePatterns = [
      '/.ssh/',
      '/.aws/',
      '/.gcp/',
      '/.kube/',
      '.env',
      'credentials',
      'secrets',
      'id_rsa',
      'id_dsa',
      'id_ecdsa',
      'id_ed25519',
      '.pem',
      '.key'
    ];
    
    // Credential patterns to detect in network payloads
    this.credentialPatterns = [
      /AKIA[0-9A-Z]{16}/,                    // AWS Access Key
      /-----BEGIN.*PRIVATE KEY-----/,         // Private keys
      /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+/, // JWT tokens
      /ghp_[a-zA-Z0-9]{36}/,                  // GitHub Personal Access Token
      /gho_[a-zA-Z0-9]{36}/,                  // GitHub OAuth Token
      /mongodb(\+srv)?:\/\/[^@]+@/,           // MongoDB connection strings
      /postgres:\/\/[^@]+@/,                  // PostgreSQL connection strings
      /mysql:\/\/[^@]+@/,                     // MySQL connection strings
      /sk_live_[0-9a-zA-Z]{24,}/,            // Stripe Live Key
      /sk_test_[0-9a-zA-Z]{24,}/,            // Stripe Test Key
      /api[_-]?key.*[:=]\s*['"][^'"]+['"]/i, // Generic API keys
      /secret.*[:=]\s*['"][^'"]+['"]/i,      // Generic secrets
      /password.*[:=]\s*['"][^'"]+['"]/i,    // Passwords
      /token.*[:=]\s*['"][^'"]+['"]/i        // Tokens
    ];
  }
  
  /**
   * Track a sensitive file read
   * @param {string} filePath - The file that was read
   */
  trackSensitiveFileRead(filePath) {
    if (!this.isSensitiveFile(filePath)) {
      return;
    }
    
    // Store read with timestamp
    this.recentSensitiveReads.set(filePath, Date.now());
    
    // Clean up old entries (older than 30 seconds)
    const cutoff = Date.now() - 30000;
    for (const [path, timestamp] of this.recentSensitiveReads) {
      if (timestamp < cutoff) {
        this.recentSensitiveReads.delete(path);
      }
    }
  }
  
  /**
   * Check if a network request might be exfiltrating data
   * @param {string} url - The URL being requested
   * @param {string} method - HTTP method
   * @param {*} body - Request body/payload
   * @returns {Object} Detection result
   */
  checkNetworkRequest(url, method = 'GET', body = null) {
    const threats = [];
    
    // 1. Check if this follows a recent sensitive file read (timing correlation)
    if (this.recentSensitiveReads.size > 0) {
      const now = Date.now();
      const recentReads = Array.from(this.recentSensitiveReads.entries())
        .filter(([_, timestamp]) => now - timestamp < 5000) // Within 5 seconds
        .map(([path]) => path);
      
      if (recentReads.length > 0 && (method === 'POST' || method === 'PUT')) {
        threats.push({
          type: 'TIMING_CORRELATION',
          severity: 'CRITICAL',
          reason: `Network ${method} within 5s of reading: ${recentReads.join(', ')}`,
          url,
          sensitiveFiles: recentReads
        });
      }
    }
    
    // 2. Check for credential patterns in request body
    if (body) {
      const bodyStr = this.stringifyBody(body);
      const detectedCredentials = this.detectCredentials(bodyStr);
      
      if (detectedCredentials.length > 0) {
        threats.push({
          type: 'CREDENTIAL_EXFILTRATION',
          severity: 'CRITICAL',
          reason: `Credentials detected in ${method} request`,
          url,
          credentialTypes: detectedCredentials
        });
      }
    }
    
    // 3. During install phase, external network is HIGHLY suspicious
    if (this.isInstallPhase() && !this.isTrustedDomain(url)) {
      threats.push({
        type: 'INSTALL_PHASE_EXTERNAL_NETWORK',
        severity: 'HIGH',
        reason: 'External network request during package installation',
        url
      });
    }
    
    return {
      suspicious: threats.length > 0,
      threats
    };
  }
  
  /**
   * Check if a file path is sensitive
   */
  isSensitiveFile(filePath) {
    return this.sensitivePatterns.some(pattern => filePath.includes(pattern));
  }
  
  /**
   * Detect credentials in text
   */
  detectCredentials(text) {
    const found = [];
    for (const pattern of this.credentialPatterns) {
      if (pattern.test(text)) {
        found.push(pattern.source);
      }
    }
    return found;
  }
  
  /**
   * Check if we're in npm install/postinstall phase
   */
  isInstallPhase() {
    const event = process.env.npm_lifecycle_event;
    return event && (
      event.includes('install') ||
      event.includes('preinstall') ||
      event.includes('postinstall')
    );
  }
  
  /**
   * Check if domain is trusted (npm registry, GitHub, etc)
   */
  isTrustedDomain(url) {
    const trustedDomains = [
      'registry.npmjs.org',
      'registry.yarnpkg.com',
      'github.com',
      'githubusercontent.com',
      'registry.npm.taobao.org',
      'npmjs.com'
    ];
    
    return trustedDomains.some(domain => url.includes(domain));
  }
  
  /**
   * Convert request body to string for inspection
   */
  stringifyBody(body) {
    if (typeof body === 'string') return body;
    if (Buffer.isBuffer(body)) return body.toString('utf8');
    if (typeof body === 'object') return JSON.stringify(body);
    return String(body);
  }
  
  /**
   * Get detection statistics
   */
  getStats() {
    return {
      recentSensitiveReads: this.recentSensitiveReads.size,
      correlations: this.suspiciousCorrelations.length
    };
  }
}

// Singleton instance
let instance = null;

function getInstance() {
  if (!instance) {
    instance = new ExfiltrationDetector();
  }
  return instance;
}

module.exports = {
  ExfiltrationDetector,
  getInstance
};
