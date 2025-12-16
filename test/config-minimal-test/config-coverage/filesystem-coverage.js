/**
 * Comprehensive Filesystem Config Coverage Tests
 * Tests EVERY filesystem config option (blocked and allowed)
 */

const {
  setupTestDir,
  cleanupTestDir,
  writeMinimalConfig,
  runWithFirewall,
  isBlocked,
  TestTracker,
  isWindows,
  isLinux,
  isMac
} = require('../utils');
const fs = require('fs');
const path = require('path');

async function runFilesystemCoverageTests() {
  const tracker = new TestTracker('filesystem-coverage');
  
  console.log('\n════════════════════════════════════════════════════════════');
  console.log('[FS-COV] FILESYSTEM CONFIG COVERAGE');
  console.log('════════════════════════════════════════════════════════════\n');
  
  // =========================================================================
  // BLOCKED READ PATHS - Test each one
  // =========================================================================
  console.log('--- Blocked Read Paths (Every Config Entry) ---\n');
  
  const blockedReadPaths = [
    // SSH Keys
    { path: '/.ssh/', file: 'id_rsa', platform: 'unix', desc: 'SSH private key' },
    { path: '/.ssh/', file: 'id_ed25519', platform: 'unix', desc: 'SSH ED25519 key' },
    
    // Cloud Provider Credentials
    { path: '/.aws/', file: 'credentials', platform: 'unix', desc: 'AWS credentials' },
    { path: '/.config/gcloud/', file: 'credentials.db', platform: 'unix', desc: 'GCP credentials' },
    { path: '/.azure/', file: 'azureProfile.json', platform: 'unix', desc: 'Azure profile' },
    
    // Kubernetes & Docker
    { path: '/.kube/', file: 'config', platform: 'unix', desc: 'Kubernetes config' },
    { path: '/.docker/', file: 'config.json', platform: 'unix', desc: 'Docker config' },
    
    // GPG Keys
    { path: '/.gnupg/', file: 'private-keys-v1.d/key.gpg', platform: 'unix', desc: 'GPG private key' },
    
    // System Files
    { path: '/etc/passwd', file: null, platform: 'unix', desc: 'System password file' },
    { path: '/etc/shadow', file: null, platform: 'unix', desc: 'System shadow file' },
    
    // Environment & Config Files
    { path: '/.env', file: null, platform: 'all', desc: 'Environment variables' },
    { path: '/.npmrc', file: null, platform: 'all', desc: 'NPM config with tokens' },
    { path: '/.gitconfig', file: null, platform: 'all', desc: 'Git config' },
    { path: '/.netrc', file: null, platform: 'unix', desc: 'Network credentials' },
    
    // Shell History (contains passwords/tokens)
    { path: '/.bash_history', file: null, platform: 'unix', desc: 'Bash history' },
    { path: '/.zsh_history', file: null, platform: 'unix', desc: 'Zsh history' },
    { path: '/.sh_history', file: null, platform: 'unix', desc: 'Shell history' },
    
    // macOS Keychain
    { path: '/keychain/', file: 'login.keychain', platform: 'mac', desc: 'macOS keychain' },
    { path: '/Library/Keychains/', file: 'System.keychain', platform: 'mac', desc: 'System keychain' },
    
    // Windows Credential Storage
    { path: 'C:\\Users\\*\\AppData\\Local\\Microsoft\\Credentials\\', file: null, platform: 'windows', desc: 'Windows Credential Manager' },
    { path: 'C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Credentials\\', file: null, platform: 'windows', desc: 'Windows Roaming Credentials' },
    { path: 'C:\\Windows\\System32\\config\\SAM', file: null, platform: 'windows', desc: 'Windows SAM database' },
    { path: 'C:\\Windows\\System32\\config\\SYSTEM', file: null, platform: 'windows', desc: 'Windows SYSTEM registry' },
    
    // Browser Credential Storage (Cross-platform)
    { path: '/.config/google-chrome/', file: 'Default/Login Data', platform: 'unix', desc: 'Chrome passwords (Linux)' },
    { path: '/Library/Application Support/Google/Chrome/', file: 'Default/Login Data', platform: 'mac', desc: 'Chrome passwords (Mac)' },
    { path: 'C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\', file: 'Default\\Login Data', platform: 'windows', desc: 'Chrome passwords (Windows)' },
    { path: '/.mozilla/firefox/', file: '*/logins.json', platform: 'unix', desc: 'Firefox passwords (Linux)' },
    { path: '/Library/Application Support/Firefox/', file: 'Profiles/*/logins.json', platform: 'mac', desc: 'Firefox passwords (Mac)' },
    { path: 'C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\', file: 'Profiles\\*\\logins.json', platform: 'windows', desc: 'Firefox passwords (Windows)' },
    
    // IDE/Editor Credentials
    { path: '/.config/Code/', file: 'User/settings.json', platform: 'unix', desc: 'VSCode settings (Linux)' },
    { path: '/Library/Application Support/Code/', file: 'User/settings.json', platform: 'mac', desc: 'VSCode settings (Mac)' },
    { path: 'C:\\Users\\*\\AppData\\Roaming\\Code\\', file: 'User\\settings.json', platform: 'windows', desc: 'VSCode settings (Windows)' },
    { path: '/.vscode/', file: 'settings.json', platform: 'all', desc: 'VSCode workspace settings' },
    { path: '/.idea/', file: 'workspace.xml', platform: 'all', desc: 'JetBrains workspace' },
    
    // Git Credentials
    { path: '/.git-credentials', file: null, platform: 'all', desc: 'Git credential store' },
    { path: '/.config/git/', file: 'credentials', platform: 'unix', desc: 'Git credentials (Linux)' },
    
    // Package Manager Tokens
    { path: '/.pypirc', file: null, platform: 'all', desc: 'PyPI credentials' },
    { path: '/.gem/', file: 'credentials', platform: 'all', desc: 'RubyGems credentials' },
    { path: '/.cargo/', file: 'credentials', platform: 'all', desc: 'Cargo credentials' },
    
    // Linux Keyring
    { path: '/.local/share/keyrings/', file: 'login.keyring', platform: 'linux', desc: 'GNOME Keyring' },
    { path: '/.local/share/kwalletd/', file: 'kdewallet.kwl', platform: 'linux', desc: 'KDE Wallet' },
    
    // Windows Registry Hives (credential storage)
    { path: 'C:\\Users\\*\\NTUSER.DAT', file: null, platform: 'windows', desc: 'User registry hive' },
    
    // Slack/Discord Tokens
    { path: '/.config/Slack/', file: 'Cookies', platform: 'unix', desc: 'Slack cookies/tokens (Linux)' },
    { path: '/Library/Application Support/Slack/', file: 'Cookies', platform: 'mac', desc: 'Slack cookies/tokens (Mac)' },
    { path: 'C:\\Users\\*\\AppData\\Roaming\\Slack\\', file: 'Cookies', platform: 'windows', desc: 'Slack cookies/tokens (Windows)' },
    { path: '/.config/discord/', file: 'Local Storage/leveldb', platform: 'unix', desc: 'Discord tokens (Linux)' },
    
    // Database Credentials
    { path: '/.pgpass', file: null, platform: 'unix', desc: 'PostgreSQL password file' },
    { path: '/.my.cnf', file: null, platform: 'unix', desc: 'MySQL credentials' },
    { path: '/.mongorc.js', file: null, platform: 'all', desc: 'MongoDB credentials' }
  ];
  
  for (const { path: blockedPath, file, platform, desc } of blockedReadPaths) {
    if (platform === 'unix' && isWindows) continue;
    if (platform === 'mac' && !isMac) continue;
    if (platform === 'linux' && !isLinux) continue;
    if (platform === 'windows' && !isWindows) continue;
    
    const testPath = file ? `${blockedPath}${file}` : blockedPath;
    const testName = `blockedReadPaths - ${desc || testPath}`;
    
    await tracker.runTest(testName, async () => {
      const testDir = setupTestDir('fs-read-' + testPath.replace(/[\/\.]/g, '_'));
      
      try {
        // Use the actual config path from the firewall config
        const configPaths = [
          '/.ssh/', '/.aws/', '/.gnupg/', '/.kube/', '/.docker/',
          '/.config/gcloud/', '/.azure/', '/etc/passwd', '/etc/shadow',
          '/.env', '/.npmrc', '/.gitconfig', '/.bash_history', '/.zsh_history',
          '/.sh_history', '/keychain/'
        ];
        
        writeMinimalConfig(testDir, {
          filesystem: {
            blockedReadPaths: configPaths.includes(blockedPath) ? configPaths : [blockedPath],
            blockedWritePaths: [],
            allowedPaths: []
          }
        });
        
        const code = `
          const fs = require('fs');
          try {
            fs.readFileSync('${testPath}', 'utf8');
            console.log('READ_SUCCESS');
          } catch (e) {
            console.log('READ_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code, { timeout: 5000 });
        
        return {
          pass: isBlocked(result.output) || result.output.includes('READ_BLOCKED'),
          reason: result.output.includes('READ_SUCCESS') ? `BYPASS: ${testPath} readable` : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  }
  
  // =========================================================================
  // BLOCKED WRITE PATHS - Test each one
  // =========================================================================
  console.log('\n--- Blocked Write Paths (Every Config Entry) ---\n');
  
  const blockedWritePaths = [
    { path: '/etc/', platform: 'unix' },
    { path: '/.ssh/', platform: 'unix' },
    { path: '/usr/local/bin/', platform: 'unix' },
    { path: '/usr/bin/', platform: 'unix' },
    { path: '/bin/', platform: 'unix' },
    { path: '/sbin/', platform: 'unix' },
    { path: '/Library/LaunchDaemons/', platform: 'mac' },
    { path: '/Library/LaunchAgents/', platform: 'mac' },
    { path: '/.github/workflows/', platform: 'all' },
    { path: '/.bashrc', platform: 'unix' },
    { path: '/.zshrc', platform: 'unix' },
    { path: '/.profile', platform: 'unix' },
    { path: '/.bash_profile', platform: 'unix' },
    { path: '/.zprofile', platform: 'unix' },
    { path: '/.git/hooks/', platform: 'all' }
  ];
  
  for (const { path: blockedPath, platform } of blockedWritePaths) {
    if (platform === 'unix' && isWindows) continue;
    if (platform === 'mac' && !isMac) continue;
    
    const testName = `blockedWritePaths - ${blockedPath}`;
    
    await tracker.runTest(testName, async () => {
      const testDir = setupTestDir('fs-write-' + blockedPath.replace(/[\/\.]/g, '_'));
      
      try {
        writeMinimalConfig(testDir, {
          filesystem: {
            blockedReadPaths: [],
            blockedWritePaths: [blockedPath],
            allowedPaths: []
          }
        });
        
        const targetFile = blockedPath.endsWith('/') 
          ? `${blockedPath}malicious.txt`
          : blockedPath;
        
        const code = `
          const fs = require('fs');
          try {
            fs.writeFileSync('${targetFile}', 'malicious');
            console.log('WRITE_SUCCESS');
          } catch (e) {
            console.log('WRITE_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code, { timeout: 5000 });
        
        return {
          pass: isBlocked(result.output) || result.output.includes('WRITE_BLOCKED'),
          reason: result.output.includes('WRITE_SUCCESS') ? `BYPASS: ${blockedPath} writable` : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  }
  
  // =========================================================================
  // BLOCKED EXTENSIONS - Test each one
  // =========================================================================
  console.log('\n--- Blocked Extensions (Every Config Entry) ---\n');
  
  const blockedExtensions = ['.sh', '.command', '.bash', '.zsh', '.py', '.rb', '.pl', '.php'];
  
  for (const ext of blockedExtensions) {
    await tracker.runTest(`blockedExtensions - ${ext}`, async () => {
      const testDir = setupTestDir('fs-ext-' + ext.substring(1));
      
      try {
        writeMinimalConfig(testDir, {
          filesystem: {
            blockedReadPaths: [],
            blockedWritePaths: [],
            blockedExtensions: [ext],
            allowedPaths: []
          }
        });
        
        const maliciousFile = path.join(testDir, `malicious${ext}`);
        
        const code = `
          const fs = require('fs');
          try {
            fs.writeFileSync('${maliciousFile.replace(/\\/g, '\\\\')}', '#!/bin/bash\\necho pwned');
            console.log('EXT_WRITE_SUCCESS');
          } catch (e) {
            console.log('EXT_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code, { timeout: 5000 });
        
        return {
          pass: isBlocked(result.output) || result.output.includes('EXT_BLOCKED'),
          reason: result.output.includes('EXT_WRITE_SUCCESS') ? `BYPASS: ${ext} writable` : 'blocked',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  }
  
  // =========================================================================
  // ALLOWED PATHS - Test each one (should NOT be blocked)
  // =========================================================================
  console.log('\n--- Allowed Paths (Every Config Entry - Should Allow) ---\n');
  
  const allowedPaths = [
    { path: '/tmp/', platform: 'unix' },
    { path: '/var/tmp/', platform: 'unix' },
    { path: '/node_modules/', platform: 'all' },
    { path: '/.npm/', platform: 'all' },
    { path: '/.yarn/', platform: 'all' },
    { path: '/.pnpm/', platform: 'all' },
    { path: '/.cache/', platform: 'all' },
    { path: '/dist/', platform: 'all' },
    { path: '/build/', platform: 'all' },
    { path: '/public/', platform: 'all' }
  ];
  
  for (const { path: allowedPath, platform } of allowedPaths) {
    if (platform === 'unix' && isWindows) continue;
    
    await tracker.runTest(`allowedPaths - ${allowedPath} (should allow)`, async () => {
      const testDir = setupTestDir('fs-allowed-' + allowedPath.replace(/[\/\.]/g, '_'));
      
      try {
        // For relative paths (starting with /), create within testDir
        // For absolute system paths (/tmp, /var/tmp), use them directly
        let testFile;
        let configAllowedPath;
        
        if (allowedPath === '/tmp/' || allowedPath === '/var/tmp/') {
          // Use actual system temp directories
          testFile = path.join(allowedPath, 'firewall-test-' + Date.now() + '.txt');
          configAllowedPath = allowedPath;
        } else if (allowedPath === '/public/') {
          // Create within testDir but use absolute path
          const allowedDir = path.join(testDir, 'public');
          fs.mkdirSync(allowedDir, { recursive: true });
          testFile = path.join(allowedDir, 'test.txt');
          configAllowedPath = allowedDir + '/';
        } else {
          // Create within testDir for other paths
          const allowedDir = path.join(testDir, allowedPath.substring(1));
          fs.mkdirSync(allowedDir, { recursive: true });
          testFile = path.join(allowedDir, 'test.txt');
          configAllowedPath = allowedDir + '/';
        }
        
        writeMinimalConfig(testDir, {
          filesystem: {
            blockedReadPaths: [],
            blockedWritePaths: [testDir + '/'],  // Block testDir
            allowedPaths: [configAllowedPath]  // Except this
          }
        });
        
        const code = `
          const fs = require('fs');
          try {
            fs.writeFileSync('${testFile.replace(/\\/g, '\\\\')}', 'allowed content');
            console.log('ALLOWED_WRITE_SUCCESS');
          } catch (e) {
            console.log('ALLOWED_BLOCKED:' + e.message);
          }
        `;
        
        const result = await runWithFirewall(testDir, code, { timeout: 5000 });
        
        // Cleanup temp file if created
        try {
          if (fs.existsSync(testFile)) fs.unlinkSync(testFile);
        } catch (e) {}
        
        return {
          pass: result.output.includes('ALLOWED_WRITE_SUCCESS'),
          reason: result.output.includes('ALLOWED_BLOCKED') ? `ERROR: ${allowedPath} blocked when should be allowed` : 'allowed',
          debug: result.output
        };
      } finally {
        cleanupTestDir(testDir);
      }
    });
  }
  
  return tracker.getSummary();
}

module.exports = { runFilesystemCoverageTests };

if (require.main === module) {
  runFilesystemCoverageTests().then(summary => {
    console.log('\nFilesystem Coverage Summary:');
    console.log(`  Passed: ${summary.passed}`);
    console.log(`  Failed: ${summary.failed}`);
    console.log(`  Skipped: ${summary.skipped}`);
    process.exit(summary.failed > 0 ? 1 : 0);
  });
}
