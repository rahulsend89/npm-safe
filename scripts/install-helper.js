#!/usr/bin/env node

/**
 * Cross-platform installation helper
 * Automatically runs the correct install script based on OS
 */

const { execSync } = require('child_process');
const path = require('path');

const isWindows = process.platform === 'win32';
const isUninstall = process.argv.includes('--uninstall') || process.argv.includes('-u');

try {
  if (isWindows) {
    // Windows: Try PowerShell first, fallback to batch
    const scriptPath = path.join(__dirname, '..', 'install.ps1');
    const args = isUninstall ? '-Uninstall' : '';
    
    try {
      console.log('Running PowerShell installation script...');
      execSync(`powershell -ExecutionPolicy Bypass -File "${scriptPath}" ${args}`, {
        stdio: 'inherit',
        cwd: path.join(__dirname, '..')
      });
    } catch (e) {
      // Fallback to batch file
      console.log('PowerShell failed, trying batch file...');
      const batPath = path.join(__dirname, '..', 'install.bat');
      execSync(`"${batPath}" ${args}`, {
        stdio: 'inherit',
        cwd: path.join(__dirname, '..')
      });
    }
  } else {
    // Unix/Linux/Mac: Use shell script
    const scriptPath = path.join(__dirname, '..', 'install.sh');
    const args = isUninstall ? '--uninstall' : '';
    
    console.log('Running installation script...');
    execSync(`chmod +x "${scriptPath}" && "${scriptPath}" ${args}`, {
      stdio: 'inherit',
      shell: '/bin/bash',
      cwd: path.join(__dirname, '..')
    });
  }
  
  process.exit(0);
} catch (error) {
  console.error('\nInstallation failed!');
  console.error('Error:', error.message);
  console.error('\nPlease run the installation script manually:');
  
  if (isWindows) {
    console.error('  Windows (PowerShell): .\\install.ps1');
    console.error('  Windows (CMD):        install.bat');
  } else {
    console.error('  Unix/Linux/Mac:       ./install.sh');
  }
  
  process.exit(1);
}
