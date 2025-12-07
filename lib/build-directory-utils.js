/**
 * Build Directory Detection Utilities
 * Centralized logic for identifying build/cache directories that should be allowed
 */

/**
 * Check if a file path is in a TypeScript/build tool cache directory
 * @param {string} filePath - The file path to check
 * @returns {boolean} - True if the path is in a build/cache directory
 */
function isBuildOrCacheDirectory(filePath) {
  // Standard build/cache directories
  const buildCacheDirs = [
    '/node_modules/.cache/',
    '/.ts-node',           // TypeScript ts-node cache (matches /.ts-node/ and /.ts-nodeXXX/)
    '/dist/',
    '/build/',
    '/.turbo/',
    '/.next/',
    '/tmp/ts-node',
    '/.cache/'
  ];
  
  // Check standard directories
  if (buildCacheDirs.some(dir => filePath.includes(dir))) {
    return true;
  }
  
  // Check for macOS ts-node temp: /var/folders/.../T/.ts-nodeXXX/compiled/
  return isMacOsTsNodeTemp(filePath);
}

/**
 * Check if a file path is in macOS TypeScript temp directory
 * Pattern: /var/folders/xx/xxxxxxx/T/.ts-nodeXXXXXX/compiled/...
 * @param {string} filePath - The file path to check
 * @returns {boolean} - True if the path matches macOS ts-node temp pattern
 */
function isMacOsTsNodeTemp(filePath) {
  return filePath.includes('/var/folders/') && 
         filePath.includes('/T/') &&
         filePath.includes('.ts-node');
}

/**
 * Check if a file is a project source file (should not count against thresholds)
 * @param {string} filePath - The file path to check
 * @param {string} projectRoot - The project root directory (process.cwd())
 * @returns {boolean} - True if this is a project source file
 */
function isProjectSourceFile(filePath, projectRoot) {
  const path = require('path');
  const resolvedPath = path.resolve(filePath);
  const cwdPath = path.resolve(projectRoot);
  
  // STRATEGY: Skip counting ALL legitimate infrastructure files
  // Focus monitoring on SUSPICIOUS behavior, not normal operations
  
  // 1. Firewall's own files - never count
  if (resolvedPath.includes('/node-firewall/')) {
    return true;
  }
  
  // 2. Any temp/cache directory - these are build artifacts, not threats
  if (resolvedPath.includes('/tmp/') ||
      resolvedPath.includes('/var/folders/') ||   // macOS temp
      resolvedPath.includes('/Temp/') ||           // Windows temp
      resolvedPath.includes('/.cache/') ||
      resolvedPath.includes('/.ts-node') ||
      resolvedPath.includes('/node_modules/.cache/')) {
    return true;
  }
  
  // 3. Node modules - reading dependencies is normal
  if (resolvedPath.includes('/node_modules/')) {
    return true;
  }
  
  // 4. Package manager caches
  if (resolvedPath.includes('/.npm/') ||
      resolvedPath.includes('/.yarn/') ||
      resolvedPath.includes('/.pnpm/')) {
    return true;
  }
  
  // 5. Project source files and config
  if (resolvedPath.startsWith(cwdPath)) {
    // Allow all files in project directory
    // The REAL threat is what happens AFTER reading (network upload, suspicious writes)
    return true;
  }
  
  // Files outside project/node_modules/temp - these ARE suspicious
  return false;
}

/**
 * Check if a file path is in a TypeScript temp compilation directory
 * @param {string} filePath - The file path to check
 * @returns {boolean} - True if in ts-node temp
 */
function isTsNodeTemp(filePath) {
  return filePath.includes('/.ts-node') || isMacOsTsNodeTemp(filePath);
}

module.exports = {
  isBuildOrCacheDirectory,
  isMacOsTsNodeTemp,
  isProjectSourceFile,
  isTsNodeTemp
};
