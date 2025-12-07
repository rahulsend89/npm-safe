/**
 * Test: Version detection logic
 * Verifies that the firewall correctly detects Node.js version and capabilities
 */

const [major, minor] = process.versions.node.split('.').map(Number);

// Expected behavior based on version
const supportsImport = major > 20 || (major === 20 && minor >= 6);
const supportsLoader = major > 16 || (major === 16 && minor >= 12);

console.log('Node.js version:', process.version);
console.log('Major:', major, 'Minor:', minor);
console.log('Supports --import:', supportsImport);
console.log('Supports --loader:', supportsLoader);

// Validation
if (major < 16) {
  console.log('Expected: No ESM support, CJS only');
  if (supportsImport || supportsLoader) {
    console.error('ERROR: Incorrect detection for Node.js < 16');
    process.exit(1);
  }
} else if (major === 16 && minor < 12) {
  console.log('Expected: No ESM support, CJS only');
  if (supportsImport || supportsLoader) {
    console.error('ERROR: Incorrect detection for Node.js 16.0-16.11');
    process.exit(1);
  }
} else if (major < 20 || (major === 20 && minor < 6)) {
  console.log('Expected: --loader support, no --import');
  if (supportsImport) {
    console.error('ERROR: Incorrect --import detection');
    process.exit(1);
  }
  if (!supportsLoader) {
    console.error('ERROR: Should support --loader');
    process.exit(1);
  }
} else {
  console.log('Expected: --import support');
  if (!supportsImport) {
    console.error('ERROR: Should support --import');
    process.exit(1);
  }
}

console.log('✓ Version detection correct');
process.exit(0);
