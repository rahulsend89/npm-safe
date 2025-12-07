/**
 * Bun Runtime Initialization
 * Entry point for Bun runtime protection
 */

const isBun = typeof Bun !== 'undefined';

if (!isBun) {
  module.exports = {};
} else {
  console.log('======================================================');
  console.log('   Bun Runtime Security Firewall');
  console.log('======================================================');
  console.log(`Bun version: ${Bun.version}`);
  console.log('');

  // Initialize Bun-specific interceptors
  const { initialize: initBunInterceptor } = require('./bun-interceptor');

  // Initialize Node.js-compatible interceptors
  const { FirewallCore } = require('./firewall-core');

  // Initialize network monitoring (compatible with Bun)
  const { initialize: initNetwork } = require('./network-monitor');

  try {
    // Initialize Bun-specific protections
    initBunInterceptor();
    
    // Initialize core firewall (works with both Node.js and Bun)
    const firewall = new FirewallCore();
    firewall.initialize();
    
    // Initialize network monitoring
    initNetwork();
    
    console.log('[Bun Init] All protections active');
    console.log('');
  } catch (error) {
    console.error('[Bun Init] Failed to initialize:', error.message);
    if (process.env.NODE_ENV !== 'production') {
      console.error(error.stack);
    }
  }

  module.exports = {
    isBun
  };
}
