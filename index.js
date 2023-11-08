/**
 * Node Firewall - Main Entry Point
 * Auto-initializes all firewall components when required with -r flag
 */

// Check if firewall is enabled
const enabled = process.env.NODE_FIREWALL === '1' || process.env.NODE_FIREWALL_FORTRESS === '1';

if (enabled) {
  // Initialize firewall core (which initializes all components)
  const { FirewallCore } = require('./lib/firewall-core');
  const firewall = new FirewallCore();
  firewall.initialize();
  
  // Initialize filesystem interceptor
  require('./lib/fs-interceptor-v2');
  
  // Initialize child process interceptor (already a singleton instance)
  require('./lib/child-process-interceptor');
  
  console.log('[Firewall] Auto-initialized on module load');
} else {
  console.warn('[Firewall] Not enabled. Set NODE_FIREWALL=1 or NODE_FIREWALL_FORTRESS=1 to activate');
}

module.exports = require('./lib/firewall-core');
