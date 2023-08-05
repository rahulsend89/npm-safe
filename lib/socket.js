const net = require('net');
const originalConnect = net.Socket.prototype.connect;
const BLOCKED_PORTS = [4444, 5555, 6666];
net.Socket.prototype.connect = function(...args) {
  const opts = args[0];
  if (opts && opts.port && BLOCKED_PORTS.includes(opts.port)) {
    throw new Error('Blocked port');
  }
  return originalConnect.apply(this, args);
};
