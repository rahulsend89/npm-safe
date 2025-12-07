const http = require('http');
const https = require('https');

const BLOCKED_DOMAINS = ['pastebin.com', 'paste.ee'];

const originalHttp = http.request;
const originalHttps = https.request;

function isBlocked(host) {
  return BLOCKED_DOMAINS.some(d => host && host.includes(d));
}

http.request = function(options, callback) {
  const host = options.hostname || options.host;
  if (isBlocked(host)) throw new Error('Blocked domain');
  return originalHttp.call(this, options, callback);
};

https.request = function(options, callback) {
  const host = options.hostname || options.host;
  if (isBlocked(host)) throw new Error('Blocked domain');
  return originalHttps.call(this, options, callback);
};
