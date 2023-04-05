const http = require('http');
const https = require('https');

const originalHttp = http.request;
const originalHttps = https.request;

http.request = function(options, callback) {
  console.log('HTTP:', options.hostname || options.host);
  return originalHttp.call(this, options, callback);
};

https.request = function(options, callback) {
  console.log('HTTPS:', options.hostname || options.host);
  return originalHttps.call(this, options, callback);
};
