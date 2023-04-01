const http = require('http');
const originalRequest = http.request;

http.request = function(options, callback) {
  const host = options.hostname || options.host;
  console.log('HTTP request to:', host);
  return originalRequest.call(this, options, callback);
};
