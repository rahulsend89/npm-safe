const fs = require('fs');
const originalWriteFile = fs.writeFile;

const SYSTEM_PATHS = ['/etc/', '/usr/bin/', '/System/'];

function isSystemPath(path) {
  return SYSTEM_PATHS.some(p => path.startsWith(p));
}

fs.writeFile = function(path, data, options, callback) {
  if (isSystemPath(path)) {
    const err = new Error('Write denied');
    return callback ? callback(err) : Promise.reject(err);
  }
  return originalWriteFile.call(this, path, data, options, callback);
};
