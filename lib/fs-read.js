const fs = require('fs');
const originalReadFile = fs.readFile;

const BLOCKED = ['.ssh', '.aws', 'id_rsa'];

function isBlocked(path) {
  return BLOCKED.some(p => path.includes(p));
}

fs.readFile = function(path, options, callback) {
  if (isBlocked(path)) {
    const err = new Error('Access denied');
    return callback ? callback(err) : Promise.reject(err);
  }
  return originalReadFile.call(this, path, options, callback);
};
