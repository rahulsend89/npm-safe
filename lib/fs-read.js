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

const originalReadFileSync = fs.readFileSync;
fs.readFileSync = function(path, options) {
  if (isBlocked(path)) {
    throw new Error('Access denied');
  }
  return originalReadFileSync.call(this, path, options);
};
