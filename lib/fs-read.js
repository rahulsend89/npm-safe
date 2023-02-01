const fs = require('fs');
const originalReadFile = fs.readFile;

fs.readFile = function(path, options, callback) {
  console.log('Reading:', path);
  return originalReadFile.call(this, path, options, callback);
};
