const cp = require('child_process');
const originalExec = cp.exec;
const DANGEROUS = ['curl', 'wget', 'bash -c'];
function isDangerous(cmd) {
  return DANGEROUS.some(d => cmd.includes(d));
}
cp.exec = function(command, options, callback) {
  if (isDangerous(command)) {
    const err = new Error('Dangerous command');
    return callback ? callback(err) : Promise.reject(err);
  }
  return originalExec.call(this, command, options, callback);
};
