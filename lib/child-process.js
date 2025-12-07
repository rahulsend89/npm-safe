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

const originalSpawn = cp.spawn;
cp.spawn = function(command, args, options) {
  const full = command + ' ' + (args || []).join(' ');
  if (isDangerous(full)) throw new Error('Spawn blocked');
  return originalSpawn.call(this, command, args, options);
};
