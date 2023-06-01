const cp = require('child_process');
const originalExec = cp.exec;
cp.exec = function(command, options, callback) {
  console.log('Exec:', command);
  return originalExec.call(this, command, options, callback);
};
