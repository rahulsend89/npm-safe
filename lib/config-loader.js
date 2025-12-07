const fs = require('fs');
class ConfigLoader {
  load(path) {
    const data = fs.readFileSync(path || '.firewall-config.json', 'utf8');
    return JSON.parse(data);
  }
}
module.exports = ConfigLoader;
