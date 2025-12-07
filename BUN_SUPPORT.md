# Bun Runtime Support

Node.js Firewall (v2.0.1+) includes native support for the Bun runtime.

## Compatibility Status

| Feature | Support Status | Notes |
|---------|----------------|-------|
| File System Blocking | ✅ Full | Intercepts `Bun.file`, `Bun.write` |
| Process Spawning | ✅ Full | Intercepts `Bun.spawn` |
| Shell Commands | ✅ Full | Intercepts `Bun.$` shell execution |
| Network Monitoring | ✅ Partial | Basic monitoring, advanced features in progress |
| Behavior Analysis | ✅ Full | Tracks file/network/spawn activity |
| Configuration | ✅ Full | Uses same `.firewall-config.json` |

## Installation with Bun

```bash
bun add -d @rahulmalik/npm-safe
```

## Usage

To use the firewall with Bun, simply preload the module using `-r` or import it at the start of your application:

```bash
# Via CLI
bun run -r @rahulmalik/npm-safe your-app.ts
```

Or in your entry file:

```typescript
import '@rahulmalik/npm-safe';

// Rest of your application code
console.log("Application running protected");
```

## Bun-Specific Protections

The firewall adds specific interceptors for Bun's native APIs:

1. **`Bun.spawn`**: Blocks blocked commands and dangerous arguments
2. **`Bun.file`**: Prevents reading from blocked paths
3. **`Bun.write`**: Prevents writing to sensitive locations
4. **`Bun.$`**: Intercepts shell tag function execution

### Example: Blocked Shell Execution

```typescript
// This will be BLOCKED if configured in .firewall-config.json
await Bun.$`rm -rf /`; 
```

### Example: Blocked File Access

```typescript
// This will be BLOCKED
const shadow = Bun.file('/etc/shadow');
await shadow.text();
```

## Configuration

No special configuration is needed for Bun. The standard `.firewall-config.json` works for both Node.js and Bun runtimes.

```json
{
  "mode": {
    "enabled": true,
    "block": true
  },
  "filesystem": {
    "blockedReadPaths": ["/etc/shadow", "/.ssh/id_rsa"]
  }
}
```

## Limitations

- `Bun.serve` network interception is currently limited compared to Node.js `http` interception.
- Some low-level Bun APIs might bypass standard Node.js hooks if not explicitly intercepted.

## Development

When developing for Bun, ensure you run tests using the Bun runtime:

```bash
bun test
```
