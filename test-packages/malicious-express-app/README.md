# Malicious Express App - Firewall Test

This is a **test application** that simulates a supply chain attack attempting data exfiltration.

##  WARNING
This app intentionally contains malicious code patterns for **TESTING PURPOSES ONLY**.
Never use this code in production or on real systems.

## Attack Vectors

This app attempts the following attacks:

1. **HTTP POST to pastebin.com** - Blocked domain
2. **HTTPS to Discord webhook** - Pattern detection
3. **Raw TCP socket to external IP** - Suspicious port (4444)
4. **HTTPS to transfer.sh** - Blocked domain
5. **HTTP to random external IP** - Not in allowedDomains
6. **DNS exfiltration** - Subdomain encoding

## Expected Firewall Behavior

With the firewall active, **ALL** attacks should be blocked with messages like:

```
 [NETWORK BLOCKED] Blocked domain: pastebin.com
 [NETWORK BLOCKED] Not in allowed domains: discord.com
 [NETWORK BLOCKED] Suspicious port: 4444
```

## How to Run

### With Firewall Protection (Recommended)

```bash
cd test-packages/malicious-express-app
npm install
NODE_FIREWALL=1 node -r ../../index.js server.js
```

### Without Firewall (Dangerous - attacks will succeed)

```bash
cd test-packages/malicious-express-app
npm install
npm run dev
```

## Testing

The app auto-triggers all attacks 2 seconds after startup.

You can also manually trigger attacks:
```bash
curl http://localhost:3000/trigger-attacks
```

## Expected Output (With Firewall)

```
 MALICIOUS APP STARTING - Testing Firewall Protection

 Server running on http://localhost:3000

 TRIGGERING ALL ATTACK VECTORS


[ATTACK 1] Attempting to exfiltrate via pastebin.com...
 [NETWORK BLOCKED] Blocked domain: pastebin.com
 [ATTACK 1] BLOCKED - Network request blocked: Blocked domain: pastebin.com

[ATTACK 2] Attempting to exfiltrate via Discord webhook...
 [NETWORK BLOCKED] Not in allowed domains: discord.com
 [ATTACK 2] BLOCKED - Network request blocked: Not in allowed domains: discord.com

[ATTACK 3] Attempting raw TCP socket to external IP...
 [NETWORK BLOCKED] Not in allowed domains: 185.199.108.153
 [ATTACK 3] BLOCKED - Network blocked: Not in allowed domains: 185.199.108.153

... etc
```

## Logs

- `malicious-app-firewall.log` - All blocked attempts
- `malicious-app-report.json` - Detailed security report
- `firewall-audit.jsonl` - Audit trail

## Cleanup

```bash
rm -f malicious-app-firewall.log malicious-app-report.json firewall-audit.jsonl
```
