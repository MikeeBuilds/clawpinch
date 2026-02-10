---
name: clawpinch
description: "Security audit toolkit for OpenClaw deployments. Scans 71 checks across 9 categories. Use when asked to audit security, harden an installation, check for vulnerabilities, or review config safety."
version: "1.2.0"
author: MikeeBuilds
license: MIT
platforms:
  - macOS
  - Linux
---

## When to Use

- User asks to "audit security", "check for vulnerabilities", or "harden" an OpenClaw deployment
- After installing or updating OpenClaw or any skill
- Before deploying to production
- During security reviews or incident response
- When investigating suspicious skill behavior

## Installation

### Method 1: npx (no install)
```bash
npx clawpinch
```

### Method 2: Global install
```bash
npm install -g clawpinch
clawpinch
```

### Method 3: From source
```bash
git clone https://github.com/MikeeBuilds/clawpinch.git
cd clawpinch
bash clawpinch.sh
```

## CLI Commands

```bash
# Standard interactive scan
clawpinch

# Deep scan (supply-chain hash verification, full skill decompilation)
clawpinch --deep

# JSON output for programmatic consumption
clawpinch --json

# Quiet mode — summary line only
clawpinch --quiet

# Show auto-fix commands in report
clawpinch --fix

# Skip interactive menu
clawpinch --no-interactive

# AI-powered remediation — scan then pipe to Claude for automated fixing
clawpinch --remediate

# Target specific config directory
clawpinch --config-dir /path/to/openclaw/config

# Version info
clawpinch --version
```

## Output Schema

Each finding is a JSON object:

```json
{
  "id": "CHK-CFG-001",
  "severity": "critical | warn | info | ok",
  "title": "Short description",
  "description": "Detailed explanation",
  "evidence": "Relevant snippet or value",
  "remediation": "How to fix",
  "auto_fix": "Shell command to fix (may be empty)"
}
```

## Check Categories

| Category | ID Range | Count | Description |
|----------|----------|-------|-------------|
| Configuration | CHK-CFG-001..010 | 10 | Gateway, TLS, auth, CORS, rate limiting |
| Secrets | CHK-SEC-001..008 | 8 | API keys, passwords, tokens, .env files |
| Network | CHK-NET-001..008 | 8 | Port exposure, WebSocket auth, DNS rebinding |
| Skills | CHK-SKL-001..010 | 10 | Permissions, signatures, eval patterns |
| Permissions | CHK-PRM-001..008 | 8 | Least-privilege, wildcards, cross-tenant |
| Cron | CHK-CRN-001..006 | 6 | Sandbox, timeouts, privilege escalation |
| CVE | CHK-CVE-001..005 | 5 | Known vulnerabilities, outdated deps |
| Supply Chain | CHK-SUP-001..008 | 8 | Registry trust, hash verification, lockfiles |
| WebMCP | CHK-WEB-001..008 | 8 | WebMCP origins, capabilities, prompt injection |

## Integration Patterns

### OpenClaw Skill
```bash
npx skills add https://github.com/MikeeBuilds/clawpinch --skill clawpinch
```

### Claude Code
```bash
# Slash commands (when repo is open in Claude Code)
/clawpinch-scan    # Run security audit
/clawpinch-fix     # Scan and fix all findings

# Direct remediation
clawpinch --remediate
```

### CI/CD
```bash
npx clawpinch --json --no-interactive | jq '[.[] | select(.severity == "critical")] | length'
# Exit code 1 if any critical findings
npx clawpinch --quiet --no-interactive
```

## Dependencies

- **Required:** `bash` >= 4.0, `jq`
- **Optional:** `openssl` (TLS checks), `nmap` / `ss` (network checks), `sha256sum` / `shasum` (supply-chain hash verification), `claude` CLI (for --remediate)

## Safety Rules

1. **No remote execution.** Runs entirely local. No outbound connections except version metadata checks.
2. **No system modifications without consent.** Scanners are read-only by default.
3. **Always redact secrets.** Secrets truncated to first 4 chars + `****` in all output.
4. **Treat all skills as untrusted.** Deny-by-default permission policy.
5. **No privilege escalation.** Never requests `sudo`.
6. **Findings are advisory.** Output is informational — operator decides whether to act.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No critical findings |
| 1 | One or more critical findings detected |
