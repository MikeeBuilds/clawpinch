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

# Show suppressed findings
bash clawpinch.sh --show-suppressed

# Disable all suppressions (full audit)
bash clawpinch.sh --no-ignore
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
│   │   ├── suppression.sh    # Finding suppression: load_suppressions(), filter_findings(), expiration handling
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
├── .clawpinch-ignore.json.example # Example suppression config with documentation
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

### Output Format with Suppressions

When suppressions are enabled (via `.clawpinch-ignore.json`), the JSON output contains two arrays:

```json
{
  "findings": [ /* active findings only */ ],
  "suppressed": [ /* suppressed findings */ ]
}
```

Suppressed findings do not count toward severity totals or exit codes. Use `--show-suppressed` to include them in terminal output (marked with `[SUPPRESSED]`), or `--no-ignore` to disable all suppressions for full audits.

## How to Add a New Check

1. Choose the appropriate scanner file in `scripts/` (or create a new `scan_*.sh`)
2. Source common helpers: `source "$(dirname "$0")/helpers/common.sh"`
3. Implement your check logic
4. Call `emit_finding "CHK-XXX-NNN" "severity" "title" "description" "evidence" "remediation" "auto_fix"`
5. Add the check to `references/check-catalog.md` and `SKILL.md` category table

## Finding Suppression

Findings can be suppressed by creating a `.clawpinch-ignore.json` file in the project root:

```json
{
  "suppressions": [
    {
      "id": "CHK-CFG-001",
      "reason": "Dev environment - open gateway is intentional",
      "expires": "2025-12-31T23:59:59Z",
      "suppressed_by": "devops@example.com",
      "suppressed_at": "2024-01-15T10:30:00Z"
    }
  ]
}
```

**Behavior:**
- Suppressed findings move to `suppressed` array in JSON output
- Suppressed findings do not count toward severity totals or exit codes
- Expired suppressions (past `expires` date) automatically reactivate
- `--show-suppressed` includes suppressed findings in output with `[SUPPRESSED]` marker
- `--no-ignore` disables all suppressions for full audit scans

**Use cases:**
- Accepted risks in development environments
- Findings under gradual remediation with expiration tracking
- Security-reviewed exceptions with documented justifications
- CI/CD pipelines that fail on active findings only

See `.clawpinch-ignore.json.example` for a fully documented template.

## Conventions

- All scanners output a JSON array to stdout
- Scanners must not modify the system (read-only)
- Secrets in evidence are redacted via `redact_line()` before display
- `auto_fix` is optional — many findings require manual remediation
- Colors respect `NO_COLOR` env var (https://no-color.org/)
- Terminal width capped between 56–80 columns
