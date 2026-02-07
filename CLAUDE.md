# ClawPinch

Security audit toolkit for OpenClaw deployments. Scans 63 checks across 9 categories (configuration, secrets, network, skills, permissions, cron, CVE, supply chain, integrity).

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
│   │   └── interactive.sh    # Post-scan menu: review, auto-fix, handoff export, AI remediation
│   ├── scan_config.sh        # CHK-CFG-001..010 — gateway, TLS, auth, CORS
│   ├── scan_secrets.py       # CHK-SEC-001..008 — API keys, passwords, tokens
│   ├── scan_network.sh       # CHK-NET-001..008 — ports, WebSocket, DNS rebinding
│   ├── scan_skills.sh        # CHK-SKL-001..010 — permissions, signatures, eval
│   ├── scan_permissions.sh   # CHK-PRM-001..008 — least-privilege, wildcards
│   ├── scan_crons.sh         # CHK-CRN-001..006 — sandbox, timeouts, privilege
│   ├── scan_cves.sh          # CHK-CVE-001..005 — known vulns, outdated deps
│   ├── scan_supply_chain.sh  # CHK-SUP-001..008 — registry trust, hash verify
│   ├── scan_integrity.sh     # CHK-INT-001 — reference data integrity verification
│   └── update_checksums.sh   # Regenerate SHA256 checksums for reference data
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

## Reference Data Integrity

ClawPinch protects its own reference data files using SHA256 checksums:

- **What's protected:** `references/known-cves.json` and `references/malicious-patterns.json`
- **How it works:** Each `.json` file has a `.json.sha256` checksum file. On every scan, `scan_integrity.sh` verifies the hash matches.
- **When verification fails:** A critical finding (CHK-INT-001) is emitted. This could indicate file corruption or tampering.
- **Updating reference data:** After modifying any `.json` file in `references/`, run `bash scripts/update_checksums.sh` to regenerate checksums.

**Common.sh helper:**
```bash
verify_json_integrity <json_file_path>  # Returns 0 if valid, 1 if failed
```

This prevents supply-chain attacks where an attacker modifies ClawPinch's CVE database or malicious pattern signatures to hide real threats.
