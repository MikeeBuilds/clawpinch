```
      ██████╗██╗      █████╗ ██╗    ██╗██████╗ ██╗███╗   ██╗ ██████╗██╗  ██╗
     ██╔════╝██║     ██╔══██╗██║    ██║██╔══██╗██║████╗  ██║██╔════╝██║  ██║
     ██║     ██║     ███████║██║ █╗ ██║██████╔╝██║██╔██╗ ██║██║     ███████║
     ██║     ██║     ██╔══██║██║███╗██║██╔═══╝ ██║██║╚██╗██║██║     ██╔══██║
     ╚██████╗███████╗██║  ██║╚███╔███╔╝██║     ██║██║ ╚████║╚██████╗██║  ██║
      ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝

            /)/)
           ( .  .)      🦀  "Don't get pinched."
          ╭(  >  <>
         /|________|\        Security audit toolkit for OpenClaw
        / |  |    | |\
       *  |__|____|_| *
```

[![npm](https://img.shields.io/npm/v/clawpinch)](https://www.npmjs.com/package/clawpinch)
![Version](https://img.shields.io/badge/version-1.2.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)

---

**ClawPinch** audits your OpenClaw deployment for misconfigurations, exposed
secrets, malicious skills, network exposure, supply-chain risks, and known CVEs
-- then tells you exactly how to fix what it finds. 63 checks across 8
categories, structured JSON output, auto-fix commands, AI-powered remediation,
and a full threat model.

---

## Install

### Option 1: npx (zero install, recommended)

```bash
npx clawpinch
```

### Option 2: Global install

```bash
npm install -g clawpinch
clawpinch
```

### Option 3: OpenClaw skill

```bash
npx skills add https://github.com/MikeeBuilds/clawpinch --skill clawpinch
```

Then move to your skills directory and run:

```bash
mv clawpinch ~/.openclaw/workspace/skills/
openclaw skill run clawpinch
```

### Option 4: From source

```bash
git clone https://github.com/MikeeBuilds/clawpinch.git
cd clawpinch
bash clawpinch.sh
```

### Requirements

- `bash` >= 4.0
- `jq` (install: `brew install jq` or `apt install jq`)
- Optional: `python3` (secrets scanner), `openssl`, `nmap`, `ss`, `sha256sum`

---

## Features

- **63 checks** across 8 scanner categories
- **Integrity verification** -- SHA256 checksums protect reference data from tampering
- **Structured JSON output** for programmatic consumption
- **Interactive review mode** with one-by-one fix workflow
- **Auto-fix commands** for findings that support automated remediation
- **AI agent remediation** -- pipe findings to Claude or any AI agent
- **Self-installing** -- AI agents can discover, install, and operate ClawPinch without human help
- **Secret redaction** -- all sensitive values masked in output
- **NO_COLOR support** -- respects [no-color.org](https://no-color.org)

---

## For AI Agents

ClawPinch is built to be operated by AI agents -- OpenClaw bots, Claude Code, or any LLM-based agent -- without human intervention.

### Quick Start for Agents

```bash
# Install and scan in one command (no human interaction)
npx clawpinch --json --no-interactive

# Scan and auto-remediate via Claude CLI
npx clawpinch --remediate
```

### OpenClaw Bot Integration

Install ClawPinch as an OpenClaw skill:

```bash
npx skills add https://github.com/MikeeBuilds/clawpinch --skill clawpinch
```

Then run from your bot:

```bash
# Get structured findings as JSON
openclaw skill run clawpinch -- --json --no-interactive

# Parse output: each finding has id, severity, title, description,
# evidence, remediation, and auto_fix fields
```

**Workflow for OpenClaw bots:**
1. Run `clawpinch --json --no-interactive` to get findings
2. Parse the JSON array -- each item follows the schema in `SKILL.md`
3. Iterate findings by severity (`critical` > `warn` > `info`)
4. For each finding: execute `auto_fix` if present, otherwise apply `remediation` manually
5. Re-run the scan to verify fixes

### Claude Code Integration

When this repo (or any project with ClawPinch installed) is open in Claude Code:

- `/clawpinch-scan` -- Run a security audit and get a summary
- `/clawpinch-fix` -- Scan and remediate all findings automatically

### Automated Remediation Pipeline

```bash
# Scan then pipe all findings to Claude for automated fixing
clawpinch --remediate
```

This runs the scan, filters out passing checks, and pipes findings to `claude -p` with tools enabled (`Bash`, `Read`, `Write`, `Edit`, `Glob`, `Grep`). Claude fixes each issue autonomously. Set `CLAWPINCH_CLAUDE_BIN` to override the Claude CLI path.

### Any AI Agent

ClawPinch works with any agent that can run shell commands and parse JSON:

```bash
# 1. Run scan
FINDINGS=$(npx clawpinch --json --no-interactive)

# 2. Get critical findings
echo "$FINDINGS" | jq '[.[] | select(.severity == "critical")]'

# 3. Get auto-fixable findings
echo "$FINDINGS" | jq '[.[] | select(.auto_fix != null and .auto_fix != "")]'

# 4. Execute a fix
echo "$FINDINGS" | jq -r '.[0].auto_fix' | bash
```

**Export a task list for your agent:**

Run ClawPinch interactively and choose menu option `[4] Export AI remediation skill`. This generates a `clawpinch-remediation-YYYY-MM-DD.md` with:
- Numbered tasks ordered by severity
- Description, evidence, and remediation per task
- Auto-fix commands where available
- Acceptance criteria and checkboxes

**Machine-readable skill definition:** See `SKILL.md` for YAML frontmatter with name, description, version, and full capability documentation. Agents can parse this to decide when and how to invoke ClawPinch.

### Interactive Mode: Ask AI

In the interactive review mode, press `[a]` on any finding to copy a structured remediation prompt to your clipboard. Works on every finding -- including those with no `auto_fix`. Paste into any AI assistant to get a fix.

---

## Usage

```bash
# Standard interactive scan (review findings, auto-fix, export reports)
bash clawpinch.sh

# Deep scan (supply-chain hash verification, skill decompilation)
bash clawpinch.sh --deep

# JSON output for CI/CD pipelines
bash clawpinch.sh --json

# Quiet mode -- summary line only
bash clawpinch.sh --quiet

# Skip interactive menu
bash clawpinch.sh --no-interactive

# AI-powered remediation -- scan then pipe findings to Claude for automated fixing
bash clawpinch.sh --remediate

# Point at a custom config directory
bash clawpinch.sh --config-dir /path/to/openclaw/config

# Print auto-fix commands (read-only -- does not execute them)
bash clawpinch.sh --fix
```

---

## Example Output

```
  ╭──────────────────────────────────────────────────────╮
  │                                                      │
  │   ██████╗██╗      █████╗ ██╗    ██╗                  │
  │  ██╔════╝██║     ██╔══██╗██║    ██║                  │
  │  ██║     ██║     ███████║██║ █╗ ██║                  │
  │  ██║     ██║     ██╔══██║██║███╗██║                  │
  │  ╚██████╗███████╗██║  ██║╚███╔███╔╝                  │
  │   ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝                  │
  │  ██████╗ ██╗███╗   ██╗ ██████╗██╗  ██╗              │
  │  ██╔══██╗██║████╗  ██║██╔════╝██║  ██║              │
  │  ██████╔╝██║██╔██╗ ██║██║     ███████║              │
  │  ██╔═══╝ ██║██║╚██╗██║██║     ██╔══██║              │
  │  ██║     ██║██║ ╚████║╚██████╗██║  ██║              │
  │  ╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝              │
  │                                                      │
  │         Don't get pinched.  v1.2.0                   │
  ╰──────────────────────────────────────────────────────╯

  [info]  OS detected: macos
  [info]  OpenClaw config: ~/.config/openclaw/openclaw.json

  ┌─ 🔧 Configuration ──────────────────────────────────┐
  ✓ Configuration  (4 findings, 1.2s)

  ┌─ 🔑 Secrets ────────────────────────────────────────┐
  ✓ Secrets  (2 findings, 0.8s)

  ┃ ● CRITICAL                            CHK-CFG-001 ┃
  ┃ exec.ask not set to always                         ┃
  ┃                                                    ┃
  ┃ The exec.ask setting controls whether the user is  ┃
  ┃ prompted before command execution.                 ┃
  ┃                                                    ┃
  ┃ Evidence: exec.ask=null                            ┃
  ┃ Fix: Set exec.ask to 'always' in openclaw.json     ┃
  └────────────────────────────────────────────────────┘

  ✓ No secrets detected                      CHK-SEC-000

  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃              ClawPinch Scan Results                ┃
  ┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
  ┃                                                    ┃
  ┃  ● CRITICAL   12    ████████████░░░░░░░░  38%     ┃
  ┃  ● WARNING     5    █████░░░░░░░░░░░░░░░  16%     ┃
  ┃  ● INFO        3    ███░░░░░░░░░░░░░░░░░  10%     ┃
  ┃  ✓ OK         11    ███████████░░░░░░░░░  35%     ┃
  ┃                                                    ┃
  ┃  Total: 31 findings across 8 scanners              ┃
  ┃  Scan completed in 3.4s                            ┃
  ┃                                                    ┃
  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

The terminal UI features:
- **Gradient ASCII art banner** -- "CLAW" in red/magenta, "PINCH" in cyan/green (256-color)
- **Braille spinner** -- animated `⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏` during each scanner with timing
- **Box-drawn finding cards** -- severity-colored left border, right-aligned check ID
- **Compact OK findings** -- single-line `✓` format
- **Dashboard summary** -- heavy-bordered box with `█░` bar charts and percentages
- **`NO_COLOR` support** -- set `NO_COLOR=1` for plain text output (respects [no-color.org](https://no-color.org))
- **256-color with 16-color fallback** -- auto-detected from `$TERM` / `$COLORTERM`

---

## All Checks (63)

### Configuration (CHK-CFG)

| ID  | Check                                          | Severity |
|-----|------------------------------------------------|----------|
| 001 | Gateway listening on 0.0.0.0                   | Critical |
| 002 | Gateway auth disabled                          | Critical |
| 003 | TLS not enabled on gateway                     | Critical |
| 004 | Debug mode enabled in production               | Warn     |
| 005 | Config file world-readable                     | Warn     |
| 006 | Default admin credentials unchanged            | Critical |
| 007 | Permissive CORS policy (wildcard origin)       | Warn     |
| 008 | Session timeout exceeds 24 hours               | Warn     |
| 009 | Rate limiting not configured                   | Warn     |
| 010 | Audit logging disabled                         | Warn     |

### Secrets (CHK-SEC)

| ID  | Check                                          | Severity |
|-----|------------------------------------------------|----------|
| 001 | API key found in config file                   | Critical |
| 002 | Hardcoded password in skill manifest           | Critical |
| 003 | Private key in config directory                | Critical |
| 004 | .env file with secrets in working dir          | Warn     |
| 005 | Token in shell history                         | Warn     |
| 006 | Unencrypted credential store                   | Warn     |
| 007 | Secret passed via environment variable         | Info     |
| 008 | Git repo contains committed secrets            | Critical |

### Network (CHK-NET)

| ID  | Check                                          | Severity |
|-----|------------------------------------------------|----------|
| 001 | Gateway port exposed to public interface       | Critical |
| 002 | WebSocket endpoint lacks authentication        | Critical |
| 003 | HTTP used instead of HTTPS                     | Critical |
| 004 | Proxy misconfiguration leaks internal IPs      | Warn     |
| 005 | DNS rebinding protection missing               | Warn     |
| 006 | Open redirect in auth callback                 | Warn     |
| 007 | Server headers disclose version info           | Info     |
| 008 | Unrestricted outbound from skill sandbox       | Warn     |

### Skills (CHK-SKL)

| ID  | Check                                          | Severity |
|-----|------------------------------------------------|----------|
| 001 | Skill requests filesystem write access         | Warn     |
| 002 | Skill requests network access                  | Warn     |
| 003 | Skill requests shell execution                 | Critical |
| 004 | Skill not signed                               | Warn     |
| 005 | Skill has known malicious hash                 | Critical |
| 006 | Skill requests access to other skills          | Warn     |
| 007 | Skill manifest references external URL         | Warn     |
| 008 | Skill uses eval() or exec() patterns           | Critical |
| 009 | Skill version pinned to mutable tag            | Warn     |
| 010 | Skill overrides safety rules                   | Critical |

### Permissions (CHK-PRM)

| ID  | Check                                          | Severity |
|-----|------------------------------------------------|----------|
| 001 | Skill granted admin-level permissions          | Critical |
| 002 | Wildcard permission grant                      | Critical |
| 003 | Channel can invoke privileged skills           | Warn     |
| 004 | No permission boundary between skills          | Warn     |
| 005 | User role allows skill installation            | Warn     |
| 006 | API token has excessive scopes                 | Warn     |
| 007 | Cross-tenant access not restricted             | Critical |
| 008 | Permission changes not audited                 | Warn     |

### Cron (CHK-CRN)

| ID  | Check                                          | Severity |
|-----|------------------------------------------------|----------|
| 001 | Cron job runs as root                          | Critical |
| 002 | Cron job executes un-reviewed skill            | Warn     |
| 003 | Cron schedule allows rapid-fire execution      | Warn     |
| 004 | Cron job lacks timeout                         | Warn     |
| 005 | Cron job output not captured                   | Info     |
| 006 | Cron job has network access                    | Warn     |

### CVE (CHK-CVE)

| ID  | Check                                          | Severity |
|-----|------------------------------------------------|----------|
| 001 | OpenClaw version vulnerable to known CVE       | Critical |
| 002 | Gateway auth bypass (CVE-2026-25253)           | Critical |
| 003 | Docker sandbox escape (CVE-2026-24763)         | Critical |
| 004 | SSH path injection (CVE-2026-25157)            | Critical |
| 005 | Outdated dependency with known vuln            | Warn     |

### Supply Chain (CHK-SUP)

| ID  | Check                                          | Severity |
|-----|------------------------------------------------|----------|
| 001 | Skill installed from untrusted registry        | Critical |
| 002 | Skill hash does not match registry             | Critical |
| 003 | Registry URL uses HTTP, not HTTPS              | Critical |
| 004 | Skill depends on deprecated package            | Warn     |
| 005 | Skill pulls transitive dep at runtime          | Warn     |
| 006 | No lockfile for installed skills               | Warn     |
| 007 | Registry certificate not pinned                | Warn     |
| 008 | Skill author identity not verified             | Warn     |

### Integrity (CHK-INT)

| ID  | Check                                          | Severity |
|-----|------------------------------------------------|----------|
| 001 | Reference data integrity check failed          | Critical |

---

## Project Structure

```
clawpinch/
  clawpinch.sh            # Main orchestrator (spinner, timing, section headers)
  scripts/
    helpers/
      common.sh           # Color system, NO_COLOR, logging, finding emitter
      report.sh           # Terminal UI rendering (banner, cards, dashboard)
      redact.sh           # Secret redaction utilities
      interactive.sh      # Post-scan menu: review, auto-fix, AI remediation
    scan_config.sh        # Configuration scanner
    scan_secrets.py       # Secrets scanner (Python)
    scan_network.sh       # Network scanner
    scan_skills.sh        # Skills scanner
    scan_permissions.sh   # Permissions scanner
    scan_crons.sh         # Cron scanner
    scan_cves.sh          # CVE scanner
    scan_supply_chain.sh  # Supply chain scanner
    scan_integrity.sh     # Reference data integrity scanner
    update_checksums.sh   # Regenerate reference data checksums
  references/
    known-cves.json       # CVE database
    malicious-patterns.json # ClawHavoc signatures
    threat-model.md       # OpenClaw threat model
    check-catalog.md      # Full check catalog with remediation
  website/
    index.html            # Project landing page
  .claude/
    commands/
      clawpinch-scan.md   # /clawpinch-scan slash command
      clawpinch-fix.md    # /clawpinch-fix slash command
  SKILL.md                # AI-readable skill definition (YAML frontmatter)
  CLAUDE.md               # Project context for Claude Code
  README.md               # This file
```

---

## Maintaining Reference Data

ClawPinch uses SHA256 checksums to verify the integrity of reference JSON files (`known-cves.json`, `malicious-patterns.json`). This protects against tampering that could cause the tool to miss real threats or inject malicious auto-fix commands.

### How Integrity Verification Works

- Each `.json` file has a corresponding `.json.sha256` checksum file
- On every scan, ClawPinch verifies the SHA256 hash matches the expected value
- If verification fails, a **critical** finding (CHK-INT-001) is emitted
- The scan continues, but you'll be warned that reference data may be compromised

### When Verification Fails

If you see `CHK-INT-001: Reference data integrity check failed`:

1. **Check if you modified the files** -- If you intentionally updated reference data, regenerate checksums (see below)
2. **Suspect tampering** -- If you didn't modify the files, restore them from a trusted source (GitHub release, npm package, or fresh clone)
3. **Review the evidence** -- The finding will list which files failed verification

### Updating Reference Data

When you update `known-cves.json` or `malicious-patterns.json`, you **must** regenerate the checksums:

```bash
# Regenerate all checksums in references/ directory
bash scripts/update_checksums.sh
```

This script:
- Finds all `.json` files in `references/`
- Computes SHA256 hashes (using `sha256sum` on Linux, `shasum -a 256` on macOS)
- Writes `.json.sha256` files in standard format: `<hash>  <filename>`
- Reports success/failure for each file

**Always run this after modifying reference data** -- otherwise the next scan will fail integrity verification.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b add-new-check`)
3. Add your check to the appropriate scanner in `scripts/`
4. Register the check ID in `references/check-catalog.md`
5. Run the test suite: `bash tests/run.sh`
6. Open a pull request

Check IDs follow the pattern `CHK-{CATEGORY}-{NNN}`. Pick the next available
number in the category.

---

## Credits

- CVE data sourced from NVD and OpenClaw security advisories
- Built with bash, jq, and healthy paranoia

---

## License

MIT
