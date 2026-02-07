# GitHub Actions SARIF Integration

This guide shows you how to integrate ClawPinch with GitHub Code Scanning using SARIF output. This enables security findings to appear inline in pull requests and in the repository's Security tab.

---

## Quick Start

Add this workflow to `.github/workflows/clawpinch.yml`:

```yaml
name: ClawPinch Security Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]
  schedule:
    # Run weekly on Monday at 9am UTC
    - cron: '0 9 * * 1'

permissions:
  contents: read
  security-events: write  # Required for uploading SARIF results

jobs:
  security-scan:
    name: ClawPinch Security Audit
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Run ClawPinch security scan
        run: |
          npx clawpinch --sarif --no-interactive > clawpinch.sarif
        continue-on-error: true  # Don't fail the build on findings

      - name: Upload SARIF results to GitHub
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: clawpinch.sarif
          category: clawpinch
```

---

## How It Works

### 1. Running the Scan

The workflow runs ClawPinch with the `--sarif` and `--no-interactive` flags:

```bash
npx clawpinch --sarif --no-interactive > clawpinch.sarif
```

- `--sarif` produces SARIF v2.1.0 JSON output instead of the standard terminal UI
- `--no-interactive` skips the post-scan menu (required for CI/CD)
- Output is redirected to `clawpinch.sarif`

### 2. Uploading Results

The `github/codeql-action/upload-sarif@v3` action uploads the SARIF file to GitHub:

```yaml
- name: Upload SARIF results to GitHub
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: clawpinch.sarif
    category: clawpinch
```

**Parameters:**
- `sarif_file`: Path to the SARIF output file
- `category`: Identifies this as a ClawPinch scan (allows multiple analysis tools)

**Requirements:**
- The workflow must have `security-events: write` permission
- The repository must have GitHub Advanced Security enabled (free for public repos, requires license for private repos)

### 3. Viewing Results in Pull Requests

Once uploaded, security findings appear in pull requests:

- **Code annotations**: Findings appear as inline comments on the relevant files
- **PR checks**: A "Code scanning results / ClawPinch" check appears in the PR status
- **Diff view**: Only findings introduced in the PR are highlighted
- **Severity badges**: Critical, warning, and info findings are color-coded

**Example PR annotation:**

```
┃ ● CRITICAL                            CHK-CFG-001 ┃
┃ exec.ask not set to always                         ┃
┃                                                     ┃
┃ The exec.ask setting controls whether the user is  ┃
┃ prompted before command execution.                 ┃
┃                                                     ┃
┃ Fix: Set exec.ask to 'always' in openclaw.json     ┃
```

### 4. Viewing Results in the Security Tab

All findings across all scans are tracked in the repository's Security tab:

1. Navigate to your repository → **Security** tab
2. Click **Code scanning** in the left sidebar
3. Filter by tool: **ClawPinch**

**Features:**
- **Timeline view**: Track when findings were introduced and fixed
- **Trend analysis**: See security posture improving over time
- **Filter by severity**: Focus on critical findings first
- **Dismissal workflow**: Mark findings as false positives or won't-fix with comments

---

## Advanced Configuration

### Run on Specific Directories

If your OpenClaw deployment is in a subdirectory:

```yaml
- name: Run ClawPinch security scan
  run: |
    npx clawpinch --sarif --no-interactive --config-dir ./infra/openclaw > clawpinch.sarif
```

### Deep Scan Mode

Enable supply-chain verification and skill decompilation:

```yaml
- name: Run ClawPinch deep scan
  run: |
    npx clawpinch --sarif --no-interactive --deep > clawpinch.sarif
```

### Fail Build on Critical Findings

By default, `continue-on-error: true` prevents failing the build. To enforce a security gate:

```yaml
- name: Run ClawPinch security scan
  run: |
    npx clawpinch --sarif --no-interactive > clawpinch.sarif

    # Check if any critical findings exist
    if jq -e '.runs[0].results[] | select(.level == "error")' clawpinch.sarif > /dev/null; then
      echo "❌ Critical security findings detected"
      exit 1
    fi
```

### Multiple SARIF Uploads

If you run multiple scans (e.g., different environments), use unique categories:

```yaml
- name: Scan production config
  run: npx clawpinch --sarif --config-dir ./prod > clawpinch-prod.sarif

- name: Upload production results
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: clawpinch-prod.sarif
    category: clawpinch-prod

- name: Scan staging config
  run: npx clawpinch --sarif --config-dir ./staging > clawpinch-staging.sarif

- name: Upload staging results
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: clawpinch-staging.sarif
    category: clawpinch-staging
```

---

## Combining with Other Scanners

SARIF allows you to aggregate results from multiple static analysis tools:

```yaml
name: Security Scanning Suite

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # ClawPinch for OpenClaw-specific checks
      - run: npx clawpinch --sarif > clawpinch.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: clawpinch.sarif
          category: clawpinch

      # Semgrep for general code patterns
      - run: semgrep --sarif > semgrep.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep.sarif
          category: semgrep

      # Trivy for container scanning
      - run: trivy image --format sarif myapp:latest > trivy.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy.sarif
          category: trivy
```

All findings appear together in the Security tab, filterable by tool.

---

## Troubleshooting

### "Resource not accessible by integration"

**Error:**
```
Error: Resource not accessible by integration
```

**Solution:**
Add `security-events: write` permission to the workflow:

```yaml
permissions:
  contents: read
  security-events: write
```

### "Advanced Security must be enabled"

**Error:**
```
Advanced Security must be enabled for this repository to use code scanning.
```

**Solution:**
- For **public repositories**: GitHub Advanced Security is free and automatically available
- For **private repositories**: Enable GitHub Advanced Security in repository settings (requires GitHub Enterprise license)

### Invalid SARIF File

**Error:**
```
Error: Invalid SARIF. The SARIF file is not valid.
```

**Solution:**
Validate the SARIF file before uploading:

```yaml
- name: Validate SARIF output
  run: |
    # Install SARIF validator
    npm install -g @microsoft/sarif-multitool

    # Validate against SARIF v2.1.0 schema
    sarif-multitool validate clawpinch.sarif
```

If validation fails, [open an issue](https://github.com/MikeeBuilds/clawpinch/issues) with the output.

### No Findings Appear in PRs

**Checklist:**
1. Verify the workflow completed successfully in the Actions tab
2. Check that `security-events: write` permission is set
3. Ensure the SARIF file was uploaded (check action logs)
4. Wait 1-2 minutes for GitHub to process the SARIF file
5. Verify findings are for files changed in the PR (GitHub only shows diff-related alerts in PR checks)

---

## SARIF Output Format Reference

ClawPinch produces SARIF v2.1.0 output with the following structure:

```json
{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "runs": [{
    "tool": {
      "driver": {
        "name": "ClawPinch",
        "version": "1.2.0",
        "informationUri": "https://github.com/MikeeBuilds/clawpinch",
        "rules": [
          {
            "id": "CHK-CFG-001",
            "name": "GatewayListeningOnAllInterfaces",
            "shortDescription": {
              "text": "Gateway listening on 0.0.0.0"
            },
            "helpUri": "https://github.com/MikeeBuilds/clawpinch#chk-cfg-001",
            "defaultConfiguration": {
              "level": "error"
            }
          }
        ]
      }
    },
    "results": [
      {
        "ruleId": "CHK-CFG-001",
        "level": "error",
        "message": {
          "text": "Gateway listening on 0.0.0.0 - restricts to localhost (127.0.0.1)",
          "markdown": "**Finding:** Gateway listening on 0.0.0.0\n\n**Fix:** Set gateway.host to '127.0.0.1' in openclaw.json"
        }
      }
    ]
  }]
}
```

**Severity Mapping:**
- `critical` → SARIF `error`
- `warn` → SARIF `warning`
- `info` → SARIF `note`
- `ok` → Not included in SARIF output (only findings)

---

## Related Documentation

- [ClawPinch README](../README.md) — Installation and usage
- [Check Catalog](../references/check-catalog.md) — Full list of 63 checks
- [SARIF Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) — Official SARIF v2.1.0 spec
- [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning) — GitHub Advanced Security docs

---

## Example: Complete CI/CD Pipeline

This workflow runs ClawPinch on every PR, uploads results to GitHub, and blocks merging on critical findings:

```yaml
name: Security Gate

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  clawpinch-scan:
    name: ClawPinch Security Scan
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run ClawPinch
        id: scan
        run: |
          npx clawpinch --sarif --no-interactive > clawpinch.sarif

          # Count critical findings
          CRITICAL=$(jq '[.runs[0].results[] | select(.level == "error")] | length' clawpinch.sarif)
          echo "critical=$CRITICAL" >> $GITHUB_OUTPUT
        continue-on-error: true

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: clawpinch.sarif
          category: clawpinch

      - name: Comment on PR
        uses: actions/github-script@v7
        with:
          script: |
            const critical = ${{ steps.scan.outputs.critical }};
            const body = critical > 0
              ? `⛔ **ClawPinch found ${critical} critical security finding(s)**\n\nReview the Code Scanning alerts for details.`
              : `✅ **ClawPinch scan passed** - No critical findings`;

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: body
            });

      - name: Enforce security gate
        if: steps.scan.outputs.critical > 0
        run: |
          echo "❌ Blocking merge: ${{ steps.scan.outputs.critical }} critical findings detected"
          exit 1
```

This enforces a security gate — PRs with critical findings cannot be merged until they're fixed.

---

## License

MIT
