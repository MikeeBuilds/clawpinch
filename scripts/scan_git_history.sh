#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# scan_git_history.sh - Git History Security Scanner
#
# Scans git repository history for accidentally committed secrets, credentials,
# and sensitive information. Outputs a JSON array of findings to stdout.
#
# Usage:
#   ./scan_git_history.sh                     # scan current directory
#   GIT_REPO_PATH=/path/to/repo ./scan_git_history.sh
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source shared helpers if available; define fallbacks otherwise
if [[ -f "${SCRIPT_DIR}/helpers/common.sh" ]]; then
    # shellcheck source=helpers/common.sh
    source "${SCRIPT_DIR}/helpers/common.sh"
fi

# Fallback: define emit_finding if not already provided by common.sh
if ! declare -f emit_finding >/dev/null 2>&1; then
    emit_finding() {
        local id="$1" severity="$2" title="$3" description="$4" evidence="$5" remediation="$6" auto_fix="${7:-}"
        jq -n \
            --arg id "$id" \
            --arg severity "$severity" \
            --arg title "$title" \
            --arg description "$description" \
            --arg evidence "$evidence" \
            --arg remediation "$remediation" \
            --arg auto_fix "$auto_fix" \
            '{id:$id, severity:$severity, title:$title, description:$description, evidence:$evidence, remediation:$remediation, auto_fix:$auto_fix}'
    }
fi

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------
# Maximum line length to scan (longer lines are likely binary data)
MAX_LINE_LENGTH=10000

# File extensions to skip (binary/media files)
SKIP_EXTENSIONS='\.(jpg|jpeg|png|gif|bmp|ico|svg|webp|pdf|zip|tar|gz|bz2|xz|7z|rar|exe|dll|so|dylib|a|o|bin|dat|mp3|mp4|avi|mov|mkv|flv|wmv|wav|ttf|otf|woff|woff2|eot)$'

# Additional files/paths to skip (performance optimization)
# Lockfiles, generated files, test fixtures rarely contain real secrets
SKIP_PATHS='(package-lock\.json|yarn\.lock|composer\.lock|Gemfile\.lock|poetry\.lock|pnpm-lock\.yaml|\.min\.(js|css)|\.map$|__snapshots__/|test/fixtures/|tests/fixtures/|spec/fixtures/)'

# Dedupe: Track found secrets to avoid duplicate findings (bash 3.2 compatible)
FOUND_SECRETS=""

# ---------------------------------------------------------------------------
# Resolve git repository path
# ---------------------------------------------------------------------------
REPO_PATH="${GIT_REPO_PATH:-.}"

# Edge case: Handle both regular repos and worktrees
# In worktrees, .git is a file, not a directory
if [[ ! -d "$REPO_PATH/.git" ]] && [[ ! -f "$REPO_PATH/.git" ]]; then
    # Not a git repo - output empty array (this is expected behavior)
    echo '[]'
    exit 0
fi

# Verify git command is available
if ! command -v git &>/dev/null; then
    echo '[]'
    exit 0
fi

# ---------------------------------------------------------------------------
# Edge case: Check if repo has any commits
# ---------------------------------------------------------------------------
if ! (cd "$REPO_PATH" && git rev-parse HEAD &>/dev/null); then
    # Empty repository with no commits
    echo '[]'
    exit 0
fi

# ---------------------------------------------------------------------------
# Edge case: Handle shallow clones
# Shallow clones have incomplete history, which means we might miss secrets.
# We'll add a warning to remediation messages if shallow clone is detected.
# ---------------------------------------------------------------------------
IS_SHALLOW=0
if [[ -f "$REPO_PATH/.git/shallow" ]]; then
    IS_SHALLOW=1
fi

# ---------------------------------------------------------------------------
# Collect findings into an array
# ---------------------------------------------------------------------------
FINDINGS=()

# ---------------------------------------------------------------------------
# Helper: Redact secret value (show only last 4 chars)
# ---------------------------------------------------------------------------
redact_secret() {
    local value="$1"
    local len=${#value}
    if [[ $len -le 4 ]]; then
        echo "****"
    else
        echo "****${value: -4}"
    fi
}

# ---------------------------------------------------------------------------
# Helper: Check if file should be skipped based on extension and path
# ---------------------------------------------------------------------------
should_skip_file() {
    local filepath="$1"

    # Skip binary/media files by extension
    if [[ "$filepath" =~ $SKIP_EXTENSIONS ]]; then
        return 0  # skip
    fi

    # Performance optimization: Skip lockfiles, generated files, test fixtures
    if [[ "$filepath" =~ $SKIP_PATHS ]]; then
        return 0  # skip
    fi

    return 1  # don't skip
}

# ---------------------------------------------------------------------------
# Secret pattern definitions (adapted from scan_secrets.py)
# Each entry is "type|pattern" separated by pipe
# ---------------------------------------------------------------------------
SECRET_PATTERNS=(
    "Slack bot token|xoxb-[A-Za-z0-9-]+"
    "Slack app token|xapp-[A-Za-z0-9-]+"
    "Slack user token|xoxp-[A-Za-z0-9-]+"
    "JWT token|eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    "Discord bot token|[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}"
    "Telegram bot token|[0-9]{8,10}:[A-Za-z0-9_-]{35}"
    "OpenAI API key|sk-proj-[A-Za-z0-9]{20,}"
    "OpenAI legacy key|sk-[A-Za-z0-9]{20,}"
    "Ethereum private key|0x[a-fA-F0-9]{64}"
    "Private key|-----BEGIN[[:space:]]+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    "Generic Bearer token|[Bb]earer[[:space:]]+[A-Za-z0-9_.~+/-]+=*"
    "AWS Access Key|AKIA[0-9A-Z]{16}"
    "GitHub Token|ghp_[A-Za-z0-9]{36}"
    "Generic API key|api[_-]?key[[:space:]]*[:=][[:space:]]*[\"'][A-Za-z0-9_-]{20,}[\"']"
)

# ---------------------------------------------------------------------------
# Scan git history for secrets
# ---------------------------------------------------------------------------
scan_git_history() {
    # Determine scan depth based on CLAWPINCH_DEEP
    local max_commits=100
    local time_limit=""

    if [[ "${CLAWPINCH_DEEP:-0}" == "1" ]]; then
        max_commits=1000
        time_limit="--since=6 months ago"
    fi

    # Performance optimization: Check repo size and warn if very large
    local total_commits
    total_commits=$(cd "$REPO_PATH" && git rev-list --count --all 2>/dev/null || echo "0")

    # Edge case: Warn if repo has many commits but we're not doing deep scan
    if [[ "$total_commits" -gt 10000 ]] && [[ "${CLAWPINCH_DEEP:-0}" != "1" ]]; then
        # Emit info finding about large repo
        local finding
        finding=$(emit_finding \
            "CHK-SEC-009" \
            "info" \
            "Large repository detected" \
            "Repository has $total_commits commits but scanning only $max_commits. Consider using --deep flag for thorough scan." \
            "total_commits=$total_commits scan_depth=$max_commits" \
            "Run with CLAWPINCH_DEEP=1 for deeper history scan" \
            "")
        FINDINGS+=("$finding")
    fi

    # Performance optimization: Use --diff-filter to only show added content
    # --no-merges skips merge commits (reduces duplicate scanning)
    # Get git log with patches
    # Format: commit hash, file path, diff lines
    # Note: --no-textconv disables textconv filters
    # Timeout protection: Use timeout command if available (GNU coreutils or timeout from macOS)
    local git_output
    local timeout_cmd=""
    if command -v timeout &>/dev/null; then
        # Timeout after 300 seconds (5 minutes) for normal scan, 900 seconds (15 min) for deep
        local timeout_seconds=300
        [[ "${CLAWPINCH_DEEP:-0}" == "1" ]] && timeout_seconds=900
        timeout_cmd="timeout ${timeout_seconds}s"
    fi

    git_output=$(cd "$REPO_PATH" && $timeout_cmd git log -p --all --no-textconv --no-merges --diff-filter=A -n "$max_commits" $time_limit --format="COMMIT:%H" 2>/dev/null || true)

    # Edge case: Check if command was killed by timeout
    local git_exit_code=$?
    if [[ $git_exit_code -eq 124 ]] || [[ $git_exit_code -eq 137 ]]; then
        # 124 = timeout killed the process, 137 = SIGKILL
        local finding
        finding=$(emit_finding \
            "CHK-SEC-010" \
            "warn" \
            "Git history scan timed out" \
            "The git history scan exceeded the time limit. Repository may be too large for complete scan." \
            "exit_code=$git_exit_code" \
            "Consider scanning a smaller time range or using --shallow-since with git clone" \
            "")
        FINDINGS+=("$finding")
        return 0
    fi

    if [[ -z "$git_output" ]]; then
        # Empty history or no commits
        return 0
    fi

    local current_commit=""
    local current_file=""
    local lines_scanned=0
    local max_lines=50000  # Safety limit to prevent runaway scans

    # Performance optimization: Early exit if we've scanned too many lines
    if [[ "${CLAWPINCH_DEEP:-0}" == "1" ]]; then
        max_lines=500000
    fi

    # Process git log output line by line
    while IFS= read -r line; do
        # Safety limit: Exit if we've scanned too many lines
        ((lines_scanned++))
        if [[ $lines_scanned -gt $max_lines ]]; then
            break
        fi

        # Extract commit hash
        if [[ "$line" =~ ^COMMIT:([a-f0-9]{40}) ]]; then
            current_commit="${BASH_REMATCH[1]}"
            current_file=""
            continue
        fi

        # Extract file path from diff header
        if [[ "$line" =~ ^\+\+\+[[:space:]]b/(.+)$ ]]; then
            current_file="${BASH_REMATCH[1]}"
            # Performance optimization: Skip binary/media files early
            if should_skip_file "$current_file"; then
                current_file=""  # Mark as skipped
            fi
            continue
        fi

        # Only check added lines (starting with +)
        if [[ ! "$line" =~ ^\+[^+] ]]; then
            continue
        fi

        # Skip if we don't have commit context or file was skipped
        if [[ -z "$current_commit" ]] || [[ -z "$current_file" ]]; then
            continue
        fi

        # Performance optimization: Skip very long lines (likely binary data)
        if [[ ${#line} -gt $MAX_LINE_LENGTH ]]; then
            continue
        fi

        # Remove the leading + from the diff line
        local content="${line:1}"

        # Edge case: Skip empty lines
        if [[ -z "${content// /}" ]]; then
            continue
        fi

        # Edge case: Skip lines with null bytes or other binary indicators
        # (some binary data may slip through extension filtering)
        if [[ "$content" == *$'\x00'* ]] || [[ "$content" =~ [[:cntrl:]]{10,} ]]; then
            continue
        fi

        # Check each secret pattern
        for pattern_entry in "${SECRET_PATTERNS[@]}"; do
            # Parse "type|pattern" format
            local secret_type="${pattern_entry%%|*}"
            local pattern="${pattern_entry#*|}"

            # Use grep -oE to extract matching secrets
            local matches
            matches=$(echo "$content" | grep -oE "$pattern" 2>/dev/null || true)

            if [[ -n "$matches" ]]; then
                while IFS= read -r secret_value; do
                    # Skip empty matches
                    [[ -z "$secret_value" ]] && continue

                    # Performance optimization: Skip very short matches (likely false positives)
                    # Exception: private keys can have short markers
                    if [[ ${#secret_value} -lt 8 ]] && [[ "$secret_type" != "Private key" ]]; then
                        continue
                    fi

                    # Edge case: Skip environment variable references (${VAR} or $VAR)
                    if [[ "$secret_value" =~ ^\$\{.*\}$ ]] || [[ "$secret_value" =~ ^\$[A-Z_][A-Z0-9_]*$ ]]; then
                        continue
                    fi

                    # Edge case: Skip placeholder/example values (case-insensitive)
                    local lower_value
                    lower_value=$(echo "$secret_value" | tr '[:upper:]' '[:lower:]')
                    if [[ "$lower_value" =~ (your|example|test|sample|placeholder|dummy|fake|xxx|yyy|zzz|000|111|abc|123|todo|fixme|redacted) ]]; then
                        continue
                    fi

                    # Performance optimization: Deduplicate findings
                    # Create a unique key for this secret
                    local secret_key="${secret_type}:${secret_value}"
                    if echo "$FOUND_SECRETS" | grep -qF "$secret_key"; then
                        continue  # Already reported this secret
                    fi
                    FOUND_SECRETS="${FOUND_SECRETS}${secret_key}"$'\n'

                    local redacted_value
                    redacted_value=$(redact_secret "$secret_value")

                    local evidence="commit=${current_commit:0:8} file=$current_file secret_type=\"$secret_type\" value=$redacted_value"

                    local title="$secret_type found in git history"
                    local description="A $secret_type was detected in commit $current_commit in file $current_file. This secret exists in the repository history even if it was later removed from current files."

                    local remediation="Remove secret from git history using git filter-repo or BFG Repo-Cleaner. Rotate the exposed credential immediately. See: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository"

                    # Add shallow clone warning to remediation if applicable
                    if [[ $IS_SHALLOW -eq 1 ]]; then
                        remediation="$remediation NOTE: This is a shallow clone - full history may contain additional secrets. Run 'git fetch --unshallow' for complete scan."
                    fi

                    # Emit finding
                    local finding
                    finding=$(emit_finding \
                        "CHK-SEC-008" \
                        "critical" \
                        "$title" \
                        "$description" \
                        "$evidence" \
                        "$remediation" \
                        "")

                    FINDINGS+=("$finding")
                done <<< "$matches"
            fi
        done
    done <<< "$git_output"
}

# Run the scan
scan_git_history

# ---------------------------------------------------------------------------
# Output all findings as a JSON array
# ---------------------------------------------------------------------------
if [[ ${#FINDINGS[@]} -eq 0 ]]; then
    echo '[]'
else
    printf '%s\n' "${FINDINGS[@]}" | jq -s '.'
fi
