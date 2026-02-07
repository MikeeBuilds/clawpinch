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
# Resolve git repository path
# ---------------------------------------------------------------------------
REPO_PATH="${GIT_REPO_PATH:-.}"

if [[ ! -d "$REPO_PATH/.git" ]]; then
    echo '[{"id":"CHK-GIT-000","severity":"info","title":"Not a git repository","description":"Could not locate .git directory","evidence":"'"$REPO_PATH"'","remediation":"Run this scanner from within a git repository","auto_fix":""}]'
    exit 0
fi

# Verify git command is available
if ! command -v git &>/dev/null; then
    echo '[{"id":"CHK-GIT-000","severity":"warn","title":"git command not found","description":"The git command is not available in PATH","evidence":"git not found","remediation":"Install git to enable history scanning","auto_fix":""}]'
    exit 0
fi

# ---------------------------------------------------------------------------
# Collect findings into an array
# ---------------------------------------------------------------------------
FINDINGS=()

# ---------------------------------------------------------------------------
# Git history scanning checks will be implemented in subsequent subtasks
# ---------------------------------------------------------------------------
# CHK-GIT-001: API keys in commit history
# CHK-GIT-002: Passwords in commit history
# CHK-GIT-003: Private keys in commit history
# CHK-GIT-004: AWS credentials in commit history
# CHK-GIT-005: Database credentials in commit history
# CHK-GIT-006: OAuth tokens in commit history
# CHK-GIT-007: Generic secrets in commit history
# CHK-GIT-008: Large binary files in history

# ---------------------------------------------------------------------------
# Output all findings as a JSON array
# ---------------------------------------------------------------------------
if [[ ${#FINDINGS[@]} -eq 0 ]]; then
    echo '[]'
else
    printf '%s\n' "${FINDINGS[@]}" | jq -s '.'
fi
