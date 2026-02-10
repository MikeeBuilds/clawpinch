#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# test_git_history.sh - Integration Test for Git History Scanner
#
# Simplified pragmatic tests focusing on edge cases and basic functionality
#
# Usage:
#   bash scripts/helpers/test_git_history.sh
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCANNER="${PROJECT_ROOT}/scripts/scan_git_history.sh"

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Color output
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
  C_GREEN='\033[0;32m'
  C_RED='\033[0;31m'
  C_BLUE='\033[0;34m'
  C_BOLD='\033[1m'
  C_RESET='\033[0m'
else
  C_GREEN='' C_RED='' C_BLUE='' C_BOLD='' C_RESET=''
fi

# Create temp directory
TEST_DIR="$(mktemp -d -t clawpinch-git-test.XXXXXX)"
function cleanup {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

echo "[info] Test directory: $TEST_DIR" >&2

# Test helper
run_test() {
    local test_name="$1"
    local test_cmd="$2"

    TESTS_RUN=$((TESTS_RUN + 1))
    printf "  [%02d] %-60s " "$TESTS_RUN" "$test_name"

    if eval "$test_cmd" &>/dev/null; then
        printf "${C_GREEN}✓ PASS${C_RESET}\n"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        printf "${C_RED}✗ FAIL${C_RESET}\n"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Test: Non-git directory
test_non_git() {
    local dir="${TEST_DIR}/not_git"
    mkdir -p "$dir"
    local output
    output=$(GIT_REPO_PATH="$dir" bash "$SCANNER")
    echo "$output" | jq -e 'type == "array" and length == 0' >/dev/null 2>&1
}

# Test: Empty repo
test_empty_repo() {
    local repo="${TEST_DIR}/empty"
    mkdir -p "$repo"
    cd "$repo"
    git init -q
    local output
    output=$(GIT_REPO_PATH="$repo" bash "$SCANNER")
    echo "$output" | jq -e 'type == "array" and length == 0' >/dev/null 2>&1
}

# Test: Valid JSON output
test_json_output() {
    local repo="${TEST_DIR}/json_test"
    mkdir -p "$repo"
    cd "$repo"
    git init -q
    git config user.email "test@test.test"
    git config user.name "Test"
    echo "clean file" > file.txt
    git add file.txt
    git commit -q -m "Add file"
    local output
    output=$(GIT_REPO_PATH="$repo" bash "$SCANNER")
    echo "$output" | jq -e 'type == "array"' >/dev/null 2>&1
}

# Test: Scanner doesn't crash on binary files
test_binary_handling() {
    local repo="${TEST_DIR}/binary"
    mkdir -p "$repo"
    cd "$repo"
    git init -q
    git config user.email "test@test.test"
    git config user.name "Test"
    printf '\x00\x01\x02\x03\x04' > binary.dat
    git add binary.dat
    git commit -q -m "Add binary"
    local output
    output=$(GIT_REPO_PATH="$repo" bash "$SCANNER" 2>&1)
    echo "$output" | jq -e 'type == "array"' >/dev/null 2>&1
}

# Test: Worktree support (doesn't crash)
test_worktree() {
    local repo="${TEST_DIR}/wt_main"
    mkdir -p "$repo"
    cd "$repo"
    git init -q
    git config user.email "test@test.test"
    git config user.name "Test"
    echo "main" > main.txt
    git add main.txt
    git commit -q -m "Main"

    local wt="${TEST_DIR}/wt_branch"
    if git worktree add -q "$wt" -b branch 2>/dev/null; then
        local output
        output=$(GIT_REPO_PATH="$wt" bash "$SCANNER" 2>&1)
        git worktree remove -f "$wt" 2>/dev/null || true
        echo "$output" | jq -e 'type == "array"' >/dev/null 2>&1
    else
        # Worktrees not supported, pass test
        return 0
    fi
}

# Test: Deep scan mode
test_deep_mode() {
    local repo="${TEST_DIR}/deep"
    mkdir -p "$repo"
    cd "$repo"
    git init -q
    git config user.email "test@test.test"
    git config user.name "Test"
    echo "file" > file.txt
    git add file.txt
    git commit -q -m "File"

    # Normal scan
    local normal
    normal=$(CLAWPINCH_DEEP=0 GIT_REPO_PATH="$repo" bash "$SCANNER")

    # Deep scan
    local deep
    deep=$(CLAWPINCH_DEEP=1 GIT_REPO_PATH="$repo" bash "$SCANNER")

    # Both should return valid JSON arrays
    echo "$normal" | jq -e 'type == "array"' >/dev/null 2>&1 && \
    echo "$deep" | jq -e 'type == "array"' >/dev/null 2>&1
}

# Run tests
printf "\n${C_BLUE}${C_BOLD}━━━ Git History Scanner Tests ━━━${C_RESET}\n\n"

printf "${C_BLUE}${C_BOLD}Edge Cases${C_RESET}\n"
run_test "Non-git directory returns empty array" "test_non_git"
run_test "Empty repository returns empty array" "test_empty_repo"
run_test "Binary file handling (no crash)" "test_binary_handling"
run_test "Worktree support (no crash)" "test_worktree"

printf "\n${C_BLUE}${C_BOLD}Functionality${C_RESET}\n"
run_test "Valid JSON output format" "test_json_output"
run_test "Deep scan mode" "test_deep_mode"

# Summary
printf "\n${C_BLUE}${C_BOLD}━━━ Test Summary ━━━${C_RESET}\n\n"
printf "  Total:  %d\n" "$TESTS_RUN"
printf "  ${C_GREEN}Passed: %d${C_RESET}\n" "$TESTS_PASSED"

if [[ $TESTS_FAILED -gt 0 ]]; then
    printf "  ${C_RED}Failed: %d${C_RESET}\n" "$TESTS_FAILED"
    printf "\n${C_RED}${C_BOLD}✗ TESTS FAILED${C_RESET}\n\n"
    exit 1
else
    printf "  Failed: 0\n"
    printf "\n${C_GREEN}${C_BOLD}✓ ALL TESTS PASSED${C_RESET}\n\n"
    exit 0
fi
