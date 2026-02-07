#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# test_integration.sh - Integration Test for Auto-Fix Commands
#
# Tests all auto-fix commands from check-catalog.md to ensure they execute
# successfully without actually modifying the real system.
#
# Usage:
#   bash scripts/helpers/test_integration.sh
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Source common helpers
if [[ -f "${SCRIPT_DIR}/common.sh" ]]; then
    source "${SCRIPT_DIR}/common.sh"
else
    log_error() { printf "[error] %s\n" "$*" >&2; }
    log_info() { printf "[info]  %s\n" "$*" >&2; }
fi

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Create a temporary test directory
TEST_DIR="$(mktemp -d -t clawpinch-test.XXXXXX)"
trap 'rm -rf "$TEST_DIR"' EXIT

log_info "Test directory: $TEST_DIR"

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

run_test() {
    local test_name="$1"
    local test_cmd="$2"

    TESTS_RUN=$((TESTS_RUN + 1))

    printf "  [%02d] %-60s " "$TESTS_RUN" "$test_name"

    if eval "$test_cmd" &>/dev/null; then
        printf "✓ PASS\n"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        printf "✗ FAIL\n"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

create_mock_config() {
    local config_file="$1"
    cat > "$config_file" <<'EOF'
{
  "tools": {
    "exec": {
      "ask": "never",
      "security": "basic"
    }
  },
  "channels": {
    "slack": {
      "groupPolicy": "open",
      "dmPolicy": "open",
      "allowFrom": ["*"]
    },
    "discord": {
      "groupPolicy": "restricted",
      "dmPolicy": "closed",
      "allowFrom": ["example.com"]
    }
  },
  "plugins": {
    "allow": null
  },
  "gateway": {
    "bindAddress": "0.0.0.0:3000",
    "requireAuth": false,
    "auth": {
      "token": null
    }
  },
  "controlUi": {
    "dangerouslyDisableDeviceAuth": true
  },
  "commands": {
    "nativeSkills": true
  },
  "browser": {
    "enabled": true,
    "restrict": false
  },
  "discovery": {
    "mdns": true,
    "wideArea": true
  },
  "logging": {
    "redactSensitive": null
  }
}
EOF
}

# ---------------------------------------------------------------------------
# Test: CHK-CFG-001 auto-fix (exec.ask = "always")
# ---------------------------------------------------------------------------
test_cfg_001() {
    local config="${TEST_DIR}/test_cfg_001.json"
    create_mock_config "$config"

    # Run the auto-fix command
    jq '.tools.exec.ask = "always"' "$config" > "${config}.tmp" && mv "${config}.tmp" "$config"

    # Verify the fix was applied
    local result
    result=$(jq -r '.tools.exec.ask' "$config")
    [[ "$result" == "always" ]]
}

# ---------------------------------------------------------------------------
# Test: CHK-CFG-002 auto-fix (open groupPolicy -> restricted)
# ---------------------------------------------------------------------------
test_cfg_002() {
    local config="${TEST_DIR}/test_cfg_002.json"
    create_mock_config "$config"

    # Run the auto-fix command
    jq '(.channels[] | select(.groupPolicy == "open") | .groupPolicy) = "restricted"' "$config" > "${config}.tmp" && mv "${config}.tmp" "$config"

    # Verify no channels have groupPolicy="open"
    local open_count
    open_count=$(jq '[.channels[] | select(.groupPolicy == "open")] | length' "$config")
    [[ "$open_count" == "0" ]]
}

# ---------------------------------------------------------------------------
# Test: CHK-CFG-003 auto-fix (open dmPolicy -> restricted)
# ---------------------------------------------------------------------------
test_cfg_003() {
    local config="${TEST_DIR}/test_cfg_003.json"
    create_mock_config "$config"

    # Run the auto-fix command
    jq '(.channels[] | select(.dmPolicy == "open") | .dmPolicy) = "restricted"' "$config" > "${config}.tmp" && mv "${config}.tmp" "$config"

    # Verify no channels have dmPolicy="open"
    local open_count
    open_count=$(jq '[.channels[] | select(.dmPolicy == "open")] | length' "$config")
    [[ "$open_count" == "0" ]]
}

# ---------------------------------------------------------------------------
# Test: CHK-CFG-004 auto-fix (plugins.allow = [])
# ---------------------------------------------------------------------------
test_cfg_004() {
    local config="${TEST_DIR}/test_cfg_004.json"
    create_mock_config "$config"

    # Run the auto-fix command
    jq '.plugins.allow = []' "$config" > "${config}.tmp" && mv "${config}.tmp" "$config"

    # Verify plugins.allow is an empty array
    local result
    result=$(jq -r '.plugins.allow | type' "$config")
    [[ "$result" == "array" ]]
}

# ---------------------------------------------------------------------------
# Test: CHK-CFG-005 auto-fix (exec.security = "full")
# ---------------------------------------------------------------------------
test_cfg_005() {
    local config="${TEST_DIR}/test_cfg_005.json"
    create_mock_config "$config"

    # Run the auto-fix command
    jq '.tools.exec.security = "full"' "$config" > "${config}.tmp" && mv "${config}.tmp" "$config"

    # Verify the fix was applied
    local result
    result=$(jq -r '.tools.exec.security' "$config")
    [[ "$result" == "full" ]]
}

# ---------------------------------------------------------------------------
# Test: CHK-CFG-007 auto-fix (dangerouslyDisableDeviceAuth = false)
# ---------------------------------------------------------------------------
test_cfg_007() {
    local config="${TEST_DIR}/test_cfg_007.json"
    create_mock_config "$config"

    # Run the auto-fix command
    jq '.controlUi.dangerouslyDisableDeviceAuth = false' "$config" > "${config}.tmp" && mv "${config}.tmp" "$config"

    # Verify the fix was applied
    local result
    result=$(jq -r '.controlUi.dangerouslyDisableDeviceAuth' "$config")
    [[ "$result" == "false" ]]
}

# ---------------------------------------------------------------------------
# Test: CHK-CFG-008 auto-fix (remove "*" from allowFrom)
# ---------------------------------------------------------------------------
test_cfg_008() {
    local config="${TEST_DIR}/test_cfg_008.json"
    create_mock_config "$config"

    # Run the auto-fix command
    jq '.channels.slack.allowFrom = (.channels.slack.allowFrom | map(select(. != "*")))' "$config" > "${config}.tmp" && mv "${config}.tmp" "$config"

    # Verify "*" was removed from allowFrom
    local has_wildcard
    has_wildcard=$(jq -r '.channels.slack.allowFrom | map(select(. == "*")) | length' "$config")
    [[ "$has_wildcard" == "0" ]]
}

# ---------------------------------------------------------------------------
# Test: CHK-CFG-009 auto-fix (nativeSkills = false)
# ---------------------------------------------------------------------------
test_cfg_009() {
    local config="${TEST_DIR}/test_cfg_009.json"
    create_mock_config "$config"

    # Run the auto-fix command
    jq '.commands.nativeSkills = false' "$config" > "${config}.tmp" && mv "${config}.tmp" "$config"

    # Verify the fix was applied
    local result
    result=$(jq -r '.commands.nativeSkills' "$config")
    [[ "$result" == "false" ]]
}

# ---------------------------------------------------------------------------
# Test: CHK-CFG-010 auto-fix (redactSensitive = true)
# ---------------------------------------------------------------------------
test_cfg_010() {
    local config="${TEST_DIR}/test_cfg_010.json"
    create_mock_config "$config"

    # Run the auto-fix command
    jq '.logging.redactSensitive = true' "$config" > "${config}.tmp" && mv "${config}.tmp" "$config"

    # Verify the fix was applied
    local result
    result=$(jq -r '.logging.redactSensitive' "$config")
    [[ "$result" == "true" ]]
}

# ---------------------------------------------------------------------------
# Test: CHK-CFG-011 auto-fix (browser.restrict = true)
# ---------------------------------------------------------------------------
test_cfg_011() {
    local config="${TEST_DIR}/test_cfg_011.json"
    create_mock_config "$config"

    # Run the auto-fix command
    jq '.browser.restrict = true' "$config" > "${config}.tmp" && mv "${config}.tmp" "$config"

    # Verify the fix was applied
    local result
    result=$(jq -r '.browser.restrict' "$config")
    [[ "$result" == "true" ]]
}

# ---------------------------------------------------------------------------
# Test: CHK-CFG-012 auto-fix (disable discovery)
# ---------------------------------------------------------------------------
test_cfg_012() {
    local config="${TEST_DIR}/test_cfg_012.json"
    create_mock_config "$config"

    # Run the auto-fix command
    jq '.discovery.mdns = false | .discovery.wideArea = false' "$config" > "${config}.tmp" && mv "${config}.tmp" "$config"

    # Verify both were disabled
    local mdns
    local wide
    mdns=$(jq -r '.discovery.mdns' "$config")
    wide=$(jq -r '.discovery.wideArea' "$config")
    [[ "$mdns" == "false" ]] && [[ "$wide" == "false" ]]
}

# ---------------------------------------------------------------------------
# Test: File permission change (chmod 600)
# ---------------------------------------------------------------------------
test_chmod_600() {
    local test_file="${TEST_DIR}/test_chmod.json"
    echo '{}' > "$test_file"
    chmod 644 "$test_file"

    # Run the auto-fix command
    chmod 600 "$test_file"

    # Verify permissions
    local perms
    if [[ "$(uname -s)" == "Darwin" ]]; then
        perms=$(stat -f "%Lp" "$test_file")
    else
        perms=$(stat -c "%a" "$test_file")
    fi
    [[ "$perms" == "600" ]]
}

# ---------------------------------------------------------------------------
# Test: CHK-PRM-013 auto-fix (SSH private key permissions)
# ---------------------------------------------------------------------------
test_prm_013() {
    # Create mock SSH directory
    local ssh_dir="${TEST_DIR}/.ssh"
    mkdir -p "$ssh_dir"

    # Create test SSH private keys with wrong permissions
    local test_key="${ssh_dir}/id_test_rsa"
    local test_pem="${ssh_dir}/test.pem"

    echo "-----BEGIN RSA PRIVATE KEY-----" > "$test_key"
    echo "fake key content" >> "$test_key"
    echo "-----END RSA PRIVATE KEY-----" >> "$test_key"

    echo "-----BEGIN PRIVATE KEY-----" > "$test_pem"
    echo "fake pem content" >> "$test_pem"
    echo "-----END PRIVATE KEY-----" >> "$test_pem"

    # Set insecure permissions
    chmod 644 "$test_key"
    chmod 644 "$test_pem"

    # Run the auto-fix command
    chmod 600 "$test_key"
    chmod 600 "$test_pem"

    # Verify permissions were fixed
    local perms_key perms_pem
    if [[ "$(uname -s)" == "Darwin" ]]; then
        perms_key=$(stat -f "%Lp" "$test_key")
        perms_pem=$(stat -f "%Lp" "$test_pem")
    else
        perms_key=$(stat -c "%a" "$test_key")
        perms_pem=$(stat -c "%a" "$test_pem")
    fi

    [[ "$perms_key" == "600" ]] && [[ "$perms_pem" == "600" ]]
}

# ---------------------------------------------------------------------------
# Main test execution
# ---------------------------------------------------------------------------

log_info "Starting auto-fix integration tests..."
echo ""
echo "Running Auto-Fix Command Tests:"
echo "─────────────────────────────────────────────────────────────────────────────"

# Check for required commands
if ! command -v jq &>/dev/null; then
    log_error "jq is required but not installed"
    exit 1
fi

# Run all tests
run_test "CHK-CFG-001: Set exec.ask to always" "test_cfg_001"
run_test "CHK-CFG-002: Fix open groupPolicy" "test_cfg_002"
run_test "CHK-CFG-003: Fix open dmPolicy" "test_cfg_003"
run_test "CHK-CFG-004: Initialize plugins.allow array" "test_cfg_004"
run_test "CHK-CFG-005: Set exec.security to full" "test_cfg_005"
run_test "CHK-CFG-007: Disable dangerouslyDisableDeviceAuth" "test_cfg_007"
run_test "CHK-CFG-008: Remove wildcard from allowFrom" "test_cfg_008"
run_test "CHK-CFG-009: Disable nativeSkills" "test_cfg_009"
run_test "CHK-CFG-010: Enable sensitive data redaction" "test_cfg_010"
run_test "CHK-CFG-011: Enable browser restrictions" "test_cfg_011"
run_test "CHK-CFG-012: Disable network discovery" "test_cfg_012"
run_test "File permissions: chmod 600" "test_chmod_600"
run_test "CHK-PRM-013: Fix SSH key permissions" "test_prm_013"

echo "─────────────────────────────────────────────────────────────────────────────"
echo ""
echo "Test Summary:"
echo "  Total:  $TESTS_RUN"
echo "  Passed: $TESTS_PASSED"
echo "  Failed: $TESTS_FAILED"
echo ""

if [[ $TESTS_FAILED -eq 0 ]]; then
    log_info "All tests passed! ✓"
    exit 0
else
    log_error "$TESTS_FAILED test(s) failed"
    exit 1
fi
