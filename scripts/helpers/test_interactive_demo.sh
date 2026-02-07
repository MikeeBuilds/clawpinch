#!/usr/bin/env bash
set -euo pipefail

# ─── ClawPinch Interactive Mode Manual Demo ──────────────────────────────────
# This script demonstrates the interactive mode workflow manually.
# Run this to see the interactive mode in action with real findings.

# Colors
readonly BLUE='\033[0;34m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly RESET='\033[0m'

printf "\n${BLUE}═══════════════════════════════════════════════════════════════${RESET}\n"
printf "${BLUE}  ClawPinch Interactive Mode Demo${RESET}\n"
printf "${BLUE}═══════════════════════════════════════════════════════════════${RESET}\n\n"

# Create a temporary test directory
DEMO_DIR="$(mktemp -d)"
echo "Demo directory: $DEMO_DIR"

# Clean up on exit
cleanup() {
  if [[ -d "$DEMO_DIR" ]]; then
    rm -rf "$DEMO_DIR"
    echo "Cleaned up demo directory"
  fi
}
trap cleanup EXIT

# Create a test openclaw.json with fixable issues
printf "${YELLOW}Step 1: Creating test configuration with security issues...${RESET}\n"
cat > "$DEMO_DIR/openclaw.json" <<'EOF'
{
  "gateway": {
    "enabled": true,
    "host": "0.0.0.0",
    "port": 3000,
    "tls": {
      "enabled": false
    },
    "requireAuth": false
  },
  "cors": {
    "origins": ["*"]
  },
  "rateLimits": {
    "enabled": false
  }
}
EOF
echo "Created $DEMO_DIR/openclaw.json"
cat "$DEMO_DIR/openclaw.json"

# Generate findings
printf "\n${YELLOW}Step 2: Generating findings...${RESET}\n"
FINDINGS_FILE="$DEMO_DIR/findings.json"

# Create synthetic findings with auto-fix commands
cat > "$FINDINGS_FILE" <<EOF
[
  {
    "id": "CHK-CFG-001",
    "severity": "critical",
    "title": "Gateway TLS disabled",
    "description": "The gateway is exposed without TLS encryption",
    "evidence": "gateway.tls.enabled = false",
    "remediation": "Enable TLS encryption for the gateway",
    "auto_fix": "jq '.gateway.tls.enabled = true' $DEMO_DIR/openclaw.json > tmp && mv tmp $DEMO_DIR/openclaw.json"
  },
  {
    "id": "CHK-CFG-002",
    "severity": "critical",
    "title": "Gateway authentication disabled",
    "description": "The gateway does not require authentication",
    "evidence": "gateway.requireAuth = false",
    "remediation": "Enable authentication for the gateway",
    "auto_fix": "jq '.gateway.requireAuth = true' $DEMO_DIR/openclaw.json > tmp && mv tmp $DEMO_DIR/openclaw.json"
  },
  {
    "id": "CHK-CFG-003",
    "severity": "warn",
    "title": "Rate limiting disabled",
    "description": "Rate limiting is not enabled",
    "evidence": "rateLimits.enabled = false",
    "remediation": "Enable rate limiting",
    "auto_fix": "jq '.rateLimits.enabled = true' $DEMO_DIR/openclaw.json > tmp && mv tmp $DEMO_DIR/openclaw.json"
  }
]
EOF

printf "${GREEN}Generated 3 findings with auto-fix commands${RESET}\n"
jq -r '.[] | "\(.id): \(.title)"' "$FINDINGS_FILE"

# Test single fix
printf "\n${YELLOW}Step 3: Testing single fix (similar to review mode)...${RESET}\n"

# Source safe_exec
source ./scripts/helpers/safe_exec.sh

# Change to demo directory for relative paths
cd "$DEMO_DIR"

# Extract first finding's auto-fix command
FIRST_FIX="jq '.gateway.tls.enabled = true' openclaw.json > tmp && mv tmp openclaw.json"
printf "Executing: ${BLUE}%s${RESET}\n" "$FIRST_FIX"

if safe_exec_command "$FIRST_FIX"; then
  printf "${GREEN}✓ Fix applied successfully${RESET}\n"
  echo "Updated config:"
  jq '.gateway.tls' openclaw.json
else
  printf "${RED}✗ Fix failed${RESET}\n"
fi

# Test auto-fix-all
printf "\n${YELLOW}Step 4: Testing auto-fix-all mode...${RESET}\n"

# Reset config
cat > openclaw.json <<'EOF'
{
  "gateway": {
    "enabled": true,
    "host": "0.0.0.0",
    "port": 3000,
    "tls": {
      "enabled": false
    },
    "requireAuth": false
  },
  "cors": {
    "origins": ["*"]
  },
  "rateLimits": {
    "enabled": false
  }
}
EOF

# Apply all fixes
ALL_FIXES=(
  "jq '.gateway.tls.enabled = true' openclaw.json > tmp && mv tmp openclaw.json"
  "jq '.gateway.requireAuth = true' openclaw.json > tmp && mv tmp openclaw.json"
  "jq '.rateLimits.enabled = true' openclaw.json > tmp && mv tmp openclaw.json"
)

PASSED=0
FAILED=0

for fix in "${ALL_FIXES[@]}"; do
  printf "  Applying: %s\n" "$fix"
  if safe_exec_command "$fix" >/dev/null 2>&1; then
    PASSED=$((PASSED + 1))
    printf "    ${GREEN}✓${RESET}\n"
  else
    FAILED=$((FAILED + 1))
    printf "    ${RED}✗${RESET}\n"
  fi
done

printf "\n${GREEN}Auto-fix complete: %d passed, %d failed${RESET}\n" "$PASSED" "$FAILED"

# Show final config
printf "\n${YELLOW}Step 5: Verifying final configuration...${RESET}\n"
cat openclaw.json

# Verify security improvements
TLS_ENABLED=$(jq -r '.gateway.tls.enabled' openclaw.json)
AUTH_ENABLED=$(jq -r '.gateway.requireAuth' openclaw.json)
RATE_ENABLED=$(jq -r '.rateLimits.enabled' openclaw.json)

printf "\n${BLUE}Security improvements:${RESET}\n"
printf "  TLS enabled: %s\n" "$TLS_ENABLED"
printf "  Auth enabled: %s\n" "$AUTH_ENABLED"
printf "  Rate limiting enabled: %s\n" "$RATE_ENABLED"

if [[ "$TLS_ENABLED" == "true" ]] && [[ "$AUTH_ENABLED" == "true" ]] && [[ "$RATE_ENABLED" == "true" ]]; then
  printf "\n${GREEN}✓ All security fixes applied successfully!${RESET}\n"
  printf "${GREEN}✓ No eval() was used - all commands executed via safe_exec_command()${RESET}\n"
else
  printf "\n${RED}✗ Some fixes were not applied${RESET}\n"
fi

printf "\n${BLUE}═══════════════════════════════════════════════════════════════${RESET}\n"
printf "${GREEN}Demo complete!${RESET}\n"
printf "${BLUE}═══════════════════════════════════════════════════════════════${RESET}\n\n"
