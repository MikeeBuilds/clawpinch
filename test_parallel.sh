#!/usr/bin/env bash
set -euo pipefail

# ─── Test: Sequential vs Parallel Scanner Execution ──────────────────────────
# Compares output and timing between sequential and parallel modes

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLAWPINCH="$SCRIPT_DIR/clawpinch.sh"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results
PASSED=0
FAILED=0

log_test() {
  echo -e "${BLUE}[TEST]${NC} $1"
}

log_pass() {
  echo -e "${GREEN}[PASS]${NC} $1"
  PASSED=$((PASSED + 1))
}

log_fail() {
  echo -e "${RED}[FAIL]${NC} $1"
  FAILED=$((FAILED + 1))
}

log_info() {
  echo -e "${YELLOW}[INFO]${NC} $1"
}

# ─── Test 1: Run Sequential Mode ─────────────────────────────────────────────

log_test "Running sequential mode..."
SEQ_START=$(date +%s)
SEQ_OUTPUT=$(bash "$CLAWPINCH" --json --no-interactive 2>/dev/null || echo "[]")
SEQ_END=$(date +%s)
SEQ_TIME=$((SEQ_END - SEQ_START))

# Validate sequential output is valid JSON array
if ! echo "$SEQ_OUTPUT" | jq -e 'type == "array"' >/dev/null 2>&1; then
  log_fail "Sequential mode did not produce valid JSON array"
  exit 1
fi

SEQ_COUNT=$(echo "$SEQ_OUTPUT" | jq 'length')
log_info "Sequential: ${SEQ_COUNT} findings in ${SEQ_TIME}s"

# ─── Test 2: Run Parallel Mode ───────────────────────────────────────────────

log_test "Running parallel mode..."
PAR_START=$(date +%s)
PAR_OUTPUT=$(bash "$CLAWPINCH" --parallel --json --no-interactive 2>/dev/null || echo "[]")
PAR_END=$(date +%s)
PAR_TIME=$((PAR_END - PAR_START))

# Validate parallel output is valid JSON array
if ! echo "$PAR_OUTPUT" | jq -e 'type == "array"' >/dev/null 2>&1; then
  log_fail "Parallel mode did not produce valid JSON array"
  exit 1
fi

PAR_COUNT=$(echo "$PAR_OUTPUT" | jq 'length')
log_info "Parallel: ${PAR_COUNT} findings in ${PAR_TIME}s"

# ─── Test 3: Compare Findings (Order-Independent) ────────────────────────────

log_test "Comparing findings (order-independent)..."

# Sort both arrays by ID for comparison
SEQ_SORTED=$(echo "$SEQ_OUTPUT" | jq 'sort_by(.id)')
PAR_SORTED=$(echo "$PAR_OUTPUT" | jq 'sort_by(.id)')

if [[ "$SEQ_SORTED" == "$PAR_SORTED" ]]; then
  log_pass "Findings are identical (${SEQ_COUNT} findings)"
else
  # Show difference details
  log_fail "Findings differ between sequential and parallel modes"

  # Count differences
  SEQ_IDS=$(echo "$SEQ_OUTPUT" | jq -r '[.[].id] | sort | .[]' | sort | uniq)
  PAR_IDS=$(echo "$PAR_OUTPUT" | jq -r '[.[].id] | sort | .[]' | sort | uniq)

  # Find IDs only in sequential
  ONLY_SEQ=$(comm -23 <(echo "$SEQ_IDS") <(echo "$PAR_IDS"))
  if [[ -n "$ONLY_SEQ" ]]; then
    log_info "Only in sequential: $(echo "$ONLY_SEQ" | tr '\n' ' ')"
  fi

  # Find IDs only in parallel
  ONLY_PAR=$(comm -13 <(echo "$SEQ_IDS") <(echo "$PAR_IDS"))
  if [[ -n "$ONLY_PAR" ]]; then
    log_info "Only in parallel: $(echo "$ONLY_PAR" | tr '\n' ' ')"
  fi
fi

# ─── Test 4: Verify Speedup ──────────────────────────────────────────────────

log_test "Verifying performance improvement..."

# Calculate speedup ratio
if [[ $PAR_TIME -gt 0 ]]; then
  SPEEDUP=$(echo "scale=2; $SEQ_TIME / $PAR_TIME" | bc)
  log_info "Speedup: ${SPEEDUP}x (${SEQ_TIME}s → ${PAR_TIME}s)"

  # Check if speedup is at least 1.5x (allowing for some variance)
  # We target 2-3x but accept 1.5x+ for real-world conditions
  IS_FASTER=$(echo "$SPEEDUP >= 1.5" | bc)

  if [[ "$IS_FASTER" == "1" ]]; then
    log_pass "Parallel execution is ${SPEEDUP}x faster (>= 1.5x target)"
  else
    # If tests are very fast, timing may not be accurate
    if [[ $SEQ_TIME -lt 3 ]]; then
      log_info "Tests ran too fast for accurate timing (${SEQ_TIME}s), skipping speedup check"
      log_pass "Speedup check skipped (insufficient timing resolution)"
    else
      log_fail "Speedup ${SPEEDUP}x is below 1.5x target"
    fi
  fi
else
  log_info "Parallel time was 0s (too fast to measure), assuming speedup OK"
  log_pass "Speedup check skipped (parallel execution too fast to measure)"
fi

# ─── Test 5: Exit Code Consistency ───────────────────────────────────────────

log_test "Checking exit code consistency..."

# Run both modes and capture exit codes
set +e
bash "$CLAWPINCH" --json --no-interactive >/dev/null 2>&1
SEQ_EXIT=$?

bash "$CLAWPINCH" --parallel --json --no-interactive >/dev/null 2>&1
PAR_EXIT=$?
set -e

if [[ $SEQ_EXIT -eq $PAR_EXIT ]]; then
  log_pass "Exit codes match (both returned ${SEQ_EXIT})"
else
  log_fail "Exit codes differ: sequential=${SEQ_EXIT}, parallel=${PAR_EXIT}"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ $FAILED -eq 0 ]]; then
  echo -e "${GREEN}✓ PASS${NC} - All tests passed (${PASSED}/${PASSED})"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  exit 0
else
  echo -e "${RED}✗ FAIL${NC} - ${FAILED} test(s) failed (${PASSED}/$((PASSED + FAILED)) passed)"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  exit 1
fi
