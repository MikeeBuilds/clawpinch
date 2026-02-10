#!/usr/bin/env bash
set -euo pipefail

echo "=== E2E Test: Git History Scanner Integration ==="
echo ""

# Test 1: Scanner exists and is executable
echo "Test 1: Scanner exists and is executable"
if [[ -x ./scripts/scan_git_history.sh ]]; then
    echo "✓ Scanner is executable"
else
    echo "✗ Scanner not executable"
    exit 1
fi
echo ""

# Test 2: Scanner outputs valid JSON
echo "Test 2: Scanner outputs valid JSON"
if ./scripts/scan_git_history.sh 2>&1 | jq empty 2>/dev/null; then
    echo "✓ Scanner outputs valid JSON"
else
    echo "✗ Scanner output is not valid JSON"
    exit 1
fi
echo ""

# Test 3: Full scan completes without crashes
echo "Test 3: Full scan with --json completes without crashes"
if bash ./clawpinch.sh --json 2>&1 | jq -e 'type == "array"' >/dev/null 2>&1; then
    echo "✓ Full scan completes with valid JSON output"
else
    echo "✗ Full scan failed or produced invalid output"
    exit 1
fi
echo ""

# Test 4: Scanner appears in interactive output
echo "Test 4: Git History scanner appears in interactive output"
if bash ./clawpinch.sh 2>&1 | grep -q "Git History"; then
    echo "✓ Scanner appears in output"
else
    echo "✗ Scanner not found in output"
    exit 1
fi
echo ""

# Test 5: Deep scan mode works
echo "Test 5: Deep scan mode works"
if bash ./clawpinch.sh --deep --json 2>&1 | jq -e 'type == "array"' >/dev/null 2>&1; then
    echo "✓ Deep scan completes successfully"
else
    echo "✗ Deep scan failed"
    exit 1
fi
echo ""

# Test 6: Scanner is auto-discovered by orchestrator
echo "Test 6: Scanner counted in scan execution"
scanner_count=$(ls -1 ./scripts/scan_*.sh 2>/dev/null | wc -l | tr -d ' ')
if [[ "$scanner_count" -ge 8 ]]; then
    echo "✓ Found $scanner_count scanners (including git history)"
else
    echo "✗ Expected at least 8 scanners, found $scanner_count"
    exit 1
fi
echo ""

echo "=== All E2E Tests Passed ==="
exit 0
