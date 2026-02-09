#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# scan_integrity.sh - ClawPinch Reference Data Integrity Scanner
#
# Verifies the integrity of reference JSON files (known-cves.json,
# malicious-patterns.json) using SHA256 checksums to detect tampering.
#
# Usage:
#   ./scan_integrity.sh
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAWPINCH_DIR="$(dirname "$SCRIPT_DIR")"
REFERENCES_DIR="$CLAWPINCH_DIR/references"

# Source shared helpers
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
# Collect findings into an array
# ---------------------------------------------------------------------------
FINDINGS=()

# Reference files to check
REFERENCE_FILES=(
    "$REFERENCES_DIR/known-cves.json"
    "$REFERENCES_DIR/malicious-patterns.json"
)

# ---------------------------------------------------------------------------
# CHK-INT-001: Verify integrity of reference JSON files
# ---------------------------------------------------------------------------
integrity_failed=0
failed_files=()

for json_file in "${REFERENCE_FILES[@]}"; do
    json_basename="$(basename "$json_file")"

    # Check if file exists
    if [[ ! -f "$json_file" ]]; then
        integrity_failed=1
        failed_files+=("$json_basename (missing)")
        continue
    fi

    # Check if checksum file exists
    sha256_file="${json_file}.sha256"
    if [[ ! -f "$sha256_file" ]]; then
        integrity_failed=1
        failed_files+=("$json_basename (no checksum)")
        continue
    fi

    # Verify integrity using the helper function
    if ! verify_json_integrity "$json_file"; then
        integrity_failed=1
        failed_files+=("$json_basename (checksum mismatch)")
    fi
done

# Emit finding based on results
if [[ $integrity_failed -eq 1 ]]; then
    # Critical: integrity check failed
    evidence_str="$(IFS=', '; echo "${failed_files[*]}")"
    FINDINGS+=("$(emit_finding \
        "CHK-INT-001" \
        "critical" \
        "Reference data integrity check failed" \
        "One or more reference JSON files failed SHA256 integrity verification. This could indicate file corruption or tampering. ClawPinch relies on these files for CVE detection and malicious pattern matching." \
        "Failed files: ${evidence_str}" \
        "Verify file integrity: (1) Check if reference files were modified, (2) If you updated them intentionally, run 'bash scripts/update_checksums.sh' to regenerate checksums, (3) If tampering is suspected, restore from a trusted source" \
        ""
    )")
else
    # OK: all integrity checks passed
    FINDINGS+=("$(emit_finding \
        "CHK-INT-001" \
        "ok" \
        "Reference data integrity verified" \
        "All reference JSON files (known-cves.json, malicious-patterns.json) passed SHA256 integrity verification. No tampering detected." \
        "Verified: known-cves.json, malicious-patterns.json" \
        "No action needed" \
        ""
    )")
fi

# ---------------------------------------------------------------------------
# Output all findings as a JSON array
# ---------------------------------------------------------------------------
if [[ ${#FINDINGS[@]} -eq 0 ]]; then
    echo '[]'
else
    printf '%s\n' "${FINDINGS[@]}" | jq -s '.'
fi
