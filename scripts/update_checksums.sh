#!/usr/bin/env bash
set -euo pipefail

# ─── ClawPinch Checksum Regenerator ─────────────────────────────────────────
# Regenerates SHA256 checksums for all reference JSON files in references/
# directory. Run this script whenever you update reference data files.
#
# Usage:
#   ./scripts/update_checksums.sh
#
# Regenerates:
#   - references/known-cves.json.sha256
#   - references/malicious-patterns.json.sha256
#
# The checksums are used by verify_json_integrity() to detect tampering.
# Always run this script after modifying reference JSON files.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers/common.sh"

REFERENCES_DIR="$(cd "$SCRIPT_DIR/../references" && pwd)"

# ─── Detect OS and hash command ─────────────────────────────────────────────

OS="$(detect_os)"

if [[ "$OS" == "macos" ]]; then
  if ! has_cmd shasum; then
    log_error "shasum command not found (required on macOS)"
    exit 1
  fi
  HASH_CMD="shasum -a 256"
else
  # Linux or unknown - use sha256sum
  if ! has_cmd sha256sum; then
    log_error "sha256sum command not found"
    exit 1
  fi
  HASH_CMD="sha256sum"
fi

log_info "Using hash command: $HASH_CMD"
log_info "References directory: $REFERENCES_DIR"

# ─── Find and process all JSON files ────────────────────────────────────────

if [[ ! -d "$REFERENCES_DIR" ]]; then
  log_error "References directory not found: $REFERENCES_DIR"
  exit 1
fi

# Find all .json files (not .sha256 files)
JSON_FILES=()
while IFS= read -r -d '' file; do
  JSON_FILES+=("$file")
done < <(find "$REFERENCES_DIR" -maxdepth 1 -name "*.json" -type f -print0 | sort -z)

if [[ ${#JSON_FILES[@]} -eq 0 ]]; then
  log_warn "No JSON files found in $REFERENCES_DIR"
  exit 0
fi

log_info "Found ${#JSON_FILES[@]} JSON file(s) to process"

# ─── Generate checksums ─────────────────────────────────────────────────────

SUCCESS_COUNT=0
FAIL_COUNT=0

for json_file in "${JSON_FILES[@]}"; do
  json_basename="$(basename "$json_file")"
  sha256_file="${json_file}.sha256"

  log_info "Processing: $json_basename"

  # Compute hash
  if ! hash_output=$($HASH_CMD "$json_file" 2>&1); then
    log_error "Failed to compute hash for $json_basename: $hash_output"
    ((FAIL_COUNT++))
    continue
  fi

  # Extract just the hash (first field)
  hash_value="$(echo "$hash_output" | awk '{print $1}')"

  if [[ -z "$hash_value" ]]; then
    log_error "Got empty hash for $json_basename"
    ((FAIL_COUNT++))
    continue
  fi

  # Write checksum file in standard format: <hash>  <filename>
  if ! echo "${hash_value}  ${json_basename}" > "$sha256_file"; then
    log_error "Failed to write checksum file: $sha256_file"
    ((FAIL_COUNT++))
    continue
  fi

  log_info "✓ Generated $json_basename.sha256"
  log_info "  Hash: $hash_value"
  ((SUCCESS_COUNT++))
done

# ─── Summary ────────────────────────────────────────────────────────────────

echo >&2
if [[ $FAIL_COUNT -eq 0 ]]; then
  log_info "Successfully generated $SUCCESS_COUNT checksum file(s)"
  exit 0
else
  log_error "Generated $SUCCESS_COUNT checksum(s), but $FAIL_COUNT failed"
  exit 1
fi
