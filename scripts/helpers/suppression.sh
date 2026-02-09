#!/usr/bin/env bash
set -euo pipefail

# ─── ClawPinch suppression helpers ──────────────────────────────────────────
# Manage finding suppressions from .clawpinch-ignore.json
# Source this file from the main orchestrator:
#   source "$(dirname "$0")/scripts/helpers/suppression.sh"

# Global variable to store loaded suppressions (JSON array)
_CLAWPINCH_SUPPRESSIONS="[]"

# ─── Load suppressions from ignore file ─────────────────────────────────────
# Usage: load_suppressions <file_path>
# Returns: 0 on success (including when file doesn't exist), 1 on invalid JSON

load_suppressions() {
  local ignore_file="${1:-.clawpinch-ignore.json}"

  # Reset suppressions
  _CLAWPINCH_SUPPRESSIONS="[]"

  # If file doesn't exist, that's OK - no suppressions to load
  if [[ ! -f "$ignore_file" ]]; then
    return 0
  fi

  # Require jq for JSON parsing
  if ! command -v jq &>/dev/null; then
    # Fallback: if jq not available, disable suppressions
    # This is a graceful degradation - better than failing the whole scan
    return 0
  fi

  # Parse the JSON file and extract suppressions array
  local parsed
  if ! parsed="$(jq -c '.suppressions // []' "$ignore_file" 2>/dev/null)"; then
    # Invalid JSON - log warning and continue with no suppressions
    if [[ -n "${_CLR_YLW:-}" ]]; then
      printf "${_CLR_YLW}[warn]${_CLR_RST}  Invalid JSON in %s - ignoring suppressions\n" "$ignore_file" >&2
    else
      printf "[warn]  Invalid JSON in %s - ignoring suppressions\n" "$ignore_file" >&2
    fi
    return 1
  fi

  # Validate that we got an array
  if ! echo "$parsed" | jq -e 'type == "array"' >/dev/null 2>&1; then
    if [[ -n "${_CLR_YLW:-}" ]]; then
      printf "${_CLR_YLW}[warn]${_CLR_RST}  .suppressions is not an array in %s\n" "$ignore_file" >&2
    else
      printf "[warn]  .suppressions is not an array in %s\n" "$ignore_file" >&2
    fi
    return 1
  fi

  _CLAWPINCH_SUPPRESSIONS="$parsed"
  return 0
}

# ─── Check if a finding ID is currently suppressed ──────────────────────────
# Usage: is_suppressed <check_id>
# Returns: 0 if suppressed and not expired, 1 otherwise

is_suppressed() {
  local check_id="$1"

  # If no suppressions loaded, nothing is suppressed
  if [[ "$_CLAWPINCH_SUPPRESSIONS" == "[]" ]]; then
    return 1
  fi

  # Require jq
  if ! command -v jq &>/dev/null; then
    return 1
  fi

  # Get current timestamp in ISO 8601 format for expiration checking
  local now
  if command -v date &>/dev/null; then
    if ! now="$(date -u +'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"; then
      now=""
    fi
  else
    now=""
  fi

  # Check if the ID is in suppressions and not expired
  local result
  if [[ -n "$now" ]]; then
    # With expiration checking
    result="$(echo "$_CLAWPINCH_SUPPRESSIONS" | jq -r --arg id "$check_id" --arg now "$now" '
      map(select(.id == $id)) |
      if length > 0 then
        .[0] |
        if .expires then
          if .expires > $now then "suppressed" else "expired" end
        else
          "suppressed"
        end
      else
        "active"
      end
    ' 2>/dev/null)"
  else
    # Without expiration checking (no date command or failed to get timestamp)
    result="$(echo "$_CLAWPINCH_SUPPRESSIONS" | jq -r --arg id "$check_id" '
      if (map(select(.id == $id)) | length > 0) then
        "suppressed"
      else
        "active"
      end
    ' 2>/dev/null)"
  fi

  [[ "$result" == "suppressed" ]]
}

# ─── Filter findings into active and suppressed arrays ──────────────────────
# Usage: filter_findings <ignore_file> < findings.json
# Reads findings JSON array from stdin
# Outputs: {"active": [...], "suppressed": [...]}

filter_findings() {
  local ignore_file="${1:-.clawpinch-ignore.json}"

  # Load suppressions if not already loaded
  if [[ "$_CLAWPINCH_SUPPRESSIONS" == "[]" ]] && [[ -f "$ignore_file" ]]; then
    load_suppressions "$ignore_file"
  fi

  # Require jq
  if ! command -v jq &>/dev/null; then
    # Fallback: all findings are active
    local findings
    findings="$(cat)"
    echo "{\"active\": $findings, \"suppressed\": []}"
    return 0
  fi

  # Get current timestamp
  local now
  if command -v date &>/dev/null; then
    if ! now="$(date -u +'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"; then
      now=""
    fi
  else
    now=""
  fi

  # Read findings from stdin and filter
  local findings
  findings="$(cat)"

  # Use jq to split findings into active and suppressed
  if [[ -n "$now" ]]; then
    # With expiration checking
    echo "$findings" | jq -c --argjson suppressions "$_CLAWPINCH_SUPPRESSIONS" --arg now "$now" '
      ($suppressions | map({(.id): .}) | add // {}) as $smap |
      reduce .[] as $f ({active: [], suppressed: []};
        $smap[$f.id] as $s |
        if $s then
          if $s.expires and $s.expires <= $now then
            .active += [$f]
          else
            .suppressed += [$f + {suppression: ($s | del(.id))}]
          end
        else
          .active += [$f]
        end
      )
    '
  else
    # Without expiration checking (treat all as unexpired)
    echo "$findings" | jq -c --argjson suppressions "$_CLAWPINCH_SUPPRESSIONS" '
      ($suppressions | map({(.id): .}) | add // {}) as $smap |
      reduce .[] as $f ({active: [], suppressed: []};
        $smap[$f.id] as $s |
        if $s then
          .suppressed += [$f + {suppression: ($s | del(.id))}]
        else
          .active += [$f]
        end
      )
    '
  fi
}
