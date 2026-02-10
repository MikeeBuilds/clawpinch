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
    printf '{"active": %s, "suppressed": []}\n' "$findings"
    return 0
  fi

  # Get current timestamp
  local now
  now="$(date -u +'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || true)"

  # Read findings from stdin and filter
  local findings
  findings="$(cat)"

  # Use jq to split findings into active and suppressed
  if [[ -n "$now" ]]; then
    # With expiration checking
    printf '%s\n' "$findings" | jq -c --argjson suppressions "$_CLAWPINCH_SUPPRESSIONS" --arg now "$now" '
      ($suppressions | map(select(.id != null) | {(.id): .}) | add // {}) as $smap |
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
    printf '%s\n' "$findings" | jq -c --argjson suppressions "$_CLAWPINCH_SUPPRESSIONS" '
      ($suppressions | map(select(.id != null) | {(.id): .}) | add // {}) as $smap |
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
