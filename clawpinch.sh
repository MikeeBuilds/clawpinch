#!/usr/bin/env bash
set -euo pipefail

# ─── ClawPinch - OpenClaw Security Audit Toolkit ────────────────────────────
# Main orchestrator: discovers and runs scanner scripts, collects findings,
# sorts by severity, and prints a formatted report.

CLAWPINCH_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS_DIR="$CLAWPINCH_DIR/scripts"
HELPERS_DIR="$SCRIPTS_DIR/helpers"

# Source helpers
source "$HELPERS_DIR/common.sh"
source "$HELPERS_DIR/report.sh"
source "$HELPERS_DIR/redact.sh"
source "$HELPERS_DIR/interactive.sh"

# ─── Signal trap for animation cleanup ──────────────────────────────────────

trap '_cleanup_animation; exit 130' INT TERM

# ─── Defaults ────────────────────────────────────────────────────────────────

DEEP=0
JSON_OUTPUT=0
SHOW_FIX=0
QUIET=0
NO_INTERACTIVE=0
REMEDIATE=0
CONFIG_DIR=""

# ─── Usage ───────────────────────────────────────────────────────────────────

usage() {
  cat <<'EOF'
Usage: clawpinch [OPTIONS]

Options:
  --deep            Run thorough / deep scans
  --json            Output findings as JSON array only
  --fix             Show auto-fix commands in report
  --quiet           Print summary line only
  --no-interactive  Disable interactive post-scan menu
  --remediate       Run scan then pipe findings to Claude for AI remediation
  --config-dir PATH Explicit path to openclaw config directory
  -h, --help        Show this help message

Exit codes:
  0   No critical findings
  1   One or more critical findings detected
EOF
  exit 0
}

# ─── Parse arguments ─────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    --deep)       DEEP=1; shift ;;
    --json)       JSON_OUTPUT=1; shift ;;
    --fix)        SHOW_FIX=1; shift ;;
    --quiet)      QUIET=1; shift ;;
    --no-interactive) NO_INTERACTIVE=1; shift ;;
    --remediate)  REMEDIATE=1; NO_INTERACTIVE=1; shift ;;
    --config-dir)
      if [[ -z "${2:-}" ]]; then
        log_error "--config-dir requires a path argument"
        exit 2
      fi
      CONFIG_DIR="$2"; shift 2 ;;
    -h|--help)    usage ;;
    -v|--version)
      node -e "console.log('clawpinch v' + require('$CLAWPINCH_DIR/package.json').version)" 2>/dev/null \
        || echo "clawpinch v1.2.1"
      exit 0 ;;
    *)
      log_error "Unknown option: $1"
      usage ;;
  esac
done

# Export settings so scanners can read them
export CLAWPINCH_DEEP="$DEEP"
export CLAWPINCH_SHOW_FIX="$SHOW_FIX"
export CLAWPINCH_CONFIG_DIR="$CONFIG_DIR"
export QUIET

# ─── Detect OS ───────────────────────────────────────────────────────────────

CLAWPINCH_OS="$(detect_os)"
export CLAWPINCH_OS

# ─── Find openclaw config ───────────────────────────────────────────────────

OPENCLAW_CONFIG=""
if config_path="$(get_openclaw_config)"; then
  OPENCLAW_CONFIG="$config_path"
fi
export OPENCLAW_CONFIG

# ─── Banner ──────────────────────────────────────────────────────────────────

if [[ "$JSON_OUTPUT" -eq 0 ]] && [[ "$QUIET" -eq 0 ]]; then
  print_header_animated
  log_info "OS detected: $CLAWPINCH_OS"
  if [[ -n "$OPENCLAW_CONFIG" ]]; then
    log_info "OpenClaw config: $OPENCLAW_CONFIG"
  else
    log_warn "OpenClaw config not found (use --config-dir to specify)"
  fi
  if [[ "$DEEP" -eq 1 ]]; then
    log_info "Deep scan enabled"
  fi
  printf '\n'
  print_init_message
fi

# ─── Discover scanner scripts ───────────────────────────────────────────────

scanners=()

# Bash scanners
for f in "$SCRIPTS_DIR"/scan_*.sh; do
  [[ -f "$f" ]] && scanners+=("$f")
done

# Python scanners
for f in "$SCRIPTS_DIR"/scan_*.py; do
  [[ -f "$f" ]] && scanners+=("$f")
done

if [[ ${#scanners[@]} -eq 0 ]]; then
  if [[ "$JSON_OUTPUT" -eq 1 ]]; then
    echo '[]'
  else
    log_warn "No scanner scripts found in $SCRIPTS_DIR"
  fi
  exit 0
fi

# ─── Run scanners and collect findings ───────────────────────────────────────

ALL_FINDINGS="[]"
scanner_count=${#scanners[@]}
scanner_idx=0
_SPINNER_PID=""

# Record scan start time
_scan_start="${EPOCHSECONDS:-$(date +%s)}"

for scanner in "${scanners[@]}"; do
  scanner_idx=$((scanner_idx + 1))
  scanner_name="$(basename "$scanner")"
  scanner_base="${scanner_name%.*}"

  # Record scanner start time
  _scanner_start="${EPOCHSECONDS:-$(date +%s)}"

  if [[ "$JSON_OUTPUT" -eq 0 ]] && [[ "$QUIET" -eq 0 ]]; then
    # Print section header for this scanner
    print_section_header "$scanner_name"

    # Start spinner
    local_category="$(_scanner_category "$scanner_name")"
    local_icon="${local_category%%|*}"
    local_name="${local_category##*|}"
    start_spinner "Running ${local_name} scanner..." "$scanner_idx" "$scanner_count"
  fi

  # Determine how to run the scanner
  output=""
  if [[ "$scanner" == *.sh ]]; then
    output="$(bash "$scanner" 2>/dev/null)" || true
  elif [[ "$scanner" == *.py ]]; then
    if has_cmd python3; then
      output="$(python3 "$scanner" 2>/dev/null)" || true
    elif has_cmd python; then
      output="$(python "$scanner" 2>/dev/null)" || true
    else
      if [[ "$JSON_OUTPUT" -eq 0 ]] && [[ "$QUIET" -eq 0 ]]; then
        stop_spinner "$local_name" 0 0
      fi
      log_warn "Skipping $scanner_name (python not found)"
      continue
    fi
  fi

  # Count findings from this scanner
  local_count=0

  # Validate output is a JSON array and merge
  if [[ -n "$output" ]]; then
    if echo "$output" | jq 'type == "array"' 2>/dev/null | grep -q 'true'; then
      local_count="$(echo "$output" | jq 'length')"
      ALL_FINDINGS="$(echo "$ALL_FINDINGS" "$output" | jq -s '.[0] + .[1]')"
    else
      log_warn "Scanner $scanner_name did not produce a valid JSON array"
    fi
  fi

  # Calculate elapsed time for this scanner
  _scanner_end="${EPOCHSECONDS:-$(date +%s)}"
  _scanner_elapsed=$(( _scanner_end - _scanner_start ))

  if [[ "$JSON_OUTPUT" -eq 0 ]] && [[ "$QUIET" -eq 0 ]]; then
    stop_spinner "$local_name" "$local_count" "$_scanner_elapsed"
  fi
done

# Calculate total scan time
_scan_end="${EPOCHSECONDS:-$(date +%s)}"
_scan_elapsed=$(( _scan_end - _scan_start ))

if [[ "$JSON_OUTPUT" -eq 0 ]] && [[ "$QUIET" -eq 0 ]]; then
  printf '\n'
fi

# ─── Sort findings by severity ───────────────────────────────────────────────
# Order: critical > warn > info > ok

SORTED_FINDINGS="$(echo "$ALL_FINDINGS" | jq '
  def sev_order:
    if . == "critical" then 0
    elif . == "warn" then 1
    elif . == "info" then 2
    elif . == "ok" then 3
    else 4
    end;
  sort_by(.severity | sev_order)
')"

# ─── Count by severity ──────────────────────────────────────────────────────

count_critical="$(echo "$SORTED_FINDINGS" | jq '[.[] | select(.severity == "critical")] | length')"
count_warn="$(echo "$SORTED_FINDINGS"     | jq '[.[] | select(.severity == "warn")] | length')"
count_info="$(echo "$SORTED_FINDINGS"     | jq '[.[] | select(.severity == "info")] | length')"
count_ok="$(echo "$SORTED_FINDINGS"       | jq '[.[] | select(.severity == "ok")] | length')"

# ─── Output ──────────────────────────────────────────────────────────────────

if [[ "$JSON_OUTPUT" -eq 1 ]]; then
  # Pure JSON output (compact for piping efficiency)
  echo "$SORTED_FINDINGS" | jq -c .
else
  if [[ "$QUIET" -eq 0 ]]; then
    # Determine if interactive mode is available
    _is_interactive=0
    if [[ "$NO_INTERACTIVE" -eq 0 ]] && [[ -t 0 ]]; then
      _is_interactive=1
    fi

    if [[ "$_is_interactive" -eq 1 ]]; then
      # Compact grouped table (new v1.1 display)
      print_findings_compact "$SORTED_FINDINGS"
    else
      # Non-interactive fallback: full card display (v1.0 behavior)
      total="$(echo "$SORTED_FINDINGS" | jq 'length')"
      if (( total > 0 )); then
        for i in $(seq 0 $((total - 1))); do
          finding="$(echo "$SORTED_FINDINGS" | jq -c ".[$i]")"
          print_finding "$finding"
        done
      else
        log_info "No findings reported by any scanner."
      fi
    fi
  fi

  # Always print summary dashboard (animated when TTY)
  print_summary_animated "$count_critical" "$count_warn" "$count_info" "$count_ok" "$scanner_count" "$_scan_elapsed"

  # Contextual completion message
  print_completion_message "$count_critical" "$count_warn"

  # Launch interactive menu if TTY and not disabled
  if [[ "$QUIET" -eq 0 ]] && [[ "$NO_INTERACTIVE" -eq 0 ]] && [[ -t 0 ]]; then
    interactive_menu "$SORTED_FINDINGS" "$scanner_count" "$_scan_elapsed"
  fi

  # ─── AI Remediation pipeline ─────────────────────────────────────────────
  if [[ "$REMEDIATE" -eq 1 ]]; then
    # Locate Claude CLI
    _claude_bin="${CLAWPINCH_CLAUDE_BIN:-}"
    if [[ -z "$_claude_bin" ]]; then
      _claude_bin="$(command -v claude 2>/dev/null || true)"
    fi
    if [[ -z "$_claude_bin" ]] && [[ -x "$HOME/.local/bin/claude" ]]; then
      _claude_bin="$HOME/.local/bin/claude"
    fi

    if [[ -z "$_claude_bin" ]]; then
      log_error "Claude CLI not found. Install it or set CLAWPINCH_CLAUDE_BIN."
    else
      _non_ok_findings="$(echo "$SORTED_FINDINGS" | jq -c '[.[] | select(.severity != "ok")]')"
      _non_ok_count="$(echo "$_non_ok_findings" | jq 'length')"

      if (( _non_ok_count > 0 )); then
        # Pre-validate auto_fix commands: strip any that fail the allowlist
        # so the AI agent only receives pre-approved commands
        _validated_findings_arr=()
        while IFS= read -r _finding; do
          _fix_cmd="$(echo "$_finding" | jq -r '.auto_fix // ""')"
          if [[ -n "$_fix_cmd" ]] && ! validate_command "$_fix_cmd"; then
            # Strip the disallowed auto_fix, keep finding for manual review
            _finding="$(echo "$_finding" | jq -c '.auto_fix = "" | .remediation = (.remediation + " [auto_fix removed: command not in allowlist]")')"
            log_warn "Stripped disallowed auto_fix from finding $(echo "$_finding" | jq -r '.id')"
          fi
          _validated_findings_arr+=("$_finding")
        done < <(echo "$_non_ok_findings" | jq -c '.[]')
        _validated_findings="$(printf '%s\n' "${_validated_findings_arr[@]}" | jq -s '.')"

        _validated_count="$(echo "$_validated_findings" | jq 'length')"
        log_info "Piping $_validated_count findings to Claude for remediation..."
        echo "$_validated_findings" | "$_claude_bin" -p \
          --allowedTools "Read,Write,Edit,Glob,Grep" \
          "You are a security remediation agent. You have been given ClawPinch security scan findings as JSON. For each finding: 1) Read the evidence to understand the issue 2) If an auto_fix field is present, it contains a pre-validated shell command — DO NOT execute it directly. Instead, translate its intent into equivalent Read/Write/Edit operations. For example: a 'sed -i s/old/new/ file' becomes an Edit tool call; a 'jq .key=val file.json > tmp && mv tmp file.json' becomes Read + Write; a 'chmod 600 file' should be noted for manual action. 3) If no auto_fix, implement the remediation manually using Write/Edit 4) Verify the fix by reading the file. Work through findings in order (critical first). Be precise and minimal in your changes. IMPORTANT: You do NOT have access to Bash. Use only Read, Write, Edit, Glob, and Grep tools."
      else
        log_info "No actionable findings for remediation."
      fi
    fi
  fi
fi

# ─── Exit code ───────────────────────────────────────────────────────────────

if (( count_critical > 0 )); then
  exit 1
else
  exit 0
fi
