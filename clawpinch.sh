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
source "$HELPERS_DIR/suppression.sh"

# ─── Defaults ────────────────────────────────────────────────────────────────

DEEP=0
JSON_OUTPUT=0
SHOW_FIX=0
QUIET=0
NO_INTERACTIVE=0
REMEDIATE=0
CONFIG_DIR=""
SHOW_SUPPRESSED=0
NO_IGNORE=0

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
  --show-suppressed Include suppressed findings in normal output
  --no-ignore       Disable all suppressions for full audit scan
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
    --show-suppressed) SHOW_SUPPRESSED=1; shift ;;
    --no-ignore)  NO_IGNORE=1; shift ;;
    --config-dir)
      if [[ -z "${2:-}" ]]; then
        log_error "--config-dir requires a path argument"
        exit 2
      fi
      CONFIG_DIR="$2"; shift 2 ;;
    -h|--help)    usage ;;
    -v|--version)
      node -e "console.log('clawpinch v' + require('$CLAWPINCH_DIR/package.json').version)" 2>/dev/null \
        || echo "clawpinch v1.2.0"
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
export CLAWPINCH_SHOW_SUPPRESSED="$SHOW_SUPPRESSED"
export CLAWPINCH_NO_IGNORE="$NO_IGNORE"
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
  print_header
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
    start_spinner "Running ${local_name} scanner..."
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

# ─── Apply suppression filtering ─────────────────────────────────────────────

ACTIVE_FINDINGS="$SORTED_FINDINGS"
SUPPRESSED_FINDINGS="[]"

# Apply filtering unless --no-ignore is set
if [[ "$NO_IGNORE" -eq 0 ]]; then
  # Look for .clawpinch-ignore.json in the OpenClaw config directory or current directory
  ignore_file=".clawpinch-ignore.json"
  if [[ -n "$OPENCLAW_CONFIG" ]] && [[ -f "$OPENCLAW_CONFIG/.clawpinch-ignore.json" ]]; then
    ignore_file="$OPENCLAW_CONFIG/.clawpinch-ignore.json"
  fi

  # Filter findings into active and suppressed
  if [[ -f "$ignore_file" ]]; then
    filtered_result="$(echo "$SORTED_FINDINGS" | filter_findings "$ignore_file")"
    ACTIVE_FINDINGS="$(echo "$filtered_result" | jq -c '.active')"
    SUPPRESSED_FINDINGS="$(echo "$filtered_result" | jq -c '.suppressed')"
  fi
fi

# For --show-suppressed mode, merge suppressed back into active for display
DISPLAY_FINDINGS="$ACTIVE_FINDINGS"
if [[ "$SHOW_SUPPRESSED" -eq 1 ]]; then
  DISPLAY_FINDINGS="$(echo "$ACTIVE_FINDINGS" "$SUPPRESSED_FINDINGS" | jq -s '.[0] + .[1] | sort_by(.severity | if . == "critical" then 0 elif . == "warn" then 1 elif . == "info" then 2 elif . == "ok" then 3 else 4 end)')"
fi

# ─── Count by severity ──────────────────────────────────────────────────────
# Count only active findings (not suppressed) for exit code calculation

count_critical="$(echo "$ACTIVE_FINDINGS" | jq '[.[] | select(.severity == "critical")] | length')"
count_warn="$(echo "$ACTIVE_FINDINGS"     | jq '[.[] | select(.severity == "warn")] | length')"
count_info="$(echo "$ACTIVE_FINDINGS"     | jq '[.[] | select(.severity == "info")] | length')"
count_ok="$(echo "$ACTIVE_FINDINGS"       | jq '[.[] | select(.severity == "ok")] | length')"

# ─── Output ──────────────────────────────────────────────────────────────────

if [[ "$JSON_OUTPUT" -eq 1 ]]; then
  # Pure JSON output with findings and suppressed arrays
  jq -n -c --argjson findings "$ACTIVE_FINDINGS" --argjson suppressed "$SUPPRESSED_FINDINGS" \
    '{findings: $findings, suppressed: $suppressed}'
else
  if [[ "$QUIET" -eq 0 ]]; then
    # Determine if interactive mode is available
    _is_interactive=0
    if [[ "$NO_INTERACTIVE" -eq 0 ]] && [[ -t 0 ]]; then
      _is_interactive=1
    fi

    if [[ "$_is_interactive" -eq 1 ]]; then
      # Compact grouped table (new v1.1 display)
      print_findings_compact "$DISPLAY_FINDINGS"
    else
      # Non-interactive fallback: full card display (v1.0 behavior)
      total="$(echo "$DISPLAY_FINDINGS" | jq 'length')"
      if (( total > 0 )); then
        for i in $(seq 0 $((total - 1))); do
          finding="$(echo "$DISPLAY_FINDINGS" | jq -c ".[$i]")"
          print_finding "$finding"
        done
      else
        log_info "No findings reported by any scanner."
      fi
    fi
  fi

  # Always print summary dashboard
  print_summary "$count_critical" "$count_warn" "$count_info" "$count_ok" "$scanner_count" "$_scan_elapsed"

  # Launch interactive menu if TTY and not disabled
  if [[ "$QUIET" -eq 0 ]] && [[ "$NO_INTERACTIVE" -eq 0 ]] && [[ -t 0 ]]; then
    interactive_menu "$DISPLAY_FINDINGS" "$scanner_count" "$_scan_elapsed"
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
      _non_ok_findings="$(echo "$ACTIVE_FINDINGS" | jq -c '[.[] | select(.severity != "ok")]')"
      _non_ok_count="$(echo "$_non_ok_findings" | jq 'length')"

      if (( _non_ok_count > 0 )); then
        log_info "Piping $_non_ok_count findings to Claude for remediation..."
        echo "$_non_ok_findings" | "$_claude_bin" -p \
          --allowedTools "Bash,Read,Write,Edit,Glob,Grep" \
          "You are a security remediation agent. You have been given ClawPinch security scan findings as JSON. For each finding: 1) Read the evidence to understand the issue 2) Apply the auto_fix command if available, otherwise implement the remediation manually 3) Verify the fix. Work through findings in order (critical first). Be precise and minimal in your changes."
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
