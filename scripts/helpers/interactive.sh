#!/usr/bin/env bash
set -euo pipefail

# ─── ClawPinch interactive mode ──────────────────────────────────────────────
# Post-scan interactive menu: review findings, auto-fix, export handoff doc.
# Sourced by clawpinch.sh — depends on common.sh & report.sh being loaded first.

# Source safe command execution module
# shellcheck source=safe_exec.sh
source "$(dirname "${BASH_SOURCE[0]}")/safe_exec.sh"

# ─── Table box-drawing constants ─────────────────────────────────────────────

readonly _TBL_TL='┌' _TBL_TR='┐' _TBL_BL='└' _TBL_BR='┘'
readonly _TBL_H='─' _TBL_V='│'
readonly _TBL_ML='├' _TBL_MR='┤'
readonly _TBL_TM='┬' _TBL_BM='┴' _TBL_MM='┼'

# ─── Prompt helpers ──────────────────────────────────────────────────────────

_prompt() {
  local msg="$1"
  local reply
  printf '%b' "$msg"
  read -r reply
  echo "$reply"
}

_confirm() {
  local msg="$1"
  local reply
  while true; do
    printf '%b' "$msg"
    read -r reply
    case "$reply" in
      [yY]|[yY][eE][sS]) return 0 ;;
      [nN]|[nN][oO])     return 1 ;;
      *) printf '  Please enter y or n.\n' ;;
    esac
  done
}

_run_fix() {
  local cmd="$1"

  # NOTE: No separate validate_command() call here — safe_exec_command()
  # performs its own comprehensive validation (blacklist + whitelist + per-command
  # checks) which is stricter and handles redirections in safe patterns like
  # "jq ... > tmp && mv tmp file.json". The allowlist-based validate_command()
  # is used only in the AI remediation pipeline (clawpinch.sh).

  printf '\n  %b$%b %s\n' "$_CLR_DIM" "$_CLR_RST" "$cmd"
  if safe_exec_command "$cmd" 2>&1 | while IFS= read -r line; do printf '  %s\n' "$line"; done; then
    printf '  %b✓ Fix applied successfully%b\n' "$_CLR_OK" "$_CLR_RST"
    return 0
  else
    printf '  %b✗ Fix command failed%b\n' "$_CLR_CRIT" "$_CLR_RST"
    return 1
  fi
}

_copy_to_clipboard() {
  local text="$1"
  local os="${CLAWPINCH_OS:-$(detect_os)}"
  case "$os" in
    macos)
      if command -v pbcopy &>/dev/null; then
        printf '%s' "$text" | pbcopy
        return 0
      fi
      ;;
    linux)
      if command -v xclip &>/dev/null; then
        printf '%s' "$text" | xclip -selection clipboard
        return 0
      elif command -v xsel &>/dev/null; then
        printf '%s' "$text" | xsel --clipboard
        return 0
      fi
      ;;
  esac
  # Fallback: write to file
  local outfile="./clawpinch-ai-prompt-$(date +%s).txt"
  printf '%s' "$text" > "$outfile"
  printf '  %b(Clipboard unavailable — saved to %s)%b\n' "$_CLR_DIM" "$outfile" "$_CLR_RST"
  return 0
}

_generate_ai_prompt() {
  local finding_json="$1"
  local f_id f_severity f_title f_description f_evidence f_remediation f_auto_fix
  f_id="$(echo "$finding_json" | jq -r '.id // ""')"
  f_severity="$(echo "$finding_json" | jq -r '.severity // "info"' | tr '[:lower:]' '[:upper:]')"
  f_title="$(echo "$finding_json" | jq -r '.title // ""')"
  f_description="$(echo "$finding_json" | jq -r '.description // ""')"
  f_evidence="$(echo "$finding_json" | jq -r '.evidence // ""')"
  f_remediation="$(echo "$finding_json" | jq -r '.remediation // ""')"
  f_auto_fix="$(echo "$finding_json" | jq -r '.auto_fix // ""')"

  local prompt="## Security Finding Remediation Request

**Finding ID:** ${f_id}
**Severity:** ${f_severity}
**Title:** ${f_title}

### Description
${f_description}

### Evidence
\`\`\`
${f_evidence}
\`\`\`

### Required Remediation
${f_remediation}"

  if [[ -n "$f_auto_fix" ]]; then
    prompt="${prompt}

### Suggested Command
\`\`\`bash
${f_auto_fix}
\`\`\`"
  fi

  prompt="${prompt}

### Instructions
1. Locate the relevant file(s) mentioned in evidence
2. Apply the remediation
3. Verify the fix"

  printf '%s' "$prompt"
}

# ─── Compact findings table ─────────────────────────────────────────────────
# Groups findings by severity, shows first N per group with "+X more" overflow.

print_findings_compact() {
  local json_array="$1"
  local w
  w="$(_box_width)"

  local total
  total="$(echo "$json_array" | jq 'length')"

  if (( total == 0 )); then
    printf '\n  No findings reported by any scanner.\n'
    return
  fi

  # Print "Scan Complete" header
  printf '\n'
  printf "  %b%s%b %bScan Complete%b " "$_CLR_BOX" "$_TBL_TL" "$_CLR_RST" "$_CLR_WHITE" "$_CLR_RST"
  local header_text="Scan Complete"
  local header_len=$(( ${#header_text} + 2 ))  # spaces around text
  local rule_len=$(( w - 4 - header_len - 1 ))
  if (( rule_len < 2 )); then rule_len=2; fi
  printf '%b' "$_CLR_BOX"
  _hline "$_TBL_H" "$rule_len" "$_CLR_BOX"
  printf "%s%b\n" "$_TBL_TR" "$_CLR_RST"
  printf '\n'

  local max_per_group=5
  local -a severities=("critical" "warn" "info" "ok")
  local -a sev_labels=("CRITICAL" "WARNING" "INFO" "OK")
  local -a sev_colors=("$_CLR_CRIT" "$_CLR_WARN" "$_CLR_INFO" "$_CLR_OK")

  # Column widths
  local col_id=13
  local col_fix=5
  local col_title=$(( w - 4 - col_id - col_fix - 8 ))  # 8 = borders + padding
  if (( col_title < 20 )); then col_title=20; fi

  local ok_count=0
  local printed_table=0

  for sev_idx in 0 1 2 3; do
    local sev="${severities[$sev_idx]}"
    local sev_label="${sev_labels[$sev_idx]}"
    local sev_clr="${sev_colors[$sev_idx]}"

    local sev_count
    sev_count="$(echo "$json_array" | jq "[.[] | select(.severity == \"$sev\")] | length")"

    if (( sev_count == 0 )); then
      continue
    fi

    # OK findings: collapsed to a count line, no table
    if [[ "$sev" == "ok" ]]; then
      ok_count="$sev_count"
      continue
    fi

    printed_table=1

    # Severity group header
    printf '  %b%s%b (%d)\n' "$sev_clr" "$sev_label" "$_CLR_RST" "$sev_count"

    # Table top border
    printf '  %s' "$_TBL_TL"
    _hline "$_TBL_H" "$col_id"
    printf '%s' "$_TBL_TM"
    _hline "$_TBL_H" "$col_title"
    printf '%s' "$_TBL_TM"
    _hline "$_TBL_H" "$col_fix"
    printf '%s\n' "$_TBL_TR"

    # Table header row
    printf '  %s' "$_TBL_V"
    printf " %b%-*s%b" "$_CLR_WHITE" $(( col_id - 2 )) "ID" "$_CLR_RST"
    printf ' %s' "$_TBL_V"
    printf " %b%-*s%b" "$_CLR_WHITE" $(( col_title - 2 )) "Title" "$_CLR_RST"
    printf ' %s' "$_TBL_V"
    printf " %b%-*s%b" "$_CLR_WHITE" $(( col_fix - 2 )) "Fix?" "$_CLR_RST"
    printf ' %s\n' "$_TBL_V"

    # Table header separator
    printf '  %s' "$_TBL_ML"
    _hline "$_TBL_H" "$col_id"
    printf '%s' "$_TBL_MM"
    _hline "$_TBL_H" "$col_title"
    printf '%s' "$_TBL_MM"
    _hline "$_TBL_H" "$col_fix"
    printf '%s\n' "$_TBL_MR"

    # Table rows
    local show_count="$max_per_group"
    if (( sev_count < show_count )); then show_count="$sev_count"; fi

    local i
    for (( i=0; i<show_count; i++ )); do
      local finding
      finding="$(echo "$json_array" | jq -c "[.[] | select(.severity == \"$sev\")][$i]")"
      local f_id f_title f_auto_fix f_suppressed
      f_id="$(echo "$finding" | jq -r '.id // ""')"
      f_title="$(echo "$finding" | jq -r '.title // ""')"
      f_auto_fix="$(echo "$finding" | jq -r '.auto_fix // ""')"
      f_suppressed="$(echo "$finding" | jq -r '.suppressed // false')"

      # Add [SUPPRESSED] prefix to title if suppressed
      if [[ "$f_suppressed" == "true" ]]; then
        f_title="[SUPPRESSED] $f_title"
      fi

      # Truncate title if needed
      local max_title_len=$(( col_title - 2 ))
      if (( ${#f_title} > max_title_len )); then
        f_title="${f_title:0:$((max_title_len - 3))}..."
      fi

      # Dim the row if suppressed
      local row_color=""
      if [[ "$f_suppressed" == "true" ]]; then
        row_color="$_CLR_DIM"
      fi

      printf '  %s' "$_TBL_V"
      printf " %b%-*s%b" "$row_color" $(( col_id - 2 )) "$f_id" "$_CLR_RST"
      printf ' %s' "$_TBL_V"
      printf " %b%-*s%b" "$row_color" $(( col_title - 2 )) "$f_title" "$_CLR_RST"
      printf ' %s' "$_TBL_V"
      if [[ -n "$f_auto_fix" ]]; then
        printf ' %b✓%b  ' "$_CLR_OK" "$_CLR_RST"
      else
        printf '  ─  '
      fi
      printf '%s\n' "$_TBL_V"
    done

    # "+N more" overflow row
    local remaining=$(( sev_count - show_count ))
    if (( remaining > 0 )); then
      local more_text="(+${remaining} more)"
      printf '  %s' "$_TBL_V"
      printf " %-*s" $(( col_id - 2 )) "..."
      printf ' %s' "$_TBL_V"
      printf " %-*s" $(( col_title - 2 )) "$more_text"
      printf ' %s' "$_TBL_V"
      printf '  ─  '
      printf '%s\n' "$_TBL_V"
    fi

    # Table bottom border
    printf '  %s' "$_TBL_BL"
    _hline "$_TBL_H" "$col_id"
    printf '%s' "$_TBL_BM"
    _hline "$_TBL_H" "$col_title"
    printf '%s' "$_TBL_BM"
    _hline "$_TBL_H" "$col_fix"
    printf '%s\n' "$_TBL_BR"

    printf '\n'
  done

  # Collapsed OK + INFO one-liner if any OK findings
  if (( ok_count > 0 )); then
    if (( printed_table == 1 )); then
      printf '  %b%s%b OK (%d)\n\n' "$_CLR_OK" "✓" "$_CLR_RST" "$ok_count"
    else
      printf '  %b✓%b OK (%d)\n\n' "$_CLR_OK" "$_CLR_RST" "$ok_count"
    fi
  fi
}

# ─── Interactive menu ────────────────────────────────────────────────────────

interactive_menu() {
  local json_array="$1"
  local scanner_count="${2:-0}"
  local elapsed="${3:-0}"

  local w
  w="$(_box_width)"
  local inner=$(( w - 4 ))

  while true; do
    printf '\n'

    # Menu box
    printf "  %b%s%b" "$_CLR_BOX" "$_TBL_TL" "$_CLR_RST"
    printf '%b' "$_CLR_BOX"
    printf ' What would you like to do? '
    local menu_hdr="What would you like to do?"
    local menu_hdr_len=$(( ${#menu_hdr} + 2 ))
    local menu_rule=$(( inner - menu_hdr_len - 1 ))
    if (( menu_rule < 2 )); then menu_rule=2; fi
    _hline "$_TBL_H" "$menu_rule" "$_CLR_BOX"
    printf "%s%b\n" "$_TBL_TR" "$_CLR_RST"

    printf "  %b%s%b%*s%b%s%b\n" "$_CLR_BOX" "$_TBL_V" "$_CLR_RST" "$inner" '' "$_CLR_BOX" "$_TBL_V" "$_CLR_RST"

    # Menu items
    local -a labels=("Review & fix findings" "Auto-fix all" "Export handoff doc" "Export AI remediation skill" "Exit")
    local -a descs=("Walk through issues one by one" "Apply all available auto-fixes" "Save findings to markdown file" "Generate task list for AI agents" "Done for now")

    local mi
    for mi in 0 1 2 3 4; do
      local num=$(( mi + 1 ))
      local label="${labels[$mi]}"
      local desc="${descs[$mi]}"
      local item_text
      item_text="$(printf '  [%d] %-22s %s' "$num" "$label" "$desc")"
      local item_len=${#item_text}
      local rpad=$(( inner - item_len ))
      if (( rpad < 0 )); then rpad=0; fi
      printf "  %b%s%b" "$_CLR_BOX" "$_TBL_V" "$_CLR_RST"
      printf '  %b[%d]%b %-22s %b%s%b' "$_CLR_WHITE" "$num" "$_CLR_RST" "$label" "$_CLR_DIM" "$desc" "$_CLR_RST"
      printf '%*s' "$rpad" ''
      printf "%b%s%b\n" "$_CLR_BOX" "$_TBL_V" "$_CLR_RST"
    done

    printf "  %b%s%b%*s%b%s%b\n" "$_CLR_BOX" "$_TBL_V" "$_CLR_RST" "$inner" '' "$_CLR_BOX" "$_TBL_V" "$_CLR_RST"

    # Menu bottom border
    printf "  %b%s%b" "$_CLR_BOX" "$_TBL_BL" "$_CLR_RST"
    printf '%b' "$_CLR_BOX"
    _hline "$_TBL_H" "$inner" "$_CLR_BOX"
    printf "%s%b\n" "$_TBL_BR" "$_CLR_RST"

    printf '\n'
    local choice
    printf '  Select [1-5]: '
    read -r choice

    case "$choice" in
      1) review_findings "$json_array" ;;
      2) auto_fix_all "$json_array" ;;
      3) export_handoff "$json_array" "$scanner_count" "$elapsed" ;;
      4) export_remediation_skill "$json_array" "$scanner_count" "$elapsed" ;;
      5) printf '\n  Goodbye.\n\n'; return 0 ;;
      *)
        printf '  %bInvalid selection. Please enter 1-5.%b\n' "$_CLR_WARN" "$_CLR_RST"
        ;;
    esac
  done
}

# ─── Review & Fix mode ──────────────────────────────────────────────────────

review_findings() {
  local json_array="$1"

  # Get non-OK findings sorted by severity
  local findings
  findings="$(echo "$json_array" | jq -c '[.[] | select(.severity != "ok")] | sort_by(
    if .severity == "critical" then 0
    elif .severity == "warn" then 1
    elif .severity == "info" then 2
    else 3
    end
  )')"

  local total
  total="$(echo "$findings" | jq 'length')"

  if (( total == 0 )); then
    printf '\n  No actionable findings to review.\n'
    return
  fi

  local i=0
  while (( i < total )); do
    local finding
    finding="$(echo "$findings" | jq -c ".[$i]")"
    local f_id f_severity f_title f_description f_evidence f_remediation f_auto_fix
    f_id="$(echo "$finding" | jq -r '.id // ""')"
    f_severity="$(echo "$finding" | jq -r '.severity // "info"')"
    f_title="$(echo "$finding" | jq -r '.title // ""')"
    f_description="$(echo "$finding" | jq -r '.description // ""')"
    f_evidence="$(echo "$finding" | jq -r '.evidence // ""')"
    f_remediation="$(echo "$finding" | jq -r '.remediation // ""')"
    f_auto_fix="$(echo "$finding" | jq -r '.auto_fix // ""')"

    local num=$(( i + 1 ))
    local sev_upper
    sev_upper="$(echo "$f_severity" | tr '[:lower:]' '[:upper:]')"
    if [[ "$f_severity" == "warn" ]]; then sev_upper="WARNING"; fi

    local sev_clr
    sev_clr="$(_severity_color "$f_severity")"

    # Progress header
    printf '\n  %b━━━ Finding %d of %d (%s) ' "$sev_clr" "$num" "$total" "$sev_upper"
    local progress_text="Finding $num of $total ($sev_upper) "
    local progress_len=$(( ${#progress_text} + 4 ))
    local w
    w="$(_box_width)"
    local rule_rem=$(( w - 2 - progress_len ))
    if (( rule_rem < 2 )); then rule_rem=2; fi
    local j
    for (( j=0; j<rule_rem; j++ )); do printf '━'; done
    printf '%b\n' "$_CLR_RST"

    # Severity badge + ID
    printf '\n  '
    _badge "$f_severity"
    local badge_len
    badge_len="$(_badge_visible_len "$f_severity")"
    local id_len=${#f_id}
    local inner=$(( w - 4 ))
    local gap=$(( inner - badge_len - id_len ))
    if (( gap < 1 )); then gap=1; fi
    printf '%*s' "$gap" ''
    printf '%b%s%b\n' "$_CLR_DIM" "$f_id" "$_CLR_RST"

    # Title
    printf '  %b%s%b\n' "$_CLR_WHITE" "$f_title" "$_CLR_RST"

    # Description (word-wrapped)
    if [[ -n "$f_description" ]]; then
      printf '\n'
      local desc_w=$(( w - 4 ))
      while IFS= read -r line; do
        printf '  %s\n' "$line"
      done < <(_word_wrap "$f_description" "$desc_w")
    fi

    # Evidence & remediation
    if [[ -n "$f_evidence" ]]; then
      printf '\n  %bEvidence:%b %s\n' "$_CLR_DIM" "$_CLR_RST" "$f_evidence"
    fi
    if [[ -n "$f_remediation" ]]; then
      printf '  %bFix:%b %s\n' "$_CLR_UL" "$_CLR_RST" "$f_remediation"
    fi

    # Actions box
    printf '\n'
    local has_fix=0
    [[ -n "$f_auto_fix" ]] && has_fix=1

    printf "  %b%s%b Actions " "$_CLR_BOX" "$_TBL_TL" "$_CLR_RST"
    local actions_rule=$(( w - 4 - 9 ))
    if (( actions_rule < 2 )); then actions_rule=2; fi
    _hline "$_TBL_H" "$actions_rule" "$_CLR_BOX"
    printf "%b%s%b\n" "$_CLR_BOX" "$_TBL_TR" "$_CLR_RST"

    if (( has_fix )); then
      printf "  %b%s%b  [f] Apply fix  [a] Ask AI  [s] Skip  [d] Details  [q] Back  %b%s%b\n" \
        "$_CLR_BOX" "$_TBL_V" "$_CLR_RST" "$_CLR_BOX" "$_TBL_V" "$_CLR_RST"
    else
      printf "  %b%s%b  %b[f] Apply fix%b  [a] Ask AI  [s] Skip  [d] Details  [q] Back  %b%s%b\n" \
        "$_CLR_BOX" "$_TBL_V" "$_CLR_RST" "$_CLR_DIM" "$_CLR_RST" "$_CLR_BOX" "$_TBL_V" "$_CLR_RST"
    fi

    printf "  %b%s%b" "$_CLR_BOX" "$_TBL_BL" "$_CLR_RST"
    _hline "$_TBL_H" $(( w - 4 )) "$_CLR_BOX"
    printf "%b%s%b\n" "$_CLR_BOX" "$_TBL_BR" "$_CLR_RST"

    printf '\n'
    local action
    printf '  Select: '
    read -r action

    case "$action" in
      [fF])
        if (( has_fix )); then
          printf '\n  Command: %b%s%b\n' "$_CLR_DIM" "$f_auto_fix" "$_CLR_RST"
          if _confirm '  Run this? [y/n]: '; then
            _run_fix "$f_auto_fix"
          else
            printf '  Skipped.\n'
          fi
        else
          printf '  %bNo auto-fix available for this finding.%b\n' "$_CLR_DIM" "$_CLR_RST"
        fi
        i=$(( i + 1 ))
        ;;
      [aA])
        local ai_prompt
        ai_prompt="$(_generate_ai_prompt "$finding")"
        _copy_to_clipboard "$ai_prompt"
        printf '  %b✓ AI remediation prompt copied to clipboard%b\n' "$_CLR_OK" "$_CLR_RST"
        i=$(( i + 1 ))
        ;;
      [sS])
        i=$(( i + 1 ))
        ;;
      [dD])
        # Show full finding card (v1.0 style)
        printf '\n'
        print_finding "$finding"
        # Don't advance — let user act on the same finding
        ;;
      [qQ])
        return
        ;;
      *)
        printf '  %bInvalid action. Use f/a/s/d/q.%b\n' "$_CLR_WARN" "$_CLR_RST"
        # Don't advance
        ;;
    esac
  done

  printf '\n  %b✓ All findings reviewed.%b\n' "$_CLR_OK" "$_CLR_RST"
}

# ─── Auto-fix all ───────────────────────────────────────────────────────────

auto_fix_all() {
  local json_array="$1"

  # Collect findings with auto_fix
  local fixable
  fixable="$(echo "$json_array" | jq -c '[.[] | select(.auto_fix != null and .auto_fix != "")]')"
  local fix_count
  fix_count="$(echo "$fixable" | jq 'length')"

  if (( fix_count == 0 )); then
    printf '\n  No findings with auto-fix commands available.\n'
    return
  fi

  local sev_clr
  sev_clr="$(_severity_color "critical")"

  printf '\n  %b━━━ Auto-Fix Mode ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%b\n' "$sev_clr" "$_CLR_RST"
  printf '\n  Found %b%d%b findings with auto-fix commands available.\n' "$_CLR_WHITE" "$fix_count" "$_CLR_RST"
  printf '\n  This will run the following commands:\n'

  local i
  for (( i=0; i<fix_count; i++ )); do
    local cmd
    cmd="$(echo "$fixable" | jq -r ".[$i].auto_fix")"
    printf '    %b%d.%b %s\n' "$_CLR_DIM" $(( i + 1 )) "$_CLR_RST" "$cmd"
  done

  printf '\n'
  if ! _confirm '  Proceed with all fixes? [y/n]: '; then
    printf '  Aborted.\n'
    return
  fi

  printf '\n'
  local passed=0
  local failed=0
  for (( i=0; i<fix_count; i++ )); do
    local f_id f_cmd
    f_id="$(echo "$fixable" | jq -r ".[$i].id")"
    f_cmd="$(echo "$fixable" | jq -r ".[$i].auto_fix")"
    printf '  [%d/%d] %s ... ' $(( i + 1 )) "$fix_count" "$f_id"

    # safe_exec_command handles its own validation (whitelist + blacklist)
    if safe_exec_command "$f_cmd" >/dev/null 2>&1; then
      printf '%b✓ pass%b\n' "$_CLR_OK" "$_CLR_RST"
      passed=$(( passed + 1 ))
    else
      printf '%b✗ fail%b\n' "$_CLR_CRIT" "$_CLR_RST"
      failed=$(( failed + 1 ))
    fi
  done

  printf '\n  Applied %b%d/%d%b fixes' "$_CLR_WHITE" "$passed" "$fix_count" "$_CLR_RST"
  if (( failed > 0 )); then
    printf ' (%b%d failed%b)' "$_CLR_CRIT" "$failed" "$_CLR_RST"
  fi
  printf '\n'
}

# ─── Export handoff doc ──────────────────────────────────────────────────────

export_handoff() {
  local json_array="$1"
  local scanner_count="${2:-0}"
  local elapsed="${3:-0}"

  local today
  today="$(date +%Y-%m-%d)"
  local outfile="./clawpinch-report-${today}.md"

  local count_critical count_warn count_info count_ok total
  count_critical="$(echo "$json_array" | jq '[.[] | select(.severity == "critical")] | length')"
  count_warn="$(echo "$json_array" | jq '[.[] | select(.severity == "warn")] | length')"
  count_info="$(echo "$json_array" | jq '[.[] | select(.severity == "info")] | length')"
  count_ok="$(echo "$json_array" | jq '[.[] | select(.severity == "ok")] | length')"
  total="$(echo "$json_array" | jq 'length')"

  {
    printf '# ClawPinch Security Report\n'
    printf 'Generated: %s\n\n' "$today"

    printf '## Summary\n'
    printf -- '- **%d Critical**, %d Warning, %d Info, %d OK\n' "$count_critical" "$count_warn" "$count_info" "$count_ok"
    printf -- '- Scan completed in %ss across %d scanners\n' "$elapsed" "$scanner_count"
    printf -- '- Total findings: %d\n\n' "$total"

    local -a sev_order=("critical" "warn" "info" "ok")
    local -a sev_headings=("Critical Findings" "Warning Findings" "Info Findings" "OK Findings")

    local s_idx
    for s_idx in 0 1 2 3; do
      local sev="${sev_order[$s_idx]}"
      local heading="${sev_headings[$s_idx]}"

      local sev_findings
      sev_findings="$(echo "$json_array" | jq -c "[.[] | select(.severity == \"$sev\")]")"
      local sev_count
      sev_count="$(echo "$sev_findings" | jq 'length')"

      if (( sev_count == 0 )); then
        continue
      fi

      printf '## %s\n\n' "$heading"

      local f_idx
      for (( f_idx=0; f_idx<sev_count; f_idx++ )); do
        local f
        f="$(echo "$sev_findings" | jq -c ".[$f_idx]")"
        local f_id f_title f_severity f_description f_evidence f_remediation f_auto_fix
        f_id="$(echo "$f" | jq -r '.id // ""')"
        f_title="$(echo "$f" | jq -r '.title // ""')"
        f_severity="$(echo "$f" | jq -r '.severity // ""')"
        f_description="$(echo "$f" | jq -r '.description // ""')"
        f_evidence="$(echo "$f" | jq -r '.evidence // ""')"
        f_remediation="$(echo "$f" | jq -r '.remediation // ""')"
        f_auto_fix="$(echo "$f" | jq -r '.auto_fix // ""')"

        local sev_upper
        sev_upper="$(echo "$f_severity" | tr '[:lower:]' '[:upper:]')"
        if [[ "$f_severity" == "warn" ]]; then sev_upper="Warning"; fi
        if [[ "$f_severity" == "critical" ]]; then sev_upper="Critical"; fi
        if [[ "$f_severity" == "info" ]]; then sev_upper="Info"; fi
        if [[ "$f_severity" == "ok" ]]; then sev_upper="OK"; fi

        printf '### %s: %s\n' "$f_id" "$f_title"
        printf '**Severity:** %s\n' "$sev_upper"

        if [[ -n "$f_description" ]]; then
          printf '\n%s\n' "$f_description"
        fi

        if [[ -n "$f_evidence" ]]; then
          # Redact evidence in the report
          local redacted_evidence
          redacted_evidence="$(redact_line "$f_evidence")"
          printf '\n**Evidence:** %s\n' "$redacted_evidence"
        fi

        if [[ -n "$f_remediation" ]]; then
          printf '**Remediation:** %s\n' "$f_remediation"
        fi

        if [[ -n "$f_auto_fix" ]]; then
          printf '**Auto-fix:** `%s`\n' "$f_auto_fix"
        fi

        printf '\n---\n\n'
      done
    done
  } > "$outfile"

  printf '\n  %b✓%b Report saved to %b%s%b\n' "$_CLR_OK" "$_CLR_RST" "$_CLR_WHITE" "$outfile" "$_CLR_RST"
}

# ─── Export AI remediation skill ─────────────────────────────────────────

export_remediation_skill() {
  local json_array="$1"
  local scanner_count="${2:-0}"
  local elapsed="${3:-0}"

  local today
  today="$(date +%Y-%m-%d)"
  local outfile="./clawpinch-remediation-${today}.md"

  local count_critical count_warn count_info
  count_critical="$(echo "$json_array" | jq '[.[] | select(.severity == "critical")] | length')"
  count_warn="$(echo "$json_array" | jq '[.[] | select(.severity == "warn")] | length')"
  count_info="$(echo "$json_array" | jq '[.[] | select(.severity == "info")] | length')"

  # Filter out OK findings
  local non_ok
  non_ok="$(echo "$json_array" | jq -c '[.[] | select(.severity != "ok")]')"
  local non_ok_count
  non_ok_count="$(echo "$non_ok" | jq 'length')"

  if (( non_ok_count == 0 )); then
    printf '\n  No actionable findings to export.\n'
    return
  fi

  {
    printf '# ClawPinch AI Remediation Task List\n\n'
    printf '> Generated: %s | Scan: %d scanners in %ss | Findings: %d critical, %d warn, %d info\n\n' \
      "$today" "$scanner_count" "$elapsed" "$count_critical" "$count_warn" "$count_info"

    printf '## Instructions for AI Agent\n'
    printf 'Work through each task in order (critical first). For each:\n'
    printf '1. Read the description and evidence\n'
    printf '2. Execute auto-fix command if provided, otherwise apply remediation manually\n'
    printf '3. Verify the evidence condition no longer exists\n\n'
    printf -- '---\n\n'

    local task_num=0
    local -a sev_order=("critical" "warn" "info")
    local -a sev_headings=("CRITICAL" "WARNING" "INFO")

    local s_idx
    for s_idx in 0 1 2; do
      local sev="${sev_order[$s_idx]}"
      local sev_heading="${sev_headings[$s_idx]}"

      local sev_findings
      sev_findings="$(echo "$non_ok" | jq -c "[.[] | select(.severity == \"$sev\")]")"
      local sev_count
      sev_count="$(echo "$sev_findings" | jq 'length')"

      if (( sev_count == 0 )); then
        continue
      fi

      printf '## %s (%d)\n\n' "$sev_heading" "$sev_count"

      local f_idx
      for (( f_idx=0; f_idx<sev_count; f_idx++ )); do
        task_num=$(( task_num + 1 ))
        local f
        f="$(echo "$sev_findings" | jq -c ".[$f_idx]")"
        local f_id f_title f_description f_evidence f_remediation f_auto_fix
        f_id="$(echo "$f" | jq -r '.id // ""')"
        f_title="$(echo "$f" | jq -r '.title // ""')"
        f_description="$(echo "$f" | jq -r '.description // ""')"
        f_evidence="$(echo "$f" | jq -r '.evidence // ""')"
        f_remediation="$(echo "$f" | jq -r '.remediation // ""')"
        f_auto_fix="$(echo "$f" | jq -r '.auto_fix // ""')"

        # Redact evidence
        local redacted_evidence
        redacted_evidence="$(redact_line "$f_evidence")"

        printf '### Task %d: %s [%s]\n' "$task_num" "$f_title" "$f_id"

        if [[ -n "$f_description" ]]; then
          printf '**Description:** %s\n' "$f_description"
        fi

        if [[ -n "$redacted_evidence" ]]; then
          printf '**Evidence:** ```%s```\n' "$redacted_evidence"
        fi

        if [[ -n "$f_remediation" ]]; then
          printf '**Remediation:** %s\n' "$f_remediation"
        fi

        if [[ -n "$f_auto_fix" ]]; then
          printf '**Auto-fix:** `%s`\n' "$f_auto_fix"
        else
          printf '**Auto-fix:** None available. Apply remediation guidance manually.\n'
        fi

        printf '**Acceptance criteria:** The condition described in evidence must no longer be present.\n'
        printf -- '- [ ] Completed\n\n'
        printf -- '---\n\n'
      done
    done
  } > "$outfile"

  printf '\n  %b✓%b AI remediation skill exported to %b%s%b\n' "$_CLR_OK" "$_CLR_RST" "$_CLR_WHITE" "$outfile" "$_CLR_RST"
}
