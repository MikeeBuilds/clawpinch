#!/usr/bin/env bash
set -euo pipefail

# ─── ClawPinch report rendering ─────────────────────────────────────────────
# Terminal UI: gradient banner, box-drawn finding cards, dashboard summary.
# Pure bash + Unicode -- no external dependencies.

# ─── Box-drawing constants ──────────────────────────────────────────────────

# Rounded corners (light)
readonly _BOX_TL='╭' _BOX_TR='╮' _BOX_BL='╰' _BOX_BR='╯'
readonly _BOX_H='─' _BOX_V='│'

# Heavy box (for summary)
readonly _HBOX_TL='┏' _HBOX_TR='┓' _HBOX_BL='┗' _HBOX_BR='┛'
readonly _HBOX_H='━' _HBOX_V='┃'
readonly _HBOX_ML='┣' _HBOX_MR='┫'

# Finding card (left heavy border)
readonly _CARD_V='┃'
readonly _CARD_BL='└' _CARD_BR='┘'
readonly _CARD_BH='─'

# Section header
readonly _SEC_TL='┌' _SEC_TR='┐'

# Spinner frames (braille)
readonly _SPINNER_FRAMES='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'

# Bar chart characters
readonly _BAR_FULL='█' _BAR_EMPTY='░'

# ─── Layout constants ──────────────────────────────────────────────────────

_box_width() {
  local w
  w="$(term_width 2>/dev/null || echo 80)"
  # Cap between 56 and 80
  if (( w > 80 )); then w=80; fi
  if (( w < 56 )); then w=56; fi
  echo "$w"
}

# ─── Box-drawing helpers ───────────────────────────────────────────────────

# Draw a horizontal line: _hline <char> <width> [color]
_hline() {
  local ch="$1" w="$2" clr="${3:-}"
  if [[ -n "$clr" ]]; then printf '%b' "$clr"; fi
  local i
  for (( i=0; i<w; i++ )); do
    printf '%s' "$ch"
  done
  if [[ -n "$clr" ]]; then printf '%b' "$_CLR_RST"; fi
}

# Pad string to width (right-pad with spaces)
_pad() {
  local str="$1" w="$2"
  local visible_len
  # Strip ANSI sequences for length calculation
  visible_len="$(printf '%b' "$str" | sed $'s/\033\\[[0-9;]*m//g' | wc -m | tr -d ' ')"
  printf '%b' "$str"
  local pad_needed=$(( w - visible_len ))
  if (( pad_needed > 0 )); then
    printf '%*s' "$pad_needed" ''
  fi
}

# ─── Gradient banner ──────────────────────────────────────────────────────

print_header() {
  local w
  w="$(_box_width)"
  local inner=$(( w - 4 ))  # 2 for "│ " left + " │" right padding

  # Banner art lines - "CLAW" in top half, "PINCH" in bottom half
  local -a claw_lines=(
    "██████╗██╗      █████╗ ██╗    ██╗"
    "██╔════╝██║     ██╔══██╗██║    ██║"
    "██║     ██║     ███████║██║ █╗ ██║"
    "██║     ██║     ██╔══██║██║███╗██║"
    "╚██████╗███████╗██║  ██║╚███╔███╔╝"
    " ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝"
  )
  local -a pinch_lines=(
    "██████╗ ██╗███╗   ██╗ ██████╗██╗  ██╗"
    "██╔══██╗██║████╗  ██║██╔════╝██║  ██║"
    "██████╔╝██║██╔██╗ ██║██║     ███████║"
    "██╔═══╝ ██║██║╚██╗██║██║     ██╔══██║"
    "██║     ██║██║ ╚████║╚██████╗██║  ██║"
    "╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝"
  )

  # Red gradient colors for CLAW (cycle through 3)
  local -a red_grad=("$_CLR_BANNER_R1" "$_CLR_BANNER_R1" "$_CLR_BANNER_R2" "$_CLR_BANNER_R2" "$_CLR_BANNER_R3" "$_CLR_BANNER_R3")
  # Cyan gradient colors for PINCH
  local -a cyan_grad=("$_CLR_BANNER_C1" "$_CLR_BANNER_C1" "$_CLR_BANNER_C2" "$_CLR_BANNER_C2" "$_CLR_BANNER_C3" "$_CLR_BANNER_C3")

  printf '\n'

  # Top border
  printf "  ${_CLR_BOX}%s" "$_BOX_TL"
  _hline "$_BOX_H" $(( w - 4 )) "$_CLR_BOX"
  printf "%s${_CLR_RST}\n" "$_BOX_TR"

  # Empty line
  printf "  ${_CLR_BOX}%s${_CLR_RST}" "$_BOX_V"
  printf '%*s' $(( w - 4 )) ''
  printf "${_CLR_BOX}%s${_CLR_RST}\n" "$_BOX_V"

  # CLAW lines
  local idx=0
  for line in "${claw_lines[@]}"; do
    local line_len=${#line}
    local lpad=3
    local rpad=$(( inner - lpad - line_len ))
    if (( rpad < 0 )); then rpad=0; fi
    printf "  ${_CLR_BOX}%s${_CLR_RST}" "$_BOX_V"
    printf '%*s' "$lpad" ''
    printf '%b%s%b' "${red_grad[$idx]}" "$line" "$_CLR_RST"
    printf '%*s' "$rpad" ''
    printf "${_CLR_BOX}%s${_CLR_RST}\n" "$_BOX_V"
    idx=$(( idx + 1 ))
  done

  # PINCH lines
  idx=0
  for line in "${pinch_lines[@]}"; do
    local line_len=${#line}
    local lpad=2
    local rpad=$(( inner - lpad - line_len ))
    if (( rpad < 0 )); then rpad=0; fi
    printf "  ${_CLR_BOX}%s${_CLR_RST}" "$_BOX_V"
    printf '%*s' "$lpad" ''
    printf '%b%s%b' "${cyan_grad[$idx]}" "$line" "$_CLR_RST"
    printf '%*s' "$rpad" ''
    printf "${_CLR_BOX}%s${_CLR_RST}\n" "$_BOX_V"
    idx=$(( idx + 1 ))
  done

  # Empty line
  printf "  ${_CLR_BOX}%s${_CLR_RST}" "$_BOX_V"
  printf '%*s' $(( w - 4 )) ''
  printf "${_CLR_BOX}%s${_CLR_RST}\n" "$_BOX_V"

  # Tagline
  local tagline="Don't get pinched.  v1.2.0"
  local tag_len=${#tagline}
  local tag_lpad=$(( (inner - tag_len) / 2 ))
  local tag_rpad=$(( inner - tag_lpad - tag_len ))
  printf "  ${_CLR_BOX}%s${_CLR_RST}" "$_BOX_V"
  printf '%*s' "$tag_lpad" ''
  printf "${_CLR_DIM}%s${_CLR_RST}" "$tagline"
  printf '%*s' "$tag_rpad" ''
  printf "${_CLR_BOX}%s${_CLR_RST}\n" "$_BOX_V"

  # Bottom border
  printf "  ${_CLR_BOX}%s" "$_BOX_BL"
  _hline "$_BOX_H" $(( w - 4 )) "$_CLR_BOX"
  printf "%s${_CLR_RST}\n" "$_BOX_BR"

  printf '\n'
}

# ─── Spinner ───────────────────────────────────────────────────────────────

# Start a braille spinner in the background.
# Usage: start_spinner "Running config scanner..."
#   Sets global _SPINNER_PID
start_spinner() {
  local msg="$1"
  local frames="$_SPINNER_FRAMES"
  local frame_count=${#frames}

  # Don't spin if not a terminal or quiet mode
  if [[ ! -t 2 ]] || [[ "${QUIET:-0}" -eq 1 ]]; then
    printf '  %s\n' "$msg" >&2
    _SPINNER_PID=""
    return
  fi

  (
    local i=0
    while true; do
      # Extract single multibyte character via substring
      # Braille chars are 3 bytes in UTF-8, but bash ${var:offset:1} works by char
      local frame="${frames:$i:1}"
      printf '\r  %b%s%b %s' "$_CLR_SPINNER" "$frame" "$_CLR_RST" "$msg" >&2
      i=$(( (i + 1) % frame_count ))
      sleep 0.08
    done
  ) &
  _SPINNER_PID=$!
  disown "$_SPINNER_PID" 2>/dev/null || true
}

# Stop the spinner and print a completion line.
# Usage: stop_spinner "Config scanner" <finding_count> <elapsed_seconds>
stop_spinner() {
  local label="$1"
  local count="${2:-0}"
  local elapsed="${3:-0}"

  if [[ -n "${_SPINNER_PID:-}" ]]; then
    kill "$_SPINNER_PID" 2>/dev/null || true
    wait "$_SPINNER_PID" 2>/dev/null || true
    _SPINNER_PID=""
  fi

  # Clear the spinner line
  printf '\r\033[K' >&2

  # Print completion
  if [[ "$_CLAWPINCH_HAS_COLOR" -eq 1 ]]; then
    printf '  %b✓%b %s  %b(%d findings, %ss)%b\n' \
      "$_CLR_OK" "$_CLR_RST" "$label" "$_CLR_DIM" "$count" "$elapsed" "$_CLR_RST" >&2
  else
    printf '  ✓ %s  (%d findings, %ss)\n' "$label" "$count" "$elapsed" >&2
  fi
}

# ─── Scanner section header ───────────────────────────────────────────────

# Maps scanner filenames to category icons and names
_scanner_category() {
  local scanner_name="$1"
  case "$scanner_name" in
    scan_config*)     echo "🔧|Configuration" ;;
    scan_secrets*)    echo "🔑|Secrets" ;;
    scan_cves*)       echo "🛡️|CVE & Versions" ;;
    scan_network*)    echo "🌐|Network" ;;
    scan_permissions*)echo "🔒|Permissions" ;;
    scan_skills*)     echo "⚡|Skills" ;;
    scan_supply*)     echo "📦|Supply Chain" ;;
    scan_crons*)      echo "⏰|Cron Jobs" ;;
    *)                echo "🔍|Scanner" ;;
  esac
}

print_section_header() {
  local scanner_name="$1"
  local w
  w="$(_box_width)"
  local category_info
  category_info="$(_scanner_category "$scanner_name")"
  local icon="${category_info%%|*}"
  local name="${category_info##*|}"

  local label=" ${icon} ${name} "
  local label_visible_len=$(( ${#name} + 4 ))  # icon + spaces
  local line_len=$(( w - 4 - label_visible_len ))
  if (( line_len < 2 )); then line_len=2; fi

  printf '\n'
  printf "  ${_CLR_BOX}%s%s${_CLR_RST}" "$_SEC_TL" "$_CARD_BH"
  printf " %s %s " "$icon" "$name"
  printf "${_CLR_BOX}"
  _hline "$_CARD_BH" "$line_len" "$_CLR_BOX"
  printf "%s${_CLR_RST}\n" "$_SEC_TR"
}

# ─── Severity badge ──────────────────────────────────────────────────────

_badge() {
  case "$1" in
    critical) printf '%b● CRITICAL%b' "$_CLR_CRIT" "$_CLR_RST" ;;
    warn)     printf '%b● WARNING%b'  "$_CLR_WARN" "$_CLR_RST" ;;
    info)     printf '%b● INFO%b'     "$_CLR_INFO" "$_CLR_RST" ;;
    ok)       printf '%b● OK%b'       "$_CLR_OK"   "$_CLR_RST" ;;
    *)        printf '● %s' "$1" ;;
  esac
}

_badge_visible_len() {
  case "$1" in
    critical) echo 10 ;;   # "● CRITICAL"
    warn)     echo 9  ;;   # "● WARNING"
    info)     echo 6  ;;   # "● INFO"
    ok)       echo 4  ;;   # "● OK"
    *)        echo $(( ${#1} + 2 )) ;;
  esac
}

_severity_color() {
  case "$1" in
    critical) printf '%s' "$_CLR_CRIT" ;;
    warn)     printf '%s' "$_CLR_WARN" ;;
    info)     printf '%s' "$_CLR_INFO" ;;
    ok)       printf '%s' "$_CLR_OK"   ;;
    *)        printf '%s' "$_CLR_DIM"  ;;
  esac
}

# ─── Finding cards ─────────────────────────────────────────────────────────

# Word-wrap text to fit within a given width
_word_wrap() {
  local text="$1" max_w="$2"
  local line="" word=""

  # Split into words
  for word in $text; do
    if [[ -z "$line" ]]; then
      line="$word"
    elif (( ${#line} + 1 + ${#word} <= max_w )); then
      line="$line $word"
    else
      echo "$line"
      line="$word"
    fi
  done
  [[ -n "$line" ]] && echo "$line"
}

print_finding() {
  local json="${1:-$(cat)}"
  local w
  w="$(_box_width)"
  local inner=$(( w - 6 ))  # "  ┃ " left (4) + " ┃" right (2)

  local id severity title description evidence remediation auto_fix
  id="$(echo "$json"          | jq -r '.id // ""')"
  severity="$(echo "$json"    | jq -r '.severity // "info"')"
  title="$(echo "$json"       | jq -r '.title // ""')"
  description="$(echo "$json" | jq -r '.description // ""')"
  evidence="$(echo "$json"    | jq -r '.evidence // ""')"
  remediation="$(echo "$json" | jq -r '.remediation // ""')"
  auto_fix="$(echo "$json"    | jq -r '.auto_fix // ""')"

  # For OK findings, use compact single-line format
  if [[ "$severity" == "ok" ]]; then
    print_finding_ok "$title" "$id"
    return
  fi

  local sev_clr
  sev_clr="$(_severity_color "$severity")"
  local badge_len
  badge_len="$(_badge_visible_len "$severity")"

  # ─ Title line: ┃ ● SEVERITY                       CHK-XXX-NNN ┃
  local id_len=${#id}
  local gap=$(( inner - badge_len - id_len ))
  if (( gap < 1 )); then gap=1; fi

  printf '  %b%s%b ' "$sev_clr" "$_CARD_V" "$_CLR_RST"
  _badge "$severity"
  printf '%*s' "$gap" ''
  printf '%b%s%b' "$_CLR_DIM" "$id" "$_CLR_RST"
  printf ' %b%s%b\n' "$sev_clr" "$_CARD_V" "$_CLR_RST"

  # ─ Title text line
  local title_pad=$(( inner - ${#title} ))
  if (( title_pad < 0 )); then title_pad=0; fi
  printf '  %b%s%b ' "$sev_clr" "$_CARD_V" "$_CLR_RST"
  printf '%b%s%b' "$_CLR_WHITE" "$title" "$_CLR_RST"
  printf '%*s' "$title_pad" ''
  printf ' %b%s%b\n' "$sev_clr" "$_CARD_V" "$_CLR_RST"

  # ─ Blank line
  printf '  %b%s%b ' "$sev_clr" "$_CARD_V" "$_CLR_RST"
  printf '%*s' "$inner" ''
  printf ' %b%s%b\n' "$sev_clr" "$_CARD_V" "$_CLR_RST"

  # ─ Description (word-wrapped)
  if [[ -n "$description" ]]; then
    while IFS= read -r line; do
      local line_len=${#line}
      local rpad=$(( inner - line_len ))
      if (( rpad < 0 )); then rpad=0; fi
      printf '  %b%s%b ' "$sev_clr" "$_CARD_V" "$_CLR_RST"
      printf '%s' "$line"
      printf '%*s' "$rpad" ''
      printf ' %b%s%b\n' "$sev_clr" "$_CARD_V" "$_CLR_RST"
    done < <(_word_wrap "$description" "$inner")
  fi

  # ─ Blank line before metadata
  if [[ -n "$evidence" ]] || [[ -n "$remediation" ]]; then
    printf '  %b%s%b ' "$sev_clr" "$_CARD_V" "$_CLR_RST"
    printf '%*s' "$inner" ''
    printf ' %b%s%b\n' "$sev_clr" "$_CARD_V" "$_CLR_RST"
  fi

  # ─ Evidence line
  if [[ -n "$evidence" ]]; then
    local ev_text="Evidence: $evidence"
    local ev_len=${#ev_text}
    local ev_pad=$(( inner - ev_len ))
    if (( ev_pad < 0 )); then
      ev_text="${ev_text:0:$inner}"
      ev_pad=0
    fi
    printf '  %b%s%b ' "$sev_clr" "$_CARD_V" "$_CLR_RST"
    printf '%b%s%b' "$_CLR_DIM" "$ev_text" "$_CLR_RST"
    printf '%*s' "$ev_pad" ''
    printf ' %b%s%b\n' "$sev_clr" "$_CARD_V" "$_CLR_RST"
  fi

  # ─ Fix line
  if [[ -n "$remediation" ]]; then
    local fix_prefix="Fix: "
    local fix_text="${fix_prefix}${remediation}"
    local fix_len=${#fix_text}
    local fix_pad=$(( inner - fix_len ))
    if (( fix_pad < 0 )); then
      fix_text="${fix_text:0:$inner}"
      fix_pad=0
    fi
    printf '  %b%s%b ' "$sev_clr" "$_CARD_V" "$_CLR_RST"
    printf '%b%s%b%s' "$_CLR_UL" "$fix_prefix" "$_CLR_RST" "$remediation"
    # Re-calculate pad using combined length
    printf '%*s' "$fix_pad" ''
    printf ' %b%s%b\n' "$sev_clr" "$_CARD_V" "$_CLR_RST"
  fi

  # ─ Auto-fix line (if --fix enabled)
  if [[ -n "$auto_fix" ]] && [[ "${CLAWPINCH_SHOW_FIX:-0}" == "1" ]]; then
    local af_text="Auto-fix: $auto_fix"
    local af_len=${#af_text}
    local af_pad=$(( inner - af_len ))
    if (( af_pad < 0 )); then
      af_text="${af_text:0:$inner}"
      af_pad=0
    fi
    printf '  %b%s%b ' "$sev_clr" "$_CARD_V" "$_CLR_RST"
    printf '%b%s%b%b%s%b' "$_CLR_OK" "Auto-fix: " "$_CLR_RST" "$_CLR_DIM" "$auto_fix" "$_CLR_RST"
    printf '%*s' "$af_pad" ''
    printf ' %b%s%b\n' "$sev_clr" "$_CARD_V" "$_CLR_RST"
  fi

  # ─ Bottom border
  printf '  %s' "$_CARD_BL"
  _hline "$_CARD_BH" $(( w - 4 ))
  printf '%s\n' "$_CARD_BR"

  # Blank line between cards
  printf '\n'
}

# Compact single-line for OK findings
print_finding_ok() {
  local title="$1"
  local id="${2:-}"
  local w
  w="$(_box_width)"

  local prefix="✓ "
  local prefix_len=2
  local id_len=${#id}
  local title_len=${#title}
  local gap=$(( w - 4 - prefix_len - title_len - id_len ))
  if (( gap < 1 )); then gap=1; fi

  printf '  %b✓%b %s' "$_CLR_OK" "$_CLR_RST" "$title"
  printf '%*s' "$gap" ''
  printf '%b%s%b\n' "$_CLR_DIM" "$id" "$_CLR_RST"
}

# ─── Bar chart helper ──────────────────────────────────────────────────────

# _bar_chart <value> <total> <bar_width>
# Outputs: ████████░░░░░░░░░░░░
_bar_chart() {
  local value="$1" total="$2" bar_w="${3:-20}"
  local filled=0
  if (( total > 0 )); then
    filled=$(( value * bar_w / total ))
  fi
  local empty=$(( bar_w - filled ))

  local i
  for (( i=0; i<filled; i++ )); do
    printf '%s' "$_BAR_FULL"
  done
  for (( i=0; i<empty; i++ )); do
    printf '%s' "$_BAR_EMPTY"
  done
}

# ─── Summary dashboard ────────────────────────────────────────────────────

print_summary() {
  local critical="${1:-0}"
  local warn="${2:-0}"
  local info="${3:-0}"
  local ok="${4:-0}"
  local scanner_count="${5:-0}"
  local elapsed="${6:-0}"
  local suppressed="${7:-0}"

  local total=$(( critical + warn + info + ok ))
  local w
  w="$(_box_width)"
  local inner=$(( w - 6 ))  # "  ┃ " + " ┃"

  printf '\n'

  # ━━━ Top border ━━━
  printf "  %b%s" "$_CLR_BOX" "$_HBOX_TL"
  _hline "$_HBOX_H" $(( w - 4 )) "$_CLR_BOX"
  printf "%s%b\n" "$_HBOX_TR" "$_CLR_RST"

  # Title line
  local title_text="ClawPinch Scan Results"
  local title_len=${#title_text}
  local title_lpad=$(( (inner - title_len) / 2 ))
  local title_rpad=$(( inner - title_lpad - title_len ))
  printf "  %b%s%b " "$_CLR_BOX" "$_HBOX_V" "$_CLR_RST"
  printf '%*s' "$title_lpad" ''
  printf '%b%s%b' "$_CLR_WHITE" "$title_text" "$_CLR_RST"
  printf '%*s' "$title_rpad" ''
  printf " %b%s%b\n" "$_CLR_BOX" "$_HBOX_V" "$_CLR_RST"

  # ━━━ Separator ━━━
  printf "  %b%s" "$_CLR_BOX" "$_HBOX_ML"
  _hline "$_HBOX_H" $(( w - 4 )) "$_CLR_BOX"
  printf "%s%b\n" "$_HBOX_MR" "$_CLR_RST"

  # Empty line
  printf "  %b%s%b " "$_CLR_BOX" "$_HBOX_V" "$_CLR_RST"
  printf '%*s' "$inner" ''
  printf " %b%s%b\n" "$_CLR_BOX" "$_HBOX_V" "$_CLR_RST"

  # Severity rows with bar charts
  local bar_w=20
  local -a sev_names=("CRITICAL" "WARNING" "INFO" "OK")
  local -a sev_counts=("$critical" "$warn" "$info" "$ok")
  local -a sev_colors=("$_CLR_CRIT" "$_CLR_WARN" "$_CLR_INFO" "$_CLR_OK")
  local -a sev_bullets=("●" "●" "●" "✓")

  local row_idx
  for row_idx in 0 1 2 3; do
    local sname="${sev_names[$row_idx]}"
    local scount="${sev_counts[$row_idx]}"
    local sclr="${sev_colors[$row_idx]}"
    local sbullet="${sev_bullets[$row_idx]}"

    # Calculate percentage
    local pct=0
    if (( total > 0 )); then
      pct=$(( scount * 100 / total ))
    fi

    # Build the row: "  ● CRITICAL   12    ████████████░░░░░░░░  38%"
    local label_part
    label_part="$(printf '%b%s %-8s%b' "$sclr" "$sbullet" "$sname" "$_CLR_RST")"
    local count_part
    count_part="$(printf '%3d' "$scount")"
    local bar_part
    bar_part="$(_bar_chart "$scount" "$total" "$bar_w")"
    local pct_part
    pct_part="$(printf '%3d%%' "$pct")"

    # Visible length: "  ● CRITICAL   " (15) + "  3" (3) + "    " (4) + bar (20) + "  " (2) + "38%" (4) = 48
    local row_visible_len=$(( 2 + 1 + 1 + 8 + 3 + 4 + bar_w + 2 + 4 ))
    local rpad=$(( inner - row_visible_len ))
    if (( rpad < 0 )); then rpad=0; fi

    printf "  %b%s%b " "$_CLR_BOX" "$_HBOX_V" "$_CLR_RST"
    printf '  %b%s %-8s%b' "$sclr" "$sbullet" "$sname" "$_CLR_RST"
    printf '%3d    ' "$scount"
    printf '%s' "$bar_part"
    printf '  %3d%%' "$pct"
    printf '%*s' "$rpad" ''
    printf " %b%s%b\n" "$_CLR_BOX" "$_HBOX_V" "$_CLR_RST"
  done

  # Empty line
  printf "  %b%s%b " "$_CLR_BOX" "$_HBOX_V" "$_CLR_RST"
  printf '%*s' "$inner" ''
  printf " %b%s%b\n" "$_CLR_BOX" "$_HBOX_V" "$_CLR_RST"

  # Total line
  local total_text
  total_text="$(printf 'Total: %d findings across %d scanners' "$total" "$scanner_count")"
  local total_len=${#total_text}
  local total_lpad=2
  local total_rpad=$(( inner - total_lpad - total_len ))
  if (( total_rpad < 0 )); then total_rpad=0; fi
  printf "  %b%s%b " "$_CLR_BOX" "$_HBOX_V" "$_CLR_RST"
  printf '%*s%s' "$total_lpad" '' "$total_text"
  printf '%*s' "$total_rpad" ''
  printf " %b%s%b\n" "$_CLR_BOX" "$_HBOX_V" "$_CLR_RST"

  # Timing line
  local time_text
  time_text="$(printf 'Scan completed in %ss' "$elapsed")"
  local time_len=${#time_text}
  local time_lpad=2
  local time_rpad=$(( inner - time_lpad - time_len ))
  if (( time_rpad < 0 )); then time_rpad=0; fi
  printf "  %b%s%b " "$_CLR_BOX" "$_HBOX_V" "$_CLR_RST"
  printf '%*s%b%s%b' "$time_lpad" '' "$_CLR_DIM" "$time_text" "$_CLR_RST"
  printf '%*s' "$time_rpad" ''
  printf " %b%s%b\n" "$_CLR_BOX" "$_HBOX_V" "$_CLR_RST"

  # Suppressed count line (only show if > 0)
  if (( suppressed > 0 )); then
    local supp_text
    supp_text="$(printf 'Suppressed: %d findings' "$suppressed")"
    local supp_len=${#supp_text}
    local supp_lpad=2
    local supp_rpad=$(( inner - supp_lpad - supp_len ))
    if (( supp_rpad < 0 )); then supp_rpad=0; fi
    printf "  %b%s%b " "$_CLR_BOX" "$_HBOX_V" "$_CLR_RST"
    printf '%*s%b%s%b' "$supp_lpad" '' "$_CLR_DIM" "$supp_text" "$_CLR_RST"
    printf '%*s' "$supp_rpad" ''
    printf " %b%s%b\n" "$_CLR_BOX" "$_HBOX_V" "$_CLR_RST"
  fi

  # Empty line
  printf "  %b%s%b " "$_CLR_BOX" "$_HBOX_V" "$_CLR_RST"
  printf '%*s' "$inner" ''
  printf " %b%s%b\n" "$_CLR_BOX" "$_HBOX_V" "$_CLR_RST"

  # ━━━ Bottom border ━━━
  printf "  %b%s" "$_CLR_BOX" "$_HBOX_BL"
  _hline "$_HBOX_H" $(( w - 4 )) "$_CLR_BOX"
  printf "%s%b\n" "$_HBOX_BR" "$_CLR_RST"

  printf '\n'
}

# ─── Aligned table ───────────────────────────────────────────────────────────
# Usage: print_table "Header1|Header2|Header3" "val1|val2|val3" "val4|val5|val6"
# Uses | as delimiter.

print_table() {
  local header="$1"
  shift
  local rows=("$@")

  # Compute column widths
  local IFS='|'
  local -a hcols
  read -ra hcols <<< "$header"
  local ncols=${#hcols[@]}
  local -a widths=()
  for (( i=0; i<ncols; i++ )); do
    widths+=( ${#hcols[$i]} )
  done

  for row in "${rows[@]}"; do
    local -a rcols
    read -ra rcols <<< "$row"
    for (( i=0; i<ncols; i++ )); do
      local len=${#rcols[$i]:-0}
      if (( len > widths[i] )); then
        widths[$i]=$len
      fi
    done
  done

  # Print header
  printf '  '
  for (( i=0; i<ncols; i++ )); do
    printf '%b%-*s%b  ' "$_CLR_WHITE" "${widths[$i]}" "${hcols[$i]}" "$_CLR_RST"
  done
  printf '\n  '
  for (( i=0; i<ncols; i++ )); do
    printf '%*s  ' "${widths[$i]}" '' | tr ' ' '─'
  done
  printf '\n'

  # Print rows
  for row in "${rows[@]}"; do
    local -a rcols
    read -ra rcols <<< "$row"
    printf '  '
    for (( i=0; i<ncols; i++ )); do
      printf "%-*s  " "${widths[$i]}" "${rcols[$i]:-}"
    done
    printf '\n'
  done
  printf '\n'
}

# ─── Legacy progress indicator (kept for backward compat) ─────────────────

print_progress() {
  local current="$1"
  local total="$2"
  local label="${3:-Scanning}"

  local pct=0
  if (( total > 0 )); then
    pct=$(( current * 100 / total ))
  fi

  local bar_width=30
  local filled=$(( pct * bar_width / 100 ))
  local empty=$(( bar_width - filled ))

  printf "\r  %b%s%b [" "$_CLR_DIM" "$label" "$_CLR_RST"
  if (( filled > 0 )); then
    printf '%b' "$_CLR_OK"
    local i
    for (( i=0; i<filled; i++ )); do printf '%s' "$_BAR_FULL"; done
    printf '%b' "$_CLR_RST"
  fi
  local j
  for (( j=0; j<empty; j++ )); do printf '%s' "$_BAR_EMPTY"; done
  printf '] %3d%% (%d/%d)' "$pct" "$current" "$total"

  if (( current == total )); then
    printf '\n'
  fi
}
