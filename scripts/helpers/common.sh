#!/usr/bin/env bash
set -euo pipefail

# ─── ClawPinch common helpers ───────────────────────────────────────────────
# Source this file from any scanner:
#   source "$(dirname "$0")/helpers/common.sh"

# ─── NO_COLOR & color capability detection ─────────────────────────────────

_CLAWPINCH_HAS_256=0
_CLAWPINCH_HAS_COLOR=1

# Respect NO_COLOR spec (https://no-color.org/)
if [[ -n "${NO_COLOR:-}" ]]; then
  _CLAWPINCH_HAS_COLOR=0
  _CLAWPINCH_HAS_256=0
elif [[ ! -t 2 ]] && [[ "${FORCE_COLOR:-}" != "1" ]]; then
  # stderr not a terminal and color not forced
  _CLAWPINCH_HAS_COLOR=0
  _CLAWPINCH_HAS_256=0
else
  # Detect 256-color / truecolor support
  if [[ "${COLORTERM:-}" == "truecolor" ]] || [[ "${COLORTERM:-}" == "24bit" ]] \
     || [[ "${TERM:-}" == *256color* ]] || [[ "${TERM:-}" == *kitty* ]] \
     || [[ "${TERM_PROGRAM:-}" == "iTerm.app" ]] || [[ "${TERM_PROGRAM:-}" == "WezTerm" ]]; then
    _CLAWPINCH_HAS_256=1
  fi
fi

export _CLAWPINCH_HAS_COLOR _CLAWPINCH_HAS_256

# ─── Color palette ─────────────────────────────────────────────────────────
# 256-color with 16-color fallback; all empty when NO_COLOR

if [[ "$_CLAWPINCH_HAS_COLOR" -eq 1 ]]; then
  if [[ "$_CLAWPINCH_HAS_256" -eq 1 ]]; then
    # 256-color palette
    _CLR_CRIT='\033[38;5;196m'       # bright red
    _CLR_WARN='\033[38;5;214m'       # orange
    _CLR_INFO='\033[38;5;39m'        # bright blue
    _CLR_OK='\033[38;5;48m'          # bright green
    _CLR_BANNER_R1='\033[38;5;196m'  # red gradient start
    _CLR_BANNER_R2='\033[38;5;201m'  # red gradient mid
    _CLR_BANNER_R3='\033[38;5;207m'  # red gradient end
    _CLR_BANNER_C1='\033[38;5;51m'   # cyan gradient start
    _CLR_BANNER_C2='\033[38;5;49m'   # cyan gradient mid
    _CLR_BANNER_C3='\033[38;5;48m'   # cyan gradient end
    _CLR_BOX='\033[38;5;240m'        # dark gray
    _CLR_SPINNER='\033[38;5;51m'     # cyan spinner
  else
    # 16-color fallback
    _CLR_CRIT='\033[1;31m'
    _CLR_WARN='\033[1;33m'
    _CLR_INFO='\033[0;34m'
    _CLR_OK='\033[0;32m'
    _CLR_BANNER_R1='\033[1;31m'
    _CLR_BANNER_R2='\033[1;31m'
    _CLR_BANNER_R3='\033[1;31m'
    _CLR_BANNER_C1='\033[0;36m'
    _CLR_BANNER_C2='\033[0;36m'
    _CLR_BANNER_C3='\033[0;36m'
    _CLR_BOX='\033[2m'
    _CLR_SPINNER='\033[0;36m'
  fi

  _CLR_RED="$_CLR_CRIT"
  _CLR_YLW="$_CLR_WARN"
  _CLR_BLU="$_CLR_INFO"
  _CLR_GRN="$_CLR_OK"
  _CLR_DIM='\033[2m'
  _CLR_BOLD='\033[1m'
  _CLR_WHITE='\033[1;37m'
  _CLR_UL='\033[4m'
  _CLR_RST='\033[0m'
else
  # NO_COLOR: all codes are empty strings
  _CLR_CRIT='' _CLR_WARN='' _CLR_INFO='' _CLR_OK=''
  _CLR_BANNER_R1='' _CLR_BANNER_R2='' _CLR_BANNER_R3=''
  _CLR_BANNER_C1='' _CLR_BANNER_C2='' _CLR_BANNER_C3=''
  _CLR_BOX='' _CLR_SPINNER=''
  _CLR_RED='' _CLR_YLW='' _CLR_BLU='' _CLR_GRN=''
  _CLR_DIM='' _CLR_BOLD='' _CLR_WHITE='' _CLR_UL='' _CLR_RST=''
fi

export _CLR_CRIT _CLR_WARN _CLR_INFO _CLR_OK
export _CLR_BANNER_R1 _CLR_BANNER_R2 _CLR_BANNER_R3
export _CLR_BANNER_C1 _CLR_BANNER_C2 _CLR_BANNER_C3
export _CLR_BOX _CLR_SPINNER
export _CLR_RED _CLR_YLW _CLR_BLU _CLR_GRN
export _CLR_DIM _CLR_BOLD _CLR_WHITE _CLR_UL _CLR_RST

# ─── Emoji support detection ─────────────────────────────────────────────

_CLAWPINCH_HAS_EMOJI=1
if [[ "$_CLAWPINCH_HAS_COLOR" -eq 0 ]] || [[ "${TERM:-}" == "linux" ]] || [[ "${TERM:-}" == "dumb" ]]; then
  _CLAWPINCH_HAS_EMOJI=0
fi
export _CLAWPINCH_HAS_EMOJI

# ─── Security tips (shown during spinner rotation) ───────────────────────

_TIPS=(
  "Rotate API keys every 90 days"
  "Never store secrets in plaintext config"
  "Use allowlists, not blocklists"
  "Pin dependency versions in production"
  "Audit cron jobs for privilege escalation"
  "Sandbox skill execution environments"
  "Enable TLS for all API endpoints"
  "Use short-lived tokens over static keys"
  "Monitor for DNS rebinding attacks"
  "Review CORS origins quarterly"
  "Hash-verify supply chain packages"
  "Restrict wildcard permissions"
  "Log all privileged operations"
  "Check CVE databases on every deploy"
  "Separate dev and prod credentials"
  "Use mTLS for service-to-service auth"
  "Validate webhook signatures"
  "Rate-limit authentication endpoints"
  "Scan for base64-encoded payloads in skills"
  "Enforce least-privilege for all agents"
  "Disable unused network ports"
  "Sign skill packages cryptographically"
  "Use read-only filesystem where possible"
  "Test disaster recovery runbooks"
  "Keep your claws sharp — audit regularly"
)

# ─── Init messages (typewriter effect on startup) ─────────────────────────

_INIT_MSGS=(
  "Sharpening claws..."
  "Checking for crabs..."
  "Snapping into action..."
  "Scanning the reef..."
  "Deploying pinch protocols..."
  "Calibrating claw sensors..."
  "Loading threat intelligence..."
  "Preparing security sweep..."
)

# ─── Glow color (animated accents) ───────────────────────────────────────

if [[ "$_CLAWPINCH_HAS_COLOR" -eq 1 ]]; then
  if [[ "$_CLAWPINCH_HAS_256" -eq 1 ]]; then
    _CLR_GLOW='\033[38;5;219m'  # pink glow for accents
  else
    _CLR_GLOW="$_CLR_BOLD"
  fi
else
  _CLR_GLOW=''
fi
export _CLR_GLOW

# ─── Terminal width helper ─────────────────────────────────────────────────

term_width() {
  local w
  if w="$(tput cols 2>/dev/null)"; then
    echo "$w"
  elif [[ -n "${COLUMNS:-}" ]]; then
    echo "$COLUMNS"
  else
    echo 80
  fi
}

# ─── Logging ────────────────────────────────────────────────────────────────

log_info()  { printf "${_CLR_BLU}[info]${_CLR_RST}  %s\n" "$*" >&2; }
log_warn()  { printf "${_CLR_YLW}[warn]${_CLR_RST}  %s\n" "$*" >&2; }
log_error() { printf "${_CLR_RED}[error]${_CLR_RST} %s\n" "$*" >&2; }

# ─── Command detection ──────────────────────────────────────────────────────

has_cmd() {
  command -v "$1" &>/dev/null
}

require_cmd() {
  if ! has_cmd "$1"; then
    log_error "Required command not found: $1"
    return 1
  fi
}

# ─── Command validation (allowlist) ─────────────────────────────────────────

validate_command() {
  # Usage: validate_command <command_string>
  # Returns 0 if ALL commands in the string are in allowlist, 1 otherwise
  local cmd_string="$1"

  if [[ -z "$cmd_string" ]]; then
    log_error "validate_command: empty command string"
    return 1
  fi

  # Find security config file (trusted locations only)
  # SECURITY: Do NOT search the project being scanned — an attacker could
  # include a malicious .auto-claude-security.json in their repo to override
  # the allowlist and bypass all command validation.
  local security_file=""

  # 1. Explicit env var override (highest priority)
  if [[ -n "${CLAWPINCH_SECURITY_CONFIG:-}" ]] && [[ -f "$CLAWPINCH_SECURITY_CONFIG" ]]; then
    security_file="$CLAWPINCH_SECURITY_CONFIG"
  fi

  # 2. ClawPinch installation directory (next to clawpinch.sh)
  if [[ -z "$security_file" ]]; then
    local install_dir
    install_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    if [[ -f "$install_dir/.auto-claude-security.json" ]]; then
      security_file="$install_dir/.auto-claude-security.json"
    fi
  fi

  # 3. User config directory (~/.config/clawpinch/)
  if [[ -z "$security_file" ]]; then
    if [[ -f "$HOME/.config/clawpinch/.auto-claude-security.json" ]]; then
      security_file="$HOME/.config/clawpinch/.auto-claude-security.json"
    fi
  fi

  # 4. Home directory fallback
  if [[ -z "$security_file" ]]; then
    if [[ -f "$HOME/.auto-claude-security.json" ]]; then
      security_file="$HOME/.auto-claude-security.json"
    fi
  fi

  if [[ -z "$security_file" ]]; then
    log_error "validate_command: .auto-claude-security.json not found. Searched: \$CLAWPINCH_SECURITY_CONFIG, <install-dir>/, ~/.config/clawpinch/, ~/. See .auto-claude-security.json.example for setup."
    return 1
  fi

  # SECURITY: Validate config file ownership and permissions to prevent
  # symlink attacks where an attacker replaces the config with a symlink
  # to a file they control, overriding the allowlist.
  local resolved_file
  resolved_file="$(readlink -f "$security_file" 2>/dev/null || realpath "$security_file" 2>/dev/null || echo "$security_file")"

  # Check file is owned by current user or root
  local file_owner
  if [[ "$(uname -s)" == "Darwin" ]]; then
    file_owner="$(stat -f '%u' "$resolved_file" 2>/dev/null)" || file_owner=""
  else
    file_owner="$(stat -c '%u' "$resolved_file" 2>/dev/null)" || file_owner=""
  fi

  if [[ -n "$file_owner" ]]; then
    local current_uid
    current_uid="$(id -u)"
    if [[ "$file_owner" != "$current_uid" ]] && [[ "$file_owner" != "0" ]]; then
      log_error "validate_command: security config '$resolved_file' is owned by uid $file_owner (expected $current_uid or root). Possible symlink attack."
      return 1
    fi
  fi

  # Check file is not world-writable
  if [[ "$(uname -s)" == "Darwin" ]]; then
    local file_perms
    file_perms="$(stat -f '%Lp' "$resolved_file" 2>/dev/null)" || file_perms=""
    if [[ -n "$file_perms" ]] && [[ "${file_perms: -1}" =~ [2367] ]]; then
      log_error "validate_command: security config '$resolved_file' is world-writable (mode $file_perms). Fix with: chmod o-w '$resolved_file'"
      return 1
    fi
  else
    if stat -c '%a' "$resolved_file" 2>/dev/null | grep -q '[2367]$'; then
      log_error "validate_command: security config '$resolved_file' is world-writable. Fix with: chmod o-w '$resolved_file'"
      return 1
    fi
  fi

  # Check if jq is available
  if ! has_cmd jq; then
    log_error "validate_command: jq is required but not installed"
    return 1
  fi

  # Validate the security config is valid JSON first
  if ! jq '.' "$security_file" >/dev/null 2>&1; then
    log_error "validate_command: $security_file is not valid JSON"
    return 1
  fi

  # Get all allowed commands from security config
  local allowed_commands
  allowed_commands="$(jq -r '
    (.base_commands // []) +
    (.stack_commands // []) +
    (.script_commands // []) +
    (.custom_commands // []) |
    .[]
  ' "$security_file" 2>/dev/null)"

  if [[ -z "$allowed_commands" ]]; then
    log_warn "validate_command: allowlist is empty in $security_file — no commands are permitted"
    return 1
  fi

  # Extract ALL commands from the string (split by |, &&, ||, ;)
  # This ensures we validate every command in a chain
  # Try to use Python script for proper quote-aware parsing
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  local parse_script="$script_dir/parse_commands.py"

  # Require Python parser — fail closed if unavailable (no insecure fallback)
  if ! [[ -f "$parse_script" ]] || ! has_cmd python3; then
    log_error "validate_command: python3 or parse_commands.py not available. Cannot securely validate command."
    return 1
  fi

  local base_commands_list
  base_commands_list="$(python3 "$parse_script" "$cmd_string")"
  if [[ $? -ne 0 || -z "$base_commands_list" ]]; then
    log_error "validate_command: Python helper failed to parse command string."
    return 1
  fi

  # Check each base command
  while IFS= read -r base_cmd; do
    # Skip empty lines
    [[ -z "$base_cmd" ]] && continue

    # Skip flags/options (start with -)
    [[ "$base_cmd" =~ ^- ]] && continue

    # Strip surrounding quotes from command token before validation
    # (shlex may return quoted tokens like "'cmd'" — strip to get bare command)
    base_cmd="${base_cmd#\'}"
    base_cmd="${base_cmd%\'}"
    base_cmd="${base_cmd#\"}"
    base_cmd="${base_cmd%\"}"
    [[ -z "$base_cmd" ]] && continue

    # Block interpreters with command execution flags (-c, -e)
    # e.g., "bash -c 'rm -rf /'" — bash is in allowlist but -c allows arbitrary code
    case "$base_cmd" in
      bash|sh|zsh|python|python3|perl|ruby|node)
        if [[ "$cmd_string" =~ [[:space:]]-[ce][[:space:]] ]] || [[ "$cmd_string" =~ [[:space:]]-[ce]$ ]]; then
          log_error "validate_command: interpreter '$base_cmd' with -c or -e flag is not allowed"
          return 1
        fi
        ;;
    esac

    # Check allowlist first (allows script_commands like ./clawpinch.sh)
    if grep -Fxq -- "$base_cmd" <<< "$allowed_commands"; then
      continue
    fi

    # Block path-based commands not in allowlist (/bin/rm, ./malicious, ~/script)
    if [[ "$base_cmd" =~ ^[/~\.] ]]; then
      log_error "validate_command: path-based command '$base_cmd' is not in the allowlist"
      return 1
    fi

    # Command not in allowlist
    log_error "validate_command: '$base_cmd' is not in the allowlist"
    return 1
  done <<< "$base_commands_list"

  # All commands validated successfully
  return 0
}

# ─── OS detection ───────────────────────────────────────────────────────────

detect_os() {
  case "$(uname -s)" in
    Darwin*) echo "macos" ;;
    Linux*)  echo "linux" ;;
    *)       echo "unknown" ;;
  esac
}

# ─── OpenClaw config helpers ────────────────────────────────────────────────

get_openclaw_config() {
  local config_dir="${CLAWPINCH_CONFIG_DIR:-}"

  # If explicit config dir was provided, use it
  if [[ -n "$config_dir" ]]; then
    if [[ -f "$config_dir/openclaw.json" ]]; then
      echo "$config_dir/openclaw.json"
      return 0
    elif [[ -f "$config_dir/config.json" ]]; then
      echo "$config_dir/config.json"
      return 0
    fi
  fi

  # Auto-detect common locations
  local os
  os="$(detect_os)"
  local search_paths=()

  if [[ "$os" == "macos" ]]; then
    search_paths=(
      "$HOME/.config/openclaw/openclaw.json"
      "$HOME/.config/openclaw/config.json"
      "$HOME/.openclaw/openclaw.json"
      "$HOME/.openclaw/config.json"
      "$HOME/Library/Application Support/openclaw/openclaw.json"
    )
  else
    search_paths=(
      "$HOME/.config/openclaw/openclaw.json"
      "$HOME/.config/openclaw/config.json"
      "$HOME/.openclaw/openclaw.json"
      "$HOME/.openclaw/config.json"
      "/etc/openclaw/openclaw.json"
    )
  fi

  for p in "${search_paths[@]}"; do
    if [[ -f "$p" ]]; then
      echo "$p"
      return 0
    fi
  done

  return 1
}

get_openclaw_version() {
  if has_cmd openclaw; then
    openclaw --version 2>/dev/null || echo "unknown"
  else
    echo "not-installed"
  fi
}

get_config_value() {
  # Usage: get_config_value <config_file> <jq_filter>
  local config_file="$1"
  local filter="$2"

  if ! has_cmd jq; then
    log_error "jq is required but not installed"
    return 1
  fi

  jq -r "$filter // empty" "$config_file" 2>/dev/null
}

# ─── Finding emitter ────────────────────────────────────────────────────────
# Each scanner outputs findings as JSON objects, one per line, collected
# into a JSON array by the orchestrator.
#
# Schema:
# {
#   "id":          "CHK-XXX-NNN",      (unique check id)
#   "severity":    "critical|warn|info|ok",
#   "title":       "Short title",
#   "description": "Longer explanation",
#   "evidence":    "Relevant snippet or value",
#   "remediation": "How to fix",
#   "auto_fix":    "Optional shell command to fix"
# }

emit_finding() {
  local id="$1"
  local severity="$2"
  local title="$3"
  local description="${4:-}"
  local evidence="${5:-}"
  local remediation="${6:-}"
  local auto_fix="${7:-}"

  if has_cmd jq; then
    jq -n -c \
      --arg id "$id" \
      --arg severity "$severity" \
      --arg title "$title" \
      --arg description "$description" \
      --arg evidence "$evidence" \
      --arg remediation "$remediation" \
      --arg auto_fix "$auto_fix" \
      '{id:$id, severity:$severity, title:$title, description:$description, evidence:$evidence, remediation:$remediation, auto_fix:$auto_fix}'
  else
    # Fallback without jq: manual JSON escaping for common chars
    _json_escape() {
      local s="$1"
      s="${s//\\/\\\\}"
      s="${s//\"/\\\"}"
      s="${s//$'\n'/\\n}"
      s="${s//$'\t'/\\t}"
      printf '%s' "$s"
    }
    printf '{"id":"%s","severity":"%s","title":"%s","description":"%s","evidence":"%s","remediation":"%s","auto_fix":"%s"}\n' \
      "$(_json_escape "$id")" \
      "$(_json_escape "$severity")" \
      "$(_json_escape "$title")" \
      "$(_json_escape "$description")" \
      "$(_json_escape "$evidence")" \
      "$(_json_escape "$remediation")" \
      "$(_json_escape "$auto_fix")"
  fi
}

# ─── Globals set by the orchestrator via env vars ───────────────────────────

CLAWPINCH_DEEP="${CLAWPINCH_DEEP:-0}"
CLAWPINCH_CONFIG_DIR="${CLAWPINCH_CONFIG_DIR:-}"
CLAWPINCH_OS="${CLAWPINCH_OS:-$(detect_os)}"
