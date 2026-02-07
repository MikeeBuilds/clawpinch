#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# scan_skills.sh -- OpenClaw Skill Malware Scanner
#
# Scans installed skills and extensions for malicious patterns associated with
# ClawHavoc and other supply-chain attacks.
#
# Output: JSON array of finding objects to stdout.
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Source common helpers if available
if [[ -f "$SCRIPT_DIR/helpers/common.sh" ]]; then
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/helpers/common.sh"
fi

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
FINDINGS="[]"
OPENCLAW_DIR="${HOME}/.openclaw"
SKILLS_DIR="${OPENCLAW_DIR}/skills"
EXTENSIONS_DIR="${OPENCLAW_DIR}/extensions"
PATTERNS_FILE="${PROJECT_ROOT}/references/malicious-patterns.json"

# Common grep options to exclude dependency directories
GREP_EXCLUDES="--exclude-dir=node_modules --exclude-dir=.git --exclude-dir=vendor --exclude-dir=__pycache__"

# Known ClawHavoc package names (built-in list)
KNOWN_MALICIOUS_NAMES=(
  "claw-havoc"
  "clawhavoc"
  "claw_havoc"
  "openclaw-backdoor"
  "openclaw-exfil"
  "claw-keylog"
  "claw-persist"
  "openclaw-rat"
  "clawhavoc-loader"
  "claw-stealer"
)

# Suspicious domains (built-in list)
SUSPICIOUS_DOMAINS=(
  "pastebin.com"
  "transfer.sh"
  "paste.ee"
  "hastebin.com"
)

# Load extra patterns from malicious-patterns.json if it exists
if [[ -f "$PATTERNS_FILE" ]] && command -v python3 &>/dev/null; then
  # Verify JSON integrity before using
  if ! verify_json_integrity "$PATTERNS_FILE"; then
    log_error "Integrity verification failed for malicious-patterns.json -- using built-in patterns only"
  else
    _loaded="$(python3 -c "
import json
try:
    d = json.load(open('$PATTERNS_FILE'))
    for n in d.get('known_malicious_packages', []):
        print('PKG:' + n)
    for s in d.get('suspicious_domains', []):
        print('DOM:' + s)
    ci = d.get('clawhavoc_indicators', {})
    for c in ci.get('c2_patterns', []):
        print('DOM:' + c)
except Exception:
    pass
" 2>/dev/null || true)"

    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      case "$line" in
        PKG:*) KNOWN_MALICIOUS_NAMES+=("${line#PKG:}") ;;
        DOM:*) SUSPICIOUS_DOMAINS+=("${line#DOM:}") ;;
      esac
    done <<< "$_loaded"
    unset _loaded
  fi
fi

# Load extraDirs from openclaw config if available
EXTRA_DIRS=()
OPENCLAW_CONFIG="${OPENCLAW_DIR}/config.json"
if [[ -f "$OPENCLAW_CONFIG" ]] && command -v python3 &>/dev/null; then
  _dirs="$(python3 -c "
import json
try:
    d = json.load(open('$OPENCLAW_CONFIG'))
    for p in d.get('extraDirs', []):
        print(p)
except Exception:
    pass
" 2>/dev/null || true)"
  while IFS= read -r dir; do
    [[ -n "$dir" ]] && EXTRA_DIRS+=("$dir")
  done <<< "$_dirs"
  unset _dirs
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Escape a string for safe JSON embedding
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

# Add a finding to the FINDINGS array
add_finding() {
  local id="$1" severity="$2" title="$3" description="$4" evidence="$5" remediation="$6"
  local obj
  obj=$(printf '{"id":"%s","severity":"%s","title":"%s","description":"%s","evidence":"%s","remediation":"%s"}' \
    "$(json_escape "$id")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$title")" \
    "$(json_escape "$description")" \
    "$(json_escape "$evidence")" \
    "$(json_escape "$remediation")")

  if [[ "$FINDINGS" == "[]" ]]; then
    FINDINGS="[$obj]"
  else
    FINDINGS="${FINDINGS%]},$obj]"
  fi
}

# Truncate evidence string to a reasonable length
truncate_evidence() {
  local s="$1"
  local max="${2:-200}"
  if [[ ${#s} -gt $max ]]; then
    printf '%s...' "${s:0:$max}"
  else
    printf '%s' "$s"
  fi
}

# Compute a rough entropy score for a file (0-8 scale)
compute_entropy() {
  local file="$1"
  python3 -c "
import math, sys
try:
    data = open(sys.argv[1], 'rb').read()
    if len(data) == 0:
        print('0.0')
        sys.exit(0)
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = -sum((c/len(data)) * math.log2(c/len(data)) for c in freq.values())
    print(f'{entropy:.2f}')
except Exception:
    print('0.0')
" "$file" 2>/dev/null || echo "0.0"
}

# Grep wrapper that applies standard exclusion directories
# Usage: skill_grep [grep_flags...] pattern directory
skill_grep() {
  # shellcheck disable=SC2086
  grep -rn $GREP_EXCLUDES "$@" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Check functions
# ---------------------------------------------------------------------------

# CHK-SKL-001: curl/wget to external URLs
check_external_downloads() {
  local skill_dir="$1" skill_name="$2"
  local matches
  matches=$(skill_grep -E '(curl|wget)\s+.*(https?://|ftp://)' "$skill_dir" | head -5)
  if [[ -n "$matches" ]]; then
    local evidence
    evidence=$(truncate_evidence "$matches")
    add_finding "CHK-SKL-001" "warn" \
      "Skill '$skill_name' contains curl/wget to external URLs" \
      "Skill downloads content from external URLs which could be used for data exfiltration or payload delivery." \
      "$evidence" \
      "Review the URLs being accessed. Ensure they are legitimate and necessary for the skill functionality."
  fi

  # Check for suspicious domains
  for domain in "${SUSPICIOUS_DOMAINS[@]}"; do
    [[ -z "$domain" ]] && continue
    local domain_matches
    # shellcheck disable=SC2086
    domain_matches=$(grep -rn $GREP_EXCLUDES -F "$domain" "$skill_dir" 2>/dev/null | head -3 || true)
    if [[ -n "$domain_matches" ]]; then
      local evidence
      evidence=$(truncate_evidence "$domain_matches")
      add_finding "CHK-SKL-001" "critical" \
        "Skill '$skill_name' references suspicious domain: $domain" \
        "The skill references a domain associated with known malicious infrastructure or paste services used for C2." \
        "$evidence" \
        "Remove references to this domain and audit the skill for data exfiltration."
    fi
  done
}

# CHK-SKL-002: npm postinstall/preinstall hooks
check_npm_hooks() {
  local skill_dir="$1" skill_name="$2"
  local pkg_json="${skill_dir}/package.json"
  if [[ -f "$pkg_json" ]]; then
    local matches
    matches=$(grep -n -E '"(postinstall|preinstall|install|prepublish)"' "$pkg_json" 2>/dev/null || true)
    if [[ -n "$matches" ]]; then
      local evidence
      evidence=$(truncate_evidence "$matches")
      add_finding "CHK-SKL-002" "critical" \
        "Skill '$skill_name' has npm lifecycle hooks" \
        "npm postinstall/preinstall hooks can execute arbitrary code during installation -- a key ClawHavoc attack vector." \
        "$evidence" \
        "Remove lifecycle hooks or audit their commands thoroughly. Consider using --ignore-scripts when installing."
    fi
  fi
}

# CHK-SKL-003: base64 encoded payloads
check_base64_payloads() {
  local skill_dir="$1" skill_name="$2"
  local matches
  matches=$(skill_grep -E '[A-Za-z0-9+/]{40,}={0,2}' \
    --include='*.js' --include='*.ts' --include='*.sh' --include='*.py' \
    --include='*.mjs' --include='*.cjs' "$skill_dir" | head -5)
  if [[ -n "$matches" ]]; then
    local evidence
    evidence=$(truncate_evidence "$matches")
    add_finding "CHK-SKL-003" "critical" \
      "Skill '$skill_name' contains base64 encoded payloads" \
      "Large base64 strings may contain obfuscated malicious code or encoded binaries." \
      "$evidence" \
      "Decode and inspect all base64 content. Remove any that is not strictly necessary."
  fi
}

# CHK-SKL-004: eval/exec calls
check_eval_exec() {
  local skill_dir="$1" skill_name="$2"
  local matches
  matches=$(skill_grep -E '\b(eval|exec|execSync|child_process|Function\s*\()\b' \
    --include='*.js' --include='*.ts' --include='*.mjs' --include='*.cjs' \
    --include='*.py' --include='*.sh' "$skill_dir" | head -5)
  if [[ -n "$matches" ]]; then
    local evidence
    evidence=$(truncate_evidence "$matches")
    add_finding "CHK-SKL-004" "warn" \
      "Skill '$skill_name' contains eval/exec calls" \
      "Dynamic code execution (eval, exec, child_process) can be used to run arbitrary commands." \
      "$evidence" \
      "Replace eval/exec with safer alternatives. If unavoidable, ensure inputs are properly sanitized."
  fi
}

# CHK-SKL-005: Download and execute remote scripts
check_download_execute() {
  local skill_dir="$1" skill_name="$2"
  local matches
  matches=$(skill_grep -E '(curl|wget|fetch|axios|http\.get|https\.get).*\|\s*(bash|sh|node|python|exec|eval)' "$skill_dir" | head -3)
  local matches2
  matches2=$(skill_grep -E '\$\((curl|wget)\s' "$skill_dir" | head -3)
  local combined="${matches}${matches2}"
  if [[ -n "$combined" ]]; then
    local evidence
    evidence=$(truncate_evidence "$combined")
    add_finding "CHK-SKL-005" "critical" \
      "Skill '$skill_name' downloads and executes remote scripts" \
      "Piping remote content directly into a shell interpreter is extremely dangerous and a hallmark of supply-chain attacks." \
      "$evidence" \
      "Never pipe remote content to a shell. Download, verify integrity, then execute locally."
  fi
}

# CHK-SKL-006: Keychain / credential store access
check_keychain_access() {
  local skill_dir="$1" skill_name="$2"
  local matches
  matches=$(skill_grep -E '(security\s+find-(generic|internet)-password|keychain|SecKeychainFind|credential[-_]?store|libsecret|kwallet|gnome-keyring|Credential\s*Manager|\.npmrc|_authToken)' \
    "$skill_dir" | head -5)
  if [[ -n "$matches" ]]; then
    local evidence
    evidence=$(truncate_evidence "$matches")
    add_finding "CHK-SKL-006" "critical" \
      "Skill '$skill_name' accesses keychain/credential stores" \
      "Accessing system credential stores can be used to steal passwords, tokens, and secrets." \
      "$evidence" \
      "Remove credential store access unless absolutely required. Skills should never need to read system keychains."
  fi
}

# CHK-SKL-007: Obfuscated/minified code (high entropy)
check_obfuscation() {
  local skill_dir="$1" skill_name="$2"
  local found_high_entropy=0
  local evidence_files=""

  # Only scan top-level skill code, not node_modules
  while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    local size
    size=$(wc -c < "$file" 2>/dev/null || echo 0)
    if [[ "$size" -gt 1024 ]]; then
      local entropy
      entropy=$(compute_entropy "$file")
      local is_high
      is_high=$(python3 -c "print(1 if float('$entropy') > 6.0 else 0)" 2>/dev/null || echo 0)
      if [[ "$is_high" -eq 1 ]]; then
        found_high_entropy=1
        local relpath="${file#"$skill_dir"/}"
        evidence_files="${evidence_files}${relpath} (entropy: ${entropy}), "
      fi
    fi
  done <<< "$(find "$skill_dir" -not -path '*/node_modules/*' -not -path '*/.git/*' -not -path '*/vendor/*' -type f \( -name '*.js' -o -name '*.ts' -o -name '*.mjs' -o -name '*.cjs' \) 2>/dev/null)"

  if [[ "$found_high_entropy" -eq 1 ]]; then
    local evidence
    evidence=$(truncate_evidence "$evidence_files")
    add_finding "CHK-SKL-007" "warn" \
      "Skill '$skill_name' has obfuscated/minified code" \
      "High entropy code files suggest obfuscation, which is commonly used to hide malicious behavior." \
      "$evidence" \
      "Inspect obfuscated files using a deobfuscator. Replace with readable source code."
  fi
}

# CHK-SKL-008: Browser profile data access
check_browser_theft() {
  local skill_dir="$1" skill_name="$2"
  local matches
  matches=$(skill_grep -E '(Cookies|Login Data|Web Data|\.default-release|places\.sqlite|cookies\.sqlite|Chrome/Default|chromium|firefox|brave|BraveSoftware|Library/Application Support/(Google|Firefox|BraveSoftware)|\.config/(google-chrome|chromium|BraveSoftware))' \
    "$skill_dir" | head -5)
  if [[ -n "$matches" ]]; then
    local evidence
    evidence=$(truncate_evidence "$matches")
    add_finding "CHK-SKL-008" "critical" \
      "Skill '$skill_name' accesses browser profile data" \
      "Accessing browser cookies, passwords, or profile data is a credential theft technique." \
      "$evidence" \
      "Remove all browser profile access. Skills must never read browser credential stores."
  fi
}

# CHK-SKL-009: Network listeners
check_network_listeners() {
  local skill_dir="$1" skill_name="$2"
  local matches
  matches=$(skill_grep -E '(net\.createServer|http\.createServer|https\.createServer|\.listen\s*\(|dgram\.createSocket|WebSocketServer|socket\.bind)' \
    --include='*.js' --include='*.ts' --include='*.mjs' --include='*.cjs' "$skill_dir" | head -5)
  if [[ -n "$matches" ]]; then
    local evidence
    evidence=$(truncate_evidence "$matches")
    add_finding "CHK-SKL-009" "warn" \
      "Skill '$skill_name' has network listeners" \
      "Opening network ports can create backdoors or be used for command-and-control communication." \
      "$evidence" \
      "Verify that network listeners are required. Remove any unnecessary server bindings."
  fi
}

# CHK-SKL-010: LaunchAgent / crontab persistence
check_persistence() {
  local skill_dir="$1" skill_name="$2"
  local matches
  matches=$(skill_grep -E '(LaunchAgents|LaunchDaemons|launchctl|crontab|com\.apple\.launchd|systemd|\.service|/etc/cron|schtasks|at\s+\d|HKEY.*\\Run|autostart)' \
    "$skill_dir" | head -5)
  if [[ -n "$matches" ]]; then
    local evidence
    evidence=$(truncate_evidence "$matches")
    add_finding "CHK-SKL-010" "critical" \
      "Skill '$skill_name' writes to LaunchAgents/crontab (persistence)" \
      "Establishing persistence via LaunchAgents, crontab, or similar mechanisms is a key malware technique." \
      "$evidence" \
      "Remove all persistence mechanisms. Skills should not survive system restart or install launch agents."
  fi
}

# CHK-SKL-011: Known ClawHavoc package names
check_malicious_names() {
  local skill_dir="$1" skill_name="$2"
  local lower_name
  lower_name=$(printf '%s' "$skill_name" | tr '[:upper:]' '[:lower:]')

  for bad_name in "${KNOWN_MALICIOUS_NAMES[@]}"; do
    [[ -z "$bad_name" ]] && continue
    local lower_bad
    lower_bad=$(printf '%s' "$bad_name" | tr '[:upper:]' '[:lower:]')
    if [[ "$lower_name" == "$lower_bad" ]]; then
      add_finding "CHK-SKL-011" "critical" \
        "Skill '$skill_name' matches known ClawHavoc package name" \
        "This skill name matches a known malicious package associated with ClawHavoc supply-chain attacks." \
        "Matched: $bad_name" \
        "Remove this skill immediately and audit your system for compromise."
      return
    fi
  done

  # Also check package.json name field and dependencies
  local pkg_json="${skill_dir}/package.json"
  if [[ -f "$pkg_json" ]]; then
    for bad_name in "${KNOWN_MALICIOUS_NAMES[@]}"; do
      [[ -z "$bad_name" ]] && continue
      if grep -qi "\"${bad_name}\"" "$pkg_json" 2>/dev/null; then
        add_finding "CHK-SKL-011" "critical" \
          "Skill '$skill_name' references known ClawHavoc package '$bad_name'" \
          "A dependency or name in package.json matches a known malicious package." \
          "Found '$bad_name' in $pkg_json" \
          "Remove this dependency and audit the skill for compromised code."
        return
      fi
    done
  fi
}

# CHK-SKL-012: Suspiciously recent modification dates
check_recent_modifications() {
  local skill_dir="$1" skill_name="$2"
  local recent_files
  recent_files=$(find "$skill_dir" -not -path '*/node_modules/*' -not -path '*/.git/*' \
    -type f -mmin -1440 2>/dev/null | head -10 || true)
  if [[ -n "$recent_files" ]]; then
    local count
    count=$(printf '%s\n' "$recent_files" | wc -l | tr -d ' ')
    local evidence
    evidence=$(truncate_evidence "$recent_files")
    add_finding "CHK-SKL-012" "info" \
      "Skill '$skill_name' has $count recently modified files" \
      "Files modified in the last 24 hours may indicate tampering or a recent update that should be reviewed." \
      "$evidence" \
      "Verify that recent modifications are expected. Compare with the published version."
  fi
}

# ---------------------------------------------------------------------------
# Scan a single skill directory
# ---------------------------------------------------------------------------
scan_skill() {
  local skill_dir="$1"
  local skill_name
  skill_name=$(basename "$skill_dir")

  # Determine source type
  local source="unknown"
  if [[ -f "${skill_dir}/.bundled" ]]; then
    source="bundled"
  elif [[ -f "${skill_dir}/.managed" ]]; then
    source="managed"
  elif [[ -f "${skill_dir}/.clawhub" ]]; then
    source="clawhub"
  elif [[ -f "${skill_dir}/package.json" ]]; then
    source="managed"
  fi

  # Gather stats (exclude node_modules for speed)
  local file_count
  file_count=$(find "$skill_dir" -not -path '*/node_modules/*' -type f 2>/dev/null | wc -l | tr -d ' ')
  local exec_count
  exec_count=$(find "$skill_dir" -not -path '*/node_modules/*' -type f -perm +111 2>/dev/null | wc -l | tr -d ' ')

  # Add info finding with skill metadata
  add_finding "CHK-SKL-000" "ok" \
    "Scanned skill: $skill_name" \
    "source=$source files=$file_count executables=$exec_count" \
    "Directory: $skill_dir" \
    "No action needed."

  # Run all checks
  check_external_downloads "$skill_dir" "$skill_name"
  check_npm_hooks "$skill_dir" "$skill_name"
  check_base64_payloads "$skill_dir" "$skill_name"
  check_eval_exec "$skill_dir" "$skill_name"
  check_download_execute "$skill_dir" "$skill_name"
  check_keychain_access "$skill_dir" "$skill_name"
  check_obfuscation "$skill_dir" "$skill_name"
  check_browser_theft "$skill_dir" "$skill_name"
  check_network_listeners "$skill_dir" "$skill_name"
  check_persistence "$skill_dir" "$skill_name"
  check_malicious_names "$skill_dir" "$skill_name"
  check_recent_modifications "$skill_dir" "$skill_name"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  local scan_dirs=()

  # Collect directories to scan
  if [[ -d "$SKILLS_DIR" ]]; then
    scan_dirs+=("$SKILLS_DIR")
  fi
  if [[ -d "$EXTENSIONS_DIR" ]]; then
    scan_dirs+=("$EXTENSIONS_DIR")
  fi
  for d in "${EXTRA_DIRS[@]+"${EXTRA_DIRS[@]}"}"; do
    [[ -n "$d" ]] && [[ -d "$d" ]] && scan_dirs+=("$d")
  done

  if [[ ${#scan_dirs[@]} -eq 0 ]]; then
    add_finding "CHK-SKL-000" "info" \
      "No skill directories found" \
      "Neither ~/.openclaw/skills/ nor ~/.openclaw/extensions/ exist. No skills to scan." \
      "Checked: $SKILLS_DIR, $EXTENSIONS_DIR" \
      "Install OpenClaw skills to enable scanning."
    printf '%s\n' "$FINDINGS"
    return 0
  fi

  # Iterate over each scan directory and each skill within it
  for scan_dir in "${scan_dirs[@]}"; do
    if [[ -d "$scan_dir" ]]; then
      for skill_dir in "$scan_dir"/*/; do
        [[ -d "$skill_dir" ]] || continue
        scan_skill "$skill_dir"
      done
    fi
  done

  # If no skills were found in any directory
  if [[ "$FINDINGS" == "[]" ]]; then
    add_finding "CHK-SKL-000" "info" \
      "No skills found in scan directories" \
      "Scan directories exist but contain no skill subdirectories." \
      "Scanned: ${scan_dirs[*]}" \
      "No action needed."
  fi

  # Output final JSON
  printf '%s\n' "$FINDINGS"
}

main "$@"
