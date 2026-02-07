#!/usr/bin/env bash
set -euo pipefail

# ─── ClawPinch: File Permissions Scanner ─────────────────────────────────────
# Audits file and directory permissions for OpenClaw configuration,
# wallet files, secrets, LaunchAgent plists, skills directories, and more.
#
# Outputs a JSON array of findings to stdout.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers/common.sh"

# ─── OS-aware stat helper ────────────────────────────────────────────────────

get_perms() {
  local file="$1"
  if [[ "$CLAWPINCH_OS" == "macos" ]]; then
    stat -f '%Lp' "$file" 2>/dev/null || echo ""
  else
    stat -c '%a' "$file" 2>/dev/null || echo ""
  fi
}

get_owner_uid() {
  local file="$1"
  if [[ "$CLAWPINCH_OS" == "macos" ]]; then
    stat -f '%u' "$file" 2>/dev/null || echo ""
  else
    stat -c '%u' "$file" 2>/dev/null || echo ""
  fi
}

# ─── Resolve the .openclaw / config directory ────────────────────────────────

OPENCLAW_DIR=""
OPENCLAW_CONFIG=""

resolve_openclaw_dir() {
  # Try to find the config file to determine the config directory
  if OPENCLAW_CONFIG="$(get_openclaw_config 2>/dev/null)"; then
    OPENCLAW_DIR="$(dirname "$OPENCLAW_CONFIG")"
  else
    # Fall back to common directories
    for d in "$HOME/.openclaw" "$HOME/.config/openclaw" "$HOME/Library/Application Support/openclaw"; do
      if [[ -d "$d" ]]; then
        OPENCLAW_DIR="$d"
        break
      fi
    done
  fi
}

resolve_openclaw_dir

# ─── Deduplicated search directories ────────────────────────────────────────
# Build a unique list of existing OpenClaw directories to avoid duplicate findings.

build_search_dirs() {
  local -a raw_dirs=("$HOME/.openclaw" "$HOME/.config/openclaw")
  [[ -n "$OPENCLAW_DIR" ]] && raw_dirs+=("$OPENCLAW_DIR")

  local -a seen=()
  SEARCH_DIRS=()

  for d in "${raw_dirs[@]}"; do
    [[ -d "$d" ]] || continue
    local real
    real="$(cd "$d" && pwd -P)"
    local dup=0
    for s in "${seen[@]:-}"; do
      [[ "$s" == "$real" ]] && { dup=1; break; }
    done
    if [[ "$dup" -eq 0 ]]; then
      seen+=("$real")
      SEARCH_DIRS+=("$d")
    fi
  done
}

SEARCH_DIRS=()
build_search_dirs

# ─── Findings accumulator ───────────────────────────────────────────────────

FINDINGS=()

add_finding() {
  FINDINGS+=("$(emit_finding "$@")")
}

# ─── CHK-PRM-001: openclaw.json permissions ─────────────────────────────────

check_openclaw_json() {
  log_info "CHK-PRM-001: Checking openclaw.json permissions"

  local targets=()
  [[ -n "$OPENCLAW_CONFIG" && -f "$OPENCLAW_CONFIG" ]] && targets+=("$OPENCLAW_CONFIG")

  # Also scan well-known locations that might be separate from the detected one
  for f in \
    "$HOME/.openclaw/openclaw.json" \
    "$HOME/.config/openclaw/openclaw.json" \
    "$HOME/Library/Application Support/openclaw/openclaw.json"; do
    if [[ -f "$f" ]] && [[ ! " ${targets[*]:-} " =~ " $f " ]]; then
      targets+=("$f")
    fi
  done

  if [[ ${#targets[@]} -eq 0 ]]; then
    add_finding "CHK-PRM-001" "info" \
      "openclaw.json not found" \
      "No openclaw.json located in standard paths" "" \
      "Create one at ~/.openclaw/openclaw.json if needed" ""
    return
  fi

  for f in "${targets[@]}"; do
    local perms
    perms="$(get_perms "$f")"
    if [[ -z "$perms" ]]; then
      continue
    fi
    if [[ "$perms" != "600" ]]; then
      add_finding "CHK-PRM-001" "critical" \
        "openclaw.json has insecure permissions" \
        "openclaw.json should be chmod 600 (owner read/write only). Current: $perms" \
        "$f mode $perms" \
        "Run: chmod 600 '$f'" \
        "chmod 600 '$f'"
    else
      add_finding "CHK-PRM-001" "ok" \
        "openclaw.json permissions correct" \
        "File is properly restricted to owner read/write" \
        "$f mode $perms" "" ""
    fi
  done
}

# ─── CHK-PRM-002: exec-approvals.json permissions ───────────────────────────

check_exec_approvals() {
  log_info "CHK-PRM-002: Checking exec-approvals.json permissions"

  local targets=()
  for d in "${SEARCH_DIRS[@]}"; do
    local f="$d/exec-approvals.json"
    [[ -f "$f" ]] && targets+=("$f")
  done

  if [[ ${#targets[@]} -eq 0 ]]; then
    add_finding "CHK-PRM-002" "info" \
      "exec-approvals.json not found" \
      "No exec-approvals.json located in standard paths" "" \
      "This file stores tool execution approvals; ensure it exists if using OpenClaw" ""
    return
  fi

  for f in "${targets[@]}"; do
    local perms
    perms="$(get_perms "$f")"
    [[ -z "$perms" ]] && continue
    if [[ "$perms" != "600" ]]; then
      add_finding "CHK-PRM-002" "critical" \
        "exec-approvals.json has insecure permissions" \
        "exec-approvals.json should be chmod 600. Current: $perms" \
        "$f mode $perms" \
        "Run: chmod 600 '$f'" \
        "chmod 600 '$f'"
    else
      add_finding "CHK-PRM-002" "ok" \
        "exec-approvals.json permissions correct" \
        "File is properly restricted to owner read/write" \
        "$f mode $perms" "" ""
    fi
  done
}

# ─── CHK-PRM-003: Wallet/key file permissions ───────────────────────────────

check_wallet_files() {
  log_info "CHK-PRM-003: Checking wallet/key file permissions"

  local found=0
  # Patterns: *.key, *.pem, *.p12, *.pfx, *wallet*, *keystore*, *.jwk
  for d in "${SEARCH_DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    while IFS= read -r -d '' f; do
      found=1
      local perms
      perms="$(get_perms "$f")"
      [[ -z "$perms" ]] && continue
      if [[ "$perms" != "600" ]]; then
        add_finding "CHK-PRM-003" "critical" \
          "Wallet/key file has insecure permissions" \
          "Wallet and key files must be chmod 600. Current: $perms" \
          "$f mode $perms" \
          "Run: chmod 600 '$f'" \
          "chmod 600 '$f'"
      else
        add_finding "CHK-PRM-003" "ok" \
          "Wallet/key file permissions correct" \
          "File is properly restricted to owner read/write" \
          "$f mode $perms" "" ""
      fi
    done < <(find "$d" -maxdepth 3 \( \
      -name '*.key' -o -name '*.pem' -o -name '*.p12' -o -name '*.pfx' \
      -o -name '*wallet*' -o -name '*keystore*' -o -name '*.jwk' \
      -o -name '*.seed' -o -name '*.mnemonic' \
    \) -type f -print0 2>/dev/null)
  done

  if [[ "$found" -eq 0 ]]; then
    add_finding "CHK-PRM-003" "info" \
      "No wallet/key files found" \
      "No wallet or key files detected in OpenClaw directories" "" "" ""
  fi
}

# ─── CHK-PRM-004: .env / .secrets file permissions ──────────────────────────

check_env_files() {
  log_info "CHK-PRM-004: Checking .env/.secrets file permissions"

  local found=0


  for d in "${SEARCH_DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    while IFS= read -r -d '' f; do
      found=1
      local perms
      perms="$(get_perms "$f")"
      [[ -z "$perms" ]] && continue
      if [[ "$perms" != "600" ]]; then
        add_finding "CHK-PRM-004" "warn" \
          ".env/.secrets file has insecure permissions" \
          "Environment and secrets files should be chmod 600. Current: $perms" \
          "$f mode $perms" \
          "Run: chmod 600 '$f'" \
          "chmod 600 '$f'"
      else
        add_finding "CHK-PRM-004" "ok" \
          ".env/.secrets file permissions correct" \
          "File is properly restricted to owner read/write" \
          "$f mode $perms" "" ""
      fi
    done < <(find "$d" -maxdepth 3 \( \
      -name '.env' -o -name '.env.*' -o -name '*.env' \
      -o -name '.secrets' -o -name '*.secrets' \
      -o -name '.credentials' -o -name '*.credentials' \
    \) -type f -print0 2>/dev/null)
  done

  if [[ "$found" -eq 0 ]]; then
    add_finding "CHK-PRM-004" "info" \
      "No .env/.secrets files found" \
      "No environment or secrets files detected in OpenClaw directories" "" "" ""
  fi
}

# ─── CHK-PRM-005: LaunchAgent plists world-readable ─────────────────────────

check_launchagent_plists() {
  log_info "CHK-PRM-005: Checking LaunchAgent plist permissions"

  if [[ "$CLAWPINCH_OS" != "macos" ]]; then
    add_finding "CHK-PRM-005" "info" \
      "LaunchAgent check skipped (not macOS)" \
      "This check only applies to macOS systems" "" "" ""
    return
  fi

  local found=0
  local plist_dir="$HOME/Library/LaunchAgents"
  [[ -d "$plist_dir" ]] || {
    add_finding "CHK-PRM-005" "info" \
      "No LaunchAgents directory found" \
      "~/Library/LaunchAgents does not exist" "" "" ""
    return
  }

  while IFS= read -r -d '' f; do
    # Only check openclaw-related plists
    local basename
    basename="$(basename "$f")"
    if [[ "$basename" == *openclaw* || "$basename" == *claw* || "$basename" == *pinch* ]]; then
      found=1
      local perms
      perms="$(get_perms "$f")"
      [[ -z "$perms" ]] && continue
      # World-readable: last digit includes read (4,5,6,7)
      local world_bits="${perms: -1}"
      if [[ "$world_bits" =~ [4567] ]]; then
        add_finding "CHK-PRM-005" "warn" \
          "LaunchAgent plist is world-readable" \
          "LaunchAgent plists should not be world-readable. Current: $perms" \
          "$f mode $perms" \
          "Run: chmod 644 '$f' (or 600 if only user needs access)" \
          "chmod 600 '$f'"
      else
        add_finding "CHK-PRM-005" "ok" \
          "LaunchAgent plist permissions acceptable" \
          "Plist is not world-readable" \
          "$f mode $perms" "" ""
      fi
    fi
  done < <(find "$plist_dir" -maxdepth 1 -name '*.plist' -type f -print0 2>/dev/null)

  if [[ "$found" -eq 0 ]]; then
    add_finding "CHK-PRM-005" "info" \
      "No OpenClaw-related LaunchAgent plists found" \
      "No plists matching openclaw/claw/pinch patterns in ~/Library/LaunchAgents" "" "" ""
  fi
}

# ─── CHK-PRM-006: Skills directory world-writable files ─────────────────────

check_skills_directory() {
  log_info "CHK-PRM-006: Checking skills directory for world-writable files"

  local found_dir=0
  local found_issue=0
  local skills_dirs=()

  for d in "${SEARCH_DIRS[@]}"; do
    [[ -d "$d/skills" ]] && skills_dirs+=("$d/skills")
  done

  if [[ ${#skills_dirs[@]} -eq 0 ]]; then
    add_finding "CHK-PRM-006" "info" \
      "No skills directory found" \
      "No skills directory detected in OpenClaw paths" "" "" ""
    return
  fi

  for d in "${skills_dirs[@]}"; do
    found_dir=1
    while IFS= read -r -d '' f; do
      found_issue=1
      local perms
      perms="$(get_perms "$f")"
      add_finding "CHK-PRM-006" "critical" \
        "World-writable file in skills directory" \
        "Files in the skills directory must not be world-writable. An attacker could inject malicious skill code." \
        "$f mode $perms" \
        "Run: chmod o-w '$f'" \
        "chmod o-w '$f'"
    done < <(find "$d" -type f -perm -o+w -print0 2>/dev/null)
  done

  if [[ "$found_dir" -eq 1 && "$found_issue" -eq 0 ]]; then
    add_finding "CHK-PRM-006" "ok" \
      "Skills directory has no world-writable files" \
      "All files in the skills directory have acceptable permissions" "" "" ""
  fi
}

# ─── CHK-PRM-007: SUID/SGID binaries in OpenClaw directories ────────────────

check_suid_sgid() {
  log_info "CHK-PRM-007: Checking for SUID/SGID binaries in OpenClaw directories"

  local found=0


  for d in "${SEARCH_DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    while IFS= read -r -d '' f; do
      found=1
      local perms
      perms="$(get_perms "$f")"
      add_finding "CHK-PRM-007" "critical" \
        "SUID/SGID binary found in OpenClaw directory" \
        "SUID/SGID binaries in OpenClaw directories are a serious security risk. They could be used for privilege escalation." \
        "$f mode $perms" \
        "Run: chmod ug-s '$f'" \
        "chmod ug-s '$f'"
    done < <(find "$d" \( -perm -4000 -o -perm -2000 \) -type f -print0 2>/dev/null)
  done

  if [[ "$found" -eq 0 ]]; then
    add_finding "CHK-PRM-007" "ok" \
      "No SUID/SGID binaries found" \
      "No SUID or SGID binaries detected in OpenClaw directories" "" "" ""
  fi
}

# ─── CHK-PRM-008: Symlinks pointing outside OpenClaw directory ───────────────

check_symlinks() {
  log_info "CHK-PRM-008: Checking for symlinks pointing outside OpenClaw directory"

  local found=0


  for d in "${SEARCH_DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    local resolved_d
    resolved_d="$(cd "$d" && pwd -P)"

    while IFS= read -r -d '' link; do
      local target
      target="$(readlink -f "$link" 2>/dev/null || readlink "$link" 2>/dev/null || echo "")"
      [[ -z "$target" ]] && continue

      # Check if the target is outside the openclaw directory
      if [[ "$target" != "$resolved_d"* ]]; then
        found=1
        add_finding "CHK-PRM-008" "warn" \
          "Symlink points outside OpenClaw directory" \
          "Symlinks pointing outside the OpenClaw directory could be used for path traversal attacks or to access unintended files." \
          "$link -> $target" \
          "Verify the symlink target is intentional; remove if not needed: rm '$link'" ""
      fi
    done < <(find "$d" -type l -print0 2>/dev/null)
  done

  if [[ "$found" -eq 0 ]]; then
    add_finding "CHK-PRM-008" "ok" \
      "No suspicious symlinks found" \
      "All symlinks within OpenClaw directories point to internal paths" "" "" ""
  fi
}

# ─── CHK-PRM-009: .openclaw directory ownership ─────────────────────────────

check_openclaw_ownership() {
  log_info "CHK-PRM-009: Checking .openclaw directory ownership"

  local found=0
  local current_uid
  current_uid="$(id -u)"

  for d in "${SEARCH_DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    found=1
    local owner_uid
    owner_uid="$(get_owner_uid "$d")"
    [[ -z "$owner_uid" ]] && continue

    if [[ "$owner_uid" != "$current_uid" ]]; then
      add_finding "CHK-PRM-009" "critical" \
        ".openclaw directory not owned by current user" \
        "The OpenClaw configuration directory is owned by UID $owner_uid but the current user is UID $current_uid. This could indicate tampering." \
        "$d owned by UID $owner_uid (current user UID $current_uid)" \
        "Run: chown -R $(id -un) '$d'" \
        "chown -R $(id -un) '$d'"
    else
      add_finding "CHK-PRM-009" "ok" \
        ".openclaw directory ownership correct" \
        "Directory is owned by the current user" \
        "$d owned by UID $owner_uid" "" ""
    fi
  done

  if [[ "$found" -eq 0 ]]; then
    add_finding "CHK-PRM-009" "info" \
      "No .openclaw directory found to check ownership" \
      "No OpenClaw configuration directory detected" "" "" ""
  fi
}

# ─── CHK-PRM-010: Credentials directory permissions ─────────────────────────

check_credentials_dir() {
  log_info "CHK-PRM-010: Checking credentials directory permissions"

  local found=0
  local cred_dirs=()

  for d in "${SEARCH_DIRS[@]}"; do
    [[ -d "$d/credentials" ]] && cred_dirs+=("$d/credentials")
  done

  if [[ ${#cred_dirs[@]} -eq 0 ]]; then
    add_finding "CHK-PRM-010" "info" \
      "No credentials directory found" \
      "No credentials directory detected in OpenClaw paths" "" "" ""
    return
  fi

  for d in "${cred_dirs[@]}"; do
    found=1
    local perms
    perms="$(get_perms "$d")"
    [[ -z "$perms" ]] && continue

    # Directory should be 700 (owner only)
    if [[ "$perms" != "700" ]]; then
      add_finding "CHK-PRM-010" "warn" \
        "Credentials directory permissions too open" \
        "The credentials directory should be chmod 700 (owner only). Current: $perms" \
        "$d mode $perms" \
        "Run: chmod 700 '$d'" \
        "chmod 700 '$d'"
    else
      add_finding "CHK-PRM-010" "ok" \
        "Credentials directory permissions correct" \
        "Directory is properly restricted to owner" \
        "$d mode $perms" "" ""
    fi
  done
}

# ─── CHK-PRM-011: Log files contain secrets ─────────────────────────────────

check_log_secrets() {
  log_info "CHK-PRM-011: Checking log files for leaked secrets"

  local found=0


  # Patterns that suggest leaked secrets
  local -a secret_patterns=(
    'PRIVATE KEY'
    'api[_-]?key[[:space:]]*[:=]'
    'secret[_-]?key[[:space:]]*[:=]'
    'password[[:space:]]*[:=]'
    'token[[:space:]]*[:=].*[A-Za-z0-9_\-]{20,}'
    'Bearer [A-Za-z0-9_\-\.]{20,}'
    'sk-[A-Za-z0-9]{20,}'
    'ghp_[A-Za-z0-9]{36}'
    'xox[bporas]-[A-Za-z0-9\-]+'
  )

  for d in "${SEARCH_DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    while IFS= read -r -d '' logfile; do
      for pattern in "${secret_patterns[@]}"; do
        if grep -qiE "$pattern" "$logfile" 2>/dev/null; then
          found=1
          local match
          match="$(grep -m1 -iE "$pattern" "$logfile" 2>/dev/null | head -c 120)"
          # Redact the actual secret value (show only first/last few chars)
          local redacted
          redacted="$(printf '%s' "$match" | sed -E 's/([A-Za-z0-9_\-]{4})[A-Za-z0-9_\-]{10,}([A-Za-z0-9_\-]{4})/\1...\2/g')"
          add_finding "CHK-PRM-011" "warn" \
            "Log file may contain secrets" \
            "A log file appears to contain sensitive values matching pattern: $pattern" \
            "$logfile: $redacted" \
            "Review and purge secrets from log files; consider rotating affected credentials" ""
          break  # One finding per log file is enough
        fi
      done
    done < <(find "$d" -maxdepth 3 \( -name '*.log' -o -name '*.log.*' -o -name 'log' \) -type f -print0 2>/dev/null)
  done

  if [[ "$found" -eq 0 ]]; then
    add_finding "CHK-PRM-011" "ok" \
      "No secrets detected in log files" \
      "Log files in OpenClaw directories do not appear to contain leaked secrets" "" "" ""
  fi
}

# ─── CHK-PRM-012: Cloud sync detection ──────────────────────────────────────

check_cloud_sync() {
  log_info "CHK-PRM-012: Checking for cloud sync of OpenClaw directories"

  local found=0


  # Cloud sync indicator paths
  local -a cloud_indicators=()

  # Dropbox
  if [[ -d "$HOME/Dropbox" ]]; then
    cloud_indicators+=("$HOME/Dropbox")
  fi

  # iCloud Drive (macOS)
  if [[ -d "$HOME/Library/Mobile Documents/com~apple~CloudDocs" ]]; then
    cloud_indicators+=("$HOME/Library/Mobile Documents/com~apple~CloudDocs")
  fi

  # OneDrive
  for od in "$HOME/OneDrive" "$HOME/OneDrive - "*/; do
    [[ -d "$od" ]] && cloud_indicators+=("$od")
  done

  # Google Drive
  for gd in "$HOME/Google Drive" "$HOME/My Drive" "$HOME/Google Drive/My Drive"; do
    [[ -d "$gd" ]] && cloud_indicators+=("$gd")
  done

  for d in "${SEARCH_DIRS[@]}"; do
    [[ -e "$d" ]] || continue

    # Resolve the real path
    local real_path
    real_path="$(cd "$d" 2>/dev/null && pwd -P)" || continue

    for cloud_dir in "${cloud_indicators[@]}"; do
      local real_cloud
      real_cloud="$(cd "$cloud_dir" 2>/dev/null && pwd -P)" || continue

      if [[ "$real_path" == "$real_cloud"* ]]; then
        found=1
        local cloud_name="unknown cloud service"
        case "$cloud_dir" in
          *Dropbox*)       cloud_name="Dropbox" ;;
          *CloudDocs*|*iCloud*) cloud_name="iCloud Drive" ;;
          *OneDrive*)      cloud_name="OneDrive" ;;
          *Google*|*"My Drive"*) cloud_name="Google Drive" ;;
        esac

        add_finding "CHK-PRM-012" "critical" \
          "OpenClaw directory synced via $cloud_name" \
          "The OpenClaw configuration directory appears to be inside a $cloud_name sync folder. This means credentials and sensitive configuration are being uploaded to the cloud, greatly increasing exposure risk." \
          "$d resolves to $real_path (inside $cloud_dir)" \
          "Move the OpenClaw directory outside of cloud-synced folders, or exclude it from sync" ""
      fi
    done

    # Also check for Dropbox xattr (macOS-specific .dropbox markers)
    if [[ "$CLAWPINCH_OS" == "macos" ]]; then
      if xattr -l "$d" 2>/dev/null | grep -qi 'dropbox' 2>/dev/null; then
        if [[ "$found" -eq 0 ]]; then
          found=1
          add_finding "CHK-PRM-012" "critical" \
            "OpenClaw directory has Dropbox extended attributes" \
            "The directory has Dropbox-related extended attributes, suggesting it is being synced." \
            "$d has Dropbox xattrs" \
            "Remove from Dropbox sync or move the directory" ""
        fi
      fi
    fi

    # Check for .dropbox, .icloud markers inside the directory
    for marker in ".dropbox" ".icloud" ".onedrive"; do
      if find "$d" -maxdepth 2 -name "$marker" -print -quit 2>/dev/null | grep -q .; then
        found=1
        add_finding "CHK-PRM-012" "critical" \
          "Cloud sync marker found inside OpenClaw directory" \
          "A $marker file was found inside the OpenClaw directory, indicating cloud sync is active." \
          "Found $marker inside $d" \
          "Move the OpenClaw directory outside of cloud-synced folders" ""
      fi
    done
  done

  if [[ "$found" -eq 0 ]]; then
    add_finding "CHK-PRM-012" "ok" \
      "No cloud sync detected for OpenClaw directories" \
      "OpenClaw directories do not appear to be inside cloud-synced folders" "" "" ""
  fi
}

# ─── CHK-PRM-013: SSH private key permissions ───────────────────────────────

check_ssh_keys() {
  log_info "CHK-PRM-013: Checking SSH private key permissions"

  local ssh_dir="$HOME/.ssh"
  local found=0

  if [[ ! -d "$ssh_dir" ]]; then
    add_finding "CHK-PRM-013" "info" \
      "No SSH directory found" \
      "No ~/.ssh directory exists on this system" "" "" ""
    return
  fi

  # Search for id_* files and *.pem files
  while IFS= read -r -d '' f; do
    found=1
    local perms
    perms="$(get_perms "$f")"
    [[ -z "$perms" ]] && continue

    if [[ "$perms" != "600" ]]; then
      add_finding "CHK-PRM-013" "critical" \
        "SSH private key has insecure permissions" \
        "SSH private keys must be chmod 600 or SSH clients will refuse to use them. Current: $perms" \
        "$f mode $perms" \
        "Run: chmod 600 '$f'" \
        "chmod 600 '$f'"
    else
      add_finding "CHK-PRM-013" "ok" \
        "SSH private key permissions correct" \
        "SSH private key is properly restricted to owner read/write" \
        "$f mode $perms" "" ""
    fi
  done < <(find "$ssh_dir" -maxdepth 1 \( \
    -name 'id_*' -o -name '*.pem' \
  \) -type f ! -name '*.pub' -print0 2>/dev/null)

  if [[ "$found" -eq 0 ]]; then
    add_finding "CHK-PRM-013" "info" \
      "No SSH private keys found" \
      "No SSH private key files detected in ~/.ssh directory" "" "" ""
  fi
}

# ─── Run all checks ─────────────────────────────────────────────────────────

main() {
  log_info "Starting file permissions scan (OS: $CLAWPINCH_OS)"

  check_openclaw_json
  check_exec_approvals
  check_wallet_files
  check_env_files
  check_launchagent_plists
  check_skills_directory
  check_suid_sgid
  check_symlinks
  check_openclaw_ownership
  check_credentials_dir
  check_log_secrets
  check_cloud_sync
  check_ssh_keys

  log_info "Permissions scan complete: ${#FINDINGS[@]} finding(s)"

  # Output findings as JSON array to stdout
  if has_cmd jq; then
    printf '%s\n' "${FINDINGS[@]}" | jq -s '.'
  else
    # Manual JSON array assembly
    printf '['
    local first=1
    for f in "${FINDINGS[@]}"; do
      if [[ "$first" -eq 1 ]]; then
        first=0
      else
        printf ','
      fi
      printf '%s' "$f"
    done
    printf ']\n'
  fi
}

main "$@"
