#!/usr/bin/env bash
set -euo pipefail

# ─── Supply Chain Scanner ─────────────────────────────────────────────────────
# Audits npm dependencies, ClawHub skills, and extension plugins for
# supply chain compromise indicators (ClawHavoc campaign and general threats).
#
# Usage: ./scan_supply_chain.sh
# Output: JSON array of findings to stdout
# ──────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers/common.sh"

PATTERNS_FILE="$SCRIPT_DIR/../references/malicious-patterns.json"
FINDINGS_FILE="$(mktemp)"
trap 'rm -f "$FINDINGS_FILE"' EXIT

# ─── Paths to scan ──────────────────────────────────────────────────────────

SKILLS_DIR="${OPENCLAW_SKILLS_DIR:-$HOME/.openclaw/skills}"
EXTENSIONS_DIR="${OPENCLAW_EXTENSIONS_DIR:-$HOME/.openclaw/extensions}"

# ─── Load malicious patterns database ───────────────────────────────────────

load_malicious_packages() {
  # Verify JSON integrity before using
  if [[ -f "$PATTERNS_FILE" ]] && ! verify_json_integrity "$PATTERNS_FILE"; then  # malicious-patterns.json
    log_error "Integrity verification failed for malicious-patterns.json -- using built-in patterns only"
    # Use hardcoded fallback
    printf '%s\n' clawhub-cli clawdhub openclaw-helper openclaw-utils \
      phantom-wallet-skill solana-pay-pro
  elif [[ -f "$PATTERNS_FILE" ]] && has_cmd jq; then
    jq -r '.known_malicious_packages[]' "$PATTERNS_FILE" 2>/dev/null
  else
    # Hardcoded fallback
    printf '%s\n' clawhub-cli clawdhub openclaw-helper openclaw-utils \
      phantom-wallet-skill solana-pay-pro
  fi
}

MALICIOUS_PACKAGES=()
while IFS= read -r pkg; do
  MALICIOUS_PACKAGES+=("$pkg")
done < <(load_malicious_packages)

# ─── CHK-SUP-001: npm postinstall hooks ─────────────────────────────────────

check_postinstall_hooks() {
  log_info "CHK-SUP-001: Scanning for npm postinstall hooks..."
  local found=0

  for nm_dir in "$SKILLS_DIR"/*/node_modules "$EXTENSIONS_DIR"/*/node_modules; do
    [[ -d "$nm_dir" ]] || continue

    while IFS= read -r pkg_json; do
      local pkg_name
      pkg_name="$(jq -r '.name // "unknown"' "$pkg_json" 2>/dev/null)" || continue
      local hook
      hook="$(jq -r '.scripts.postinstall // empty' "$pkg_json" 2>/dev/null)" || continue

      if [[ -n "$hook" ]]; then
        found=1
        emit_finding \
          "CHK-SUP-001" \
          "critical" \
          "npm postinstall hook detected" \
          "Package '$pkg_name' has a postinstall script that runs automatically on install. This is a common vector for supply chain attacks." \
          "postinstall: $hook (in $pkg_json)" \
          "Review the postinstall script. Remove the package if it is not trusted."
      fi
    done < <(find "$nm_dir" -maxdepth 2 -name "package.json" -not -path "*/node_modules/*/node_modules/*" 2>/dev/null)
  done

  if [[ "$found" -eq 0 ]]; then
    emit_finding \
      "CHK-SUP-001" \
      "ok" \
      "No npm postinstall hooks found" \
      "No packages with postinstall scripts detected in skill or extension node_modules." \
      "" \
      ""
  fi
}

# ─── CHK-SUP-002: npm preinstall hooks ──────────────────────────────────────

check_preinstall_hooks() {
  log_info "CHK-SUP-002: Scanning for npm preinstall hooks..."
  local found=0

  for nm_dir in "$SKILLS_DIR"/*/node_modules "$EXTENSIONS_DIR"/*/node_modules; do
    [[ -d "$nm_dir" ]] || continue

    while IFS= read -r pkg_json; do
      local pkg_name
      pkg_name="$(jq -r '.name // "unknown"' "$pkg_json" 2>/dev/null)" || continue
      local hook
      hook="$(jq -r '.scripts.preinstall // empty' "$pkg_json" 2>/dev/null)" || continue

      if [[ -n "$hook" ]]; then
        found=1
        emit_finding \
          "CHK-SUP-002" \
          "critical" \
          "npm preinstall hook detected" \
          "Package '$pkg_name' has a preinstall script. Preinstall hooks execute before the package is fully installed and are a high-risk supply chain vector." \
          "preinstall: $hook (in $pkg_json)" \
          "Review the preinstall script carefully. Remove the package if untrusted."
      fi
    done < <(find "$nm_dir" -maxdepth 2 -name "package.json" -not -path "*/node_modules/*/node_modules/*" 2>/dev/null)
  done

  if [[ "$found" -eq 0 ]]; then
    emit_finding \
      "CHK-SUP-002" \
      "ok" \
      "No npm preinstall hooks found" \
      "No packages with preinstall scripts detected in skill or extension node_modules." \
      "" \
      ""
  fi
}

# ─── CHK-SUP-003: Known ClawHavoc typosquats ────────────────────────────────

check_typosquat_packages() {
  log_info "CHK-SUP-003: Checking for known malicious/typosquat packages..."
  local found=0

  for nm_dir in "$SKILLS_DIR"/*/node_modules "$EXTENSIONS_DIR"/*/node_modules; do
    [[ -d "$nm_dir" ]] || continue

    for mal_pkg in "${MALICIOUS_PACKAGES[@]}"; do
      if [[ -d "$nm_dir/$mal_pkg" ]]; then
        found=1
        local version="unknown"
        if [[ -f "$nm_dir/$mal_pkg/package.json" ]] && has_cmd jq; then
          version="$(jq -r '.version // "unknown"' "$nm_dir/$mal_pkg/package.json" 2>/dev/null)"
        fi
        emit_finding \
          "CHK-SUP-003" \
          "critical" \
          "Known malicious package installed: $mal_pkg" \
          "Package '$mal_pkg' (v$version) is a known ClawHavoc typosquat/malicious package. It should be removed immediately." \
          "Found at $nm_dir/$mal_pkg" \
          "Remove immediately: rm -rf '$nm_dir/$mal_pkg' and audit what it may have accessed."
      fi
    done
  done

  if [[ "$found" -eq 0 ]]; then
    emit_finding \
      "CHK-SUP-003" \
      "ok" \
      "No known malicious packages found" \
      "None of the known ClawHavoc typosquat packages were detected." \
      "" \
      ""
  fi
}

# ─── CHK-SUP-004: Suspiciously recent publish dates ─────────────────────────

check_recent_packages() {
  log_info "CHK-SUP-004: Checking for suspiciously recent packages..."
  local found=0
  local cutoff_days=2
  local now
  now="$(date +%s)"

  for nm_dir in "$SKILLS_DIR"/*/node_modules "$EXTENSIONS_DIR"/*/node_modules; do
    [[ -d "$nm_dir" ]] || continue

    while IFS= read -r pkg_json; do
      # Check the file modification time as a proxy for install/publish recency
      local mtime
      if [[ "$CLAWPINCH_OS" == "macos" ]]; then
        mtime="$(stat -f '%m' "$pkg_json" 2>/dev/null)" || continue
      else
        mtime="$(stat -c '%Y' "$pkg_json" 2>/dev/null)" || continue
      fi

      local age_days=$(( (now - mtime) / 86400 ))
      if [[ "$age_days" -lt "$cutoff_days" ]]; then
        local pkg_name
        pkg_name="$(jq -r '.name // "unknown"' "$pkg_json" 2>/dev/null)" || continue
        local version
        version="$(jq -r '.version // "unknown"' "$pkg_json" 2>/dev/null)" || continue
        found=1
        emit_finding \
          "CHK-SUP-004" \
          "warn" \
          "Recently installed package: $pkg_name@$version" \
          "Package was installed within the last $age_days day(s). New or recently updated packages deserve extra scrutiny." \
          "$pkg_json (modified $age_days days ago)" \
          "Verify the package is legitimate and expected."
      fi
    done < <(find "$nm_dir" -maxdepth 2 -name "package.json" -not -path "*/node_modules/*/node_modules/*" 2>/dev/null)
  done

  if [[ "$found" -eq 0 ]]; then
    emit_finding \
      "CHK-SUP-004" \
      "ok" \
      "No suspiciously recent packages found" \
      "All installed packages are older than $cutoff_days days." \
      "" \
      ""
  fi
}

# ─── CHK-SUP-005: ClawHub-installed skills ──────────────────────────────────

check_clawhub_skills() {
  log_info "CHK-SUP-005: Checking ClawHub-installed skills..."

  if has_cmd clawhub; then
    local skills_list
    skills_list="$(clawhub list 2>/dev/null)" || skills_list=""

    if [[ -n "$skills_list" ]]; then
      while IFS= read -r skill_line; do
        [[ -z "$skill_line" ]] && continue
        emit_finding \
          "CHK-SUP-005" \
          "info" \
          "ClawHub skill installed: $skill_line" \
          "Skill was installed via ClawHub marketplace. Verify it is still maintained and trusted." \
          "$skill_line" \
          "Review the skill's source and permissions."
      done <<< "$skills_list"
    else
      emit_finding \
        "CHK-SUP-005" \
        "ok" \
        "No ClawHub skills installed" \
        "No skills found via clawhub list." \
        "" \
        ""
    fi
  else
    # Fall back to checking the skills directory directly
    local found=0
    if [[ -d "$SKILLS_DIR" ]]; then
      for skill_dir in "$SKILLS_DIR"/*/; do
        [[ -d "$skill_dir" ]] || continue
        local skill_name
        skill_name="$(basename "$skill_dir")"
        found=1
        emit_finding \
          "CHK-SUP-005" \
          "info" \
          "Installed skill: $skill_name" \
          "Skill found in skills directory. Verify it is legitimate and expected." \
          "$skill_dir" \
          "Review the skill's source and permissions."
      done
    fi

    if [[ "$found" -eq 0 ]]; then
      emit_finding \
        "CHK-SUP-005" \
        "ok" \
        "No installed skills found" \
        "Skills directory is empty or does not exist." \
        "" \
        ""
    fi
  fi
}

# ─── CHK-SUP-006: Skills from unverified GitHub URLs ────────────────────────

check_unverified_github_skills() {
  log_info "CHK-SUP-006: Checking for skills installed from unverified GitHub URLs..."
  local found=0

  for skill_dir in "$SKILLS_DIR"/*/; do
    [[ -d "$skill_dir" ]] || continue

    # Check package.json for repository URLs
    local pkg_json="$skill_dir/package.json"
    if [[ -f "$pkg_json" ]] && has_cmd jq; then
      local repo_url
      repo_url="$(jq -r '(.repository.url // .repository // .homepage // "") | select(. != "")' "$pkg_json" 2>/dev/null)" || continue

      if [[ "$repo_url" =~ github\.com ]] && [[ ! "$repo_url" =~ github\.com/(openclaw-official|clawhub-verified)/ ]]; then
        local skill_name
        skill_name="$(basename "$skill_dir")"
        found=1
        emit_finding \
          "CHK-SUP-006" \
          "warn" \
          "Skill from unverified GitHub source: $skill_name" \
          "Skill '$skill_name' was installed from a GitHub repository that is not in the verified organizations list." \
          "Source: $repo_url" \
          "Verify the repository is trustworthy. Prefer skills from verified publishers."
      fi
    fi

    # Check .clawhub-origin or .git/config for source info
    if [[ -f "$skill_dir/.clawhub-origin" ]]; then
      local origin
      origin="$(head -1 "$skill_dir/.clawhub-origin" 2>/dev/null)" || continue
      if [[ "$origin" =~ github\.com ]] && [[ ! "$origin" =~ github\.com/(openclaw-official|clawhub-verified)/ ]]; then
        local skill_name
        skill_name="$(basename "$skill_dir")"
        found=1
        emit_finding \
          "CHK-SUP-006" \
          "warn" \
          "Skill from unverified GitHub URL: $skill_name" \
          "Skill '$skill_name' origin is a non-verified GitHub repository." \
          "Origin: $origin" \
          "Verify the repository and author are trustworthy."
      fi
    fi
  done

  if [[ "$found" -eq 0 ]]; then
    emit_finding \
      "CHK-SUP-006" \
      "ok" \
      "No skills from unverified GitHub sources" \
      "All detected skills originate from verified sources or have no detectable GitHub origin." \
      "" \
      ""
  fi
}

# ─── CHK-SUP-007: Extensions not in plugins.allow whitelist ──────────────────

check_extension_whitelist() {
  log_info "CHK-SUP-007: Checking extensions against plugins.allow whitelist..."

  # Read plugins.allow from openclaw.json config (it's an array inside the JSON)
  local config_file
  config_file="$(get_openclaw_config 2>/dev/null)" || config_file="$HOME/.openclaw/openclaw.json"

  if [[ ! -f "$config_file" ]]; then
    emit_finding \
      "CHK-SUP-007" \
      "warn" \
      "Cannot check plugin whitelist" \
      "Could not locate openclaw.json to read plugins.allow." \
      "Searched: $config_file" \
      "Ensure openclaw.json exists with a plugins.allow array."
    return
  fi

  local allow_json
  allow_json="$(jq -r '.plugins.allow // empty' "$config_file" 2>/dev/null)"

  if [[ -z "$allow_json" ]] || [[ "$allow_json" == "null" ]]; then
    emit_finding \
      "CHK-SUP-007" \
      "warn" \
      "No plugins.allow whitelist configured" \
      "openclaw.json does not have a plugins.allow array. Without a whitelist, any extension can load." \
      "config: $config_file" \
      "Add a plugins.allow array to openclaw.json listing only trusted plugins."
    return
  fi

  log_info "Reading plugins.allow from $config_file"

  # Read allowed plugins into an array
  local allowed=()
  while IFS= read -r name; do
    [[ -n "$name" ]] && allowed+=("$name")
  done < <(jq -r '.plugins.allow[]?' "$config_file" 2>/dev/null)

  local found=0
  for ext_dir in "$EXTENSIONS_DIR"/*/; do
    [[ -d "$ext_dir" ]] || continue
    local ext_name
    ext_name="$(basename "$ext_dir")"

    local whitelisted=0
    for allowed_name in "${allowed[@]}"; do
      if [[ "$ext_name" == "$allowed_name" ]]; then
        whitelisted=1
        break
      fi
    done

    if [[ "$whitelisted" -eq 0 ]]; then
      found=1
      emit_finding \
        "CHK-SUP-007" \
        "critical" \
        "Extension not in plugins.allow: $ext_name" \
        "Extension '$ext_name' is installed but not listed in the plugins.allow whitelist. It may be unauthorized." \
        "Extension: $ext_dir" \
        "Add '$ext_name' to plugins.allow in openclaw.json if trusted, or remove the extension."
    fi
  done

  if [[ "$found" -eq 0 ]]; then
    emit_finding \
      "CHK-SUP-007" \
      "ok" \
      "All extensions are whitelisted" \
      "Every installed extension is present in the plugins.allow whitelist." \
      "" \
      ""
  fi
}

# ─── CHK-SUP-008: Native/compiled binaries in node_modules ──────────────────

check_native_binaries() {
  log_info "CHK-SUP-008: Scanning for native/compiled binaries in node_modules..."
  local found=0

  for nm_dir in "$SKILLS_DIR"/*/node_modules "$EXTENSIONS_DIR"/*/node_modules; do
    [[ -d "$nm_dir" ]] || continue

    while IFS= read -r binary_file; do
      found=1
      local rel_path="${binary_file#"$nm_dir"/}"
      emit_finding \
        "CHK-SUP-008" \
        "warn" \
        "Native binary in node_modules: $rel_path" \
        "A compiled binary file was found inside node_modules. Native addons can execute arbitrary code outside the Node.js sandbox." \
        "$binary_file" \
        "Verify the binary is from a legitimate native addon (e.g. node-gyp build artifact)."
    done < <(find "$nm_dir" \( -name "*.node" -o -name "*.dylib" -o -name "*.so" -o -name "*.dll" \) -type f 2>/dev/null)
  done

  if [[ "$found" -eq 0 ]]; then
    emit_finding \
      "CHK-SUP-008" \
      "ok" \
      "No native binaries found in node_modules" \
      "No .node, .dylib, .so, or .dll files detected in skill or extension node_modules." \
      "" \
      ""
  fi
}

# ─── Main ────────────────────────────────────────────────────────────────────

main() {
  log_info "ClawPinch Supply Chain Scanner starting..."
  log_info "Skills directory: $SKILLS_DIR"
  log_info "Extensions directory: $EXTENSIONS_DIR"

  require_cmd jq || { log_error "jq is required for this scanner"; exit 1; }

  # Run all checks, collecting findings line by line
  {
    check_postinstall_hooks
    check_preinstall_hooks
    check_typosquat_packages
    check_recent_packages
    check_clawhub_skills
    check_unverified_github_skills
    check_extension_whitelist
    check_native_binaries
  } > "$FINDINGS_FILE"

  # Convert newline-delimited JSON objects into a JSON array
  if [[ -s "$FINDINGS_FILE" ]]; then
    jq -s '.' "$FINDINGS_FILE"
  else
    echo '[]'
  fi

  log_info "Supply chain scan complete."
}

main "$@"
