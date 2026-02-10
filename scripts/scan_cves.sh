#!/usr/bin/env bash
set -euo pipefail

# ─── ClawPinch CVE & Version Checker ─────────────────────────────────────────
# Checks the installed OpenClaw version against known CVEs and verifies
# that legacy clawdbot artifacts have been removed.
#
# Output: JSON array of finding objects to stdout.
# Logs/progress go to stderr.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers/common.sh"

REFERENCES_DIR="$(cd "$SCRIPT_DIR/../references" && pwd)"
KNOWN_CVES_FILE="$REFERENCES_DIR/known-cves.json"

# ─── Semver helpers ──────────────────────────────────────────────────────────

# Parse a version string like "1.2.3" or "2026.1.29" into comparable integers.
# Returns three space-separated numbers: major minor patch
parse_version() {
  local ver="$1"
  # Strip leading 'v' if present
  ver="${ver#v}"
  # Strip any pre-release/build suffix (e.g. -beta.1, +build123)
  ver="${ver%%-*}"
  ver="${ver%%+*}"

  local major minor patch
  IFS='.' read -r major minor patch <<< "$ver"
  echo "${major:-0} ${minor:-0} ${patch:-0}"
}

# Compare two version strings.
# Returns: 0 if a >= b, 1 if a < b
version_gte() {
  local a_major a_minor a_patch b_major b_minor b_patch
  read -r a_major a_minor a_patch <<< "$(parse_version "$1")"
  read -r b_major b_minor b_patch <<< "$(parse_version "$2")"

  if (( a_major > b_major )); then return 0; fi
  if (( a_major < b_major )); then return 1; fi
  if (( a_minor > b_minor )); then return 0; fi
  if (( a_minor < b_minor )); then return 1; fi
  if (( a_patch >= b_patch )); then return 0; fi
  return 1
}

# ─── Collect findings ────────────────────────────────────────────────────────

FINDINGS=()

add_finding() {
  FINDINGS+=("$(emit_finding "$@")")
}

# ─── Get installed version ───────────────────────────────────────────────────

CURRENT_VERSION="$(get_openclaw_version)"
log_info "Detected OpenClaw version: $CURRENT_VERSION"

if [[ "$CURRENT_VERSION" == "not-installed" ]]; then
  add_finding \
    "CHK-CVE-001" "critical" \
    "OpenClaw not installed -- cannot verify CVE patches" \
    "openclaw binary was not found on PATH. All CVE checks are skipped." \
    "openclaw not found" \
    "Install OpenClaw: npm install -g openclaw"

  # Skip version-based checks but still run legacy artifact checks
  CURRENT_VERSION=""
elif [[ "$CURRENT_VERSION" == "unknown" ]]; then
  add_finding \
    "CHK-CVE-001" "warn" \
    "Unable to determine OpenClaw version" \
    "openclaw --version returned an unexpected result. CVE version checks may be inaccurate." \
    "openclaw --version returned unknown" \
    "Ensure openclaw is properly installed and accessible."

  CURRENT_VERSION=""
fi

# ─── CVE checks (version-based) ─────────────────────────────────────────────

if [[ -n "$CURRENT_VERSION" ]]; then
  # Verify known-cves.json exists
  if [[ ! -f "$KNOWN_CVES_FILE" ]]; then
    log_warn "known-cves.json not found at $KNOWN_CVES_FILE -- skipping CVE database checks"
  else
    # Verify JSON integrity before using
    if ! verify_json_integrity "$KNOWN_CVES_FILE"; then  # known-cves.json
      log_error "Integrity verification failed for known-cves.json -- skipping CVE database checks"
    else
      # CHK-CVE-001: CVE-2026-25253 -- 1-Click RCE
      cve_001_fixed="2026.1.29"
      if ! version_gte "$CURRENT_VERSION" "$cve_001_fixed"; then
        add_finding \
          "CHK-CVE-001" "critical" \
          "Vulnerable to CVE-2026-25253: 1-Click RCE via auth token exfiltration" \
          "Cross-site WebSocket hijacking. Control UI trusts gatewayUrl from query string, leaking gateway auth token. CVSS 8.8." \
          "Installed: $CURRENT_VERSION, fixed in: $cve_001_fixed" \
          "Upgrade OpenClaw to >= $cve_001_fixed: npm update -g openclaw"
      else
        add_finding \
          "CHK-CVE-001" "ok" \
          "Not vulnerable to CVE-2026-25253" \
          "Installed version ($CURRENT_VERSION) includes the fix for CVE-2026-25253." \
          "Installed: $CURRENT_VERSION >= $cve_001_fixed" \
          ""
      fi

      # CHK-CVE-002: CVE-2026-24763 -- Docker command injection
      cve_002_fixed="2026.1.29"
      if ! version_gte "$CURRENT_VERSION" "$cve_002_fixed"; then
        add_finding \
          "CHK-CVE-002" "critical" \
          "Vulnerable to CVE-2026-24763: Command injection in Docker sandbox" \
          "Unsafe PATH env var handling in shell command construction. CVSS 8.8." \
          "Installed: $CURRENT_VERSION, fixed in: $cve_002_fixed" \
          "Upgrade OpenClaw to >= $cve_002_fixed: npm update -g openclaw"
      else
        add_finding \
          "CHK-CVE-002" "ok" \
          "Not vulnerable to CVE-2026-24763" \
          "Installed version ($CURRENT_VERSION) includes the fix for CVE-2026-24763." \
          "Installed: $CURRENT_VERSION >= $cve_002_fixed" \
          ""
      fi

      # CHK-CVE-003: CVE-2026-25157 -- SSH command injection
      cve_003_fixed="2026.1.29"
      if ! version_gte "$CURRENT_VERSION" "$cve_003_fixed"; then
        add_finding \
          "CHK-CVE-003" "critical" \
          "Vulnerable to CVE-2026-25157: OS command injection via SSH project path" \
          "Unescaped project root path in sshNodeCommand error echo. CVSS 8.8." \
          "Installed: $CURRENT_VERSION, fixed in: $cve_003_fixed" \
          "Upgrade OpenClaw to >= $cve_003_fixed: npm update -g openclaw"
      else
        add_finding \
          "CHK-CVE-003" "ok" \
          "Not vulnerable to CVE-2026-25157" \
          "Installed version ($CURRENT_VERSION) includes the fix for CVE-2026-25157." \
          "Installed: $CURRENT_VERSION >= $cve_003_fixed" \
          ""
      fi
    fi
  fi

  # CHK-CVE-004: Check if on latest available version
  LATEST_VERSION=""
  if has_cmd npm; then
    log_info "Checking npm registry for latest OpenClaw version..."
    LATEST_VERSION="$(timeout 10 npm view openclaw version 2>/dev/null || true)"
  fi

  if [[ -n "$LATEST_VERSION" ]]; then
    if ! version_gte "$CURRENT_VERSION" "$LATEST_VERSION"; then
      add_finding \
        "CHK-CVE-004" "info" \
        "OpenClaw is not on the latest available version" \
        "A newer version is available on npm. Staying current ensures you have the latest security patches." \
        "Installed: $CURRENT_VERSION, latest: $LATEST_VERSION" \
        "Upgrade with: npm update -g openclaw"
    else
      add_finding \
        "CHK-CVE-004" "ok" \
        "OpenClaw is up to date" \
        "Installed version matches or exceeds the latest available on npm." \
        "Installed: $CURRENT_VERSION, latest: $LATEST_VERSION" \
        ""
    fi
  else
    add_finding \
      "CHK-CVE-004" "info" \
      "Could not determine latest OpenClaw version from npm" \
      "npm registry lookup failed or timed out. Unable to verify if a newer version is available." \
      "npm view openclaw version returned no result" \
      "Check manually: npm view openclaw version"
  fi
fi

# ─── Legacy clawdbot checks (always run) ─────────────────────────────────────

# CHK-CVE-005: Legacy clawdbot LaunchAgents
legacy_agents_found=()
os="$(detect_os)"

if [[ "$os" == "macos" ]]; then
  launch_agent_dirs=(
    "$HOME/Library/LaunchAgents"
    "/Library/LaunchAgents"
  )

  for dir in "${launch_agent_dirs[@]}"; do
    if [[ -d "$dir" ]]; then
      while IFS= read -r -d '' plist; do
        legacy_agents_found+=("$plist")
      done < <(find "$dir" -maxdepth 1 -name '*clawdbot*' -print0 2>/dev/null || true)
    fi
  done
fi

# Also check for clawdbot systemd services on Linux
if [[ "$os" == "linux" ]]; then
  systemd_dirs=(
    "$HOME/.config/systemd/user"
    "/etc/systemd/system"
  )

  for dir in "${systemd_dirs[@]}"; do
    if [[ -d "$dir" ]]; then
      while IFS= read -r -d '' svc; do
        legacy_agents_found+=("$svc")
      done < <(find "$dir" -maxdepth 1 -name '*clawdbot*' -print0 2>/dev/null || true)
    fi
  done
fi

if [[ ${#legacy_agents_found[@]} -gt 0 ]]; then
  evidence_list=""
  for f in "${legacy_agents_found[@]}"; do
    evidence_list+="$f "
  done
  add_finding \
    "CHK-CVE-005" "warn" \
    "Legacy clawdbot LaunchAgents/services still present" \
    "Found clawdbot service definitions that may be leftover from a previous installation. These could auto-launch outdated or vulnerable software." \
    "Found: ${evidence_list% }" \
    "Remove the legacy plist/service files: launchctl unload <path> && rm <path>"
else
  add_finding \
    "CHK-CVE-005" "ok" \
    "No legacy clawdbot LaunchAgents/services found" \
    "No clawdbot service definitions were detected." \
    "Searched standard LaunchAgent/systemd directories" \
    ""
fi

# CHK-CVE-006: Legacy clawdbot environment variables
legacy_env_vars=()
for var in CLAWDBOT_HOME CLAWDBOT_TOKEN CLAWDBOT_CONFIG CLAWDBOT_API_KEY; do
  if [[ -n "${!var:-}" ]]; then
    legacy_env_vars+=("$var")
  fi
done

# Also check shell profile files for clawdbot references
profile_files=(
  "$HOME/.bashrc"
  "$HOME/.bash_profile"
  "$HOME/.zshrc"
  "$HOME/.zprofile"
  "$HOME/.profile"
)

profile_hits=()
for pf in "${profile_files[@]}"; do
  if [[ -f "$pf" ]] && grep -qi 'clawdbot' "$pf" 2>/dev/null; then
    profile_hits+=("$pf")
  fi
done

if [[ ${#legacy_env_vars[@]} -gt 0 || ${#profile_hits[@]} -gt 0 ]]; then
  evidence=""
  if [[ ${#legacy_env_vars[@]} -gt 0 ]]; then
    evidence+="Active env vars: ${legacy_env_vars[*]}. "
  fi
  if [[ ${#profile_hits[@]} -gt 0 ]]; then
    evidence+="References in: ${profile_hits[*]}."
  fi
  add_finding \
    "CHK-CVE-006" "info" \
    "Legacy clawdbot environment variables or profile references detected" \
    "Found references to the deprecated clawdbot tooling. These should be cleaned up to avoid confusion with the current OpenClaw installation." \
    "${evidence% }" \
    "Remove clawdbot references from shell profiles and unset env vars."
else
  add_finding \
    "CHK-CVE-006" "ok" \
    "No legacy clawdbot environment variables detected" \
    "No clawdbot-related environment variables or shell profile references found." \
    "Checked common shell profiles and environment" \
    ""
fi

# ─── Output results as JSON array ────────────────────────────────────────────

if [[ ${#FINDINGS[@]} -eq 0 ]]; then
  echo "[]"
else
  # Join findings into a JSON array
  printf '[\n'
  for i in "${!FINDINGS[@]}"; do
    if (( i > 0 )); then
      printf ',\n'
    fi
    printf '  %s' "${FINDINGS[$i]}"
  done
  printf '\n]\n'
fi
