#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# scan_config.sh - OpenClaw Configuration Security Scanner
#
# Analyzes openclaw.json for security misconfigurations and outputs a JSON
# array of findings to stdout.
#
# Usage:
#   ./scan_config.sh                          # auto-detect config
#   OPENCLAW_CONFIG_PATH=/path/to/config.json ./scan_config.sh
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source shared helpers if available; define fallbacks otherwise
if [[ -f "${SCRIPT_DIR}/helpers/common.sh" ]]; then
    # shellcheck source=helpers/common.sh
    source "${SCRIPT_DIR}/helpers/common.sh"
fi

# Fallback: define emit_finding if not already provided by common.sh
if ! declare -f emit_finding >/dev/null 2>&1; then
    emit_finding() {
        local id="$1" severity="$2" title="$3" description="$4" evidence="$5" remediation="$6" auto_fix="${7:-}"
        jq -n \
            --arg id "$id" \
            --arg severity "$severity" \
            --arg title "$title" \
            --arg description "$description" \
            --arg evidence "$evidence" \
            --arg remediation "$remediation" \
            --arg auto_fix "$auto_fix" \
            '{id:$id, severity:$severity, title:$title, description:$description, evidence:$evidence, remediation:$remediation, auto_fix:$auto_fix}'
    }
fi

# ---------------------------------------------------------------------------
# Resolve config path
# ---------------------------------------------------------------------------
CONFIG_PATH="${OPENCLAW_CONFIG_PATH:-${HOME}/.openclaw/openclaw.json}"

if [[ ! -f "$CONFIG_PATH" ]]; then
    echo '[{"id":"CHK-CFG-000","severity":"critical","title":"Config file not found","description":"Could not locate openclaw.json","evidence":"'"$CONFIG_PATH"'","remediation":"Create the config file or set OPENCLAW_CONFIG_PATH","auto_fix":""}]'
    exit 1
fi

# Validate that the file is valid JSON
if ! jq empty "$CONFIG_PATH" 2>/dev/null; then
    echo '[{"id":"CHK-CFG-000","severity":"critical","title":"Config file is not valid JSON","description":"The config file could not be parsed as JSON","evidence":"'"$CONFIG_PATH"'","remediation":"Fix JSON syntax errors in the config file","auto_fix":""}]'
    exit 1
fi

# ---------------------------------------------------------------------------
# Collect findings into an array
# ---------------------------------------------------------------------------
FINDINGS=()

# Helper to read a jq expression from the config; returns "null" if missing
cfg() {
    jq -r "$1 // \"null\"" "$CONFIG_PATH"
}

cfg_raw() {
    jq -r "$1" "$CONFIG_PATH"
}

# ---------------------------------------------------------------------------
# CHK-CFG-001: exec.ask not set to "always" -> CRITICAL
# ---------------------------------------------------------------------------
exec_ask="$(cfg '.tools.exec.ask')"
if [[ "$exec_ask" != "always" ]]; then
    FINDINGS+=("$(emit_finding \
        "CHK-CFG-001" \
        "critical" \
        "exec.ask not set to always" \
        "The exec.ask setting controls whether the user is prompted before command execution. It must be set to 'always' to prevent unattended command execution." \
        "exec.ask=${exec_ask}" \
        "Set exec.ask to 'always' in openclaw.json" \
        "jq '.exec.ask = \"always\"' \"${CONFIG_PATH}\" > \"${CONFIG_PATH}.tmp\" && mv \"${CONFIG_PATH}.tmp\" \"${CONFIG_PATH}\""
    )")
fi

# ---------------------------------------------------------------------------
# CHK-CFG-002: Any channel has groupPolicy="open" -> CRITICAL
# ---------------------------------------------------------------------------
open_group_channels="$(jq -r '[.channels | to_entries[]? | select(.value.groupPolicy == "open") | .key] | join(", ")' "$CONFIG_PATH")"
if [[ -n "$open_group_channels" ]]; then
    FINDINGS+=("$(emit_finding \
        "CHK-CFG-002" \
        "critical" \
        "Channel with open groupPolicy detected" \
        "Channels with groupPolicy=open allow any user to join groups, which may expose sensitive conversations and data." \
        "channels with open groupPolicy: ${open_group_channels}" \
        "Set groupPolicy to 'restricted' or 'closed' for all channels" \
        "jq '(.channels[] | select(.groupPolicy == \"open\") | .groupPolicy) = \"restricted\"' \"${CONFIG_PATH}\" > \"${CONFIG_PATH}.tmp\" && mv \"${CONFIG_PATH}.tmp\" \"${CONFIG_PATH}\""
    )")
fi

# ---------------------------------------------------------------------------
# CHK-CFG-003: Any channel has dmPolicy="open" -> CRITICAL
# ---------------------------------------------------------------------------
open_dm_channels="$(jq -r '[.channels | to_entries[]? | select(.value.dmPolicy == "open") | .key] | join(", ")' "$CONFIG_PATH")"
if [[ -n "$open_dm_channels" ]]; then
    FINDINGS+=("$(emit_finding \
        "CHK-CFG-003" \
        "critical" \
        "Channel with open dmPolicy detected" \
        "Channels with dmPolicy=open allow unrestricted direct messages, which can be exploited for social engineering or data exfiltration." \
        "channels with open dmPolicy: ${open_dm_channels}" \
        "Set dmPolicy to 'restricted' or 'closed' for all channels" \
        "jq '(.channels[] | select(.dmPolicy == \"open\") | .dmPolicy) = \"restricted\"' \"${CONFIG_PATH}\" > \"${CONFIG_PATH}.tmp\" && mv \"${CONFIG_PATH}.tmp\" \"${CONFIG_PATH}\""
    )")
fi

# ---------------------------------------------------------------------------
# CHK-CFG-004: plugins.allow not set (no plugin whitelist) -> CRITICAL
# ---------------------------------------------------------------------------
plugins_allow="$(cfg_raw '.plugins.allow // empty')"
if [[ -z "$plugins_allow" ]] || [[ "$plugins_allow" == "null" ]]; then
    FINDINGS+=("$(emit_finding \
        "CHK-CFG-004" \
        "critical" \
        "No plugin whitelist configured" \
        "Without plugins.allow, any plugin can be loaded. A whitelist restricts which plugins are permitted to run." \
        "plugins.allow is not set" \
        "Add a plugins.allow array listing only trusted plugins" \
        "jq '.plugins.allow = []' \"${CONFIG_PATH}\" > \"${CONFIG_PATH}.tmp\" && mv \"${CONFIG_PATH}.tmp\" \"${CONFIG_PATH}\""
    )")
fi

# ---------------------------------------------------------------------------
# CHK-CFG-005: exec.security not "full" -> WARN
# ---------------------------------------------------------------------------
exec_security="$(cfg '.tools.exec.security')"
if [[ "$exec_security" != "full" ]]; then
    FINDINGS+=("$(emit_finding \
        "CHK-CFG-005" \
        "warn" \
        "exec.security not set to full" \
        "The exec.security setting controls the level of sandboxing applied to command execution. Setting it to 'full' enables maximum protection." \
        "exec.security=${exec_security}" \
        "Set exec.security to 'full' in openclaw.json" \
        "jq '.exec.security = \"full\"' \"${CONFIG_PATH}\" > \"${CONFIG_PATH}.tmp\" && mv \"${CONFIG_PATH}.tmp\" \"${CONFIG_PATH}\""
    )")
fi

# ---------------------------------------------------------------------------
# CHK-CFG-006: gateway.auth.token is missing -> WARN
# ---------------------------------------------------------------------------
gateway_token="$(cfg '.gateway.auth.token')"
if [[ "$gateway_token" == "null" ]] || [[ -z "$gateway_token" ]]; then
    FINDINGS+=("$(emit_finding \
        "CHK-CFG-006" \
        "warn" \
        "Gateway auth token is missing" \
        "Without a gateway.auth.token, the gateway may accept unauthenticated connections." \
        "gateway.auth.token is not set" \
        "Set a strong gateway.auth.token in openclaw.json" \
        ""
    )")
fi

# ---------------------------------------------------------------------------
# CHK-CFG-007: controlUi.dangerouslyDisableDeviceAuth is true -> CRITICAL
# ---------------------------------------------------------------------------
disable_device_auth="$(cfg '.controlUi.dangerouslyDisableDeviceAuth')"
if [[ "$disable_device_auth" == "true" ]]; then
    FINDINGS+=("$(emit_finding \
        "CHK-CFG-007" \
        "critical" \
        "Device authentication is disabled" \
        "controlUi.dangerouslyDisableDeviceAuth=true disables device-level authentication for the control UI, allowing anyone with network access to control the system." \
        "controlUi.dangerouslyDisableDeviceAuth=true" \
        "Set controlUi.dangerouslyDisableDeviceAuth to false" \
        "jq '.controlUi.dangerouslyDisableDeviceAuth = false' \"${CONFIG_PATH}\" > \"${CONFIG_PATH}.tmp\" && mv \"${CONFIG_PATH}.tmp\" \"${CONFIG_PATH}\""
    )")
fi

# ---------------------------------------------------------------------------
# CHK-CFG-008: allowFrom contains "*" wildcard -> WARN
# ---------------------------------------------------------------------------
has_wildcard_allowfrom="$(jq -r 'if [.channels | to_entries[]? | select(.value.allowFrom? // [] | map(select(. == "*")) | length > 0) | .key] | length > 0 then "true" else "false" end' "$CONFIG_PATH")"
if [[ "$has_wildcard_allowfrom" == "true" ]]; then
    FINDINGS+=("$(emit_finding \
        "CHK-CFG-008" \
        "warn" \
        "allowFrom contains wildcard" \
        "The allowFrom list contains '*', which permits connections from any origin. This should be restricted to specific trusted origins." \
        "allowFrom contains '*'" \
        "Replace '*' in allowFrom with specific allowed origins" \
        "jq '.allowFrom = (.allowFrom | map(select(. != \"*\")))' \"${CONFIG_PATH}\" > \"${CONFIG_PATH}.tmp\" && mv \"${CONFIG_PATH}.tmp\" \"${CONFIG_PATH}\""
    )")
fi

# ---------------------------------------------------------------------------
# CHK-CFG-009: commands.nativeSkills enabled on channels with open policies -> WARN
# ---------------------------------------------------------------------------
native_skills_enabled="$(cfg '.commands.nativeSkills')"
if [[ "$native_skills_enabled" == "true" ]]; then
    has_open_channel="$(jq -r 'if [.channels | to_entries[]? | select(.value.groupPolicy == "open" or .value.dmPolicy == "open")] | length > 0 then "true" else "false" end' "$CONFIG_PATH")"
    if [[ "$has_open_channel" == "true" ]]; then
        FINDINGS+=("$(emit_finding \
            "CHK-CFG-009" \
            "warn" \
            "Native skills enabled with open channel policies" \
            "commands.nativeSkills is enabled while channels with open group or DM policies exist. This combination allows untrusted users to invoke native skills." \
            "commands.nativeSkills=true with open channel policies" \
            "Disable nativeSkills or restrict channel policies" \
            "jq '.commands.nativeSkills = false' \"${CONFIG_PATH}\" > \"${CONFIG_PATH}.tmp\" && mv \"${CONFIG_PATH}.tmp\" \"${CONFIG_PATH}\""
        )")
    fi
fi

# ---------------------------------------------------------------------------
# CHK-CFG-010: logging.redactSensitive not set -> INFO
# ---------------------------------------------------------------------------
redact_sensitive="$(cfg '.logging.redactSensitive')"
if [[ "$redact_sensitive" == "null" ]]; then
    FINDINGS+=("$(emit_finding \
        "CHK-CFG-010" \
        "info" \
        "Sensitive data redaction not configured" \
        "logging.redactSensitive is not set. When enabled, sensitive data such as tokens and credentials are redacted from log output." \
        "logging.redactSensitive is not set" \
        "Set logging.redactSensitive to true in openclaw.json" \
        "jq '.logging.redactSensitive = true' \"${CONFIG_PATH}\" > \"${CONFIG_PATH}.tmp\" && mv \"${CONFIG_PATH}.tmp\" \"${CONFIG_PATH}\""
    )")
fi

# ---------------------------------------------------------------------------
# CHK-CFG-011: browser control enabled without restrictions -> WARN
# ---------------------------------------------------------------------------
browser_enabled="$(cfg '.browser.enabled')"
browser_restrict="$(cfg '.browser.restrict')"
if [[ "$browser_enabled" == "true" ]] && [[ "$browser_restrict" == "null" || "$browser_restrict" == "false" ]]; then
    FINDINGS+=("$(emit_finding \
        "CHK-CFG-011" \
        "warn" \
        "Browser control enabled without restrictions" \
        "browser.enabled is true but browser.restrict is not set or false. Unrestricted browser control can be used to access arbitrary web content." \
        "browser.enabled=true, browser.restrict=${browser_restrict}" \
        "Enable browser.restrict or disable browser control entirely" \
        "jq '.browser.restrict = true' \"${CONFIG_PATH}\" > \"${CONFIG_PATH}.tmp\" && mv \"${CONFIG_PATH}.tmp\" \"${CONFIG_PATH}\""
    )")
fi

# ---------------------------------------------------------------------------
# CHK-CFG-012: discovery.mdns or wideArea enabled (exposes gateway) -> WARN
# ---------------------------------------------------------------------------
mdns_enabled="$(cfg '.discovery.mdns')"
wide_area_enabled="$(cfg '.discovery.wideArea')"
if [[ "$mdns_enabled" == "true" ]] || [[ "$wide_area_enabled" == "true" ]]; then
    evidence_parts=()
    [[ "$mdns_enabled" == "true" ]] && evidence_parts+=("discovery.mdns=true")
    [[ "$wide_area_enabled" == "true" ]] && evidence_parts+=("discovery.wideArea=true")
    evidence_str="$(IFS=', '; echo "${evidence_parts[*]}")"
    FINDINGS+=("$(emit_finding \
        "CHK-CFG-012" \
        "warn" \
        "Network discovery enabled" \
        "Discovery protocols (mDNS/wide-area) are enabled, which broadcasts the gateway's presence on the network and may expose it to untrusted devices." \
        "${evidence_str}" \
        "Disable discovery.mdns and discovery.wideArea unless required" \
        "jq '.discovery.mdns = false | .discovery.wideArea = false' \"${CONFIG_PATH}\" > \"${CONFIG_PATH}.tmp\" && mv \"${CONFIG_PATH}.tmp\" \"${CONFIG_PATH}\""
    )")
fi

# ---------------------------------------------------------------------------
# Output all findings as a JSON array
# ---------------------------------------------------------------------------
if [[ ${#FINDINGS[@]} -eq 0 ]]; then
    echo '[]'
else
    printf '%s\n' "${FINDINGS[@]}" | jq -s '.'
fi
