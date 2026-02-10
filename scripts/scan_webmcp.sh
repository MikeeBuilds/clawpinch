#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# scan_webmcp.sh - WebMCP Security Scanner for OpenClaw
#
# Scans for WebMCP-related misconfigurations, untrusted origins, excessive
# capability grants, prompt injection risks, and data exfiltration vectors.
#
# Updated to match the real Chrome 146.0.7651.0 WebMCP API shape:
#   - navigator.modelContext.provideContext({ tools: [...] })  (primary)
#   - navigator.modelContext.registerTool({ name, description, inputSchema, execute })
#   - navigator.modelContext.unregisterTool(name)
#   - navigator.modelContext.clearContext()
#   - Each tool requires: name, description, inputSchema, execute (callback)
#
# Outputs a JSON array of finding objects to stdout.
#
# Usage:
#   ./scan_webmcp.sh
#   OPENCLAW_CONFIG_PATH=/path/to/config.json ./scan_webmcp.sh
#   CLAWPINCH_DEEP=1 ./scan_webmcp.sh    # deep scan mode
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source shared helpers if available; define fallbacks otherwise
if [[ -f "${SCRIPT_DIR}/helpers/common.sh" ]]; then
    # shellcheck source=helpers/common.sh
    source "${SCRIPT_DIR}/helpers/common.sh"
elif [[ -f "${SCRIPT_DIR}/../../clawpinch/scripts/helpers/common.sh" ]]; then
    source "${SCRIPT_DIR}/../../clawpinch/scripts/helpers/common.sh"
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

if ! declare -f log_info >/dev/null 2>&1; then
    log_info()  { echo "[info]  $*" >&2; }
    log_warn()  { echo "[warn]  $*" >&2; }
    log_error() { echo "[error] $*" >&2; }
fi

if ! declare -f detect_os >/dev/null 2>&1; then
    detect_os() {
        case "$(uname -s)" in
            Darwin*) echo "macos" ;;
            Linux*)  echo "linux" ;;
            *)       echo "unknown" ;;
        esac
    }
fi

# ---------------------------------------------------------------------------
# Config & environment
# ---------------------------------------------------------------------------
CLAWPINCH_DEEP="${CLAWPINCH_DEEP:-0}"
OPENCLAW_DIR="${OPENCLAW_DIR:-${HOME}/.openclaw}"
CONFIG_PATH="${OPENCLAW_CONFIG_PATH:-${OPENCLAW_DIR}/openclaw.json}"
WORKSPACE_DIR="${OPENCLAW_DIR}/workspace"
SKILLS_DIR="${OPENCLAW_DIR}/skills"

# ---------------------------------------------------------------------------
# Trusted origins — default allow-list for WebMCP service origins.
# Override by setting WEBMCP_TRUSTED_ORIGINS (comma-separated).
# ---------------------------------------------------------------------------
DEFAULT_TRUSTED_ORIGINS="localhost,127.0.0.1,::1,chrome-extension://,moz-extension://,safari-web-extension://"
TRUSTED_ORIGINS="${WEBMCP_TRUSTED_ORIGINS:-$DEFAULT_TRUSTED_ORIGINS}"
IFS=',' read -ra TRUSTED_ORIGIN_LIST <<< "$TRUSTED_ORIGINS"

# ---------------------------------------------------------------------------
# Sensitive capability keywords
# ---------------------------------------------------------------------------
SENSITIVE_CAPS=("filesystem" "shell" "exec" "network" "outbound" "process" "admin" "sudo" "root" "system" "os" "child_process" "spawn" "eval")
SENSITIVE_DATA_PATTERNS=("memory" "context" "history" "conversation" "agent_state" "session" "credentials" "secrets" "keychain" "token" "MEMORY.md" "SOUL.md" "USER.md")
PROMPT_INJECTION_PATTERNS=(
    "ignore previous"
    "ignore all previous"
    "disregard"
    "forget your instructions"
    "new instructions"
    "override"
    "you are now"
    "act as"
    "pretend to be"
    "system prompt"
    "jailbreak"
    "DAN"
    "do anything now"
    "bypass"
    "ignore safety"
    "ignore restrictions"
    "<\|im_start\|>"
    "\\[INST\\]"
    "\\[/INST\\]"
    "<<SYS>>"
    "<</SYS>>"
    "\\\\n\\\\nHuman:"
    "\\\\n\\\\nAssistant:"
)

# ---------------------------------------------------------------------------
# Collect findings
# ---------------------------------------------------------------------------
FINDINGS=()

# ---------------------------------------------------------------------------
# Utility: check if a string matches any trusted origin
# ---------------------------------------------------------------------------
is_trusted_origin() {
    local origin="$1"
    for trusted in "${TRUSTED_ORIGIN_LIST[@]}"; do
        trusted="$(echo "$trusted" | xargs)"  # trim whitespace
        if [[ -z "$trusted" ]]; then continue; fi
        # Exact match or substring match (origin starts with trusted prefix)
        if [[ "$origin" == "$trusted" ]] || [[ "$origin" == "${trusted}"* ]] || [[ "$origin" == *"://${trusted}"* ]] || [[ "$origin" == *"://${trusted}:"* ]]; then
            return 0
        fi
    done
    return 1
}

# ---------------------------------------------------------------------------
# Utility: case-insensitive grep for pattern in text
# ---------------------------------------------------------------------------
contains_pattern() {
    local text="$1" pattern="$2"
    echo "$text" | grep -qi "$pattern" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Gather WebMCP-related files across the OpenClaw installation
# ---------------------------------------------------------------------------
gather_webmcp_files() {
    local search_dirs=("$OPENCLAW_DIR")
    [[ -d "$WORKSPACE_DIR" ]] && search_dirs+=("$WORKSPACE_DIR")
    [[ -d "$SKILLS_DIR" ]] && search_dirs+=("$SKILLS_DIR")

    # Find files that might contain WebMCP declarations:
    # - JSON files with "webmcp", "modelContext", "services", "capabilities"
    # - YAML/YML files with similar content
    # - Browser extension manifests
    # - JS/TS files using the Chrome 146 WebMCP API:
    #     provideContext, registerTool, unregisterTool, clearContext
    local found_files=()
    for dir in "${search_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            while IFS= read -r -d '' f; do
                found_files+=("$f")
            done < <(find "$dir" -maxdepth 5 \
                \( -name "*.json" -o -name "*.yaml" -o -name "*.yml" -o -name "*.toml" \
                   -o -name "manifest.json" \
                   -o -name "*.js" -o -name "*.ts" -o -name "*.mjs" -o -name "*.mts" \
                   -o -name "*.jsx" -o -name "*.tsx" \) \
                -not -path "*/node_modules/*" \
                -not -path "*/.git/*" \
                -print0 2>/dev/null || true)
        fi
    done

    printf '%s\n' "${found_files[@]}"
}

# ---------------------------------------------------------------------------
# Utility: extract JSON array or object from file safely
# ---------------------------------------------------------------------------
safe_jq() {
    local file="$1" filter="$2"
    if command -v jq &>/dev/null && [[ -f "$file" ]]; then
        jq -r "$filter" "$file" 2>/dev/null || true
    fi
}

# ---------------------------------------------------------------------------
# CHK-WEB-001: WebMCP endpoint connects to untrusted origin
# ---------------------------------------------------------------------------
check_untrusted_origins() {
    log_info "CHK-WEB-001: Checking for untrusted WebMCP origins..."

    local found_any=false

    # Check openclaw.json for webmcp service declarations
    if [[ -f "$CONFIG_PATH" ]] && command -v jq &>/dev/null; then
        # Look for webmcp.services, webmcp.endpoints, or mcpServers with URLs
        local endpoints
        endpoints=$(jq -r '
            ((.webmcp.services // [])[] | .origin // empty),
            ((.webmcp.endpoints // [])[] | .origin // empty),
            ((.webmcp.endpoints // [])[] | .url // empty),
            ((.mcpServers // {}) | to_entries[]? | .value.url // empty),
            ((.webmcp.trustedOrigins // [])[] | select(. != null))
        ' "$CONFIG_PATH" 2>/dev/null || true)

        while IFS= read -r endpoint; do
            [[ -z "$endpoint" ]] && continue
            found_any=true
            # Extract the origin (scheme + host) from the URL
            local origin
            origin=$(echo "$endpoint" | sed -E 's|(https?://[^/:]+).*|\1|;s|(wss?://[^/:]+).*|\1|')
            local host
            host=$(echo "$origin" | sed -E 's|.*://||')

            if ! is_trusted_origin "$host"; then
                FINDINGS+=("$(emit_finding \
                    "CHK-WEB-001" \
                    "critical" \
                    "WebMCP endpoint connects to untrusted origin" \
                    "A WebMCP service declaration references an origin ($origin) that is not in the trusted origins list. Untrusted origins can serve malicious tool definitions that the agent will execute." \
                    "Untrusted origin: $endpoint (host: $host)" \
                    "Add the origin to WEBMCP_TRUSTED_ORIGINS if trusted, or remove the service declaration. Only connect to origins you control or explicitly trust." \
                    ""
                )")
            fi
        done <<< "$endpoints"
    fi

    # Scan workspace and skill files for WebMCP origin references
    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        [[ ! -f "$file" ]] && continue

        local content
        content=$(cat "$file" 2>/dev/null || true)

        # Look for WebMCP-like URL patterns (including Chrome 146 API methods)
        if echo "$content" | grep -qiE "webmcp|modelContext|mcpServer|provideContext|registerTool" 2>/dev/null; then
            # Extract URLs from the file
            local urls
            urls=$(echo "$content" | grep -oE '(https?|wss?)://[A-Za-z0-9._~:/?#\[\]@!$&'"'"'()*+,;=-]+' 2>/dev/null || true)
            while IFS= read -r url; do
                [[ -z "$url" ]] && continue
                local host
                host=$(echo "$url" | sed -E 's|.*://([^/:]+).*|\1|')
                if ! is_trusted_origin "$host"; then
                    found_any=true
                    FINDINGS+=("$(emit_finding \
                        "CHK-WEB-001" \
                        "critical" \
                        "WebMCP endpoint connects to untrusted origin" \
                        "File $file contains a WebMCP-related configuration referencing untrusted origin ($host). Untrusted WebMCP origins can inject malicious tools into the agent context." \
                        "File: $file, URL: $url" \
                        "Verify the origin is trusted and add to allow-list, or remove the reference." \
                        ""
                    )")
                fi
            done <<< "$urls"
        fi
    done < <(gather_webmcp_files)

    if ! $found_any; then
        log_info "  No WebMCP service declarations found to check for untrusted origins."
    fi
}

# ---------------------------------------------------------------------------
# CHK-WEB-002: WebMCP service declares excessive capabilities
# ---------------------------------------------------------------------------
check_excessive_capabilities() {
    log_info "CHK-WEB-002: Checking for excessive WebMCP capabilities..."

    local found_any=false

    # Check config for capability declarations
    if [[ -f "$CONFIG_PATH" ]] && command -v jq &>/dev/null; then
        local cap_data
        cap_data=$(jq -r '
            ((.webmcp.services // [])[] | "\(.name // "unnamed"): \((.capabilities // []) | join(","))"),
            ((.mcpServers // {}) | to_entries[]? | "\(.key): \((.value.capabilities // []) | join(","))")
        ' "$CONFIG_PATH" 2>/dev/null || true)

        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            found_any=true
            local svc_name cap_str
            svc_name="${line%%:*}"
            cap_str="${line#*: }"

            for sensitive in "${SENSITIVE_CAPS[@]}"; do
                if contains_pattern "$cap_str" "$sensitive"; then
                    FINDINGS+=("$(emit_finding \
                        "CHK-WEB-002" \
                        "warn" \
                        "WebMCP service declares excessive capabilities" \
                        "WebMCP service '$svc_name' declares capabilities that include '$sensitive'. Services exposing filesystem, shell, or network operations significantly expand the attack surface." \
                        "Service: $svc_name, Capability match: $sensitive, Capabilities: $cap_str" \
                        "Apply least-privilege: remove '$sensitive' capability unless strictly required. Scope capabilities to specific resources." \
                        ""
                    )")
                    break  # one finding per service
                fi
            done
        done <<< "$cap_data"
    fi

    # Scan all WebMCP-related files for capability declarations
    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        [[ ! -f "$file" ]] && continue
        [[ "$file" == "$CONFIG_PATH" ]] && continue  # already checked

        local content
        content=$(cat "$file" 2>/dev/null || true)

        if echo "$content" | grep -qi "capabilities\|permissions" 2>/dev/null; then
            if echo "$content" | grep -qiE "webmcp|modelContext|mcpServer|provideContext|registerTool" 2>/dev/null; then
                for sensitive in "${SENSITIVE_CAPS[@]}"; do
                    if contains_pattern "$content" "\"$sensitive\""; then
                        found_any=true
                        FINDINGS+=("$(emit_finding \
                            "CHK-WEB-002" \
                            "warn" \
                            "WebMCP service declares excessive capabilities" \
                            "File $file contains a WebMCP-related configuration declaring '$sensitive' capability. Excessive capabilities give WebMCP services access to dangerous operations." \
                            "File: $file, Capability match: $sensitive" \
                            "Review and restrict capabilities in $file. Apply least-privilege." \
                            ""
                        )")
                        break  # one finding per file
                    fi
                done
            fi
        fi
    done < <(gather_webmcp_files)

    if ! $found_any; then
        log_info "  No excessive capability declarations found."
    fi
}

# ---------------------------------------------------------------------------
# CHK-WEB-003: WebMCP modelContext lacks capability scoping
# ---------------------------------------------------------------------------
check_model_context_scoping() {
    log_info "CHK-WEB-003: Checking for unscoped modelContext declarations..."

    local found_any=false

    # Check config for modelContext
    if [[ -f "$CONFIG_PATH" ]] && command -v jq &>/dev/null; then
        # Look for modelContext with wildcard or missing capability scoping
        local mc_data
        mc_data=$(jq -r '
            (.modelContext // {}) | to_entries[]? | "\(.key): \(.value | tostring)"
        ' "$CONFIG_PATH" 2>/dev/null || true)

        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            found_any=true
            local mc_name mc_value
            mc_name="${line%%:*}"
            mc_value="${line#*: }"

            # Check for wildcards in capability grants
            if echo "$mc_value" | grep -qE '"\*"|: ?\*|"all"|"any"' 2>/dev/null; then
                FINDINGS+=("$(emit_finding \
                    "CHK-WEB-003" \
                    "warn" \
                    "WebMCP modelContext lacks capability scoping" \
                    "modelContext '$mc_name' uses wildcard or overly broad capability grants ('*', 'all', 'any'). This allows any WebMCP service to access the full model context without restriction." \
                    "modelContext: $mc_name, Value contains wildcard grant" \
                    "Scope modelContext capabilities to specific services and resource types. Replace '*' with explicit capability lists." \
                    ""
                )")
            fi

            # Check for missing capability restrictions entirely
            if ! echo "$mc_value" | grep -qiE 'capabilities|scope|restrict|allow' 2>/dev/null; then
                FINDINGS+=("$(emit_finding \
                    "CHK-WEB-003" \
                    "warn" \
                    "WebMCP modelContext lacks capability scoping" \
                    "modelContext '$mc_name' does not define any capability scoping or restrictions. Without explicit scoping, all services can access this context data." \
                    "modelContext: $mc_name, No capability scoping found" \
                    "Add a 'capabilities' or 'scope' field to the modelContext declaration to restrict which services can access it." \
                    ""
                )")
            fi
        done <<< "$mc_data"
    fi

    # Scan files for modelContext declarations
    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        [[ ! -f "$file" ]] && continue
        [[ "$file" == "$CONFIG_PATH" ]] && continue

        local content
        content=$(cat "$file" 2>/dev/null || true)

        if echo "$content" | grep -qi "modelContext" 2>/dev/null; then
            found_any=true

            # Check for wildcard grants
            if echo "$content" | grep -qE '"modelContext"[^}]*"\*"' 2>/dev/null || \
               echo "$content" | grep -qE 'modelContext:.*\*' 2>/dev/null; then
                FINDINGS+=("$(emit_finding \
                    "CHK-WEB-003" \
                    "warn" \
                    "WebMCP modelContext lacks capability scoping" \
                    "File $file contains a modelContext declaration with wildcard or overly broad capability grants. This allows unrestricted access to model context data." \
                    "File: $file contains wildcard modelContext grant" \
                    "Replace wildcard grants with explicit capability scoping in modelContext declarations." \
                    ""
                )")
            fi
        fi
    done < <(gather_webmcp_files)

    if ! $found_any; then
        log_info "  No unscoped modelContext declarations found."
    fi
}

# ---------------------------------------------------------------------------
# CHK-WEB-004: WebMCP cross-origin service injection
# ---------------------------------------------------------------------------
check_cross_origin_injection() {
    log_info "CHK-WEB-004: Checking for cross-origin service injection risks..."

    local found_any=false

    if [[ -f "$CONFIG_PATH" ]] && command -v jq &>/dev/null; then
        # Extract all service declarations with their origins (null-safe)
        local svc_origins
        svc_origins=$(jq -r '
            [(.webmcp.services // [])[] | {name: (.name // "unnamed"), origin: (.origin // null // "unknown")}] |
            map(select(.origin != null)) |
            group_by(.origin) |
            map(select(length > 0) | {origin: .[0].origin, services: [.[].name]}) |
            .[] | "\(.origin // "unknown")|\(.services | join(","))"
        ' "$CONFIG_PATH" 2>/dev/null || true)

        # Check if origins can register services that look like they belong to other origins
        local all_origins=()
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            found_any=true
            local origin svc_list
            origin="${line%%|*}"
            svc_list="${line#*|}"
            all_origins+=("$origin")
        done <<< "$svc_origins"

        # If multiple distinct origins exist, check for namespace collision
        if [[ ${#all_origins[@]} -gt 1 ]]; then
            # Check if any origin lacks origin-binding / namespace isolation
            local isolation
            isolation=$(jq -r '.webmcp.originIsolation // "null"' "$CONFIG_PATH" 2>/dev/null || echo "null")
            if [[ "$isolation" == "null" ]] || [[ "$isolation" == "false" ]]; then
                FINDINGS+=("$(emit_finding \
                    "CHK-WEB-004" \
                    "critical" \
                    "WebMCP cross-origin service injection" \
                    "Multiple WebMCP service origins detected (${all_origins[*]}) but origin isolation is not enabled. One origin could register services that impersonate another origin's services, hijacking tool calls." \
                    "Origins: ${all_origins[*]}, originIsolation: $isolation" \
                    "Enable webmcp.originIsolation in openclaw.json. Use origin-namespaced service names (e.g., 'origin.example.com/serviceName')." \
                    "jq '.webmcp.originIsolation = true' \"${CONFIG_PATH}\" > \"${CONFIG_PATH}.tmp\" && mv \"${CONFIG_PATH}.tmp\" \"${CONFIG_PATH}\""
                )")
            fi
        fi

        # Check for services without origin binding
        local unbound_svcs
        unbound_svcs=$(jq -r '
            [(.webmcp.services // [])[] | select(.origin == null or .origin == "") | .name // "unnamed"] | join(", ")
        ' "$CONFIG_PATH" 2>/dev/null || true)
        if [[ -n "$unbound_svcs" ]]; then
            found_any=true
            FINDINGS+=("$(emit_finding \
                "CHK-WEB-004" \
                "critical" \
                "WebMCP cross-origin service injection" \
                "WebMCP services without origin binding detected: $unbound_svcs. Services without origin binding can be impersonated by any connected origin." \
                "Unbound services: $unbound_svcs" \
                "Bind every WebMCP service to a specific origin. Set the 'origin' field in each service declaration." \
                ""
            )")
        fi
    fi

    # Scan browser extension policies for cross-origin WebMCP risks
    local extension_dirs=()
    if [[ "$(detect_os)" == "macos" ]]; then
        extension_dirs+=(
            "$HOME/Library/Application Support/Google/Chrome/Default/Extensions"
            "$HOME/Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions"
            "$HOME/Library/Application Support/Microsoft Edge/Default/Extensions"
        )
    else
        extension_dirs+=(
            "$HOME/.config/google-chrome/Default/Extensions"
            "$HOME/.config/BraveSoftware/Brave-Browser/Default/Extensions"
            "$HOME/.config/microsoft-edge/Default/Extensions"
        )
    fi

    for ext_dir in "${extension_dirs[@]}"; do
        if [[ -d "$ext_dir" ]]; then
            while IFS= read -r -d '' manifest; do
                [[ ! -f "$manifest" ]] && continue
                local manifest_content
                manifest_content=$(cat "$manifest" 2>/dev/null || true)

                if echo "$manifest_content" | grep -qiE "webmcp|model\.context|mcpServer|provideContext|registerTool" 2>/dev/null; then
                    found_any=true
                    # Check if extension has cross-origin permissions
                    local has_all_urls
                    has_all_urls=$(echo "$manifest_content" | grep -c '"<all_urls>"' 2>/dev/null || echo "0")
                    if [[ "$has_all_urls" -gt 0 ]]; then
                        FINDINGS+=("$(emit_finding \
                            "CHK-WEB-004" \
                            "critical" \
                            "WebMCP cross-origin service injection via browser extension" \
                            "Browser extension at $manifest has <all_urls> permission and references WebMCP. It could inject services across any origin." \
                            "Extension manifest: $manifest, has <all_urls> permission" \
                            "Restrict extension permissions to specific origins. Review the extension for WebMCP service injection capabilities." \
                            ""
                        )")
                    fi
                fi
            done < <(find "$ext_dir" -name "manifest.json" -print0 2>/dev/null || true)
        fi
    done

    if ! $found_any; then
        log_info "  No cross-origin injection risks found."
    fi
}

# ---------------------------------------------------------------------------
# CHK-WEB-005: WebMCP service data exfiltration risk
# ---------------------------------------------------------------------------
check_data_exfiltration() {
    log_info "CHK-WEB-005: Checking for data exfiltration risks..."

    local found_any=false

    if [[ -f "$CONFIG_PATH" ]] && command -v jq &>/dev/null; then
        # Check if any WebMCP service has access to sensitive data paths
        local svc_data
        svc_data=$(jq -r '
            (.webmcp.services // [])[] | "\(.name // "unnamed")|\(.dataAccess // [] | join(","))|\(.scope // "")"
        ' "$CONFIG_PATH" 2>/dev/null || true)

        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            found_any=true
            local svc_name data_access scope
            svc_name="$(echo "$line" | cut -d'|' -f1)"
            data_access="$(echo "$line" | cut -d'|' -f2)"
            scope="$(echo "$line" | cut -d'|' -f3)"

            for pattern in "${SENSITIVE_DATA_PATTERNS[@]}"; do
                if contains_pattern "$data_access" "$pattern" || contains_pattern "$scope" "$pattern"; then
                    FINDINGS+=("$(emit_finding \
                        "CHK-WEB-005" \
                        "critical" \
                        "WebMCP service data exfiltration risk" \
                        "WebMCP service '$svc_name' can access sensitive agent data matching '$pattern'. A compromised or malicious service could exfiltrate conversation history, memory, credentials, or other agent state." \
                        "Service: $svc_name, Sensitive data access: $pattern" \
                        "Remove access to sensitive data from the service declaration. Use data access scoping to limit what each service can read." \
                        ""
                    )")
                    break
                fi
            done
        done <<< "$svc_data"
    fi

    # Check for WebMCP services that reference sensitive file paths
    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        [[ ! -f "$file" ]] && continue
        [[ "$file" == "$CONFIG_PATH" ]] && continue

        local content
        content=$(cat "$file" 2>/dev/null || true)

        if echo "$content" | grep -qiE "webmcp|mcpServer|provideContext|registerTool|modelContext" 2>/dev/null; then
            for pattern in "${SENSITIVE_DATA_PATTERNS[@]}"; do
                if contains_pattern "$content" "$pattern"; then
                    found_any=true
                    FINDINGS+=("$(emit_finding \
                        "CHK-WEB-005" \
                        "critical" \
                        "WebMCP service data exfiltration risk" \
                        "File $file contains WebMCP configuration referencing sensitive data pattern '$pattern'. This indicates a WebMCP service may have access to agent memory, context, or credentials." \
                        "File: $file, Pattern: $pattern" \
                        "Audit the WebMCP service configuration. Remove references to sensitive agent data and restrict data access scope." \
                        ""
                    )")
                    break
                fi
            done
        fi
    done < <(gather_webmcp_files)

    # Check if any WebMCP service can access the workspace memory directory
    if [[ -d "$WORKSPACE_DIR" ]]; then
        local memory_dir="$WORKSPACE_DIR/memory"
        if [[ -d "$memory_dir" ]] && [[ -f "$CONFIG_PATH" ]] && command -v jq &>/dev/null; then
            local has_fs_access
            has_fs_access=$(jq -r '
                [(.webmcp.services // [])[] | select(
                    (.capabilities // [] | map(select(test("filesystem|file|read|write"; "i"))) | length > 0) or
                    (.dataAccess // [] | map(select(test("workspace|memory|\\.openclaw"; "i"))) | length > 0)
                ) | .name // "unnamed"] | join(", ")
            ' "$CONFIG_PATH" 2>/dev/null || true)

            if [[ -n "$has_fs_access" ]]; then
                found_any=true
                FINDINGS+=("$(emit_finding \
                    "CHK-WEB-005" \
                    "critical" \
                    "WebMCP service data exfiltration risk" \
                    "WebMCP services with filesystem access ($has_fs_access) could read agent memory files from $memory_dir. These files contain conversation history and personal context." \
                    "Services with filesystem access: $has_fs_access, Memory dir exists: $memory_dir" \
                    "Revoke filesystem access from WebMCP services or restrict to a safe subdirectory." \
                    ""
                )")
            fi
        fi
    fi

    if ! $found_any; then
        log_info "  No data exfiltration risks found."
    fi
}

# ---------------------------------------------------------------------------
# CHK-WEB-006: WebMCP prompt injection via service description
# ---------------------------------------------------------------------------
check_prompt_injection() {
    log_info "CHK-WEB-006: Checking for prompt injection in service descriptions..."

    local found_any=false

    if [[ -f "$CONFIG_PATH" ]] && command -v jq &>/dev/null; then
        # Extract all service descriptions and tool names
        # Covers both config-level service declarations and provideContext-style
        # tool registrations (Chrome 146 API: provideContext({ tools: [...] }))
        local svc_descs
        svc_descs=$(jq -r '
            ((.webmcp.services // [])[] | "\(.name // "unnamed")|\(.description // "")"),
            ((.webmcp.tools // [])[] | "\(.name // "unnamed")|\(.description // "")"),
            ((.mcpServers // {}) | to_entries[]? | "\(.key)|\(.value.description // "")")
        ' "$CONFIG_PATH" 2>/dev/null || true)

        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local svc_name svc_desc
            svc_name="${line%%|*}"
            svc_desc="${line#*|}"
            [[ -z "$svc_desc" ]] && continue
            found_any=true

            for pattern in "${PROMPT_INJECTION_PATTERNS[@]}"; do
                if echo "$svc_desc" | grep -qiE "$pattern" 2>/dev/null; then
                    FINDINGS+=("$(emit_finding \
                        "CHK-WEB-006" \
                        "critical" \
                        "WebMCP prompt injection via service description" \
                        "WebMCP service '$svc_name' has a description containing a prompt injection pattern ('$pattern'). Service descriptions are included in the model context and can manipulate agent behavior." \
                        "Service: $svc_name, Injection pattern: $pattern, Description excerpt: $(echo "$svc_desc" | head -c 200)" \
                        "Remove or sanitize the service description. Do not include instruction-like text in service descriptions. Consider description content filtering." \
                        ""
                    )")
                    break
                fi
            done
        done <<< "$svc_descs"
    fi

    # Scan all WebMCP-related files for prompt injection in descriptions
    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        [[ ! -f "$file" ]] && continue
        [[ "$file" == "$CONFIG_PATH" ]] && continue

        local content
        content=$(cat "$file" 2>/dev/null || true)

        # Only check files with WebMCP references (config or Chrome 146 API)
        if echo "$content" | grep -qiE "webmcp|mcpServer|modelContext|provideContext|registerTool" 2>/dev/null; then
            # Extract description-like fields
            local descriptions
            descriptions=$(echo "$content" | grep -oiE '"description"\s*:\s*"[^"]*"' 2>/dev/null || true)

            while IFS= read -r desc_line; do
                [[ -z "$desc_line" ]] && continue
                found_any=true

                for pattern in "${PROMPT_INJECTION_PATTERNS[@]}"; do
                    if echo "$desc_line" | grep -qiE "$pattern" 2>/dev/null; then
                        FINDINGS+=("$(emit_finding \
                            "CHK-WEB-006" \
                            "critical" \
                            "WebMCP prompt injection via service description" \
                            "File $file contains a WebMCP service description with prompt injection pattern ('$pattern'). Injected instructions in service descriptions are processed by the model and can override safety behaviors." \
                            "File: $file, Pattern: $pattern" \
                            "Review and sanitize all service descriptions in $file. Strip instruction-like content." \
                            ""
                        )")
                        break 2  # one finding per file
                    fi
                done
            done <<< "$descriptions"
        fi
    done < <(gather_webmcp_files)

    # -----------------------------------------------------------------------
    # Deep scan: Check JS/TS files for prompt injection in execute callbacks
    # and provideContext tool registrations (Chrome 146 API).
    #
    # In the real API, tools are registered via:
    #   navigator.modelContext.provideContext({ tools: [{ name, description,
    #       inputSchema, execute: function(input) { ... } }] })
    #   navigator.modelContext.registerTool({ name, description,
    #       inputSchema, execute: function(input) { ... } })
    #
    # The execute callback source code can contain prompt injection payloads
    # that get returned to the model as tool output.
    # -----------------------------------------------------------------------
    if [[ "$CLAWPINCH_DEEP" == "1" ]]; then
        log_info "  Deep scan: checking JS/TS files for execute callback injection..."

        local js_search_dirs=("$OPENCLAW_DIR")
        [[ -d "$WORKSPACE_DIR" ]] && js_search_dirs+=("$WORKSPACE_DIR")
        [[ -d "$SKILLS_DIR" ]] && js_search_dirs+=("$SKILLS_DIR")

        for dir in "${js_search_dirs[@]}"; do
            [[ ! -d "$dir" ]] && continue
            while IFS= read -r -d '' jsfile; do
                [[ ! -f "$jsfile" ]] && continue
                local jscontent
                jscontent=$(cat "$jsfile" 2>/dev/null || true)

                # Look for provideContext or registerTool calls
                if echo "$jscontent" | grep -qE '(provideContext|registerTool|modelContext)' 2>/dev/null; then
                    found_any=true

                    # Check for injection patterns in the entire file (covers
                    # execute callbacks, description strings, and tool names)
                    for pattern in "${PROMPT_INJECTION_PATTERNS[@]}"; do
                        if echo "$jscontent" | grep -qiE "$pattern" 2>/dev/null; then
                            FINDINGS+=("$(emit_finding \
                                "CHK-WEB-006" \
                                "critical" \
                                "WebMCP prompt injection in tool execute callback" \
                                "File $jsfile uses the WebMCP API (provideContext/registerTool) and contains prompt injection pattern ('$pattern'). Execute callbacks that return attacker-controlled strings can inject instructions into the model context." \
                                "File: $jsfile, Pattern: $pattern" \
                                "Audit execute callback return values. Sanitize any user/external data before returning it from tool execute functions. Do not embed instruction-like text in tool output." \
                                ""
                            )")
                            break  # one finding per file
                        fi
                    done
                fi
            done < <(find "$dir" -maxdepth 5 \
                \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" -o -name "*.mts" -o -name "*.jsx" -o -name "*.tsx" \) \
                -not -path "*/node_modules/*" \
                -not -path "*/.git/*" \
                -print0 2>/dev/null || true)
        done
    fi

    if ! $found_any; then
        log_info "  No prompt injection patterns found in service descriptions."
    fi
}

# ---------------------------------------------------------------------------
# CHK-WEB-007: WebMCP service lacks authentication
# ---------------------------------------------------------------------------
check_missing_auth() {
    log_info "CHK-WEB-007: Checking for unauthenticated WebMCP services..."

    local found_any=false

    if [[ -f "$CONFIG_PATH" ]] && command -v jq &>/dev/null; then
        # Check global WebMCP auth configuration
        local global_auth
        global_auth=$(jq -r '.webmcp.auth // "null"' "$CONFIG_PATH" 2>/dev/null || echo "null")

        if [[ "$global_auth" == "null" ]] || [[ "$global_auth" == "false" ]] || [[ "$global_auth" == "none" ]]; then
            # Check if any services exist without per-service auth
            local svc_count
            svc_count=$(jq -r '(.webmcp.services // []) | length' "$CONFIG_PATH" 2>/dev/null || echo "0")

            if [[ "$svc_count" -gt 0 ]]; then
                found_any=true
                FINDINGS+=("$(emit_finding \
                    "CHK-WEB-007" \
                    "warn" \
                    "WebMCP service lacks authentication" \
                    "WebMCP global authentication is not configured but $svc_count service(s) are declared. Without auth, any origin that can reach the WebMCP endpoint can invoke services." \
                    "webmcp.auth: $global_auth, Service count: $svc_count" \
                    "Enable webmcp.auth with token-based or OAuth authentication. Set a strong token in webmcp.auth.token." \
                    "jq '.webmcp.auth = {\"type\": \"token\", \"required\": true}' \"${CONFIG_PATH}\" > \"${CONFIG_PATH}.tmp\" && mv \"${CONFIG_PATH}.tmp\" \"${CONFIG_PATH}\""
                )")
            fi
        fi

        # Check individual services for auth overrides
        local noauth_svcs
        noauth_svcs=$(jq -r '
            [(.webmcp.services // [])[] |
             select(.auth == null or .auth == false or .auth == "none" or .auth.required == false) |
             .name // "unnamed"] | join(", ")
        ' "$CONFIG_PATH" 2>/dev/null || true)

        if [[ -n "$noauth_svcs" ]]; then
            found_any=true
            FINDINGS+=("$(emit_finding \
                "CHK-WEB-007" \
                "warn" \
                "WebMCP service lacks authentication" \
                "The following WebMCP services have no authentication requirement: $noauth_svcs. Unauthenticated services can be invoked by any connected client without verifying identity." \
                "Unauthenticated services: $noauth_svcs" \
                "Add auth requirements to each service: set 'auth.required: true' in the service declaration." \
                ""
            )")
        fi

        # Check MCP servers for auth
        local mcp_noauth
        mcp_noauth=$(jq -r '
            [(.mcpServers // {}) | to_entries[]? |
             select(.value.auth == null or .value.auth == false) |
             .key] | join(", ")
        ' "$CONFIG_PATH" 2>/dev/null || true)

        if [[ -n "$mcp_noauth" ]]; then
            found_any=true
            FINDINGS+=("$(emit_finding \
                "CHK-WEB-007" \
                "warn" \
                "WebMCP service lacks authentication" \
                "MCP server(s) configured without authentication: $mcp_noauth. Connections to these servers are not authenticated, allowing potential MITM or unauthorized access." \
                "MCP servers without auth: $mcp_noauth" \
                "Configure auth for each MCP server connection. Use token-based auth at minimum." \
                ""
            )")
        fi
    fi

    if ! $found_any; then
        log_info "  No unauthenticated WebMCP services found (or no WebMCP services configured)."
    fi
}

# ---------------------------------------------------------------------------
# CHK-WEB-008: WebMCP declarative form auto-submission risk
# ---------------------------------------------------------------------------
check_form_auto_submission() {
    log_info "CHK-WEB-008: Checking for declarative form auto-submission risks..."

    local found_any=false

    if [[ -f "$CONFIG_PATH" ]] && command -v jq &>/dev/null; then
        # Check for form-type services with auto-submit enabled
        local form_svcs
        form_svcs=$(jq -r '
            (.webmcp.services // [])[] |
            select(.type == "form" or .type == "declarative-form" or .inputSchema != null) |
            "\(.name // "unnamed")|\(.autoSubmit // "null")|\(.confirmRequired // "null")"
        ' "$CONFIG_PATH" 2>/dev/null || true)

        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            found_any=true
            local svc_name auto_submit confirm_required
            svc_name="$(echo "$line" | cut -d'|' -f1)"
            auto_submit="$(echo "$line" | cut -d'|' -f2)"
            confirm_required="$(echo "$line" | cut -d'|' -f3)"

            if [[ "$auto_submit" == "true" ]] || [[ "$auto_submit" != "false" && "$confirm_required" != "true" ]]; then
                FINDINGS+=("$(emit_finding \
                    "CHK-WEB-008" \
                    "warn" \
                    "WebMCP declarative form auto-submission risk" \
                    "WebMCP form service '$svc_name' may auto-submit data without user confirmation. Declarative forms can be pre-filled by the model and submitted automatically, potentially sending sensitive data to external endpoints." \
                    "Service: $svc_name, autoSubmit: $auto_submit, confirmRequired: $confirm_required" \
                    "Set 'autoSubmit: false' and 'confirmRequired: true' for all form-type WebMCP services." \
                    ""
                )")
            fi
        done <<< "$form_svcs"

        # Check for inputSchema services that could auto-submit
        local schema_svcs
        schema_svcs=$(jq -r '
            (.webmcp.services // [])[] |
            select(.inputSchema != null and (.confirmRequired == null or .confirmRequired == false)) |
            .name // "unnamed"
        ' "$CONFIG_PATH" 2>/dev/null || true)

        while IFS= read -r svc_name; do
            [[ -z "$svc_name" ]] && continue
            found_any=true
            FINDINGS+=("$(emit_finding \
                "CHK-WEB-008" \
                "warn" \
                "WebMCP declarative form auto-submission risk" \
                "WebMCP service '$svc_name' defines an inputSchema but does not require user confirmation. The agent could auto-fill and submit this form with sensitive data from context." \
                "Service: $svc_name, has inputSchema, confirmRequired not set" \
                "Add 'confirmRequired: true' to services with inputSchema to ensure user reviews before submission." \
                ""
            )")
        done <<< "$schema_svcs"
    fi

    # Scan files for form-like WebMCP declarations
    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        [[ ! -f "$file" ]] && continue
        [[ "$file" == "$CONFIG_PATH" ]] && continue

        local content
        content=$(cat "$file" 2>/dev/null || true)

        if echo "$content" | grep -qiE "webmcp|mcpServer|provideContext|registerTool|modelContext" 2>/dev/null; then
            if echo "$content" | grep -qiE "auto.?submit|inputSchema|declarative.?form" 2>/dev/null; then
                if ! echo "$content" | grep -qi "confirmRequired.*true" 2>/dev/null; then
                    found_any=true
                    FINDINGS+=("$(emit_finding \
                        "CHK-WEB-008" \
                        "warn" \
                        "WebMCP declarative form auto-submission risk" \
                        "File $file contains WebMCP form declarations without explicit user confirmation requirements. Auto-submitted forms could leak sensitive context data." \
                        "File: $file contains form/inputSchema without confirmRequired" \
                        "Add 'confirmRequired: true' to all form-type declarations in $file." \
                        ""
                    )")
                fi
            fi
        fi
    done < <(gather_webmcp_files)

    if ! $found_any; then
        log_info "  No form auto-submission risks found."
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log_info "WebMCP Security Scanner starting..."
    log_info "Config path: $CONFIG_PATH"
    log_info "OpenClaw dir: $OPENCLAW_DIR"
    log_info "Deep scan: $CLAWPINCH_DEEP"

    # Verify jq is available
    if ! command -v jq &>/dev/null; then
        echo '[{"id":"CHK-WEB-000","severity":"critical","title":"jq not found","description":"The jq command is required for JSON parsing but was not found.","evidence":"command -v jq returned non-zero","remediation":"Install jq: brew install jq (macOS) or apt-get install jq (Linux)","auto_fix":""}]'
        exit 1
    fi

    # Run all checks
    check_untrusted_origins
    check_excessive_capabilities
    check_model_context_scoping
    check_cross_origin_injection
    check_data_exfiltration
    check_prompt_injection
    check_missing_auth
    check_form_auto_submission

    # Output all findings as a JSON array
    if [[ ${#FINDINGS[@]} -eq 0 ]]; then
        echo '[]'
    else
        printf '%s\n' "${FINDINGS[@]}" | jq -s '.'
    fi
}

main "$@"
