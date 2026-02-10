# ClawPinch WebMCP Check Catalog

Complete reference for all 8 WebMCP security checks. Each entry includes the
check ID, severity, description, and remediation.

Scanner: `scan_webmcp.sh`
Category prefix: `CHK-WEB`

---

## WebMCP (CHK-WEB)

### CHK-WEB-001 -- WebMCP endpoint connects to untrusted origin
- **Severity:** Critical
- **Description:** A WebMCP service declaration references an origin (hostname, URL, or endpoint) that is not in the trusted origins allow-list. WebMCP origins serve tool definitions that the agent will execute — an untrusted origin can serve malicious tools that exfiltrate data, modify files, or execute arbitrary commands on the host.
- **Evidence:** The scanner extracts all origins from `webmcp.services[].origin`, `webmcp.endpoints[].url`, and `mcpServers.*.url` in `openclaw.json`, as well as URLs found in any WebMCP-related config files across the workspace and skills directories. Each origin is compared against the trusted origins list.
- **Remediation:** Add the origin to `WEBMCP_TRUSTED_ORIGINS` (environment variable, comma-separated) if it is genuinely trusted. Otherwise, remove the service declaration. Only connect to WebMCP origins you control or have explicitly verified.
- **Auto-fix:** N/A — requires manual trust decision.
- **References:** WebMCP Threat Model §1 (Untrusted Origin Attack)

### CHK-WEB-002 -- WebMCP service declares excessive capabilities
- **Severity:** Warn
- **Description:** A WebMCP service declares capabilities that include sensitive operations such as `filesystem`, `shell`, `exec`, `network`, `process`, `admin`, `sudo`, `root`, `system`, `os`, `child_process`, `spawn`, or `eval`. Services with these capabilities can read/write arbitrary files, execute system commands, or make network connections — dramatically expanding the attack surface.
- **Evidence:** The scanner checks capability lists in `webmcp.services[].capabilities` and `mcpServers.*.capabilities` from the config, plus any file in the workspace/skills tree that contains both WebMCP references and sensitive capability keywords.
- **Remediation:** Apply the principle of least privilege. Remove sensitive capabilities unless the service strictly requires them. Scope capabilities to specific resources (e.g., `filesystem:read:/tmp/safe-dir` instead of `filesystem`).
- **Auto-fix:** N/A — requires understanding of service requirements.
- **References:** WebMCP Threat Model §2 (Capability Escalation)

### CHK-WEB-003 -- WebMCP modelContext lacks capability scoping
- **Severity:** Warn
- **Description:** A `modelContext` declaration uses wildcard (`*`), `all`, or `any` capability grants, or lacks any capability scoping entirely. Without scoping, all connected WebMCP services can access the full model context, including conversation history, system prompts, and agent state. This violates the principle of least privilege and enables data leakage to untrusted services.
- **Evidence:** The scanner parses `modelContext` entries from `openclaw.json` and scans workspace files for `modelContext` declarations. It flags entries containing wildcard grants or missing `capabilities`/`scope`/`restrict`/`allow` fields.
- **Remediation:** Add explicit `capabilities` or `scope` fields to each `modelContext` declaration. Replace `*` with a list of specific services that should have access. Example: `"scope": ["trusted-service-1", "trusted-service-2"]`.
- **Auto-fix:** N/A — requires knowledge of which services need context access.
- **References:** WebMCP Threat Model §3 (Context Leakage)

### CHK-WEB-004 -- WebMCP cross-origin service injection
- **Severity:** Critical
- **Description:** Multiple WebMCP service origins are configured but origin isolation (`webmcp.originIsolation`) is not enabled, or services lack origin binding. Without isolation, one origin can register services with names that collide with or impersonate services from another origin. An attacker controlling any connected origin can hijack tool calls intended for trusted services.
- **Evidence:** The scanner groups services by origin from `webmcp.services[]` in `openclaw.json`, checks the `webmcp.originIsolation` setting, identifies services without an `origin` field, and scans browser extension manifests for WebMCP-related extensions with `<all_urls>` permission.
- **Remediation:** Enable `webmcp.originIsolation: true` in `openclaw.json`. Ensure every service declaration includes an `origin` field. Use origin-namespaced service names (e.g., `example.com/myService`). Review browser extensions for excessive permissions.
- **Auto-fix:** `jq '.webmcp.originIsolation = true' openclaw.json > tmp && mv tmp openclaw.json`
- **References:** WebMCP Threat Model §4 (Cross-Origin Impersonation)

### CHK-WEB-005 -- WebMCP service data exfiltration risk
- **Severity:** Critical
- **Description:** A WebMCP service has access to sensitive agent data — including `memory`, `context`, `history`, `conversation`, `agent_state`, `session`, `credentials`, `secrets`, `keychain`, `token`, `MEMORY.md`, `SOUL.md`, or `USER.md`. A compromised or malicious service with access to this data can exfiltrate private conversations, personal context, and authentication credentials.
- **Evidence:** The scanner checks `dataAccess` and `scope` fields in service declarations, scans WebMCP-related files for sensitive data pattern references, and checks whether services with filesystem capabilities could access the workspace `memory/` directory.
- **Remediation:** Remove access to sensitive data from WebMCP service declarations. Use data access scoping (`dataAccess: []` with explicit allow-list). Never grant filesystem access to WebMCP services that connect to external origins. Isolate agent memory from WebMCP service scope.
- **Auto-fix:** N/A — requires per-service data access review.
- **References:** WebMCP Threat Model §5 (Data Exfiltration)

### CHK-WEB-006 -- WebMCP prompt injection via service description
- **Severity:** Critical
- **Description:** A WebMCP service description contains patterns consistent with prompt injection — phrases like "ignore previous instructions", "you are now", "act as", "system prompt", "jailbreak", or LLM-specific control tokens (`[INST]`, `<<SYS>>`, `<|im_start|>`). Service descriptions are included in the model context and directly influence agent behavior. A malicious description can override safety rules, change the agent's persona, or instruct it to perform harmful actions.
- **Evidence:** The scanner extracts `description` fields from `webmcp.services[]` and `mcpServers.*` in the config, plus description-like fields from all WebMCP-related files in the workspace. Each is tested against a library of known prompt injection patterns.
- **Remediation:** Sanitize all service descriptions. Remove instruction-like text, control tokens, and persona-override phrases. Implement server-side description content filtering. Consider limiting description length and character set.
- **Auto-fix:** N/A — requires manual review and sanitization.
- **References:** WebMCP Threat Model §6 (Indirect Prompt Injection)

### CHK-WEB-007 -- WebMCP service lacks authentication
- **Severity:** Warn
- **Description:** WebMCP services are configured without authentication requirements. This includes: global `webmcp.auth` not set or disabled, individual services with `auth: null/false/none`, or MCP server connections without auth configuration. Unauthenticated services can be invoked by any connected client, and unauthenticated connections to MCP servers are vulnerable to MITM attacks.
- **Evidence:** The scanner checks `webmcp.auth` global config, per-service `auth` fields in `webmcp.services[]`, and `auth` fields in `mcpServers.*` entries.
- **Remediation:** Enable authentication globally: set `webmcp.auth.type` to `"token"` or `"oauth"` with `webmcp.auth.required: true`. For individual services, set `auth.required: true`. For MCP server connections, configure auth tokens.
- **Auto-fix:** `jq '.webmcp.auth = {"type": "token", "required": true}' openclaw.json > tmp && mv tmp openclaw.json`
- **References:** WebMCP Threat Model §7 (Unauthenticated Access)

### CHK-WEB-008 -- WebMCP declarative form auto-submission risk
- **Severity:** Warn
- **Description:** A WebMCP form-type service (type `form`, `declarative-form`, or any service with `inputSchema`) allows auto-submission without requiring user confirmation. The model can pre-fill form fields with data from the conversation context (including credentials, personal information, and other sensitive data) and submit automatically to the service endpoint. Without `confirmRequired: true`, the user never sees what data is being sent.
- **Evidence:** The scanner checks services with `type: "form"` or `inputSchema` in config, looking for `autoSubmit: true` or missing `confirmRequired: true`. It also scans workspace files for form-like WebMCP declarations.
- **Remediation:** Set `autoSubmit: false` and `confirmRequired: true` for all form-type WebMCP services. This ensures the user can review form data before submission. Consider also adding a `sensitiveFields` declaration to mask credentials in the review UI.
- **Auto-fix:** N/A — requires per-service configuration review.
- **References:** WebMCP Threat Model §8 (Form Data Leakage)
