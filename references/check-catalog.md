# ClawPinch Check Catalog

Complete reference for all 63 checks. Each entry includes the check ID,
severity, description, and remediation.

---

## Configuration (CHK-CFG)

### CHK-CFG-001 -- Gateway listening on 0.0.0.0
- **Severity:** Critical
- **Description:** The gateway `bindAddress` is set to `0.0.0.0`, exposing it on all network interfaces. Any device on the local network (or the internet, if port-forwarded) can connect.
- **Remediation:** Set `gateway.bindAddress` to `127.0.0.1:<port>` in `openclaw.json`.
- **Auto-fix:** `jq '.gateway.bindAddress = "127.0.0.1:3000"' openclaw.json > tmp && mv tmp openclaw.json`

### CHK-CFG-002 -- Gateway auth disabled
- **Severity:** Critical
- **Description:** The gateway does not require authentication. Anyone who can reach the gateway port can issue commands.
- **Remediation:** Set `gateway.requireAuth` to `true` and configure an auth token.
- **Auto-fix:** `jq '.gateway.requireAuth = true' openclaw.json > tmp && mv tmp openclaw.json`

### CHK-CFG-003 -- TLS not enabled on gateway
- **Severity:** Critical
- **Description:** The gateway communicates over unencrypted HTTP/WS. Credentials and conversation data are transmitted in plaintext.
- **Remediation:** Configure `gateway.tls.certFile` and `gateway.tls.keyFile` in `openclaw.json`.

### CHK-CFG-004 -- Debug mode enabled in production
- **Severity:** Warn
- **Description:** Debug mode exposes stack traces, internal state, and may disable security features.
- **Remediation:** Set `gateway.debug` to `false`.

### CHK-CFG-005 -- Config file world-readable
- **Severity:** Warn
- **Description:** The `openclaw.json` file has permissions that allow any user on the system to read it. It may contain secrets.
- **Remediation:** `chmod 600 openclaw.json`
- **Auto-fix:** `chmod 600 "$CONFIG_PATH"`

### CHK-CFG-006 -- Default admin credentials unchanged
- **Severity:** Critical
- **Description:** The gateway is using default admin credentials (`admin`/`admin` or similar). Automated scanners check for these first.
- **Remediation:** Change admin credentials immediately and rotate the auth token.

### CHK-CFG-007 -- Permissive CORS policy (wildcard origin)
- **Severity:** Warn
- **Description:** `gateway.cors.allowedOrigins` is set to `*`, allowing any website to make cross-origin requests to the gateway.
- **Remediation:** Restrict `allowedOrigins` to specific trusted domains.

### CHK-CFG-008 -- Session timeout exceeds 24 hours
- **Severity:** Warn
- **Description:** Long session timeouts increase the window for session hijacking.
- **Remediation:** Set `gateway.sessionTimeout` to 3600 (1 hour) or less.

### CHK-CFG-009 -- Rate limiting not configured
- **Severity:** Warn
- **Description:** Without rate limiting, the gateway is vulnerable to brute-force attacks and denial of service.
- **Remediation:** Configure `gateway.rateLimit` with appropriate thresholds.

### CHK-CFG-010 -- Audit logging disabled
- **Severity:** Warn
- **Description:** Without audit logging, there is no record of who did what. Incident response is severely hampered.
- **Remediation:** Set `gateway.auditLog.enabled` to `true`.

---

## Secrets (CHK-SEC)

### CHK-SEC-001 -- API key found in config file
- **Severity:** Critical
- **Description:** A string matching API key patterns (e.g., `sk-`, `key-`, `AKIA`) was found in the configuration file.
- **Remediation:** Move secrets to a dedicated secrets manager or an `.env` file excluded from version control.

### CHK-SEC-002 -- Hardcoded password in skill manifest
- **Severity:** Critical
- **Description:** A skill manifest contains a field with a literal password value.
- **Remediation:** Use environment variable references or a secrets API instead of hardcoded values.

### CHK-SEC-003 -- Private key in config directory
- **Severity:** Critical
- **Description:** A PEM-encoded private key file was found in the OpenClaw config directory.
- **Remediation:** Move private keys to a secure location with `chmod 600` and reference via path.

### CHK-SEC-004 -- .env file with secrets in working directory
- **Severity:** Warn
- **Description:** A `.env` file containing secret-like values exists in the working directory and may be accidentally committed.
- **Remediation:** Add `.env` to `.gitignore`. Verify it is not tracked by version control.

### CHK-SEC-005 -- Token in shell history
- **Severity:** Warn
- **Description:** An API token or password was found in shell history files (`~/.bash_history`, `~/.zsh_history`).
- **Remediation:** Clear the history entry. Use environment variables or config files instead of passing secrets on the command line.

### CHK-SEC-006 -- Unencrypted credential store
- **Severity:** Warn
- **Description:** The OpenClaw credential store is not encrypted at rest.
- **Remediation:** Enable credential store encryption in `openclaw.json`.

### CHK-SEC-007 -- Secret passed via environment variable
- **Severity:** Info
- **Description:** Secrets are passed via environment variables. While better than hardcoding, env vars can leak through process listings and child processes.
- **Remediation:** Consider a secrets manager for high-sensitivity deployments.

### CHK-SEC-008 -- Git repo contains committed secrets
- **Severity:** Critical
- **Description:** Git history contains commits with secret values. Even if removed from HEAD, secrets persist in history.
- **Remediation:** Rotate the exposed secret. Use `git filter-repo` to purge from history.

---

## Network (CHK-NET)

### CHK-NET-001 -- Gateway port exposed to public interface
- **Severity:** Critical
- **Description:** The gateway port is reachable from a non-loopback interface, confirmed by a port scan.
- **Remediation:** Bind to `127.0.0.1` or place behind a reverse proxy that handles authentication.

### CHK-NET-002 -- WebSocket endpoint lacks authentication
- **Severity:** Critical
- **Description:** The WebSocket endpoint accepts connections without an auth token. Any client can connect and issue commands.
- **Remediation:** Enable WebSocket authentication in gateway config.

### CHK-NET-003 -- HTTP used instead of HTTPS
- **Severity:** Critical
- **Description:** The gateway serves over plain HTTP. Traffic including auth tokens is unencrypted.
- **Remediation:** Enable TLS. Use a reverse proxy (nginx, Caddy) if you do not want to manage certificates directly.

### CHK-NET-004 -- Proxy misconfiguration leaks internal IPs
- **Severity:** Warn
- **Description:** Response headers or error pages reveal internal IP addresses.
- **Remediation:** Configure the reverse proxy to strip `X-Forwarded-For` and internal headers from responses.

### CHK-NET-005 -- DNS rebinding protection missing
- **Severity:** Warn
- **Description:** The gateway does not validate the `Host` header, making it vulnerable to DNS rebinding attacks.
- **Remediation:** Configure `gateway.allowedHosts` to list only expected hostnames.

### CHK-NET-006 -- Open redirect in auth callback
- **Severity:** Warn
- **Description:** The authentication callback URL does not validate the redirect target. An attacker can craft a URL that redirects to a malicious site after login.
- **Remediation:** Validate that redirect URLs match an allow-list of trusted domains.

### CHK-NET-007 -- Server headers disclose version info
- **Severity:** Info
- **Description:** The `Server` or `X-Powered-By` headers reveal the gateway software and version.
- **Remediation:** Remove or override version-disclosing headers.

### CHK-NET-008 -- Unrestricted outbound from skill sandbox
- **Severity:** Warn
- **Description:** Skills in the sandbox can make arbitrary outbound network connections, enabling data exfiltration.
- **Remediation:** Configure network policy to restrict skill outbound access to an allow-list.

---

## Skills (CHK-SKL)

### CHK-SKL-001 -- Skill requests filesystem write access
- **Severity:** Warn
- **Description:** A skill manifest declares `filesystem:write` permission. This allows the skill to modify files on the host.
- **Remediation:** Review whether write access is truly necessary. Prefer read-only skills.

### CHK-SKL-002 -- Skill requests network access
- **Severity:** Warn
- **Description:** A skill manifest declares `network:*` or `network:outbound` permission.
- **Remediation:** Restrict to specific domains/ports if the skill needs network access.

### CHK-SKL-003 -- Skill requests shell execution
- **Severity:** Critical
- **Description:** A skill manifest declares `shell:exec` permission, granting it the ability to run arbitrary system commands.
- **Remediation:** Remove the skill or ensure it is thoroughly reviewed and sandboxed.

### CHK-SKL-004 -- Skill not signed
- **Severity:** Warn
- **Description:** The skill does not have a valid cryptographic signature. Its origin and integrity cannot be verified.
- **Remediation:** Install only signed skills from trusted registries.

### CHK-SKL-005 -- Skill has known malicious hash
- **Severity:** Critical
- **Description:** The skill's content hash matches a known-malicious hash in the threat intelligence database.
- **Remediation:** Remove the skill immediately. Investigate for signs of compromise.

### CHK-SKL-006 -- Skill requests access to other skills
- **Severity:** Warn
- **Description:** The skill declares `skills:invoke` permission, allowing it to call other skills. A malicious skill could escalate privileges through cross-skill invocation.
- **Remediation:** Remove `skills:invoke` unless the skill absolutely requires it.

### CHK-SKL-007 -- Skill manifest references external URL
- **Severity:** Warn
- **Description:** The skill manifest contains a URL pointing to an external server. The skill may fetch code or configuration at runtime.
- **Remediation:** Ensure the URL is from a trusted source. Prefer bundling resources.

### CHK-SKL-008 -- Skill uses eval() or exec() patterns
- **Severity:** Critical
- **Description:** The skill source code contains `eval()`, `exec()`, `Function()`, or similar dynamic code execution patterns.
- **Remediation:** Remove the skill or replace dynamic execution with static logic.

### CHK-SKL-009 -- Skill version pinned to mutable tag
- **Severity:** Warn
- **Description:** The skill version is pinned to a mutable tag like `latest` or `stable` rather than a specific version hash.
- **Remediation:** Pin to an immutable version hash or specific version number.

### CHK-SKL-010 -- Skill overrides safety rules
- **Severity:** Critical
- **Description:** The skill manifest includes directives that override or disable safety rules.
- **Remediation:** Remove the skill. Safety rule overrides are never acceptable for third-party skills.

---

## Permissions (CHK-PRM)

### CHK-PRM-001 -- Skill granted admin-level permissions
- **Severity:** Critical
- **Description:** A skill has been granted `admin` or `*` permission scope, giving it full control.
- **Remediation:** Apply least-privilege: grant only the specific permissions the skill needs.

### CHK-PRM-002 -- Wildcard permission grant
- **Severity:** Critical
- **Description:** A permission rule uses a wildcard (`*`) that matches all resources.
- **Remediation:** Replace wildcards with specific resource names.

### CHK-PRM-003 -- Channel can invoke privileged skills
- **Severity:** Warn
- **Description:** A channel binding allows invocation of skills with `shell:exec` or `admin` permissions.
- **Remediation:** Restrict channel-accessible skills to a safe allow-list.

### CHK-PRM-004 -- No permission boundary between skills
- **Severity:** Warn
- **Description:** Skills share the same permission context and can access each other's resources.
- **Remediation:** Enable skill isolation in the gateway config.

### CHK-PRM-005 -- User role allows skill installation
- **Severity:** Warn
- **Description:** Non-admin user roles have the `skills:install` permission. Any user can add arbitrary skills.
- **Remediation:** Restrict `skills:install` to admin roles only.

### CHK-PRM-006 -- API token has excessive scopes
- **Severity:** Warn
- **Description:** An API token is configured with more scopes than needed for its purpose.
- **Remediation:** Create scoped tokens for specific integrations.

### CHK-PRM-007 -- Cross-tenant access not restricted
- **Severity:** Critical
- **Description:** In a multi-tenant deployment, tenant isolation is not enforced. Skills or users in one tenant can access resources in another.
- **Remediation:** Enable tenant isolation in the gateway config.

### CHK-PRM-008 -- Permission changes not audited
- **Severity:** Warn
- **Description:** Changes to permission rules are not logged. Malicious permission escalation cannot be detected after the fact.
- **Remediation:** Enable audit logging for permission changes.

### CHK-PRM-013 -- SSH private key has overly permissive permissions
- **Severity:** Critical
- **Description:** SSH private key files (e.g., `~/.ssh/id_rsa`, `~/.ssh/id_ed25519`) have permissions more permissive than 600. SSH clients often refuse to use keys with incorrect permissions, and they can be read by other users on the system.
- **Remediation:** Set SSH key permissions to 600 (read/write owner only): `chmod 600 ~/.ssh/id_rsa`
- **Auto-fix:** `chmod 600 "$KEY_PATH"`

---

## Cron (CHK-CRN)

### CHK-CRN-001 -- Cron job runs as root
- **Severity:** Critical
- **Description:** A scheduled skill invocation runs with root/admin privileges.
- **Remediation:** Run cron jobs under a dedicated low-privilege service account.

### CHK-CRN-002 -- Cron job executes un-reviewed skill
- **Severity:** Warn
- **Description:** A cron job invokes a skill that has not been marked as reviewed/approved.
- **Remediation:** Review and approve all skills before scheduling them.

### CHK-CRN-003 -- Cron schedule allows rapid-fire execution
- **Severity:** Warn
- **Description:** A cron job runs more frequently than once per minute, which may indicate abuse or misconfiguration.
- **Remediation:** Set a reasonable minimum interval for scheduled skills.

### CHK-CRN-004 -- Cron job lacks timeout
- **Severity:** Warn
- **Description:** A scheduled skill invocation has no timeout configured. A hung skill will block the cron slot indefinitely.
- **Remediation:** Set a `timeout` value in the cron job definition.

### CHK-CRN-005 -- Cron job output not captured
- **Severity:** Info
- **Description:** Cron job output (stdout/stderr) is discarded. Errors and unexpected behavior will go unnoticed.
- **Remediation:** Configure output capture to a log file or monitoring system.

### CHK-CRN-006 -- Cron job has network access
- **Severity:** Warn
- **Description:** A scheduled skill can make outbound network connections, enabling scheduled data exfiltration.
- **Remediation:** Restrict network access for cron-invoked skills unless explicitly required.

---

## CVE (CHK-CVE)

### CHK-CVE-001 -- OpenClaw version vulnerable to known CVE
- **Severity:** Critical
- **Description:** The installed OpenClaw version is older than the fix version for one or more known CVEs.
- **Remediation:** Upgrade to the latest OpenClaw release.

### CHK-CVE-002 -- Gateway auth bypass (CVE-2026-25253)
- **Severity:** Critical
- **Description:** OpenClaw versions before 2026.1.29 are vulnerable to cross-site WebSocket hijacking. The control UI trusts a `gatewayUrl` query parameter, allowing an attacker to steal the gateway auth token.
- **Remediation:** Upgrade to OpenClaw >= 2026.1.29.

### CHK-CVE-003 -- Docker sandbox escape (CVE-2026-24763)
- **Severity:** Critical
- **Description:** OpenClaw versions before 2026.1.29 have unsafe PATH handling in the Docker sandbox. An attacker can inject a malicious binary via PATH manipulation.
- **Remediation:** Upgrade to OpenClaw >= 2026.1.29.

### CHK-CVE-004 -- SSH path injection (CVE-2026-25157)
- **Severity:** Critical
- **Description:** OpenClaw versions before 2026.1.29 echo the project root path into a shell command without escaping, allowing OS command injection via a crafted project name.
- **Remediation:** Upgrade to OpenClaw >= 2026.1.29.

### CHK-CVE-005 -- Outdated dependency with known vuln
- **Severity:** Warn
- **Description:** A dependency used by OpenClaw or an installed skill has a known vulnerability.
- **Remediation:** Update the dependency to a patched version.

---

## Supply Chain (CHK-SUP)

### CHK-SUP-001 -- Skill installed from untrusted registry
- **Severity:** Critical
- **Description:** A skill was installed from a registry not in the trusted registry list.
- **Remediation:** Remove the skill or add the registry to the trusted list after verification.

### CHK-SUP-002 -- Skill hash does not match registry
- **Severity:** Critical
- **Description:** The SHA-256 hash of the installed skill does not match the hash published by the registry. The skill may have been tampered with.
- **Remediation:** Re-install the skill from the registry. If the mismatch persists, do not use the skill.

### CHK-SUP-003 -- Registry URL uses HTTP, not HTTPS
- **Severity:** Critical
- **Description:** A skill registry is configured with an `http://` URL. Skill downloads are vulnerable to man-in-the-middle attacks.
- **Remediation:** Change the registry URL to use `https://`.

### CHK-SUP-004 -- Skill depends on deprecated package
- **Severity:** Warn
- **Description:** A skill declares a dependency on a package that has been deprecated by its maintainer.
- **Remediation:** Contact the skill author or find an alternative skill.

### CHK-SUP-005 -- Skill pulls transitive dependency at runtime
- **Severity:** Warn
- **Description:** The skill downloads or installs dependencies at runtime, bypassing install-time verification.
- **Remediation:** Bundle all dependencies at build time. Avoid runtime `npm install`, `pip install`, etc.

### CHK-SUP-006 -- No lockfile for installed skills
- **Severity:** Warn
- **Description:** There is no lockfile pinning installed skill versions. Skill versions may drift silently.
- **Remediation:** Generate and commit a skill lockfile: `openclaw skill lock`

### CHK-SUP-007 -- Registry certificate not pinned
- **Severity:** Warn
- **Description:** TLS certificate pinning is not configured for skill registries. A compromised CA could issue a fraudulent certificate.
- **Remediation:** Configure certificate pinning for critical registries.

### CHK-SUP-008 -- Skill author identity not verified
- **Severity:** Warn
- **Description:** The skill does not include a verified author signature. The claimed author cannot be confirmed.
- **Remediation:** Prefer skills with verified author signatures.
