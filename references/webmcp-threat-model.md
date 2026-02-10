# WebMCP Threat Model

## Overview

WebMCP (Chrome 146+) exposes a `navigator.modelContext` API that allows websites
and web apps to declare structured services for AI agents. Instead of agents
navigating a human UI, they can query and execute services directly.

**Attack surface:** Any website the agent visits can declare WebMCP services.
These services inject tool definitions, descriptions, and capabilities into the
agent's model context — the most privileged part of the agent's decision-making
pipeline.

---

## §1 — Untrusted Origin Attack

**Threat:** A malicious or compromised website declares WebMCP services that the
agent connects to, granting the attacker a direct channel to influence agent
behavior and receive agent-collected data.

**Attack Vector:**
1. User visits or agent navigates to malicious site
2. Site declares `navigator.modelContext` services
3. Agent discovers and connects to these services
4. Attacker's tools are now in the agent's tool inventory

**Impact:** Full agent compromise — attacker can serve tools that exfiltrate
data, modify files, send messages, or execute commands.

**Mitigation:** Maintain a strict allow-list of trusted WebMCP origins. Reject
all service declarations from unknown origins.

---

## §2 — Capability Escalation

**Threat:** A WebMCP service requests capabilities beyond what it needs (e.g.,
filesystem write, shell exec, network outbound), gaining access to sensitive
system resources.

**Attack Vector:**
1. Service declares broad capabilities in its manifest
2. Agent grants requested capabilities without verification
3. Service uses capabilities to access/modify resources outside its intended scope

**Impact:** Unauthorized file access, command execution, network exfiltration.

**Mitigation:** Enforce least-privilege capability grants. Require human approval
for sensitive capabilities. Deny `shell`, `exec`, `admin` by default.

---

## §3 — Context Leakage

**Threat:** WebMCP `modelContext` declarations without scoping expose the full
agent context (conversation history, system prompts, memory files) to all
connected services.

**Attack Vector:**
1. Agent connects to multiple WebMCP services
2. Service A (malicious) has unscoped context access
3. Service A reads conversation data intended only for Service B
4. Sensitive data (credentials, personal info) is leaked to Service A

**Impact:** Privacy breach, credential theft, conversation data exfiltration.

**Mitigation:** Scope `modelContext` to specific services. Never use wildcard
grants. Isolate agent memory from WebMCP service access.

---

## §4 — Cross-Origin Impersonation

**Threat:** Without origin isolation, one WebMCP origin can register services
with names that collide with trusted services from another origin.

**Attack Vector:**
1. Trusted origin `bank.com` registers a `transferFunds` service
2. Attacker origin `evil.com` also registers `transferFunds`
3. Agent calls `transferFunds` — the call routes to the attacker's version
4. Attacker captures transfer details or redirects funds

**Impact:** Service hijacking, financial theft, data interception.

**Mitigation:** Enable origin isolation. Namespace service names by origin.
Verify service identity before execution.

---

## §5 — Data Exfiltration

**Threat:** A WebMCP service with access to sensitive agent data (memory,
credentials, session state) can transmit that data to an external endpoint.

**Attack Vector:**
1. Service gains `dataAccess` to agent memory or session
2. Service reads MEMORY.md, USER.md, SOUL.md, or credential stores
3. Service sends collected data to attacker-controlled endpoint

**Impact:** Complete privacy breach — personal data, credentials, conversation
history, and agent configuration exposed.

**Mitigation:** Never grant filesystem or data access to external-origin
services. Isolate agent memory behind an access control boundary. Monitor
outbound traffic from WebMCP services.

---

## §6 — Indirect Prompt Injection

**Threat:** WebMCP service descriptions are injected into the model context.
A malicious description can contain prompt injection payloads that override
agent behavior.

**Attack Vector:**
1. Malicious service sets its `description` to contain injection text
2. Description includes "ignore previous instructions", persona overrides, or
   control tokens (`[INST]`, `<<SYS>>`, `<|im_start|>`)
3. Agent processes description as part of context
4. Agent behavior is hijacked — safety rules bypassed, actions redirected

**Impact:** Full agent behavior compromise. Safety bypasses. Unauthorized
actions executed on behalf of the user.

**Mitigation:** Sanitize and validate service descriptions. Enforce character
limits and content filtering. Treat all service metadata as untrusted input.

---

## §7 — Unauthenticated Access

**Threat:** WebMCP services without authentication can be invoked by any
connected client, and connections to MCP servers without auth are vulnerable to
man-in-the-middle attacks.

**Attack Vector:**
1. WebMCP endpoint has no auth requirement
2. Attacker on the network intercepts or directly connects
3. Attacker invokes services or modifies responses

**Impact:** Unauthorized service invocation, response tampering, data
interception.

**Mitigation:** Require authentication for all WebMCP services. Use TLS for all
connections. Implement token-based or OAuth authentication.

---

## §8 — Form Data Leakage

**Threat:** Declarative form-based WebMCP services can auto-submit data without
user review. The model may pre-fill forms with sensitive conversation data.

**Attack Vector:**
1. Form service declares `inputSchema` with auto-submit enabled
2. Model fills form fields from conversation context
3. Fields include credentials, personal data, or sensitive information
4. Form auto-submits to the service endpoint without user confirmation
5. Sensitive data is sent to potentially untrusted service

**Impact:** Credential leakage, personal data exposure, unintended data sharing.

**Mitigation:** Disable auto-submit. Require user confirmation for all form
submissions. Mark sensitive fields. Filter conversation data from form pre-fill.

---

## Risk Summary

| Threat | Severity | Likelihood | Impact |
|--------|----------|-----------|--------|
| Untrusted Origin | Critical | High | Full compromise |
| Capability Escalation | Critical | Medium | System access |
| Context Leakage | High | High | Privacy breach |
| Cross-Origin Impersonation | Critical | Medium | Service hijack |
| Data Exfiltration | Critical | Medium | Data theft |
| Prompt Injection | Critical | High | Behavior override |
| Unauthenticated Access | High | Medium | MITM / unauthorized |
| Form Data Leakage | Medium | Medium | Data exposure |

---

## References

- Chrome 146 WebMCP preview: `chrome://flags/#web-mcp`
- `navigator.modelContext` API proposal
- Liad Yosef (@liadyosef) on MCP Apps + WebMCP convergence
- Maximiliano Firtman (@firt) on Chrome 146 WebMCP implementation
