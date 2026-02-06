#!/usr/bin/env python3
"""
scan_secrets.py - Secret detection scanner for OpenClaw configuration files.

Scans all OpenClaw config files for plaintext secrets, hardcoded tokens,
insecure file permissions, and other credential hygiene issues.

Output: JSON array of findings to stdout.
"""

import argparse
import json
import os
import re
import stat
import sys
import glob as globmod
import plistlib
from pathlib import Path


# ---------------------------------------------------------------------------
# Secret-matching patterns
# ---------------------------------------------------------------------------

SECRET_KEY_PATTERNS = re.compile(
    r"(token|password|passwd|secret|apikey|api_key|apptoken|app_token|"
    r"bottoken|bot_token|signingsecret|signing_secret|cookie|oauth|"
    r"privatekey|private_key|client_secret|access_key|secret_key|"
    r"webhook_url|webhook_secret)",
    re.IGNORECASE,
)

# Value patterns that look like real secrets (not env-var references)
SECRET_VALUE_PATTERNS = [
    ("Slack bot token", re.compile(r"xoxb-[A-Za-z0-9\-]+")),
    ("Slack app token", re.compile(r"xapp-[A-Za-z0-9\-]+")),
    ("Slack user token", re.compile(r"xoxp-[A-Za-z0-9\-]+")),
    ("Bearer token", re.compile(r"Bearer\s+[A-Za-z0-9\-_.~+/]+=*", re.IGNORECASE)),
    ("JWT token", re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("Discord bot token", re.compile(r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}")),
    ("Telegram bot token", re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}")),
    ("OpenAI API key", re.compile(r"sk-proj-[A-Za-z0-9]{20,}")),
    ("OpenAI legacy key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("Ethereum private key", re.compile(r"0x[a-fA-F0-9]{64}")),
]

ENV_VAR_REF = re.compile(r"^\$\{.+\}$|^\$[A-Z_][A-Z0-9_]*$")

PRIVATE_KEY_HEADER = re.compile(r"-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")


def redact(value: str) -> str:
    """Redact a secret value, showing only the last 4 characters."""
    s = str(value).strip()
    if len(s) <= 4:
        return "****"
    return "****" + s[-4:]


def is_env_ref(value: str) -> bool:
    """Check if a value is an environment variable reference rather than a hardcoded secret."""
    return bool(ENV_VAR_REF.match(str(value).strip()))


def is_suspicious_value(value: str) -> bool:
    """Heuristic: does this string look like it could be a hardcoded secret?"""
    v = str(value).strip()
    if not v or len(v) < 8:
        return False
    if is_env_ref(v):
        return False
    # Skip values that look like URLs, file paths, semver versions, or prose
    if v.startswith(("http://", "https://", "/", "./", "../")):
        return False
    if re.match(r"^\d+\.\d+\.\d+", v):  # semver
        return False
    if " " in v and len(v.split()) > 3:  # prose/sentences
        return False
    for _, pat in SECRET_VALUE_PATTERNS:
        if pat.search(v):
            return True
    return False


def detect_secret_type(value: str) -> str:
    """Return a human-readable label for the type of secret detected."""
    v = str(value).strip()
    for label, pat in SECRET_VALUE_PATTERNS:
        if pat.search(v):
            return label
    return "Possible secret/credential"


# ---------------------------------------------------------------------------
# Finding builder
# ---------------------------------------------------------------------------

class Findings:
    def __init__(self):
        self._items = []
        self._counters = {}

    def add(self, check_id: str, severity: str, title: str, description: str,
            evidence: str = "", remediation: str = ""):
        self._items.append({
            "id": check_id,
            "severity": severity,
            "title": title,
            "description": description,
            "evidence": evidence,
            "remediation": remediation,
        })

    def next_id(self, prefix: str) -> str:
        n = self._counters.get(prefix, 0) + 1
        self._counters[prefix] = n
        return f"{prefix}-{n:03d}"

    @property
    def items(self):
        return self._items


# ---------------------------------------------------------------------------
# JSON recursive scanner
# ---------------------------------------------------------------------------

def walk_json(obj, path="", callback=None):
    """Recursively walk a JSON structure, calling callback(key_path, key, value) on strings."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            key_path = f"{path}.{k}" if path else k
            if isinstance(v, str):
                if callback:
                    callback(key_path, k, v)
            else:
                walk_json(v, key_path, callback)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            key_path = f"{path}[{i}]"
            if isinstance(v, str):
                if callback:
                    callback(key_path, str(i), v)
            else:
                walk_json(v, key_path, callback)


def scan_json_file(filepath: str, findings: Findings, check_id: str, severity: str, label: str):
    """Scan a JSON file for hardcoded secrets."""
    try:
        with open(filepath, "r") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return

    def _check(key_path, key, value):
        key_lower = key.lower().replace("-", "_")
        if SECRET_KEY_PATTERNS.search(key_lower) and not is_env_ref(value) and len(value.strip()) >= 4:
            stype = detect_secret_type(value)
            findings.add(
                check_id, severity,
                f"Hardcoded secret in {label}",
                f"Key '{key_path}' in {filepath} contains a hardcoded {stype.lower()}.",
                f"key={key_path} value={redact(value)}",
                f"Replace the hardcoded value with an env-var reference like ${{SECRET_NAME}} and store the real value in a secrets manager.",
            )
        elif is_suspicious_value(value) and not is_env_ref(value):
            # Value-pattern match even if key name is innocuous
            stype = detect_secret_type(value)
            if stype != "Possible secret/credential":
                findings.add(
                    check_id, severity,
                    f"Suspicious credential value in {label}",
                    f"Key '{key_path}' in {filepath} contains what looks like a {stype.lower()}.",
                    f"key={key_path} value={redact(value)}",
                    f"If this is a credential, replace it with an env-var reference and use a secrets manager.",
                )

    walk_json(data, callback=_check)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_openclaw_json(config_dir: str, findings: Findings):
    """CHK-SEC-001: Hardcoded secrets in openclaw.json."""
    fp = os.path.join(config_dir, "openclaw.json")
    if os.path.isfile(fp):
        scan_json_file(fp, findings, "CHK-SEC-001", "critical", "openclaw.json")


def check_exec_approvals(config_dir: str, findings: Findings):
    """CHK-SEC-002: Hardcoded secrets in exec-approvals.json."""
    fp = os.path.join(config_dir, "exec-approvals.json")
    if os.path.isfile(fp):
        scan_json_file(fp, findings, "CHK-SEC-002", "critical", "exec-approvals.json")


def check_clawtasks_private_keys(config_dir: str, findings: Findings):
    """CHK-SEC-003: Private keys in .clawtasks/ or skills directories."""
    dirs_to_scan = [
        os.path.join(config_dir, ".clawtasks"),
        os.path.join(config_dir, "skills"),
    ]
    # Directories to skip entirely during recursive walk
    SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".cache", "dist", "build"}

    for scan_dir in dirs_to_scan:
        if not os.path.isdir(scan_dir):
            continue
        for root, _dirs, files in os.walk(scan_dir):
            # Prune directories we should never scan
            _dirs[:] = [d for d in _dirs if d not in SKIP_DIRS]
            for fname in files:
                fpath = os.path.join(root, fname)
                # Skip files that are unlikely to contain secrets
                if fname.endswith((".d.ts", ".map", ".md", ".txt", ".lock", ".log",
                                   ".png", ".jpg", ".gif", ".svg", ".woff", ".woff2",
                                   ".ttf", ".eot", ".ico")):
                    continue
                if fname in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
                    continue
                # Check for key file extensions
                if fname.endswith((".pem", ".key", ".p12", ".pfx", ".jks")):
                    findings.add(
                        "CHK-SEC-003", "critical",
                        "Private key file found",
                        f"File {fpath} looks like a private key file based on its extension.",
                        f"file={fpath}",
                        "Remove private key files from config directories. Store them in a secure vault.",
                    )
                    continue
                # Check file content for PEM headers
                try:
                    with open(fpath, "r", errors="ignore") as f:
                        content = f.read(4096)
                    if PRIVATE_KEY_HEADER.search(content):
                        findings.add(
                            "CHK-SEC-003", "critical",
                            "Private key embedded in file",
                            f"File {fpath} contains a PEM-encoded private key.",
                            f"file={fpath}",
                            "Remove private keys from config directories. Use a secrets manager or secure vault.",
                        )
                    # Also scan JSON files in .clawtasks for secrets
                    if fname.endswith(".json"):
                        scan_json_file(fpath, findings, "CHK-SEC-003", "critical",
                                       os.path.relpath(fpath, config_dir))
                except OSError:
                    pass


def check_cron_jobs(config_dir: str, findings: Findings):
    """CHK-SEC-004: API keys in cron job payloads."""
    fp = os.path.join(config_dir, "cron", "jobs.json")
    if os.path.isfile(fp):
        scan_json_file(fp, findings, "CHK-SEC-004", "critical", "cron/jobs.json")


def check_launch_agents(config_dir: str, findings: Findings):
    """CHK-SEC-005: Secrets in LaunchAgent plist files."""
    plist_dirs = [
        os.path.expanduser("~/Library/LaunchAgents"),
        os.path.join(config_dir, "launchagents"),
    ]
    for pdir in plist_dirs:
        if not os.path.isdir(pdir):
            continue
        for fname in os.listdir(pdir):
            if not fname.endswith(".plist"):
                continue
            # Only scan openclaw / claw related plists
            if "claw" not in fname.lower() and "openclaw" not in fname.lower():
                continue
            fpath = os.path.join(pdir, fname)
            try:
                with open(fpath, "rb") as f:
                    plist_data = plistlib.load(f)
            except Exception:
                # Try as text and scan for patterns
                try:
                    with open(fpath, "r", errors="ignore") as f:
                        content = f.read()
                    _scan_text_for_secrets(content, fpath, findings, "CHK-SEC-005", "warn",
                                           f"LaunchAgent plist {fname}")
                except OSError:
                    pass
                continue

            # Walk the plist as a dict
            def _check_plist(key_path, key, value):
                key_lower = key.lower().replace("-", "_")
                if SECRET_KEY_PATTERNS.search(key_lower) and not is_env_ref(value) and len(value.strip()) >= 4:
                    stype = detect_secret_type(value)
                    findings.add(
                        "CHK-SEC-005", "warn",
                        f"Secret in LaunchAgent plist",
                        f"Key '{key_path}' in {fpath} contains a hardcoded {stype.lower()}.",
                        f"key={key_path} value={redact(value)}",
                        "Move secrets out of plist files. Use environment variables or a secrets manager.",
                    )
                elif is_suspicious_value(value) and not is_env_ref(value):
                    stype = detect_secret_type(value)
                    if stype != "Possible secret/credential":
                        findings.add(
                            "CHK-SEC-005", "warn",
                            f"Suspicious value in LaunchAgent plist",
                            f"Key '{key_path}' in {fpath} looks like a {stype.lower()}.",
                            f"key={key_path} value={redact(value)}",
                            "If this is a credential, move it to a secrets manager.",
                        )

            walk_json(plist_data, callback=_check_plist)

            # Also check ProgramArguments and EnvironmentVariables specifically
            env_vars = plist_data.get("EnvironmentVariables", {})
            if isinstance(env_vars, dict):
                for k, v in env_vars.items():
                    if isinstance(v, str) and SECRET_KEY_PATTERNS.search(k.lower()) and not is_env_ref(v):
                        findings.add(
                            "CHK-SEC-005", "warn",
                            "Secret in LaunchAgent environment variable",
                            f"Environment variable '{k}' in {fpath} contains a hardcoded secret.",
                            f"key=EnvironmentVariables.{k} value={redact(v)}",
                            "Use keychain or a secrets manager instead of hardcoding in plist files.",
                        )

            prog_args = plist_data.get("ProgramArguments", [])
            if isinstance(prog_args, list):
                for i, arg in enumerate(prog_args):
                    if isinstance(arg, str) and is_suspicious_value(arg):
                        stype = detect_secret_type(arg)
                        if stype != "Possible secret/credential":
                            findings.add(
                                "CHK-SEC-005", "warn",
                                "Suspicious argument in LaunchAgent",
                                f"ProgramArguments[{i}] in {fpath} looks like a {stype.lower()}.",
                                f"key=ProgramArguments[{i}] value={redact(arg)}",
                                "Avoid passing secrets as command-line arguments. Use environment variables or a config file.",
                            )


def _scan_text_for_secrets(content: str, filepath: str, findings: Findings,
                           check_id: str, severity: str, label: str):
    """Scan raw text content for secret patterns."""
    for line_no, line in enumerate(content.splitlines(), 1):
        for pat_label, pat in SECRET_VALUE_PATTERNS:
            m = pat.search(line)
            if m and not is_env_ref(m.group(0)):
                findings.add(
                    check_id, severity,
                    f"{pat_label} found in {label}",
                    f"Line {line_no} in {filepath} contains what looks like a {pat_label.lower()}.",
                    f"line={line_no} value={redact(m.group(0))}",
                    f"Remove hardcoded credentials from {label}. Use a secrets manager.",
                )


def check_env_files(config_dir: str, findings: Findings):
    """CHK-SEC-006: .env files with secrets not chmod 600."""
    env_patterns = [
        os.path.join(config_dir, ".env"),
        os.path.join(config_dir, ".env.*"),
        os.path.join(config_dir, "**", ".env"),
        os.path.join(config_dir, "**", ".env.*"),
    ]
    seen = set()
    for pattern in env_patterns:
        for fpath in globmod.glob(pattern, recursive=True):
            if fpath in seen:
                continue
            seen.add(fpath)
            if not os.path.isfile(fpath):
                continue
            try:
                fstat = os.stat(fpath)
                mode = fstat.st_mode
                # Check if group or other have any permissions
                if mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP |
                           stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH):
                    oct_mode = oct(mode & 0o777)
                    findings.add(
                        "CHK-SEC-006", "warn",
                        ".env file has overly permissive permissions",
                        f"{fpath} has permissions {oct_mode}; should be 0o600.",
                        f"file={fpath} mode={oct_mode}",
                        f"Run: chmod 600 {fpath}",
                    )
            except OSError:
                pass

            # Also scan .env content for hardcoded secrets
            try:
                with open(fpath, "r", errors="ignore") as f:
                    for line_no, line in enumerate(f, 1):
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "=" in line:
                            key, _, value = line.partition("=")
                            key = key.strip()
                            value = value.strip().strip("'\"")
                            if SECRET_KEY_PATTERNS.search(key.lower()) and value and not is_env_ref(value):
                                # .env files are expected to contain secrets,
                                # but we flag permission issues (already done above)
                                # and value-based pattern matches
                                for pat_label, pat in SECRET_VALUE_PATTERNS:
                                    if pat.search(value):
                                        findings.add(
                                            "CHK-SEC-006", "warn",
                                            f"Secret in .env file ({pat_label})",
                                            f"Key '{key}' in {fpath} line {line_no} contains a {pat_label.lower()}. "
                                            f"Ensure the file is chmod 600 and not committed to version control.",
                                            f"key={key} value={redact(value)}",
                                            f"Ensure {fpath} is chmod 600 and listed in .gitignore.",
                                        )
                                        break
            except OSError:
                pass


def check_config_permissions(config_dir: str, findings: Findings):
    """CHK-SEC-007: Config files not chmod 600."""
    sensitive_files = [
        "openclaw.json",
        "exec-approvals.json",
        os.path.join("cron", "jobs.json"),
    ]
    for relpath in sensitive_files:
        fpath = os.path.join(config_dir, relpath)
        if not os.path.isfile(fpath):
            continue
        try:
            fstat = os.stat(fpath)
            mode = fstat.st_mode
            if mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP |
                       stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH):
                oct_mode = oct(mode & 0o777)
                findings.add(
                    "CHK-SEC-007", "warn",
                    f"Config file has overly permissive permissions",
                    f"{fpath} has permissions {oct_mode}; sensitive config should be 0o600.",
                    f"file={fpath} mode={oct_mode}",
                    f"Run: chmod 600 {fpath}",
                )
        except OSError:
            pass


def check_stale_secrets(config_dir: str, findings: Findings):
    """CHK-SEC-008: Secrets that look like they haven't been rotated (same value across backup files)."""
    # Look for backup/versioned config files
    backup_patterns = [
        os.path.join(config_dir, "*.bak"),
        os.path.join(config_dir, "*.backup"),
        os.path.join(config_dir, "*.old"),
        os.path.join(config_dir, "*~"),
        os.path.join(config_dir, "backups", "*"),
    ]

    primary_files = {
        "openclaw.json": os.path.join(config_dir, "openclaw.json"),
        "exec-approvals.json": os.path.join(config_dir, "exec-approvals.json"),
    }

    # Collect secrets from primary files
    primary_secrets = {}  # {(filename, key_path): value}
    for label, fp in primary_files.items():
        if not os.path.isfile(fp):
            continue
        try:
            with open(fp, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        def _collect(key_path, key, value, _label=label):
            key_lower = key.lower().replace("-", "_")
            if SECRET_KEY_PATTERNS.search(key_lower) and not is_env_ref(value) and len(value.strip()) >= 8:
                primary_secrets[(_label, key_path)] = value

        walk_json(data, callback=_collect)

    if not primary_secrets:
        return

    # Scan backup files
    backup_files = []
    for pattern in backup_patterns:
        backup_files.extend(globmod.glob(pattern))

    for bak_path in backup_files:
        if not os.path.isfile(bak_path):
            continue
        bak_name = os.path.basename(bak_path)
        # Determine which primary file this backup corresponds to
        matched_primary = None
        for label in primary_files:
            base = label.replace(".json", "")
            if base in bak_name:
                matched_primary = label
                break
        if not matched_primary:
            continue

        try:
            with open(bak_path, "r") as f:
                bak_data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        def _compare(key_path, key, value, _mp=matched_primary, _bp=bak_path):
            lookup = (_mp, key_path)
            if lookup in primary_secrets and primary_secrets[lookup] == value:
                findings.add(
                    "CHK-SEC-008", "info",
                    "Secret appears unchanged across backup",
                    f"Key '{key_path}' has the same value in {_mp} and backup {_bp}. "
                    f"The secret may not have been rotated.",
                    f"key={key_path} current_file={_mp} backup_file={os.path.basename(_bp)}",
                    "Rotate secrets regularly. Ensure backup files are removed after rotation.",
                )

        walk_json(bak_data, callback=_compare)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Scan OpenClaw config files for plaintext secrets."
    )
    parser.add_argument(
        "--config-dir",
        default=os.path.expanduser("~/.openclaw"),
        help="Path to the OpenClaw config directory (default: ~/.openclaw)",
    )
    args = parser.parse_args()
    config_dir = os.path.abspath(args.config_dir)

    findings = Findings()

    # Run all checks
    check_openclaw_json(config_dir, findings)
    check_exec_approvals(config_dir, findings)
    check_clawtasks_private_keys(config_dir, findings)
    check_cron_jobs(config_dir, findings)
    check_launch_agents(config_dir, findings)
    check_env_files(config_dir, findings)
    check_config_permissions(config_dir, findings)
    check_stale_secrets(config_dir, findings)

    # If no findings, output an OK summary
    if not findings.items:
        findings.add(
            "CHK-SEC-000", "ok",
            "No secrets detected",
            f"No hardcoded secrets or permission issues found in {config_dir}.",
            "",
            "",
        )

    json.dump(findings.items, sys.stdout, indent=2)
    sys.stdout.write("\n")

    # Exit with non-zero if any critical findings
    if any(f["severity"] == "critical" for f in findings.items):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
