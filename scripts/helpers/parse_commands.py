#!/usr/bin/env python3
"""Parse shell command string and extract base commands while respecting quotes.

Security: rejects commands containing dangerous shell constructs that could
hide malicious commands (command substitution, process substitution, backticks).
"""
import sys
import shlex
import re


# Patterns that indicate hidden command execution — reject the entire string
_DANGEROUS_PATTERNS = [
    r'\$\(',       # command substitution: $(...)
    r'`',          # backtick command substitution: `...`
    r'<\(',        # process substitution: <(...)
    r'>\(',        # process substitution: >(...)
]

_DANGEROUS_RE = re.compile('|'.join(_DANGEROUS_PATTERNS))


def extract_commands(cmd_string):
    """Extract all base commands from a shell command string.

    Raises ValueError if the command string contains dangerous shell
    constructs that could hide commands from validation.
    """
    # Reject strings containing command/process substitution or backticks
    # Check outside of single-quoted regions (single quotes prevent expansion)
    # Simple approach: check the raw string — even quoted $() is suspicious
    # in an auto-fix context and should be rejected
    if _DANGEROUS_RE.search(cmd_string):
        raise ValueError(
            f"Command string contains dangerous shell construct: {cmd_string!r}"
        )

    commands = []

    # Split by command separators: |, &&, ||, ;, &
    # Use a simple state machine to handle quotes
    in_single = False
    in_double = False
    current = ""
    i = 0

    while i < len(cmd_string):
        c = cmd_string[i]

        # Track quote state
        if c == "'" and not in_double:
            in_single = not in_single
            current += c
        elif c == '"' and not in_single:
            in_double = not in_double
            current += c
        # Check for separators outside quotes
        elif not in_single and not in_double:
            if i < len(cmd_string) - 1 and cmd_string[i:i+2] in ['&&', '||']:
                if current.strip():
                    commands.append(current.strip())
                current = ""
                i += 1  # skip second char
            elif c in ['|', ';']:
                if current.strip():
                    commands.append(current.strip())
                current = ""
            elif c == '&':
                # Background operator — treat as separator
                if current.strip():
                    commands.append(current.strip())
                current = ""
            elif c == '\n':
                # Newline — treat as separator
                if current.strip():
                    commands.append(current.strip())
                current = ""
            else:
                current += c
        else:
            current += c

        i += 1

    if current.strip():
        commands.append(current.strip())

    # Extract base command from each segment
    base_commands = []
    for cmd in commands:
        try:
            # Use shlex to properly parse the command
            tokens = shlex.split(cmd)
            if tokens:
                base_commands.append(tokens[0])
        except ValueError:
            # If shlex fails, reject — don't fall back to insecure parsing
            raise ValueError(f"Failed to parse command segment: {cmd!r}")

    return base_commands

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd = " ".join(sys.argv[1:])
    else:
        cmd = sys.stdin.read().strip()

    try:
        commands = extract_commands(cmd)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    for c in commands:
        print(c)
