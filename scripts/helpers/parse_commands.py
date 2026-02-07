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


def _check_dangerous_outside_single_quotes(cmd_string):
    """Check for dangerous patterns outside single-quoted regions.

    Single quotes in shell prevent all expansion, so $() inside single
    quotes is literal text (e.g. sed 's/$(pwd)/path/g' is safe).
    Returns True if a dangerous pattern is found outside single quotes.
    """
    in_single = False
    i = 0
    while i < len(cmd_string):
        c = cmd_string[i]
        if c == "'" and not in_single:
            # Entering single-quoted region — skip to closing quote
            in_single = True
            i += 1
            continue
        elif c == "'" and in_single:
            in_single = False
            i += 1
            continue

        if not in_single:
            # Check if a dangerous pattern starts at this position
            remaining = cmd_string[i:]
            if _DANGEROUS_RE.match(remaining):
                return True

        i += 1
    return False


def extract_commands(cmd_string):
    """Extract all base commands from a shell command string.

    Raises ValueError if the command string contains dangerous shell
    constructs that could hide commands from validation.
    """
    # Reject strings containing command/process substitution or backticks
    # Only check outside single-quoted regions (single quotes prevent expansion)
    if _check_dangerous_outside_single_quotes(cmd_string):
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

        # Handle backslash escape (only outside single quotes)
        if c == "\\" and not in_single and i + 1 < len(cmd_string):
            current += c + cmd_string[i + 1]
            i += 2
            continue

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
