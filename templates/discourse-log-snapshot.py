#!/usr/bin/env python3
import datetime
import os
import re
import subprocess
from collections import deque

CONTAINER = os.environ.get("DISCOURSE_CONTAINER", "app")
MAX_LINES = int(os.environ.get("MAX_LINES", "2000"))
OUTPUT_PATH = os.environ.get(
    "OUTPUT_PATH", "/var/www/errorpages/logs/discourse.log"
)

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b"
)
JWT_RE = re.compile(r"\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._-]+")
HEADER_RE = re.compile(r"(?i)\b(authorization|cookie|set-cookie)\b\s*:\s*[^\s]+")
KEY_VALUE_RE = re.compile(
    r"(?i)\b(password|passwd|secret|api[_-]?key|apikey|token|auth|jwt|session)\b\s*[:=]\s*[^\s,;]+"
)
AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")


def now_utc():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")


def sanitize(line: str) -> str:
    line = BEARER_RE.sub("Bearer <redacted>", line)
    line = HEADER_RE.sub(lambda m: f"{m.group(1)}: <redacted>", line)
    line = KEY_VALUE_RE.sub(lambda m: f"{m.group(1)}=<redacted>", line)
    line = JWT_RE.sub("<redacted-jwt>", line)
    line = AWS_KEY_RE.sub("<redacted-aws-key>", line)
    line = EMAIL_RE.sub("<redacted-email>", line)
    line = IPV4_RE.sub("<redacted-ip>", line)
    def redact_ipv6(match: re.Match) -> str:
        value = match.group(0)
        if any(ch in "abcdefABCDEF" for ch in value):
            return "<redacted-ipv6>"
        return value

    line = IPV6_RE.sub(redact_ipv6, line)
    return line


def write_output(lines):
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as handle:
        handle.writelines(lines)
    os.chmod(OUTPUT_PATH, 0o644)


def container_exists() -> bool:
    try:
        result = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.Names}}"],
            check=False,
            capture_output=True,
            text=True,
        )
    except Exception:
        return False
    if result.returncode != 0:
        return False
    names = {name.strip() for name in result.stdout.splitlines() if name.strip()}
    return CONTAINER in names


def main():
    if not container_exists():
        write_output([f"{now_utc()} [log-sanitizer] container '{CONTAINER}' not found\n"])
        return

    result = subprocess.run(
        [
            "docker",
            "logs",
            "--timestamps",
            "--tail",
            str(MAX_LINES),
            CONTAINER,
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    lines = deque(maxlen=MAX_LINES)
    output = result.stdout or ""
    if result.returncode != 0:
        output = output + f"\n{now_utc()} [log-sanitizer] docker logs exited {result.returncode}\n"

    for raw_line in output.splitlines():
        lines.append(sanitize(raw_line) + "\n")

    if not lines:
        lines.append(f"{now_utc()} [log-sanitizer] no logs yet\n")

    write_output(lines)


if __name__ == "__main__":
    main()
