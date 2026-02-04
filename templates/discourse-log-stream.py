#!/usr/bin/env python3
import datetime
import os
import re
import subprocess
import select
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONTAINER = os.environ.get("DISCOURSE_CONTAINER", "app")
MAX_LINES = int(os.environ.get("MAX_LINES", "2000"))
LISTEN_HOST = os.environ.get("LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "9123"))
REBUILD_LOG = os.environ.get("REBUILD_LOG", "/var/www/errorpages/logs/rebuild.log")
TAIL_LINES = int(os.environ.get("TAIL_LINES", "200"))

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")
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


def container_exists() -> bool:
    result = subprocess.run(
        ["docker", "ps", "-a", "--format", "{{.Names}}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return False
    names = {name.strip() for name in result.stdout.splitlines() if name.strip()}
    return CONTAINER in names


def docker_log_stream():
    return subprocess.Popen(
        [
            "docker",
            "logs",
            "--timestamps",
            "--tail",
            str(max(TAIL_LINES, 0)),
            "-f",
            CONTAINER,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )


def rebuild_log_stream():
    os.makedirs(os.path.dirname(REBUILD_LOG), exist_ok=True)
    with open(REBUILD_LOG, "a", encoding="utf-8"):
        pass
    return subprocess.Popen(
        ["tail", "-F", "-n", "0", REBUILD_LOG],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )


def send_event(handler, data: str, event: str | None = None) -> bool:
    try:
        if event:
            handler.wfile.write(f"event: {event}\n".encode("utf-8"))
        for line in data.splitlines():
            handler.wfile.write(f"data: {line}\n".encode("utf-8"))
        handler.wfile.write(b"\n")
        handler.wfile.flush()
        return True
    except BrokenPipeError:
        return False


def send_comment(handler, text: str) -> bool:
    try:
        handler.wfile.write(f": {text}\n\n".encode("utf-8"))
        handler.wfile.flush()
        return True
    except BrokenPipeError:
        return False


class LogStreamHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_GET(self):
        if self.path not in ("/", "/stream"):
            self.send_response(404)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.flush()

        self.wfile.write(b"retry: 2000\n\n")
        self.wfile.flush()

        if not send_event(self, "connected", event="status"):
            return

        while True:
            docker_proc = None
            rebuild_proc = None
            try:
                while True:
                    if rebuild_proc is None or rebuild_proc.poll() is not None:
                        rebuild_proc = rebuild_log_stream()
                    if docker_proc is None or docker_proc.poll() is not None:
                        if container_exists():
                            docker_proc = docker_log_stream()
                        else:
                            docker_proc = None

                    sources = []
                    if rebuild_proc and rebuild_proc.stdout:
                        sources.append(rebuild_proc.stdout)
                    if docker_proc and docker_proc.stdout:
                        sources.append(docker_proc.stdout)

                    if not sources:
                        if not send_event(
                            self,
                            f"{now_utc()} waiting for logs",
                            event="status",
                        ):
                            return
                        if not send_comment(self, "waiting"):
                            return
                        time.sleep(2)
                        continue

                    ready, _, _ = select.select(sources, [], [], 5)
                    if ready:
                        for source in ready:
                            raw_line = source.readline()
                            if not raw_line:
                                if docker_proc and source is docker_proc.stdout:
                                    docker_proc = None
                                if rebuild_proc and source is rebuild_proc.stdout:
                                    rebuild_proc = None
                                continue
                            line = sanitize(raw_line.rstrip("\n"))
                            if not send_event(self, line):
                                return
                    else:
                        if not send_event(self, "streaming logs", event="status"):
                            return
            except BrokenPipeError:
                return
            finally:
                for proc in (docker_proc, rebuild_proc):
                    if proc is None:
                        continue
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                    try:
                        proc.wait(timeout=2)
                    except Exception:
                        pass


def main():
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), LogStreamHandler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    main()
