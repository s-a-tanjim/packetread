#!/usr/bin/env python3
"""Record the README demo with asciinema 3 and render it with agg 1.9+."""

import errno
import fcntl
import os
from pathlib import Path
import pty
import select
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time

ROOT = Path(__file__).resolve().parent.parent
CAPTURE = "tests/fixtures/demo.pcap"
BINARY = ROOT / "target/release/packetread"
ASSETS = ROOT / "docs/assets"


def command_line(command):
    print("\033[1;36m$ \033[0m", end="", flush=True)
    for character in command:
        print(character, end="", flush=True)
        time.sleep(0.025)
    print(flush=True)
    time.sleep(0.3)


def session():
    """Drive the real TUI in a nested terminal; asciinema captures its output."""
    print("\033[2J\033[H", end="", flush=True)
    command_line("packetread")
    time.sleep(0.9)
    pid, terminal = pty.fork()
    if pid == 0:
        fcntl.ioctl(1, termios.TIOCSWINSZ, struct.pack("HHHH", 44, 140, 0, 0))
        os.execv(str(BINARY), ["packetread"])

    output = bytearray()
    closed = False
    query_tail = b""

    def pump(seconds, until=None):
        nonlocal closed, query_tail
        if until and until in output:
            return
        deadline = time.monotonic() + seconds
        while not closed and time.monotonic() < deadline:
            if not select.select([terminal], [], [], min(0.05, max(0, deadline - time.monotonic())))[0]:
                continue
            try:
                data = os.read(terminal, 65536)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                data = b""
            if not data:
                closed = True
                break
            # Crossterm asks for the cursor position while initializing. There
            # is no interactive terminal emulator behind this nested PTY.
            queries = query_tail + data
            for _ in range(queries.count(b"\x1b[6n")):
                os.write(terminal, b"\x1b[1;1R")
            query_tail = queries[-3:]
            output.extend(data)
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
            if until and until in output:
                return
        if until and until not in output:
            raise RuntimeError(f"TUI did not reach {until!r}")

    def keys(text, pause):
        if closed:
            raise RuntimeError("TUI exited before the demo finished")
        for character in text:
            os.write(terminal, character.encode())
            pump(0.08)
        pump(pause)

    try:
        pump(10, until=b"READY")
        pump(1.2)
        keys("o", 0.7)                    # Open the capture from inside the app.
        keys(CAPTURE, 0.6)
        keys("\r", 0)
        pump(10, until=b"FINISHED")
        keys("g", 2)                      # Browse from the first packet.
        keys("jj", 1.5)                   # Select the DNS query.
        keys("2Gkkkk", 2.5)               # Highlight the DNS transaction ID.
        keys("j", 1)                      # Then highlight the DNS flags.
        keys("\r", 0.8)                   # Collapse and expand the DNS layer.
        keys("\r", 0.8)
        keys("1/proto=dns\r", 2.5)        # Narrow eleven packets to two.
        keys("j", 1.5)                    # Inspect the response.
        keys("/\x15proto=tcp port=443\r", 2.5)
        keys('/\x15dns.qry.name contains "example"\r', 2.5)  # Typed field filter.
        keys("/\x15\r", 0.5)              # Clear the filter.
        keys("g", 1)
        keys("S", 2.5)                    # Statistics.
        keys("\x1b", 0.5)
        keys("D", 2.5)                    # Flow diagram between hosts.
        keys("\x1b", 0.5)
        keys("?", 2)
        keys("\x1b", 0.5)
        keys("q", 0)
        pump(5)
        if not closed:
            raise RuntimeError("TUI did not exit after q")
        _, status = os.waitpid(pid, 0)
        pid = None
        if os.waitstatus_to_exitcode(status) != 0:
            raise RuntimeError("TUI exited unsuccessfully")
    finally:
        os.close(terminal)
        if pid is not None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)

    print("\033[2J\033[H\033[1;36mSummarize captures from the command line\033[0m\n", flush=True)
    command_line(f"packetread summary {CAPTURE}")
    subprocess.run([str(BINARY), "summary", CAPTURE], check=True)
    print("\nSynthetic fixture only. No live traffic or capture privileges needed.", flush=True)
    time.sleep(3)


def record():
    for tool in ("cargo", "asciinema", "agg"):
        if not shutil.which(tool):
            sys.exit(f"Missing {tool}; see docs/DEMO.md for prerequisites.")
    subprocess.run(["cargo", "build", "--release", "--locked"], check=True)
    ASSETS.mkdir(parents=True, exist_ok=True)
    cast = ASSETS / "demo.cast"
    gif = ASSETS / "demo.gif"
    with tempfile.TemporaryDirectory(prefix="packetread-demo-") as config:
        environment = {
            **os.environ,
            "ASCIINEMA_CONFIG_HOME": config,
            "TERM": "xterm-256color",
            "COLORTERM": "truecolor",
            "SHELL": "/bin/sh",
        }
        environment.pop("NO_COLOR", None)
        subprocess.run([
            "asciinema", "record", "--headless", "--overwrite", "--return",
            "--output-format", "asciicast-v2", "--window-size", "140x44",
            "--capture-env", "TERM,COLORTERM", "--title", "Packetread: browse, inspect, filter",
            "--command", f"{shlex.quote(sys.executable)} scripts/record-demo.py --session",
            str(cast),
        ], env=environment, check=True, timeout=90)
    subprocess.run([
        "agg", "--font-family", "DejaVu Sans Mono", "--font-size", "14",
        "--line-height", "1.2", "--theme", "github-dark", "--fps-cap", "12",
        "--last-frame-duration", "2", str(cast), str(gif),
    ], check=True)
    print(f"Created {cast.relative_to(ROOT)} and {gif.relative_to(ROOT)}")


if __name__ == "__main__":
    os.chdir(ROOT)
    if sys.argv[1:] == ["--session"]:
        session()
    elif sys.argv[1:]:
        sys.exit("Usage: python3 scripts/record-demo.py")
    else:
        record()
