"""External GDB handoff with bounded child lifetime and restored signal handlers."""

import os
import signal
import subprocess
import sys
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from gnwmanager.cli._parsers import GnWType
from gnwmanager.cli.main import app
from gnwmanager.elf import find_elf


@contextmanager
def _forward_signals(callback):
    previous = {}
    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, callback)
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def _reap(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            process.kill()
    process.wait(timeout=2)


def _check_signals(received):
    if received:
        raise SystemExit(128 + received[0])


def launch_debugger(gnw, *, elf=None, port=None):
    """Run the configured executable against the owned proxy or explicit probe."""
    backend = gnw.backend
    lease = getattr(backend, "session_lease", None)
    if lease is not None:
        if port is not None:
            raise ValueError("Session GDB uses its Unix proxy; --port is only supported for standalone probes")
        endpoint = backend.debugger_endpoint()
        lease.status()
        target = f"target remote {endpoint}"
    else:
        if elf is None:
            elf = find_elf()
        port = 3333 if port is None else port
        backend.start_gdbserver(port, logging=False, blocking=False)
        target = f"target extended-remote :{port}"

    cmd = [os.environ.get("GDB", "arm-none-eabi-gdb")]
    if elf is not None:
        cmd.append(str(elf))
    cmd += ["-ex", target]
    process = None
    received = []

    def handle_signal(signum, _frame):
        # Defer signals received inside Popen until the returned handle is
        # published. The guard stays installed through final child reap.
        received.append(signum)
        if process is not None and process.poll() is None:
            process.send_signal(signum)

    with _forward_signals(handle_signal):
        try:
            process = subprocess.Popen(
                cmd, stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr, start_new_session=True
            )
            _check_signals(received)
            while process.poll() is None:
                if lease is not None:
                    lease.check()
                _check_signals(received)
                try:
                    process.wait(timeout=0.05)
                except subprocess.TimeoutExpired:
                    continue
            code = process.wait(timeout=2)
            _check_signals(received)
            if code:
                raise SystemExit(code)
        finally:
            if process is not None:
                _reap(process)


@app.command(group="Developer")
def gdb(elf: Optional[Path] = None, port: Optional[int] = None, *, gnw: GnWType):
    """Launch GDB on the current session proxy or an explicitly selected probe."""
    launch_debugger(gnw, elf=elf, port=port)


@app.command(group="Developer")
def gdbserver(port: Optional[int] = None, *, gnw: GnWType):
    """Publish the owned Unix proxy until interrupted; keep the lease alive."""
    backend = gnw.backend
    lease = getattr(backend, "session_lease", None)
    if lease is None:
        return backend.start_gdbserver(3333 if port is None else port)
    if port is not None:
        raise ValueError("Session GDB uses its Unix proxy; --port is only supported for standalone probes")
    endpoint = backend.debugger_endpoint()
    lease.status()
    print(f"target remote {endpoint}", flush=True)
    stop = threading.Event()
    received = []

    def handle_signal(signum, _frame):
        received.append(signum)
        stop.set()

    with _forward_signals(handle_signal):
        while not stop.wait(0.05):
            lease.check()
    # An interrupted standalone server cannot establish that a peer completed.
    backend.session_owner.failed = True
    _check_signals(received)
