"""CLI routing and mutation admission against real private Unix RPC/RSP peers."""

import contextlib
import importlib
import inspect
import json
import socket
import threading
import time
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from test_session_client import UnixService, session

main = importlib.import_module("gnwmanager.cli.main")


@pytest.fixture
def private():
    with TemporaryDirectory(prefix="gnw-cli-", dir="/tmp") as name:
        path = Path(name)
        path.chmod(0o700)
        yield path


class RSPPeer:
    """Accept serial managed clients and record every actual RSP command."""

    def __init__(self, service):
        self.service = service
        self.commands = []
        self.clients = []
        self.workers = []
        self.stop = threading.Event()
        service.gdb_listener.settimeout(0.05)
        self.worker = threading.Thread(target=self.accept, daemon=True)
        self.worker.start()

    def accept(self):
        while not self.stop.is_set():
            try:
                client, _ = self.service.gdb_listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.clients.append(client)
            client.settimeout(0.05)
            worker = threading.Thread(target=self.serve, args=(client,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def serve(self, client):
        data = bytearray()
        while not self.stop.is_set():
            try:
                chunk = client.recv(8192)
                if not chunk:
                    return
                data.extend(chunk)
                while b"$" in data and b"#" in data:
                    start = data.index(b"$")
                    end = data.index(b"#", start)
                    if len(data) < end + 3:
                        break
                    cmd = bytes(data[start + 1 : end])
                    del data[: end + 3]
                    self.commands.append(cmd)
                    if cmd == b"c":
                        client.sendall(b"+")
                        continue
                    if cmd.startswith(b"qSupported"):
                        reply = b""
                    elif cmd.startswith(b"m"):
                        size = int(cmd.split(b",")[1], 16)
                        reply = b"00" * size
                    elif cmd.startswith(b"p"):
                        reply = b"00000000"
                    elif cmd == b"?":
                        reply = b"S05"
                    else:
                        reply = b"OK"
                    client.sendall(b"+$" + reply + b"#" + f"{sum(reply) & 255:02x}".encode())
            except socket.timeout:
                continue
            except OSError:
                return

    def close(self):
        self.stop.set()
        for client in self.clients:
            with contextlib.suppress(OSError):
                client.shutdown(socket.SHUT_RDWR)
            client.close()
        self.worker.join(1)
        for worker in self.workers:
            worker.join(1)
        assert not self.worker.is_alive()
        assert not any(worker.is_alive() for worker in self.workers)


@pytest.fixture
def peer(private):
    with UnixService(private) as service:
        rsp = RSPPeer(service)
        try:
            yield service, rsp
        finally:
            rsp.close()


def route(directory, **kwargs):
    api = importlib.import_module("gnwmanager.cli.session_route")
    return api.SessionRoute(directory=directory, heartbeat_interval=0.05, **kwargs)


def test_default_route_is_auto():
    assert inspect.signature(main.main).parameters["backend"].default == "auto"


def test_no_ui_never_falls_back_to_probe(private, monkeypatch):
    monkeypatch.setattr(main, "SessionRoute", lambda **kw: route(private, **kw))
    monkeypatch.setattr(main, "OCDBackend", {})
    with pytest.raises(SystemExit) as error:
        main.main("device-state")
    assert error.value.code == 1


def test_sessions_lists_without_acquiring(peer, monkeypatch, capsys):
    service, _ = peer
    monkeypatch.setattr(main, "SessionRoute", lambda **kw: route(service.directory, **kw))
    main.main("sessions")
    assert service.sessions[0]["sessionId"] in capsys.readouterr().out
    assert not any(r["method"] == "acquire" for r in service.requests)


def test_multicommand_controls_share_lease_without_gdb(peer, monkeypatch):
    service, rsp = peer
    monkeypatch.setattr(main, "SessionRoute", lambda **kw: route(service.directory, **kw))
    main.main("device-state", "--", "power", "pause", "--", "press", "0x10", "--duration-ms", "5")
    assert sum(r["method"] == "acquire" for r in service.requests) == 1
    released = [r for r in service.requests if r["method"] == "release"]
    assert len(released) == 1 and released[0]["params"]["completion"]["success"]
    assert rsp.commands == []
    assert [r["params"]["action"] for r in service.requests if r["method"] == "control"] == ["pause", "press"]


def test_multi_requires_explicit_selection(private):
    from gnwmanager.session_client import SessionError

    with UnixService(private, sessions=[session(), session()]) as service:
        selected = service.sessions[1]["sessionId"]
        owner = route(private)
        with pytest.raises(SessionError, match="Multiple"):
            owner.lease()
        owner.close()
        assert not any(r["method"] == "acquire" for r in service.requests)
        service.sessions.reverse()  # Peer status/release describes the selected target.
        owner = route(private, session_id=selected)
        assert owner.lease().session_id == selected
        owner.close()


def test_backend_marks_before_actual_rsp_and_retains_tcp_defaults(peer):
    service, rsp = peer
    owner = route(service.directory)
    try:
        backend = owner.backend()
        backend.write_memory(0x20000000, b"ab")
        backend.write_register("pc", 0x20000001)
        backend.reset_and_halt()
        backend.resume()
        assert any(c.startswith(b"M20000000") for c in rsp.commands)
        assert any(c.startswith(b"Pf=") for c in rsp.commands)
        assert b"c" in rsp.commands
        assert any(r["method"] == "mark" and r["params"]["memoryWritten"] for r in service.requests)
        assert any(r["method"] == "mark" and r["params"]["executionChanged"] for r in service.requests)
    finally:
        owner.close()
    assert [r for r in service.requests if r["method"] == "release"][-1]["params"]["completion"] == {
        "success": True,
        "managerUploaded": False,
        "memoryWritten": True,
        "executionChanged": True,
    }


@pytest.mark.parametrize("action", ["write", "register", "reset", "resume", "upload"])
def test_busy_mark_prevents_actual_mutation(peer, action):
    from gnwmanager.session_client import SessionError

    service, rsp = peer
    owner = route(service.directory)
    backend = owner.backend()
    before = list(rsp.commands)

    def handler(_service, request, _peer, send):
        if request["method"] == "mark":
            send(
                {
                    "protocol": 1,
                    "id": request["id"],
                    "ok": False,
                    "error": {"code": "BUSY", "message": "operation active"},
                }
            )
        else:
            send()

    service.handler = handler
    functions = {
        "write": lambda: backend.write_memory(0x20000000, b"ab"),
        "register": lambda: backend.write_register("pc", 0x20000001),
        "reset": backend.reset_and_halt,
        "resume": backend.resume,
        "upload": owner.gnw().start_gnwmanager,
    }
    try:
        with pytest.raises(SessionError) as error:
            functions[action]()
        assert error.value.code == "BUSY"
        assert rsp.commands == before
    finally:
        owner.close()


def test_shell_nested_error_keeps_single_lease_and_failed_completion(peer, monkeypatch):
    service, _ = peer
    monkeypatch.setattr(main, "SessionRoute", lambda **kw: route(service.directory, **kw))

    # Exercise the actual shell dispatcher, including its injected GnW owner.
    def interactive(_app, *, dispatcher, prompt):
        bound = inspect.signature(main.main).bind("power", "pause")
        dispatcher(main.main, bound, {})
        bound = inspect.signature(main.main).bind("power", "invalid")
        dispatcher(main.main, bound, {})

    monkeypatch.setattr(type(main.app), "interactive_shell", interactive)
    from cyclopts.exceptions import CoercionError

    with pytest.raises(CoercionError):
        main.main("shell", exit_on_error=False)
    assert sum(r["method"] == "acquire" for r in service.requests) == 1
    release = [r for r in service.requests if r["method"] == "release"][-1]
    assert not release["params"]["completion"]["success"]


def test_offline_verify_fetch_and_bad_restore_do_not_discover(tmp_path, monkeypatch):
    from functools import partial
    from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

    from test_full_backup import Backend, FakeGnW

    from gnwmanager.cli.session_route import SessionRoute
    from gnwmanager.full_backup import capture_backup

    archive = tmp_path / "archive"
    capture_backup(FakeGnW(Backend()), archive)
    monkeypatch.setattr(SessionRoute, "sessions", lambda _self: pytest.fail("offline discovery"))
    main.main("verify-backup", str(archive))
    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(SimpleHTTPRequestHandler, directory=str(archive)))
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    try:
        main.main("fetch-backup", f"http://127.0.0.1:{server.server_port}/", "--dest", str(tmp_path / "fetched"))
    finally:
        server.shutdown()
        worker.join(2)
        server.server_close()
    (archive / "bank1.bin").write_bytes(b"bad")
    with pytest.raises(SystemExit) as error:
        main.main("restore-backup", str(archive), "--yes")
    assert error.value.code == 1


def test_declined_restore_does_not_discover(tmp_path, monkeypatch):
    from test_full_backup import Backend, FakeGnW

    from gnwmanager.cli.session_route import SessionRoute
    from gnwmanager.full_backup import capture_backup

    archive = tmp_path / "archive"
    capture_backup(FakeGnW(Backend()), archive)
    monkeypatch.setattr(SessionRoute, "sessions", lambda _self: pytest.fail("declined discovery"))
    monkeypatch.setattr("builtins.input", lambda _: "NO")
    main.main("restore-backup", str(archive), exit_on_error=False)


def test_session_external_gdb_receives_only_proxy_and_restores_signals(peer, monkeypatch):
    import signal

    from gnwmanager.cli._gdb import gdb

    service, rsp = peer
    owner = route(service.directory)
    gnw = owner.gnw(operation="debug")
    prior = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
    argv = []

    class Child:
        def __init__(self, args, **kwargs):
            argv.extend(args)
            assert gnw.backend._socket is None
            assert kwargs.get("shell", False) is False
            self.returncode = 0

        def poll(self):
            return 0

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr("gnwmanager.cli._gdb.subprocess.Popen", Child)
    try:
        gdb(gnw=gnw)
        assert "target remote " + str(service.proxy) in argv
        assert "None" not in argv
        assert prior == {s: signal.getsignal(s) for s in prior}
    finally:
        owner.close()
    assert not rsp.stop.is_set()  # fixture remains live until teardown


def test_cold_reconnect_keeps_lease_and_validates_latch(peer):
    service, _ = peer
    owner = route(service.directory)
    backend = owner.backend()
    lease_id = backend.session_lease.lease_id
    try:
        backend.cold_reconnect(expected_rdp=0)
        assert backend.session_lease.lease_id == lease_id
        assert sum(r["method"] == "acquire" for r in service.requests) == 1
        assert [r["params"]["action"] for r in service.requests if r["method"] == "control"] == ["cold-start"]
        assert not any(r["method"] == "control" and r["params"]["action"] == "press" for r in service.requests)
    finally:
        owner.close()


def test_failed_cold_latch_cannot_report_success(peer):
    from gnwmanager.session_client import SessionError

    service, _ = peer
    owner = route(service.directory)
    backend = owner.backend()
    try:
        with pytest.raises(SessionError, match="RDP latch"):
            backend.cold_reconnect(expected_rdp=0xAA)
        assert owner.failed
    finally:
        owner.close()
    assert not [r for r in service.requests if r["method"] == "release"][-1]["params"]["completion"]["success"]


def test_session_lock_and_no_backup_unlock_use_cold_latch(peer, monkeypatch):
    from gnwmanager.cli._lock import lock
    from gnwmanager.cli._unlock import unlock

    service, rsp = peer
    owner = route(service.directory)
    gnw = owner.gnw()
    monkeypatch.setattr(gnw, "start_gnwmanager", lambda **kw: None)
    monkeypatch.setattr("builtins.input", lambda _: "")
    monkeypatch.setattr("gnwmanager.cli._lock.sleep", lambda _: None)
    monkeypatch.setattr("gnwmanager.cli._unlock.sleep", lambda _: None)
    latch = []
    monkeypatch.setattr(gnw, "is_locked", lambda: len(latch) == 1)
    # Latch helper itself has independent real-RPC/RSP tests above; here ensure
    # command dispatch chooses it rather than physical prompts or warm reset.
    monkeypatch.setattr(gnw.backend, "cold_reconnect", lambda **kw: latch.append(kw))
    try:
        lock(skip_check=True, interactive=False, gnw=gnw)
        unlock(no_backup=True, gnw=gnw)
        assert latch == [{"expected_rdp": 0x55}, {"expected_rdp": 0xAA}]
        assert not any(c.startswith(b"qRcmd") for c in rsp.commands)
    finally:
        owner.close()


def test_shared_owner_reopens_gdb_after_debugger_handoff(peer, monkeypatch):
    service, rsp = peer
    monkeypatch.setattr(main, "SessionRoute", lambda **kw: route(service.directory, **kw))

    # Actual public commands; start --halt needs an open RSP after gdb closes it.
    class Child:
        def __init__(self, *args, **kwargs):
            pass

        def poll(self):
            return 0

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr("gnwmanager.cli._gdb.subprocess.Popen", Child)
    main.main("gdb", "--", "start", "bank1", "--halt")
    assert sum(r["method"] == "acquire" for r in service.requests) == 1
    assert sum(c.startswith(b"qSupported") for c in rsp.commands) == 2
    assert any(c.startswith(b"Pf=") for c in rsp.commands)


def test_payload_failure_message_does_not_say_complete(capsys):
    from gnwmanager.cli._unlock import _message

    with pytest.raises(RuntimeError, match="payload failed"), _message("Waiting for payload"):
        raise RuntimeError("payload failed")
    assert "complete!" not in capsys.readouterr().out


def test_missing_debugger_reports_failed_release_and_preserves_handlers(peer, monkeypatch):
    import signal

    service, _ = peer
    monkeypatch.setattr(main, "SessionRoute", lambda **kw: route(service.directory, **kw))
    previous = {signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)}

    def absent(*args, **kwargs):
        raise FileNotFoundError("configured GDB executable is absent")

    monkeypatch.setattr("gnwmanager.cli._gdb.subprocess.Popen", absent)
    with pytest.raises(FileNotFoundError):
        main.main("gdb")
    assert previous == {signum: signal.getsignal(signum) for signum in previous}
    assert not [r for r in service.requests if r["method"] == "release"][-1]["params"]["completion"]["success"]


def test_consumed_gdb_reply_cannot_return_success_after_lease_expiry(peer, monkeypatch):
    from gnwmanager.session_client import SessionError

    service, _ = peer
    owner = route(service.directory, timeout_ms=1000)
    backend = owner.backend()
    original = backend._wait_for_packet

    def delayed_consumption():
        reply = original()
        # The real command and its response completed while valid; scheduling
        # after consumption crosses the immutable lease deadline.
        while time.monotonic() <= backend.session_lease.deadline + 0.02:
            time.sleep(0.01)
        return reply

    monkeypatch.setattr(backend, "_wait_for_packet", delayed_consumption)
    try:
        with pytest.raises(SessionError):
            backend.read_memory(0x20000000, 4)
    finally:
        owner.failed = True
        with contextlib.suppress(SessionError):
            owner.close()


def test_consumed_continue_ack_cannot_return_success_after_lease_expiry(peer, monkeypatch):
    from gnwmanager.session_client import SessionError

    service, rsp = peer
    owner = route(service.directory, timeout_ms=1000)
    backend = owner.backend()
    original = backend._wait_for_ack
    consumed = []

    def delayed_consumption(packet):
        result = original(packet)
        if packet.startswith(b"$c#"):
            consumed.append(packet)
            # Consume the actual Unix ACK before simulating rescheduling past
            # the immutable lease deadline; do not fabricate an RSP response.
            while time.monotonic() <= backend.session_lease.deadline + 0.02:
                time.sleep(0.01)
        return result

    monkeypatch.setattr(backend, "_wait_for_ack", delayed_consumption)
    try:
        with pytest.raises(SessionError) as error:
            backend.resume()
        assert error.value.code == "LEASE_EXPIRED"
        assert consumed and rsp.commands.count(b"c") == 1
    finally:
        owner.failed = True
        with contextlib.suppress(SessionError):
            owner.close()
    assert not any(r["method"] == "release" and r["params"]["completion"]["success"] for r in service.requests)
    assert any(r["method"] == "mark" and r["params"]["executionChanged"] for r in service.requests)


def test_reconnect_revalidates_private_directory(peer):
    from gnwmanager.session_client import SessionError

    service, _ = peer
    owner = route(service.directory)
    backend = owner.backend()
    backend.close()
    service.directory.chmod(0o777)
    try:
        with pytest.raises(SessionError):
            backend.open()
        assert backend._socket is None
    finally:
        service.directory.chmod(0o700)
        owner.close()


@pytest.mark.parametrize("mark_error", [False, True])
def test_external_handoff_invalidates_manager_phase_and_reloads_firmware(peer, mark_error):
    from gnwmanager.session_client import SessionError

    service, rsp = peer
    owner = route(service.directory)
    gnw = owner.gnw()
    gnw.start_gnwmanager(resume=False)
    gnw.context_counter = 37
    gnw._external_flash_size = 1234
    gnw._external_flash_block_size = 5678
    gnw._in_flight_retry = [{"attempts": 1}, None]
    first_uploads = sum(c.startswith(b"M240e6800,") for c in rsp.commands)
    assert first_uploads == 1 and gnw._gnwmanager_started

    def reject(_service, request, _peer, send):
        if request["method"] == "mark":
            send(
                {
                    "protocol": 1,
                    "id": request["id"],
                    "ok": False,
                    "error": {"code": "BUSY", "message": "active control"},
                }
            )
        else:
            send()

    try:
        if mark_error:
            # Use a fresh acknowledged phase so mark genuinely reaches the peer.
            owner.lease().control("warm-reset")
            service.handler = reject
            with pytest.raises(SessionError):
                gnw.backend.debugger_endpoint()
        else:
            gnw.backend.debugger_endpoint()
        assert not gnw._gnwmanager_started
        assert gnw.context_counter == 1
        assert gnw._external_flash_size == gnw._external_flash_block_size == 0
        assert gnw._in_flight_retry == [None, None]
        service.handler = None
        owner.backend()
        gnw.start_gnwmanager(resume=False)
        assert sum(c.startswith(b"M240e6800,") for c in rsp.commands) == 2
        assert sum(r["method"] == "acquire" for r in service.requests) == 1
    finally:
        owner.close()


@pytest.mark.parametrize("signum", [2, 15])
def test_signal_during_child_creation_reaps_owned_process(peer, monkeypatch, signum):
    import os
    import signal
    import subprocess
    import sys

    service, _ = peer
    monkeypatch.setattr(main, "SessionRoute", lambda **kw: route(service.directory, **kw))
    created = []
    original = subprocess.Popen
    previous = signal.getsignal(signum)

    def interrupt(_signal, _frame):
        raise KeyboardInterrupt("unprotected spawn window")

    signal.signal(signum, interrupt)

    def spawn(*args, **kwargs):
        child = original(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        created.append(child)
        # Real signal after actual creation while our wrapper hasn't returned
        # the handle; the launch guard must defer it until it can reap.
        os.kill(os.getpid(), signum)
        return child

    monkeypatch.setattr("gnwmanager.cli._gdb.subprocess.Popen", spawn)
    try:
        with pytest.raises((SystemExit, KeyboardInterrupt)) as error:
            main.main("gdb")
        assert created and created[0].poll() is not None, "owned process leaked across spawn signal"
        assert isinstance(error.value, SystemExit) and error.value.code == 128 + signum
        assert signal.getsignal(signum) is interrupt
        assert not [r for r in service.requests if r["method"] == "release"][-1]["params"]["completion"]["success"]
    finally:
        signal.signal(signum, previous)
        for child in created:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=2)
            child.stdin.close()
