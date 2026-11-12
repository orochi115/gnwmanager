import contextlib
import importlib
import json
import socket
import threading
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

import pytest


@pytest.fixture
def api():
    assert importlib.util.find_spec("gnwmanager.session_client") is not None, "session client is not implemented"
    return importlib.import_module("gnwmanager.session_client")


@pytest.fixture
def directory():
    with TemporaryDirectory(prefix="gnw-sc-", dir="/tmp") as name:
        path = Path(name)
        path.chmod(0o700)
        yield path


def session(session_id=None):
    return {
        "sessionId": session_id or str(uuid4()),
        "profileName": "synthetic",
        "model": "zelda",
        "kernel": "gwemu",
        "execution": "paused",
        "powered": True,
        "capabilities": ["manage", "gdb", "backup", "device-control"],
    }


class UnixService:
    """Small real concurrent RPC peer; never launches or touches product data."""

    def __init__(self, directory, sessions=None, handler=None):
        self.directory = directory
        self.server_id = str(uuid4())
        self.endpoint = directory / f"r-{self.server_id.replace('-', '')[:16]}.sock"
        self.descriptor = {
            "protocol": 1,
            "serverId": self.server_id,
            "pid": 123,
            "endpoint": str(self.endpoint),
        }
        self.descriptor_path = directory / f"{self.server_id}.json"
        self.descriptor_path.write_text(json.dumps(self.descriptor))
        self.descriptor_path.chmod(0o600)
        self.sessions = [session()] if sessions is None else sessions
        self.handler = handler
        self.requests = []
        self.workers = []
        self.peers = []
        self.errors = []
        self.stop = threading.Event()
        self.proxy = directory / f"l-{uuid4().hex[:16]}.sock"
        self.gdb_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.gdb_listener.bind(str(self.proxy))
        self.proxy.chmod(0o600)
        self.gdb_listener.listen(1)
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.endpoint))
        self.endpoint.chmod(0o600)
        self.listener.listen(16)
        self.listener.settimeout(0.05)
        self.worker = threading.Thread(target=self._accept, daemon=True)
        self.worker.start()

    def _accept(self):
        while not self.stop.is_set():
            try:
                peer, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.peers.append(peer)
            peer.settimeout(0.05)
            worker = threading.Thread(target=self._read, args=(peer,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def _read(self, peer):
        buffer = bytearray()
        lock = threading.Lock()
        while not self.stop.is_set():
            try:
                data = peer.recv(4096)
                if not data:
                    return
                buffer.extend(data)
                while b"\n" in buffer:
                    line, _, rest = buffer.partition(b"\n")
                    buffer = bytearray(rest)
                    request = json.loads(line)
                    self.requests.append(request)
                    worker = threading.Thread(target=self._respond, args=(peer, lock, request), daemon=True)
                    self.workers.append(worker)
                    worker.start()
            except socket.timeout:
                continue
            except OSError:
                return
            except BaseException as error:
                self.errors.append(error)
                return

    def default_result(self, request):
        method = request["method"]
        if method == "hello":
            return {"serverId": self.server_id, "protocol": 1}
        if method == "list":
            return {"sessions": self.sessions}
        if method == "acquire":
            return {
                "leaseId": str(uuid4()),
                "sessionId": request["params"]["sessionId"],
                "gdbEndpoint": str(self.proxy),
                "initial": {
                    "execution": "paused",
                    "devicePower": {
                        "battery": 100,
                        "batteryPresent": True,
                        "usbPower": False,
                        "powered": True,
                    },
                },
                "expiresAt": time.time() * 1000 + request["params"]["timeoutMs"],
            }
        if method in ("heartbeat", "status"):
            return {
                "session": self.sessions[0],
                "expiresAt": time.time() * 1000 + 300000,
            }
        if method == "control":
            return {
                "session": self.sessions[0],
                "devicePower": {
                    "battery": 100,
                    "batteryPresent": True,
                    "usbPower": False,
                    "powered": True,
                },
            }
        return {"session": self.sessions[0]}

    def _respond(self, peer, lock, request):
        def send(response=None, fragments=False):
            response = response or {
                "protocol": 1,
                "id": request["id"],
                "ok": True,
                "result": self.default_result(request),
            }
            data = json.dumps(response).encode() + b"\n"
            with lock:
                try:
                    if fragments:
                        for byte in data:
                            if self.stop.is_set():
                                return
                            peer.sendall(bytes([byte]))
                    else:
                        peer.sendall(data)
                except OSError:
                    pass

        try:
            if self.handler:
                self.handler(self, request, peer, send)
            else:
                send()
        except OSError:
            # A client disconnects immediately on protocol failure or timeout.
            pass
        except BaseException as error:
            self.errors.append(error)

    def close(self):
        self.stop.set()
        self.listener.close()
        self.gdb_listener.close()
        for peer in self.peers:
            with contextlib.suppress(OSError):
                peer.shutdown(socket.SHUT_RDWR)
            peer.close()
        self.worker.join(1)
        for worker in self.workers:
            worker.join(1)
        assert not self.worker.is_alive()
        assert all(not worker.is_alive() for worker in self.workers)
        assert not self.errors

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def test_shared_protocol_fixture(api):
    fixture = json.loads((Path(__file__).parent / "fixtures/session-protocol.json").read_text())
    for request in fixture["validRequests"]:
        api.validate_request(request)
    for item in fixture["invalidRequests"]:
        with pytest.raises(api.SessionError) as caught:
            api.validate_request(item["request"])
        assert caught.value.code == item["code"]


def test_discovery_only_reachable_sessions_does_not_delete_stale(api, directory):
    stale_id = str(uuid4())
    stale = directory / f"{stale_id}.json"
    stale.write_text(
        json.dumps(
            {
                "protocol": 1,
                "serverId": stale_id,
                "pid": 1,
                "endpoint": str(directory / f"r-{stale_id.replace('-', '')[:16]}.sock"),
            }
        )
    )
    stale.chmod(0o600)
    with UnixService(directory) as service:
        found = api.discover_sessions(directory=directory, timeout=0.2)
        assert len(found) == 1
        assert found[0].session == service.sessions[0]
        assert found[0].descriptor == service.descriptor
        assert stale.exists()
        assert api.select_session(found).session == service.sessions[0]


def test_multi_session_never_selects_first(api, directory):
    with UnixService(directory) as first, UnixService(directory) as second:
        found = api.discover_sessions(directory=directory)
        assert len(found) == 2
        with pytest.raises(api.SessionError, match="Multiple"):
            api.select_session(found)
        chosen = api.select_session(found, second.sessions[0]["sessionId"])
        assert chosen.session == second.sessions[0]
        with pytest.raises(api.SessionError, match="No"):
            api.select_session([], None)
        with pytest.raises(api.SessionError):
            api.select_session(found, first.server_id)


@pytest.mark.parametrize("mode", [0o755, 0o770, 0o600])
def test_nonprivate_directory_rejected_without_chmod(api, directory, mode):
    directory.chmod(mode)
    with pytest.raises(api.SessionError):
        api.discover_sessions(directory=directory)
    assert directory.stat().st_mode & 0o777 == mode
    directory.chmod(0o700)


def test_directory_symlink_rejected(api, directory):
    alias = directory.parent / f"gnw-link-{uuid4().hex[:8]}"
    alias.symlink_to(directory)
    try:
        with pytest.raises(api.SessionError):
            api.discover_sessions(directory=alias)
    finally:
        alias.unlink()


@pytest.mark.parametrize("target", ["descriptor", "endpoint"])
def test_untrusted_file_modes_or_symlinks_are_not_connected(api, directory, target):
    with UnixService(directory) as service:
        path = service.descriptor_path if target == "descriptor" else service.endpoint
        path.chmod(0o644)
        assert api.discover_sessions(directory=directory) == []
        assert not service.requests
        path.chmod(0o600)
        original = path.with_name(path.name + ".old")
        path.rename(original)
        path.symlink_to(original)
        assert api.discover_sessions(directory=directory) == []
        assert not service.requests


def test_hello_identity_mismatch_not_discovered(api, directory):
    def handler(service, request, _peer, send):
        result = service.default_result(request)
        if request["method"] == "hello":
            result["serverId"] = str(uuid4())
        send({"protocol": 1, "id": request["id"], "ok": True, "result": result})

    with UnixService(directory, handler=handler):
        assert api.discover_sessions(directory=directory) == []


def test_fragmented_rpc_and_out_of_order_responses(api, directory):
    gate = threading.Event()

    def handler(service, request, _peer, send):
        if request["method"] == "list":
            gate.wait(0.3)
        elif request["method"] == "status":
            gate.set()
        send(fragments=True)

    with (
        UnixService(directory, handler=handler) as service,
        api.SessionClient(service.descriptor, directory=directory) as client,
    ):
        results = []
        worker = threading.Thread(target=lambda: results.append(client.request("list", {})))
        worker.start()
        # Nonleased RPC status shape used only by this peer to force reordering.
        reply = client.request(
            "status",
            {"sessionId": service.sessions[0]["sessionId"], "leaseId": str(uuid4())},
        )
        worker.join(1)
        assert not worker.is_alive()
        assert reply["session"] == service.sessions[0]
        assert results == [{"sessions": service.sessions}]


def test_error_response_exposes_stable_code(api, directory):
    def handler(_service, request, _peer, send):
        if request["method"] == "list":
            send(
                {
                    "protocol": 1,
                    "id": request["id"],
                    "ok": False,
                    "error": {"code": "BUSY", "message": "Device is busy"},
                }
            )
        else:
            send()

    with (
        UnixService(directory, handler=handler) as service,
        api.SessionClient(service.descriptor, directory=directory) as client,
    ):
        with pytest.raises(api.SessionError) as caught:
            client.request("list", {})
        assert caught.value.code == "BUSY"


def test_late_read_response_does_not_satisfy_next_request(api, directory):
    def handler(service, request, _peer, send):
        if request["method"] == "list":
            service.stop.wait(0.15)
        send()

    with (
        UnixService(directory, handler=handler) as service,
        api.SessionClient(service.descriptor, directory=directory) as client,
    ):
        with pytest.raises(api.SessionError, match="Timed out"):
            client.request("list", {}, timeout=0.03)
        reply = client.request("hello", {"serverId": service.server_id})
        assert reply["serverId"] == service.server_id
        service.stop.wait(0.18)
        assert client.request("hello", {"serverId": service.server_id}) == {
            "protocol": 1,
            "serverId": service.server_id,
        }


def test_lease_context_explicit_release_success_and_exception(api, directory):
    with UnixService(directory) as service:
        with api.SessionClient(service.descriptor, directory=directory) as client:
            with client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=0.02) as lease:
                assert lease.gdb_endpoint == service.proxy
                lease.mark(memory_written=True)
            with (
                pytest.raises(ValueError, match="operation failed"),
                client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=0.02),
            ):
                raise ValueError("operation failed")
        releases = [r["params"]["completion"] for r in service.requests if r["method"] == "release"]
        assert releases == [
            {
                "success": True,
                "managerUploaded": False,
                "memoryWritten": True,
                "executionChanged": False,
            },
            {
                "success": False,
                "managerUploaded": False,
                "memoryWritten": False,
                "executionChanged": False,
            },
        ]
        assert not lease.heartbeat_thread.is_alive()
        assert not client.reader_thread.is_alive()


def test_heartbeat_independent_of_long_control_and_real_gdb_read(api, directory):
    def handler(service, request, _peer, send):
        if request["method"] == "control":
            service.stop.wait(0.15)
        send()

    with UnixService(directory, handler=handler) as service:
        gdb_errors = []

        def gdb_peer():
            try:
                service.gdb_listener.settimeout(1)
                peer, _ = service.gdb_listener.accept()
                with peer:
                    peer.settimeout(1)
                    peer.recv(4096)
                    service.stop.wait(0.18)
                    peer.sendall(b"+$00#60")
                    peer.recv(1)
            except BaseException as error:
                gdb_errors.append(error)

        worker = threading.Thread(target=gdb_peer)
        worker.start()
        with (
            api.SessionClient(service.descriptor, directory=directory) as client,
            client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=0.02) as lease,
        ):
            from gnwmanager.ocdbackend.gdb_backend import GDBBackend

            backend = GDBBackend(unix_socket=lease.gdb_endpoint)
            backend._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            backend._socket.connect(str(lease.gdb_endpoint))
            results = []
            reader = threading.Thread(target=lambda: results.append(backend.read_memory(0x20000000, 1)))
            reader.start()
            lease.control("press", {"mask": 16, "durationMs": 150})
            reader.join(1)
            backend.close()
            assert results == [b"\x00"]
            assert len([r for r in service.requests if r["method"] == "heartbeat"]) >= 4
        worker.join(1)
        assert not worker.is_alive()
        assert not gdb_errors


def test_heartbeat_failure_saved_for_main_operation_and_failed_release(api, directory):
    def handler(_service, request, _peer, send):
        if request["method"] == "heartbeat":
            send(
                {
                    "protocol": 1,
                    "id": request["id"],
                    "ok": False,
                    "error": {"code": "LEASE_EXPIRED", "message": "Lease expired"},
                }
            )
        else:
            send()

    with UnixService(directory, handler=handler) as service:
        with api.SessionClient(service.descriptor, directory=directory) as client:
            lease = client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=0.01)
            lease.heartbeat_thread.join(1)
            with pytest.raises(api.SessionError) as caught:
                lease.status()
            assert caught.value.code == "LEASE_EXPIRED"
            with pytest.raises(api.SessionError):
                lease.release()
        release = [r for r in service.requests if r["method"] == "release"]
        assert not release or release[0]["params"]["completion"]["success"] is False


def test_heartbeat_cannot_extend_absolute_deadline(api, directory):
    def handler(service, request, _peer, send):
        result = service.default_result(request)
        if request["method"] == "acquire":
            result["expiresAt"] = time.time() * 1000 + 100
        send({"protocol": 1, "id": request["id"], "ok": True, "result": result})

    with UnixService(directory, handler=handler) as service:
        with api.SessionClient(service.descriptor, directory=directory) as client:
            lease = client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=0.01)
            lease.heartbeat_thread.join(1)
            with pytest.raises(api.SessionError) as caught:
                lease.status()
            assert caught.value.code == "LEASE_EXPIRED"
            lease.close()
        assert not lease.heartbeat_thread.is_alive()


def test_mark_cache_cleared_on_own_reset_but_completion_accumulates(api, directory):
    with UnixService(directory) as service:
        with (
            api.SessionClient(service.descriptor, directory=directory) as client,
            client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=1) as lease,
        ):
            lease.mark(memory_written=True)
            lease.mark(memory_written=True)
            lease.control("warm-reset")
            lease.mark(memory_written=True)
        marks = [r for r in service.requests if r["method"] == "mark"]
        assert len(marks) == 2
        assert [r for r in service.requests if r["method"] == "release"][0]["params"]["completion"]["memoryWritten"]


def test_failed_mark_not_acknowledged_or_counted(api, directory):
    def handler(_service, request, _peer, send):
        if request["method"] == "mark":
            send(
                {
                    "protocol": 1,
                    "id": request["id"],
                    "ok": False,
                    "error": {"code": "BUSY", "message": "Device is busy"},
                }
            )
        else:
            send()

    with UnixService(directory, handler=handler) as service:
        with (
            api.SessionClient(service.descriptor, directory=directory) as client,
            client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=1) as lease,
        ):
            for _ in range(2):
                with pytest.raises(api.SessionError) as caught:
                    lease.mark(memory_written=True)
                assert caught.value.code == "BUSY"
        assert len([r for r in service.requests if r["method"] == "mark"]) == 2
        assert not [r for r in service.requests if r["method"] == "release"][0]["params"]["completion"]["memoryWritten"]


@pytest.mark.parametrize("kind", ["oversize", "bad-id", "bad-protocol", "bad-ok"])
def test_malformed_response_disconnects_and_wakes_pending(api, directory, kind):
    def handler(_service, request, peer, send):
        if request["method"] != "list":
            send()
            return
        if kind == "oversize":
            peer.sendall(b"x" * 65537)
            return
        response = {"protocol": 1, "id": request["id"], "ok": True, "result": {}}
        response[{"bad-id": "id", "bad-protocol": "protocol", "bad-ok": "ok"}[kind]] = {
            "bad-id": 4,
            "bad-protocol": 2,
            "bad-ok": 1,
        }[kind]
        send(response)

    with (
        UnixService(directory, handler=handler) as service,
        api.SessionClient(service.descriptor, directory=directory) as client,
    ):
        started = time.monotonic()
        with pytest.raises(api.SessionError):
            client.request("list", {})
        assert time.monotonic() - started < 1
        client.reader_thread.join(1)
        assert not client.reader_thread.is_alive()


def test_disconnect_wakes_all_pending_and_close_is_bounded(api, directory):
    connected = threading.Event()

    def handler(_service, request, peer, send):
        if request["method"] == "list":
            connected.set()
            peer.shutdown(socket.SHUT_RDWR)
        else:
            send()

    with UnixService(directory, handler=handler) as service:
        with api.SessionClient(service.descriptor, directory=directory) as client:
            with pytest.raises(api.SessionError):
                client.request("list", {})
            assert connected.is_set()
        assert not client.reader_thread.is_alive()


def test_failed_release_disconnects_owner_instead_of_leaving_hidden_lease(api, directory):
    def handler(_service, request, _peer, send):
        if request["method"] == "release":
            send(
                {
                    "protocol": 1,
                    "id": request["id"],
                    "ok": False,
                    "error": {"code": "INTERNAL", "message": "Release failed"},
                }
            )
        else:
            send()

    with (
        UnixService(directory, handler=handler) as service,
        api.SessionClient(service.descriptor, directory=directory) as client,
    ):
        lease = client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=0.02)
        with pytest.raises(api.SessionError, match="Release failed"):
            lease.release()
        client.reader_thread.join(0.5)
        assert not client.reader_thread.is_alive()
        assert not lease.heartbeat_thread.is_alive()
        with pytest.raises(api.SessionError):
            client.request("list", {})


def test_wrong_uid_directory_is_rejected(api, directory, monkeypatch):
    monkeypatch.setattr(api.os, "getuid", lambda: directory.stat().st_uid + 1)
    with pytest.raises(api.SessionError, match="private"):
        api.discover_sessions(directory=directory)


def test_deadline_counts_admission_delay(api, directory):
    admission = threading.Event()

    def handler(service, request, _peer, send):
        if request["method"] == "acquire":
            admission.set()
            service.stop.wait(0.08)
        send()

    with (
        UnixService(directory, handler=handler) as service,
        api.SessionClient(service.descriptor, directory=directory) as client,
    ):
        started = time.monotonic()
        lease = client.acquire(service.sessions[0]["sessionId"], timeout_ms=1000, heartbeat_interval=1)
        assert admission.is_set()
        assert lease.deadline <= started + 1.01
        lease.close()


def test_closed_client_cannot_reopen_as_if_it_were_connected(api, directory):
    with UnixService(directory) as service:
        client = api.SessionClient(service.descriptor, directory=directory).open()
        client.close()
        with pytest.raises(api.SessionError):
            client.open()


def test_descriptor_chmod_during_open_is_rejected_by_fd_metadata(api, directory, monkeypatch):
    with UnixService(directory) as service:
        original = api.os.open

        def change_permissions(path, *args, **kwargs):
            fd = original(path, *args, **kwargs)
            if Path(path) == service.descriptor_path:
                service.descriptor_path.chmod(0o644)
            return fd

        monkeypatch.setattr(api.os, "open", change_permissions)
        assert api.discover_sessions(directory=directory) == []
        assert not service.requests


def test_rpc_total_deadline_survives_continuing_slow_fragments(api, directory):
    def handler(service, request, peer, send):
        if request["method"] != "list":
            send()
            return
        response = json.dumps({"protocol": 1, "id": request["id"], "ok": True, "result": {}}).encode() + b"\n"
        for byte in response:
            if service.stop.wait(0.01):
                return
            try:
                peer.sendall(bytes([byte]))
            except OSError:
                return

    with (
        UnixService(directory, handler=handler) as service,
        api.SessionClient(service.descriptor, directory=directory) as client,
    ):
        started = time.monotonic()
        with pytest.raises(api.SessionError, match="Timed out"):
            client.request("list", {}, timeout=0.05)
        assert time.monotonic() - started < 0.2


def test_mutation_rpc_timeout_disconnects_owner_and_stops_threads(api, directory):
    def handler(service, request, _peer, send):
        if request["method"] == "control":
            service.stop.wait(0.2)
        send()

    with UnixService(directory, handler=handler) as service:
        client = api.SessionClient(service.descriptor, directory=directory, rpc_timeout=0.03).open()
        lease = client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=1)
        try:
            with pytest.raises(api.SessionError, match="Timed out"):
                lease.control("pause")
            client.reader_thread.join(1)
            assert not client.reader_thread.is_alive()
            with pytest.raises(api.SessionError):
                lease.status()
        finally:
            lease.close()
        assert not lease.heartbeat_thread.is_alive()


def test_untrusted_native_or_foreign_proxy_reply_revokes_admitted_lease(api, directory):
    def handler(service, request, _peer, send):
        result = service.default_result(request)
        if request["method"] == "acquire":
            result["gdbEndpoint"] = str(directory / "n-0123456789abcdef.sock")
        send({"protocol": 1, "id": request["id"], "ok": True, "result": result})

    with (
        UnixService(directory, handler=handler) as service,
        api.SessionClient(service.descriptor, directory=directory) as client,
    ):
        with pytest.raises(api.SessionError):
            client.acquire(service.sessions[0]["sessionId"])
        assert not client.reader_thread.is_alive()


@pytest.mark.parametrize("method", ["status", "mark", "control", "heartbeat"])
def test_leased_reply_for_another_runtime_is_rejected_and_revoked(api, directory, method):
    def handler(service, request, _peer, send):
        result = service.default_result(request)
        if request["method"] == method:
            result["session"] = session()
        send({"protocol": 1, "id": request["id"], "ok": True, "result": result})

    with UnixService(directory, handler=handler) as service:
        client = api.SessionClient(service.descriptor, directory=directory).open()
        lease = client.acquire(
            service.sessions[0]["sessionId"],
            heartbeat_interval=0.01 if method == "heartbeat" else 1,
        )
        try:
            with pytest.raises(api.SessionError):
                if method == "heartbeat":
                    lease.heartbeat_thread.join(1)
                    lease.status()
                elif method == "status":
                    lease.status()
                elif method == "mark":
                    lease.mark(memory_written=True)
                else:
                    lease.control("pause")
            client.reader_thread.join(1)
            assert not client.reader_thread.is_alive()
        finally:
            lease.close()


def test_press_uses_duration_budget_beyond_default_rpc_timeout(api, directory):
    def handler(service, request, _peer, send):
        if request["method"] == "control":
            service.stop.wait(0.1)
        send()

    with (
        UnixService(directory, handler=handler) as service,
        api.SessionClient(service.descriptor, directory=directory, rpc_timeout=0.03) as client,
        client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=0.01) as lease,
    ):
        lease.control("press", {"mask": 1, "durationMs": 100})
        assert len([request for request in service.requests if request["method"] == "heartbeat"]) >= 3


def test_successful_release_is_not_revoked_by_heartbeat_waking_at_close(api, directory, monkeypatch):
    heartbeat_entered = threading.Event()
    continue_heartbeat = threading.Event()
    release_seen = threading.Event()

    def handler(service, request, _peer, send):
        if request["method"] == "release":
            release_seen.set()
            service.stop.wait(0.08)
        send()

    with (
        UnixService(directory, handler=handler) as service,
        api.SessionClient(service.descriptor, directory=directory) as client,
    ):
        lease = client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=0.01)
        original = lease.check

        def gate():
            if threading.current_thread() is lease.heartbeat_thread:
                heartbeat_entered.set()
                assert continue_heartbeat.wait(1)
            original()

        monkeypatch.setattr(lease, "check", gate)
        assert heartbeat_entered.wait(1)
        errors = []

        def release():
            try:
                lease.release()
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=release)
        worker.start()
        assert release_seen.wait(1)
        continue_heartbeat.set()
        worker.join(1)
        assert not worker.is_alive()
        assert not errors
        assert client.request("list", {}) == {"sessions": service.sessions}


def test_partial_request_write_timeout_disconnects_even_for_readonly_rpc(api, directory):
    with UnixService(directory) as service, api.SessionClient(service.descriptor, directory=directory) as client:
        original = client._socket

        class PartialWrite:
            sent = False

            def __getattr__(self, name):
                return getattr(original, name)

            def send(self, data):
                if not self.sent:
                    self.sent = True
                    return original.send(data[:5])
                raise BlockingIOError

        client._socket = PartialWrite()
        try:
            with pytest.raises(api.SessionError, match="Timed out"):
                client.request("list", {}, timeout=0.02)
            client.reader_thread.join(0.3)
            assert not client.reader_thread.is_alive()
        finally:
            client._socket = original


def test_close_interrupts_heartbeat_waiting_for_rpc_write_lock(api, directory):
    with UnixService(directory) as service:
        client = api.SessionClient(service.descriptor, directory=directory).open()
        lease = client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=0.01)
        client._write_lock.acquire()
        try:
            end = time.monotonic() + 1
            while not client._pending and time.monotonic() < end:
                time.sleep(0.005)
            assert client._pending, "heartbeat must actually be waiting on the held write lock"
            started = time.monotonic()
            client.close()
            assert time.monotonic() - started < 0.5
            assert not lease.heartbeat_thread.is_alive()
        finally:
            client._write_lock.release()
            client.close()


@pytest.mark.parametrize("action", ["warm-reset", "cold-start"])
def test_reset_reply_window_rejects_cached_mark_without_blocking_heartbeat(api, directory, monkeypatch, action):
    replied = threading.Event()
    finish_reset = threading.Event()
    heartbeat = threading.Event()

    def handler(_service, request, _peer, send):
        if request["method"] == "heartbeat":
            heartbeat.set()
        send()

    with (
        UnixService(directory, handler=handler) as service,
        api.SessionClient(service.descriptor, directory=directory) as client,
    ):
        with client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=0.01) as lease:
            lease.mark(memory_written=True)
            original = client.request

            def gated(method, params, **kwargs):
                result = original(method, params, **kwargs)
                if method == "control" and params["action"] == action:
                    replied.set()
                    assert finish_reset.wait(2), "caller must consume reset reply within test deadline"
                return result

            monkeypatch.setattr(client, "request", gated)
            errors = []

            def reset():
                try:
                    lease.control(action)
                except BaseException as error:
                    errors.append(error)

            worker = threading.Thread(target=reset)
            worker.start()
            try:
                assert replied.wait(1), "actual RPC reset response must arrive before concurrent mark"
                with pytest.raises(api.SessionError) as caught:
                    lease.mark(memory_written=True)
                assert caught.value.code == "BUSY"
                assert heartbeat.wait(1), "reset reply wait must not stop independent heartbeat"
                assert len([r for r in service.requests if r["method"] == "mark"]) == 1
            finally:
                finish_reset.set()
                worker.join(1)
                assert not worker.is_alive()
            assert not errors
            lease.mark(memory_written=True)
            lease.mark(memory_written=True)
            assert len([r for r in service.requests if r["method"] == "mark"]) == 2
        completion = [r["params"]["completion"] for r in service.requests if r["method"] == "release"][0]
        assert completion["success"] and completion["memoryWritten"]


@pytest.mark.parametrize("action", ["warm-reset", "cold-start"])
def test_failed_reset_invalidates_preexisting_mark_acknowledgement(api, directory, action):
    def handler(_service, request, _peer, send):
        if request["method"] == "control":
            send(
                {
                    "protocol": 1,
                    "id": request["id"],
                    "ok": False,
                    "error": {"code": "UNCERTAIN", "message": "Reset completion cannot be confirmed"},
                }
            )
        else:
            send()

    with (
        UnixService(directory, handler=handler) as service,
        api.SessionClient(service.descriptor, directory=directory) as client,
        client.acquire(service.sessions[0]["sessionId"]) as lease,
    ):
        lease.mark(memory_written=True)
        with pytest.raises(api.SessionError) as caught:
            lease.control(action)
        assert caught.value.code == "UNCERTAIN"
        lease.mark(memory_written=True)
        assert len([r for r in service.requests if r["method"] == "mark"]) == 2


def test_overlapping_resets_keep_mark_cache_suspended_until_both_return(api, directory, monkeypatch):
    replied = {action: threading.Event() for action in ("warm-reset", "cold-start")}
    finish = {action: threading.Event() for action in replied}
    errors = []
    with (
        UnixService(directory) as service,
        api.SessionClient(service.descriptor, directory=directory) as client,
        client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=0.01) as lease,
    ):
        lease.mark(memory_written=True)
        original = client.request

        def gated(method, params, **kwargs):
            result = original(method, params, **kwargs)
            if method == "control":
                action = params["action"]
                replied[action].set()
                assert finish[action].wait(2)
            return result

        monkeypatch.setattr(client, "request", gated)

        def reset(action):
            try:
                lease.control(action)
            except BaseException as error:
                errors.append(error)

        workers = {action: threading.Thread(target=reset, args=(action,)) for action in replied}
        for worker in workers.values():
            worker.start()
        try:
            assert all(event.wait(1) for event in replied.values())
            finish["warm-reset"].set()
            workers["warm-reset"].join(1)
            assert not workers["warm-reset"].is_alive()
            with pytest.raises(api.SessionError) as caught:
                lease.mark(memory_written=True)
            assert caught.value.code == "BUSY"
        finally:
            for event in finish.values():
                event.set()
            for worker in workers.values():
                worker.join(1)
                assert not worker.is_alive()
        assert not errors
        lease.mark(memory_written=True)
        lease.mark(memory_written=True)
        assert len([r for r in service.requests if r["method"] == "mark"]) == 2


@pytest.mark.parametrize("action", ["warm-reset", "cold-start"])
@pytest.mark.parametrize("reset_fails", [False, True])
def test_mark_reply_delayed_across_reset_cannot_authorize_mutation(api, directory, monkeypatch, action, reset_fails):
    marked = threading.Event()
    finish_mark = threading.Event()
    errors = []
    mutations = []

    def handler(_service, request, _peer, send):
        if request["method"] == "control" and reset_fails:
            send(
                {
                    "protocol": 1,
                    "id": request["id"],
                    "ok": False,
                    "error": {"code": "UNCERTAIN", "message": "Reset completion cannot be confirmed"},
                }
            )
        else:
            send()

    with (
        UnixService(directory, handler=handler) as service,
        api.SessionClient(service.descriptor, directory=directory) as client,
    ):
        with client.acquire(service.sessions[0]["sessionId"]) as lease:
            original = client.request

            def gated(method, params, **kwargs):
                result = original(method, params, **kwargs)
                if method == "mark" and not marked.is_set():
                    marked.set()
                    assert finish_mark.wait(2)
                return result

            monkeypatch.setattr(client, "request", gated)

            def mutate():
                try:
                    lease.mark(memory_written=True, execution_changed=True)
                    mutations.append("GDB action authorized")
                except BaseException as error:
                    errors.append(error)

            worker = threading.Thread(target=mutate)
            worker.start()
            try:
                assert marked.wait(1), "real remote mark acknowledgement must arrive first"
                if reset_fails:
                    with pytest.raises(api.SessionError) as caught:
                        lease.control(action)
                    assert caught.value.code == "UNCERTAIN"
                else:
                    lease.control(action)
            finally:
                finish_mark.set()
                worker.join(1)
                assert not worker.is_alive()
            assert not mutations, "stale mark success must not authorize a subsequent GDB action"
            assert len(errors) == 1 and isinstance(errors[0], api.SessionError)
            assert errors[0].code == "BUSY"
            # The old remote acknowledgement still records cumulative changes,
            # but the next caller needs a real mark in the current reset phase.
            lease.mark(memory_written=True)
            lease.mark(memory_written=True)
            assert len([r for r in service.requests if r["method"] == "mark"]) == 2
        completion = [r["params"]["completion"] for r in service.requests if r["method"] == "release"][0]
        assert completion["memoryWritten"] and completion["executionChanged"]


@pytest.mark.parametrize("invalidate", ["release", "disconnect", "expiry"])
def test_acknowledged_mark_cannot_return_authorization_after_lease_invalidation(
    api, directory, monkeypatch, invalidate
):
    marked = threading.Event()
    finish_mark = threading.Event()
    errors = []
    mutations = []

    def handler(service, request, _peer, send):
        result = service.default_result(request)
        if request["method"] == "acquire" and invalidate == "expiry":
            result["expiresAt"] = time.time() * 1000 + 100
        send({"protocol": 1, "id": request["id"], "ok": True, "result": result})

    with (
        UnixService(directory, handler=handler) as service,
        api.SessionClient(service.descriptor, directory=directory) as client,
    ):
        lease = client.acquire(service.sessions[0]["sessionId"], timeout_ms=1000)
        original = client.request

        def gated(method, params, **kwargs):
            result = original(method, params, **kwargs)
            if method == "mark":
                marked.set()
                assert finish_mark.wait(2)
            return result

        monkeypatch.setattr(client, "request", gated)

        def mutate():
            try:
                lease.mark(memory_written=True)
                mutations.append("GDB action authorized")
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=mutate)
        worker.start()
        try:
            assert marked.wait(1)
            if invalidate == "release":
                lease.release()
            elif invalidate == "disconnect":
                client.close()
            else:
                lease.heartbeat_thread.join(1)
                assert not lease.heartbeat_thread.is_alive(), "real fixed deadline must expire while reply is held"
        finally:
            finish_mark.set()
            worker.join(1)
            assert not worker.is_alive()
        assert not mutations, "invalid lease acknowledgement must not authorize a GDB action"
        assert len(errors) == 1 and isinstance(errors[0], api.SessionError)
        assert errors[0].code == ("LEASE_EXPIRED" if invalidate == "expiry" else "NOT_OWNER")
        if not lease._closed:
            lease.close()


def test_reset_timeout_revokes_cached_mark_and_joins_independent_workers(api, directory):
    control_entered = threading.Event()

    def handler(service, request, _peer, send):
        if request["method"] == "control":
            control_entered.set()
            service.stop.wait(1)
        else:
            send()

    with (
        UnixService(directory, handler=handler) as service,
        api.SessionClient(service.descriptor, directory=directory, rpc_timeout=0.1) as client,
    ):
        lease = client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=0.01)
        lease.mark(memory_written=True)
        with pytest.raises(api.SessionError) as caught:
            lease.control("warm-reset")
        assert caught.value.code == "LEASE_EXPIRED"
        assert control_entered.is_set()
        with pytest.raises(api.SessionError):
            lease.mark(memory_written=True)
        with pytest.raises(api.SessionError):
            lease.release()
        assert not client.reader_thread.is_alive()
        assert not lease.heartbeat_thread.is_alive()
        releases = [r["params"]["completion"] for r in service.requests if r["method"] == "release"]
        assert not releases or not releases[0]["success"]


def test_released_pending_heartbeat_cannot_expire_a_new_lease(api, directory):
    seen = threading.Event()
    old_id = None

    def handler(_service, request, _peer, send):
        if request["method"] == "heartbeat" and request["params"]["leaseId"] == old_id:
            seen.set()
            return
        send()

    with (
        UnixService(directory, handler=handler) as service,
        api.SessionClient(service.descriptor, directory=directory, rpc_timeout=1.8) as client,
    ):
        old = client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=0.01)
        old_id = old.lease_id
        assert seen.wait(1), "old heartbeat must be genuinely pending at the peer"
        result = old.release()
        alive_after_release = old.heartbeat_thread.is_alive()
        assert result["session"]["execution"] == "paused"
        with client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=0.02) as new:
            assert new.status()["session"]["execution"] == "paused"
            # Pass the original heartbeat's actual RPC deadline; the same
            # connection must remain valid for the fresh owner throughout.
            assert not service.stop.wait(1.9)
            assert new.status()["session"]["execution"] == "paused"
            assert client._failure is None
        assert not alive_after_release
        assert not old.heartbeat_thread.is_alive()
        assert not client._pending


def test_retired_heartbeat_at_request_entry_never_sends_for_old_owner(api, directory, monkeypatch):
    entered, finish = threading.Event(), threading.Event()
    old_id = None
    with (
        UnixService(directory) as service,
        api.SessionClient(service.descriptor, directory=directory, rpc_timeout=1.8) as client,
    ):
        original = client.request

        def gated(method, params, **kwargs):
            if method == "heartbeat" and params["leaseId"] == old_id:
                entered.set()
                assert finish.wait(4), "release gate must have finite cleanup"
            return original(method, params, **kwargs)

        monkeypatch.setattr(client, "request", gated)
        old = client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=0.01)
        old_id = old.lease_id
        assert entered.wait(1)
        try:
            old.release()
            with client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=0.02) as new:
                finish.set()
                old.heartbeat_thread.join(1)
                assert not old.heartbeat_thread.is_alive()
                assert new.status()["session"]["execution"] == "paused"
                assert client._failure is None
                assert not [
                    r for r in service.requests if r["method"] == "heartbeat" and r["params"]["leaseId"] == old_id
                ]
        finally:
            finish.set()
            old.heartbeat_thread.join(1)
            assert not old.heartbeat_thread.is_alive()


def test_release_cancels_heartbeat_waiting_for_write_lock(api, directory):
    with (
        UnixService(directory) as service,
        api.SessionClient(service.descriptor, directory=directory) as client,
    ):
        old = client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=0.01)
        errors = []
        replies = []

        def release():
            try:
                replies.append(old.release())
            except BaseException as error:
                errors.append(error)

        client._write_lock.acquire()
        worker = threading.Thread(target=release)
        try:
            end = time.monotonic() + 1
            while not client._pending and time.monotonic() < end:
                time.sleep(0.005)
            assert client._pending, "heartbeat must wait on the actual transport lock"
            worker.start()
            old.heartbeat_thread.join(0.3)
            assert not old.heartbeat_thread.is_alive(), "normal retirement must cancel the old lock waiter"
        finally:
            client._write_lock.release()
            if worker.ident is not None:
                worker.join(1)
                assert not worker.is_alive()
        assert not errors
        assert replies[0]["session"]["execution"] == "paused"
        with client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=0.02) as new:
            assert new.status()["session"]["execution"] == "paused"


def test_retiring_partial_heartbeat_frame_disconnects_tainted_transport(api, directory):
    with (
        UnixService(directory) as service,
        api.SessionClient(service.descriptor, directory=directory, rpc_timeout=1.8) as client,
    ):
        original = client._socket
        partial = threading.Event()

        class PartialHeartbeat:
            def __getattr__(self, name):
                return getattr(original, name)

            def send(self, data):
                if not partial.is_set():
                    count = original.send(data[:5])
                    partial.set()
                    return count
                raise BlockingIOError

        old = client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=0.03)
        client._socket = PartialHeartbeat()
        try:
            assert partial.wait(1), "heartbeat must actually have sent a partial JSON frame"
            started = time.monotonic()
            with pytest.raises(api.SessionError) as caught:
                old.release()
            assert caught.value.code == "NOT_OWNER"
            assert time.monotonic() - started < 0.5
            assert client._failure is not None
            assert not old.heartbeat_thread.is_alive()
            assert not client._pending
            with pytest.raises(api.SessionError):
                client.acquire(service.sessions[0]["sessionId"])
        finally:
            client._socket = original
        assert not [r for r in service.requests if r["method"] == "release"]


@pytest.mark.parametrize("method", ["status", "mark", "control"])
def test_retired_lease_call_at_admission_cannot_reach_new_owner(api, directory, monkeypatch, method):
    entered, finish = threading.Event(), threading.Event()
    errors = []
    with (
        UnixService(directory) as service,
        api.SessionClient(service.descriptor, directory=directory) as client,
    ):
        old = client.acquire(service.sessions[0]["sessionId"])
        original = client.request

        def gated(name, params, **kwargs):
            if name == method and params["leaseId"] == old.lease_id:
                entered.set()
                assert finish.wait(3)
            return original(name, params, **kwargs)

        monkeypatch.setattr(client, "request", gated)

        def call():
            try:
                if method == "status":
                    old.status()
                elif method == "mark":
                    old.mark(memory_written=True)
                else:
                    old.control("pause")
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=call)
        worker.start()
        try:
            assert entered.wait(1)
            old.release()
            with client.acquire(service.sessions[0]["sessionId"]) as new:
                finish.set()
                worker.join(1)
                assert not worker.is_alive()
                assert len(errors) == 1 and errors[0].code == "NOT_OWNER"
                assert new.status()["session"]["execution"] == "paused"
                assert client._failure is None
                assert not [
                    r for r in service.requests if r["method"] == method and r["params"].get("leaseId") == old.lease_id
                ]
        finally:
            finish.set()
            worker.join(1)
            assert not worker.is_alive()


@pytest.mark.parametrize("method", ["heartbeat", "status"])
def test_delayed_retired_readonly_error_does_not_fail_new_owner(api, directory, method):
    seen, reply, replied = threading.Event(), threading.Event(), threading.Event()
    old_id = None
    errors = []

    def handler(service, request, _peer, send):
        if request["method"] == method and request["params"]["leaseId"] == old_id:
            seen.set()
            assert reply.wait(3)
            send(
                {
                    "protocol": 1,
                    "id": request["id"],
                    "ok": False,
                    "error": {"code": "LEASE_EXPIRED", "message": "Retired owner"},
                }
            )
            replied.set()
        else:
            send()

    with (
        UnixService(directory, handler=handler) as service,
        api.SessionClient(service.descriptor, directory=directory) as client,
    ):
        old = client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=0.01 if method == "heartbeat" else 10)
        old_id = old.lease_id

        def status():
            try:
                old.status()
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=status) if method == "status" else old.heartbeat_thread
        if method == "status":
            worker.start()
        try:
            assert seen.wait(1)
            old.release()
            worker.join(0.3)
            assert not worker.is_alive(), "retired readonly waiter must leave before the old reply"
            with client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=0.01) as new:
                reply.set()
                assert replied.wait(1)
                assert new.status()["session"]["execution"] == "paused"
                assert client._failure is None
            assert not client._pending
            if method == "status":
                assert len(errors) == 1 and errors[0].code == "NOT_OWNER"
        finally:
            reply.set()
            worker.join(1)
            assert not worker.is_alive()


def test_active_heartbeat_rpc_timeout_still_revokes_owner(api, directory):
    seen = threading.Event()

    def handler(_service, request, _peer, send):
        if request["method"] == "heartbeat":
            seen.set()
        else:
            send()

    with (
        UnixService(directory, handler=handler) as service,
        api.SessionClient(service.descriptor, directory=directory, rpc_timeout=0.08) as client,
    ):
        lease = client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=0.01)
        assert seen.wait(1)
        lease.heartbeat_thread.join(1)
        assert not lease.heartbeat_thread.is_alive()
        assert client._failure.code == "LEASE_EXPIRED"
        with pytest.raises(api.SessionError) as caught:
            lease.status()
        assert caught.value.code == "LEASE_EXPIRED"
        with pytest.raises(api.SessionError):
            lease.release()
        assert not client.reader_thread.is_alive()
        assert not client._pending


@pytest.mark.parametrize("method", ["mark", "control"])
def test_release_with_unacknowledged_mutation_fails_closed(api, directory, method):
    seen = threading.Event()
    errors = []

    def handler(_service, request, _peer, send):
        if request["method"] == method:
            seen.set()
        else:
            send()

    with (
        UnixService(directory, handler=handler) as service,
        api.SessionClient(service.descriptor, directory=directory) as client,
    ):
        lease = client.acquire(service.sessions[0]["sessionId"])

        def mutate():
            try:
                if method == "mark":
                    lease.mark(memory_written=True)
                else:
                    lease.control("warm-reset")
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=mutate)
        worker.start()
        try:
            assert seen.wait(1), "real mutation frame must reach the peer"
            with pytest.raises(api.SessionError) as caught:
                lease.release()
            assert caught.value.code == "NOT_OWNER"
            worker.join(1)
            assert not worker.is_alive()
            assert len(errors) == 1 and errors[0].code == "NOT_OWNER"
            assert client._failure is not None
            assert not client.reader_thread.is_alive()
            assert not client._pending
            assert not [r for r in service.requests if r["method"] == "release"]
            with pytest.raises(api.SessionError):
                client.acquire(service.sessions[0]["sessionId"])
        finally:
            client.close()
            worker.join(1)
            assert not worker.is_alive()


def test_retirement_wins_over_heartbeat_timeout_failure_publication(api, directory, monkeypatch):
    entered, finish = threading.Event(), threading.Event()

    def handler(_service, request, _peer, send):
        if request["method"] != "heartbeat":
            send()

    with (
        UnixService(directory, handler=handler) as service,
        api.SessionClient(service.descriptor, directory=directory, rpc_timeout=0.08) as client,
    ):
        original = client._fail

        def gated(error, **kwargs):
            if error.code == "LEASE_EXPIRED" and kwargs.get("cancel_event") is not None:
                entered.set()
                assert finish.wait(3)
            return original(error, **kwargs)

        monkeypatch.setattr(client, "_fail", gated)
        old = client.acquire(service.sessions[0]["sessionId"], heartbeat_interval=0.01)
        try:
            assert entered.wait(1)
            old.release()
            with client.acquire(service.sessions[0]["sessionId"]) as new:
                finish.set()
                old.heartbeat_thread.join(1)
                assert not old.heartbeat_thread.is_alive()
                assert new.status()["session"]["execution"] == "paused"
                assert client._failure is None
        finally:
            finish.set()
            old.heartbeat_thread.join(1)
            assert not old.heartbeat_thread.is_alive()
