"""Discover and lease the desktop's current gwemu session over private Unix RPC."""

import contextlib
import json
import math
import os
import select
import socket
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from uuid import UUID, uuid4

from gnwmanager.exceptions import DebugProbeConnectionError

_MAX_LINE = 65536
_ERROR_CODES = frozenset(
    [
        "INVALID_REQUEST",
        "UNSUPPORTED_VERSION",
        "NOT_FOUND",
        "STALE_SESSION",
        "BUSY",
        "LEASE_EXPIRED",
        "NOT_OWNER",
        "NO_POWER",
        "UNCERTAIN",
        "TARGET_UNSAFE",
        "UNSUPPORTED",
        "INTERNAL",
    ]
)
_FLAGS = ("managerUploaded", "memoryWritten", "executionChanged")
_EXECUTIONS = ("running", "paused", "unpowered", "unknown")


class SessionError(DebugProbeConnectionError):
    """A transport, discovery or stable server-protocol failure."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class _RequestCancelledError(SessionError):
    """A retired lease's request; distinct from shared transport failure."""

    def __init__(self):
        super().__init__("NOT_OWNER", "Manager lease is closed")


def _raise_session_error(code, message):
    raise SessionError(code, message)


def _invalid(message="Invalid manager protocol message"):
    _raise_session_error("INVALID_REQUEST", message)


def _uuid(value):
    if not isinstance(value, str):
        return False
    try:
        return str(UUID(value)) == value
    except ValueError:
        return False


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _keys(value, required, optional=()):
    return isinstance(value, dict) and set(required) <= set(value) <= set(required) | set(optional)


def validate_request(request):
    """Validate the shared version-one request contract before sending it."""
    if not isinstance(request, dict) or type(request.get("protocol")) is not int:
        _invalid()
    if request["protocol"] != 1:
        raise SessionError("UNSUPPORTED_VERSION", "Unsupported manager protocol version")
    if not _keys(request, ("protocol", "id", "method", "params")):
        _invalid()
    if not isinstance(request["id"], str) or not 1 <= len(request["id"]) <= 128:
        _invalid()
    method, params = request["method"], request["params"]
    if not isinstance(params, dict):
        _invalid()
    if method == "hello":
        valid = _keys(params, ("serverId",)) and _uuid(params["serverId"])
    elif method == "list":
        valid = not params
    elif method == "acquire":
        valid = (
            _keys(params, ("sessionId", "operation", "timeoutMs"))
            and _uuid(params["sessionId"])
            and params["operation"] in ("read", "manage", "debug")
            and _integer(params["timeoutMs"], 1000, 3600000)
        )
    elif method in ("heartbeat", "status", "mark", "control", "release"):
        identity = ("sessionId", "leaseId")
        valid = all(_uuid(params.get(key)) for key in identity)
        if method in ("heartbeat", "status"):
            valid = valid and _keys(params, identity)
        elif method == "mark":
            valid = valid and _keys(params, (*identity, *_FLAGS)) and all(type(params[key]) is bool for key in _FLAGS)
        elif method == "release":
            completion = params.get("completion")
            valid = (
                valid
                and _keys(params, (*identity, "completion"))
                and _keys(completion, ("success", *_FLAGS))
                and all(type(completion[key]) is bool for key in ("success", *_FLAGS))
            )
        else:
            valid = valid and _keys(params, (*identity, "action"), ("value",))
            action = params.get("action")
            value = params.get("value")
            if action in ("pause", "resume", "warm-reset", "cold-start"):
                valid = valid and "value" not in params
            elif action == "battery":
                valid = valid and _integer(value, 0, 100)
            elif action in ("battery-present", "usb-power"):
                valid = valid and type(value) is bool
            elif action == "press":
                valid = (
                    valid
                    and _keys(value, ("mask", "durationMs"))
                    and _integer(value["mask"], 0, 4095)
                    and _integer(value["durationMs"], 1, 30000)
                )
            else:
                valid = False
    else:
        valid = False
    if not valid:
        _invalid()
    try:
        length = len(json.dumps(request, allow_nan=False).encode("utf-8")) + 1
    except (ValueError, TypeError) as error:
        raise SessionError("INVALID_REQUEST", "Invalid request encoding") from error
    if length > _MAX_LINE:
        _invalid("Manager request is too large")


def _directory(directory=None, *, missing_ok=False):
    if os.name == "nt":
        from gnwmanager.windows_transport import private_windows_path
        path = Path(directory) if directory is not None else Path(os.environ["LOCALAPPDATA"]) / "gnw-manager"
        if not path.is_absolute():
            _invalid("Manager directory must be absolute")
        if not path.exists() and missing_ok:
            return path
        private_windows_path(path)
        if not path.is_dir():
            _invalid("Manager directory is not a directory")
        return path
    if os.name != "posix" or not hasattr(os, "getuid") or not hasattr(socket, "AF_UNIX"):
        raise SessionError("UNSUPPORTED", "Current desktop sessions require POSIX Unix sockets")
    path = Path(directory) if directory is not None else Path(f"/tmp/gnw-manager-{os.getuid()}")
    if not path.is_absolute():
        _invalid("Manager directory must be absolute")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if missing_ok:
            return path
        raise SessionError("NOT_FOUND", "Manager directory does not exist") from None
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise SessionError("INVALID_REQUEST", "Manager directory is not private")
    return path


def _private_file(path, *, socket_file=False):
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SessionError("NOT_FOUND", "Manager endpoint is unavailable") from error
    if os.name == "nt":
        from gnwmanager.windows_transport import private_windows_path
        private_windows_path(path)
        if not stat.S_ISREG(metadata.st_mode):
            _invalid("Windows manager endpoint is not a regular private file")
        return metadata
    kind = stat.S_ISSOCK if socket_file else stat.S_ISREG
    if not kind(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
        _invalid("Manager endpoint is not private")
    return metadata


def _descriptor(descriptor, directory):
    if (
        not _keys(descriptor, ("protocol", "serverId", "pid", "endpoint"))
        or type(descriptor["protocol"]) is not int
        or descriptor["protocol"] != 1
        or not _uuid(descriptor["serverId"])
        or not _integer(descriptor["pid"], 1, 2**53 - 1)
        or not isinstance(descriptor["endpoint"], str)
    ):
        _invalid("Invalid manager descriptor")
    expected = directory / f"r-{descriptor['serverId'].replace('-', '')[:16]}.sock"
    if descriptor["endpoint"] != str(expected):
        _invalid("Manager descriptor endpoint does not match server identity")
    return expected


def _session(value):
    if (
        not _keys(
            value,
            (
                "sessionId",
                "profileName",
                "model",
                "kernel",
                "execution",
                "powered",
                "capabilities",
            ),
        )
        or not _uuid(value["sessionId"])
        or not isinstance(value["profileName"], str)
        or value["model"] not in ("mario", "zelda")
        or value["kernel"] != "gwemu"
        or value["execution"] not in _EXECUTIONS
        or type(value["powered"]) is not bool
        or not isinstance(value["capabilities"], list)
        or not all(isinstance(item, str) for item in value["capabilities"])
    ):
        _invalid("Invalid manager session descriptor")
    return value


def _response(value):
    if not isinstance(value, dict) or type(value.get("protocol")) is not int or value["protocol"] != 1:
        _invalid("Invalid manager response version")
    if not isinstance(value.get("id"), str) or not 1 <= len(value["id"]) <= 128 or type(value.get("ok")) is not bool:
        _invalid("Invalid manager response identity")
    if value["ok"]:
        if not _keys(value, ("protocol", "id", "ok", "result")) or not isinstance(value["result"], dict):
            _invalid("Invalid manager response result")
    else:
        error = value.get("error")
        if (
            not _keys(value, ("protocol", "id", "ok", "error"))
            or not _keys(error, ("code", "message"))
            or error["code"] not in _ERROR_CODES
            or not isinstance(error["message"], str)
        ):
            _invalid("Invalid manager error response")
    return value


def _device_power(value):
    if (
        not _keys(value, ("battery", "batteryPresent", "usbPower", "powered"))
        or type(value["battery"]) not in (int, float)
        or not math.isfinite(value["battery"])
        or not 0 <= value["battery"] <= 100
        or any(type(value[key]) is not bool for key in ("batteryPresent", "usbPower", "powered"))
    ):
        _invalid("Invalid manager device power result")


def _result(method, params, result):
    if method == "hello":
        if result != {"serverId": params["serverId"], "protocol": 1} or type(result.get("protocol")) is not int:
            _raise_session_error("STALE_SESSION", "Manager server identity does not match")
    elif method == "list":
        if not _keys(result, ("sessions",)) or not isinstance(result["sessions"], list):
            _invalid("Invalid manager session list")
        for item in result["sessions"]:
            _session(item)
    elif method in ("status", "heartbeat", "mark", "control", "release"):
        required = ("session",)
        if method in ("status", "heartbeat"):
            required += ("expiresAt",)
        if method == "control":
            required += ("devicePower",)
        if not _keys(result, required):
            _invalid("Invalid leased manager result")
        session = _session(result["session"])
        if session["sessionId"] != params["sessionId"]:
            _raise_session_error("STALE_SESSION", "Manager reply belongs to another runtime")
        if method in ("status", "heartbeat") and (
            type(result["expiresAt"]) not in (int, float) or not math.isfinite(result["expiresAt"])
        ):
            _invalid("Invalid manager deadline result")
        if method == "control":
            _device_power(result["devicePower"])
    return result


@dataclass(frozen=True)
class DiscoveredSession:
    descriptor: dict
    session: dict


@dataclass
class _Pending:
    event: threading.Event
    method: str
    params: dict
    result: Optional[dict] = None
    error: Optional[BaseException] = None


class SessionClient:
    """One independently read RPC connection, optionally owning one active lease."""

    def __init__(self, descriptor, *, directory=None, rpc_timeout=10.0):
        self.directory = _directory(directory)
        self.descriptor = dict(descriptor)
        self.endpoint = _descriptor(self.descriptor, self.directory)
        if not isinstance(rpc_timeout, (int, float)) or not math.isfinite(rpc_timeout) or rpc_timeout <= 0:
            _invalid("RPC timeout must be positive")
        self.rpc_timeout = rpc_timeout
        self._socket = None
        self._state_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._pending = {}
        self._failure = None
        self._stop = threading.Event()
        self.reader_thread = None
        self._lease = None

    def open(self):
        if self._failure is not None:
            raise self._failure
        if self._socket is not None:
            return self
        if self._stop.is_set():
            raise SessionError("NOT_OWNER", "Manager connection is closed")
        _directory(self.directory)
        metadata = _private_file(self.endpoint, socket_file=True)
        from gnwmanager.windows_transport import connect_endpoint
        peer = None
        try:
            peer = connect_endpoint(self.endpoint, self.rpc_timeout)
            after = _private_file(self.endpoint, socket_file=True)
            if (metadata.st_dev, metadata.st_ino) != (after.st_dev, after.st_ino):
                _invalid("Manager endpoint changed during connection")
            peer.setblocking(False)
            self._socket = peer
            self.reader_thread = threading.Thread(target=self._read, name="gnw-session-reader", daemon=True)
            self.reader_thread.start()
            hello = self.request("hello", {"serverId": self.descriptor["serverId"]})
            if (
                hello != {"serverId": self.descriptor["serverId"], "protocol": 1}
                or type(hello.get("protocol")) is not int
            ):
                _raise_session_error("STALE_SESSION", "Manager server identity does not match")
        except BaseException:
            if peer is not None:
                peer.close()
            self.close()
            raise
        return self

    def _fail(self, error, *, cancel_event=None):
        with self._state_lock:
            if cancel_event is not None and cancel_event.is_set():
                return False
            if self._failure is None:
                self._failure = error
            self._stop.set()
            for pending in self._pending.values():
                pending.error = self._failure
                pending.event.set()
        peer = self._socket
        if peer is not None:
            with contextlib.suppress(OSError):
                peer.shutdown(socket.SHUT_RDWR)
        return True

    def _read(self):
        buffer = bytearray()
        peer = self._socket
        try:
            while not self._stop.is_set():
                readable, _, _ = select.select([peer], [], [], 0.2)
                if not readable:
                    continue
                try:
                    data = peer.recv(8192)
                except BlockingIOError:
                    continue
                if not data:
                    _raise_session_error("NOT_OWNER", "Manager connection closed")
                buffer.extend(data)
                while b"\n" in buffer:
                    index = buffer.index(b"\n")
                    if index + 1 > _MAX_LINE:
                        _invalid("Manager response is too large")
                    line = bytes(buffer[:index])
                    del buffer[: index + 1]
                    response = _response(json.loads(line.decode("utf-8")))
                    with self._state_lock:
                        pending = self._pending.get(response["id"])
                        if pending is not None:
                            if response["ok"]:
                                pending.result = _result(pending.method, pending.params, response["result"])
                            else:
                                pending.error = SessionError(
                                    response["error"]["code"],
                                    response["error"]["message"],
                                )
                            pending.event.set()
                if len(buffer) >= _MAX_LINE:
                    _invalid("Manager response is too large")
        except BaseException as error:
            if not isinstance(error, SessionError):
                error = SessionError("INTERNAL", "Manager RPC connection failed")
            self._fail(error)

    def request(self, method, params, *, timeout=None, deadline=None, cancel_event=None):
        def check_cancelled():
            if cancel_event is not None and cancel_event.is_set():
                raise _RequestCancelledError()

        check_cancelled()
        timeout = self.rpc_timeout if timeout is None else timeout
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            _invalid("RPC timeout must be positive")
        until = time.monotonic() + timeout
        if deadline is not None:
            until = min(until, deadline)
        request = {
            "protocol": 1,
            "id": str(uuid4()),
            "method": method,
            "params": params,
        }
        validate_request(request)
        data = json.dumps(request, ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"
        if len(data) > _MAX_LINE:
            _invalid("Manager request is too large")
        pending = _Pending(threading.Event(), method, params)
        offset = 0
        packet_sent = False
        with self._state_lock:
            check_cancelled()
            if self._failure is not None:
                raise self._failure
            if self._socket is None or self._stop.is_set():
                raise SessionError("NOT_OWNER", "Manager connection is closed")
            if len(self._pending) >= 8:
                raise SessionError("BUSY", "Too many manager requests are outstanding")
            self._pending[request["id"]] = pending
        try:
            while True:
                check_cancelled()
                if self._failure is not None:
                    raise self._failure
                remaining = until - time.monotonic()
                if remaining <= 0:
                    _raise_session_error("LEASE_EXPIRED", "Timed out sending manager request")
                if self._write_lock.acquire(timeout=min(remaining, 0.05)):
                    break
            try:
                while offset < len(data):
                    check_cancelled()
                    if self._failure is not None:
                        raise self._failure
                    remaining = until - time.monotonic()
                    if remaining <= 0:
                        _raise_session_error("LEASE_EXPIRED", "Timed out sending manager request")
                    _, writable, _ = select.select([], [self._socket], [], min(remaining, 0.05))
                    if not writable:
                        continue
                    check_cancelled()
                    try:
                        sent = self._socket.send(data[offset:])
                    except BlockingIOError:
                        continue
                    if sent == 0:
                        _raise_session_error("NOT_OWNER", "Manager connection closed")
                    offset += sent
                packet_sent = True
            finally:
                self._write_lock.release()
            while not pending.event.is_set():
                check_cancelled()
                remaining = until - time.monotonic()
                if remaining <= 0:
                    _raise_session_error("LEASE_EXPIRED", "Timed out waiting for manager response")
                pending.event.wait(min(remaining, 0.05))
            check_cancelled()
            if pending.error is not None:
                raise pending.error
        except _RequestCancelledError as error:
            # A partial frame taints framing. An unacknowledged mutation may
            # still execute remotely. Both require disconnecting the owner.
            if (offset > 0 and not packet_sent) or (packet_sent and method in ("mark", "control")):
                self._fail(error)
            raise
        except (OSError, ValueError) as error:
            failure = SessionError("NOT_OWNER", "Manager RPC connection failed")
            self._fail(failure)
            raise failure from error
        except SessionError as error:
            # A timed-out mutation may still execute remotely: disconnect owner
            # immediately so the server cancels it instead of returning success.
            if error.code == "LEASE_EXPIRED" and (
                method not in ("hello", "list", "status") or (offset > 0 and not packet_sent)
            ):
                # Admission retirement and failure publication use the same
                # state lock: no final check/fail gap can revoke a fresh owner.
                cancellation = (
                    cancel_event if method in ("heartbeat", "status") and (offset == 0 or packet_sent) else None
                )
                if not self._fail(error, cancel_event=cancellation):
                    raise _RequestCancelledError() from error
            raise
        else:
            return pending.result
        finally:
            with self._state_lock:
                self._pending.pop(request["id"], None)

    def acquire(
        self,
        session_id,
        *,
        operation="manage",
        timeout_ms=300000,
        heartbeat_interval=10.0,
    ):
        if self._lease is not None:
            raise SessionError("BUSY", "This manager connection already owns a lease")
        if (
            not isinstance(heartbeat_interval, (int, float))
            or not math.isfinite(heartbeat_interval)
            or heartbeat_interval <= 0
        ):
            _invalid("Heartbeat interval must be positive")
        started, wall_started = time.monotonic(), time.time()
        result = self.request(
            "acquire",
            {"sessionId": session_id, "operation": operation, "timeoutMs": timeout_ms},
        )
        try:
            lease = SessionLease(
                self,
                result,
                session_id,
                operation,
                timeout_ms,
                heartbeat_interval,
                started,
                wall_started,
            )
            self._lease = lease
            lease.heartbeat_thread.start()
        except BaseException:
            # Admission may have succeeded: only disconnect can reliably revoke
            # a malformed or untrusted reply which cannot identify its lease.
            self.close()
            raise
        else:
            return lease

    def close(self):
        if self._lease is not None:
            self._lease._stop.set()
        self._fail(SessionError("NOT_OWNER", "Manager connection closed"))
        peer = self._socket
        if peer is not None:
            peer.close()
        thread = self.reader_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(1)
        if self._lease is not None:
            self._lease._join_heartbeat()
        # Keep the reference until reader has left; concurrent pending sends
        # receive a socket error rather than accidentally using a new connection.

    def __enter__(self):
        return self.open()

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            if self._lease is not None and not self._lease._closed:
                self._lease.release(success=exc_type is None)
        except BaseException:
            if exc_type is None:
                raise
        finally:
            self.close()


class SessionLease:
    """Connection-owned, fixed-deadline management context with independent heartbeat."""

    def __init__(
        self,
        client,
        result,
        session_id,
        operation,
        timeout_ms,
        heartbeat_interval,
        started,
        wall_started,
    ):
        if (
            not _keys(result, ("leaseId", "sessionId", "gdbEndpoint", "initial", "expiresAt"))
            or not _uuid(result["leaseId"])
            or result["sessionId"] != session_id
            or not isinstance(result["gdbEndpoint"], str)
            or not _keys(result["initial"], ("execution", "devicePower"))
            or result["initial"]["execution"] not in _EXECUTIONS
            or not isinstance(result["initial"]["devicePower"], dict)
            or type(result["expiresAt"]) not in (int, float)
            or not math.isfinite(result["expiresAt"])
        ):
            _invalid("Invalid manager lease response")
        _device_power(result["initial"]["devicePower"])
        endpoint = Path(result["gdbEndpoint"])
        name = endpoint.name
        if (
            endpoint.parent != client.directory
            or len(name) != 23
            or not name.startswith("l-")
            or not name.endswith(".sock")
            or any(character not in "0123456789abcdef" for character in name[2:18])
        ):
            _invalid("Invalid managed GDB endpoint")
        _directory(client.directory)
        _private_file(endpoint, socket_file=True)
        deadline = min(
            started + timeout_ms / 1000,
            started + result["expiresAt"] / 1000 - wall_started,
        )
        if deadline <= time.monotonic():
            raise SessionError("LEASE_EXPIRED", "Manager lease expired")
        self.client = client
        self.session_id = session_id
        self.lease_id = result["leaseId"]
        self.operation = operation
        self.gdb_endpoint = endpoint
        self.initial = result["initial"]
        self.expires_at = result["expiresAt"]
        self.deadline = deadline
        self._interval = heartbeat_interval
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._mark_lock = threading.Lock()
        self._error = None
        self._closed = False
        self._epoch = 0
        self._resets = 0
        self._acknowledged = dict.fromkeys(_FLAGS, False)
        self._completion = dict.fromkeys(_FLAGS, False)
        self.heartbeat_thread = threading.Thread(target=self._heartbeat, name="gnw-session-heartbeat", daemon=True)

    def _identity(self):
        return {"sessionId": self.session_id, "leaseId": self.lease_id}

    def _check_locked(self):
        if self._error is not None:
            raise self._error
        if self._closed:
            raise SessionError("NOT_OWNER", "Manager lease is closed")
        if time.monotonic() >= self.deadline:
            raise SessionError("LEASE_EXPIRED", "Manager lease expired")
        if self.client._failure is not None:
            raise self.client._failure

    def check(self):
        with self._lock:
            self._check_locked()

    def _heartbeat(self):
        try:
            while not self._stop.wait(min(self._interval, max(0, self.deadline - time.monotonic()))):
                self.check()
                self.client.request("heartbeat", self._identity(), deadline=self.deadline, cancel_event=self._stop)
        except BaseException as error:
            with self._lock:
                if self._closed or self._stop.is_set():
                    return
                self._error = error
            self._stop.set()
            self.client._fail(error)

    def _join_heartbeat(self):
        if self.heartbeat_thread.ident is not None and self.heartbeat_thread is not threading.current_thread():
            self.heartbeat_thread.join(1)

    def status(self):
        self.check()
        result = self.client.request("status", self._identity(), deadline=self.deadline, cancel_event=self._stop)
        _session(result.get("session"))
        return result

    def mark(self, *, manager_uploaded=False, memory_written=False, execution_changed=False):
        requested = dict(zip(_FLAGS, (manager_uploaded, memory_written, execution_changed)))
        if not all(type(value) is bool for value in requested.values()):
            _invalid("Mutation flags must be booleans")
        with self._mark_lock:
            self.check()
            with self._lock:
                self._check_locked()
                if self._resets and any(requested.values()):
                    raise SessionError("BUSY", "Wait for application reset before mutating the target")
                epoch = self._epoch
                fresh = {flag: value and not self._acknowledged[flag] for flag, value in requested.items()}
                if not any(fresh.values()):
                    return None
            result = self.client.request(
                "mark", {**self._identity(), **fresh}, deadline=self.deadline, cancel_event=self._stop
            )
            _session(result.get("session"))
            with self._lock:
                for flag, value in fresh.items():
                    # Remote acknowledgement is cumulative even when a reset
                    # or revocation makes this caller's authorization stale.
                    self._completion[flag] |= value
                self._check_locked()
                if self._epoch != epoch or self._resets:
                    raise SessionError("BUSY", "Application reset invalidated this mutation mark; retry it")
                for flag, value in fresh.items():
                    self._acknowledged[flag] |= value
                return result

    def control(self, action, value=None):
        self.check()
        params = {**self._identity(), "action": action}
        if value is not None:
            params["value"] = value
        timeout = self.client.rpc_timeout
        if action == "press" and isinstance(value, dict) and type(value.get("durationMs")) is int:
            timeout = min((value["durationMs"] + 10000) / 1000, 40)
        resetting = action in ("warm-reset", "cold-start")
        if resetting:
            with self._lock:
                # The server can restore readiness before this caller consumes
                # the reply. Suspend cached marks across the entire RPC window.
                self._resets += 1
                self._epoch += 1
                self._acknowledged = dict.fromkeys(_FLAGS, False)
        try:
            result = self.client.request(
                "control", params, timeout=timeout, deadline=self.deadline, cancel_event=self._stop
            )
            _session(result.get("session"))
            if not isinstance(result.get("devicePower"), dict):
                _invalid("Invalid manager control result")
            return result
        finally:
            if resetting:
                with self._lock:
                    # Invalidate even after failure; late acknowledgements and
                    # overlapping resets must never reinstate the prior phase.
                    self._epoch += 1
                    self._acknowledged = dict.fromkeys(_FLAGS, False)
                    self._resets -= 1

    def release(self, *, success=True):
        if type(success) is not bool:
            _invalid("Completion success must be boolean")
        with self._lock:
            if self._closed:
                return None
            self._closed = True
            with self.client._state_lock:
                self._stop.set()
            failure = self._error or self.client._failure
            expired = time.monotonic() >= self.deadline
            completion = {
                "success": success and failure is None and not expired,
                **self._completion,
            }
        with self.client._state_lock:
            uncertain_mutation = any(
                pending.method in ("mark", "control") and pending.params.get("leaseId") == self.lease_id
                for pending in self.client._pending.values()
            )
        if uncertain_mutation:
            # Do not acknowledge successful completion while another caller
            # can still change the target or add remote completion flags.
            self.client._fail(SessionError("NOT_OWNER", "Manager mutation was interrupted by lease release"))
        released = False
        try:
            result = self.client.request(
                "release",
                {**self._identity(), "completion": completion},
                deadline=self.deadline,
            )
            _session(result.get("session"))
            released = True
            if failure is not None:
                raise failure
            if expired:
                raise SessionError("LEASE_EXPIRED", "Manager lease expired")
            return result
        finally:
            self._join_heartbeat()
            if self.client._lease is self:
                self.client._lease = None
            # Any failed release disconnects the owner to revoke uncertain work.
            if failure is not None or expired or not released:
                self.client.close()

    def close(self):
        """Abandon the lease conservatively; never imply successful completion."""
        self._stop.set()
        with self._lock:
            self._closed = True
        self.client.close()
        self._join_heartbeat()

    def __enter__(self):
        self.check()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            self.release(success=exc_type is None)
        except BaseException:
            if exc_type is None:
                raise


def discover_sessions(*, directory=None, timeout=1.0):
    """List reachable sessions after private-path and server-identity validation."""
    path = _directory(directory, missing_ok=True)
    if not path.exists():
        return []
    found = []
    for entry in sorted(path.glob("*.json")):
        try:
            metadata = _private_file(entry)
            if not _uuid(entry.stem) or metadata.st_size > _MAX_LINE:
                continue
            descriptor_fd = os.open(entry, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
            with os.fdopen(descriptor_fd, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if (
                    (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
                    or not stat.S_ISREG(opened.st_mode)
                    or (os.name != "nt" and (opened.st_uid != os.getuid()
                    or stat.S_IMODE(opened.st_mode) != 0o600))
                ):
                    continue
                descriptor = json.loads(stream.read(_MAX_LINE + 1))
            endpoint = _descriptor(descriptor, path)
            if entry.stem != descriptor["serverId"]:
                continue
            _private_file(endpoint, socket_file=True)
            with SessionClient(descriptor, directory=path, rpc_timeout=timeout) as client:
                response = client.request("list", {})
                if not _keys(response, ("sessions",)) or not isinstance(response["sessions"], list):
                    _invalid("Invalid session list response")
                for item in response["sessions"]:
                    found.append(DiscoveredSession(descriptor, _session(item)))
        except (SessionError, OSError, ValueError, TypeError, KeyError):
            # Stale/untrusted descriptors are left untouched, never adopted or deleted.
            continue
    return found


def select_session(sessions, session_id=None):
    """Select explicitly when several sessions are available; never choose the first."""
    if session_id is not None:
        matches = [item for item in sessions if item.session["sessionId"] == session_id]
        if len(matches) == 1:
            return matches[0]
        raise SessionError("NOT_FOUND", "No unique matching desktop session")
    if not sessions:
        raise SessionError("NOT_FOUND", "No running desktop session")
    if len(sessions) != 1:
        raise SessionError("INVALID_REQUEST", "Multiple desktop sessions; specify a session ID")
    return sessions[0]
