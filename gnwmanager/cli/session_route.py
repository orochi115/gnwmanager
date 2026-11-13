"""Lazy CLI ownership of one desktop session and its managed GDB connection."""

import socket
import stat
import time
from contextlib import contextmanager

from gnwmanager.exceptions import DebugProbeConnectionError
from gnwmanager.gnw import GnW
from gnwmanager.ocdbackend.gdb_backend import GDBBackend, GDBError
from gnwmanager.session_client import SessionClient, SessionError, discover_sessions, select_session


class SessionGDBBackend(GDBBackend):
    """Mark mutations before emitting RSP; closing RSP never ends the lease."""

    def __init__(self, lease, owner):
        self.session_lease = lease
        self.session_owner = owner
        super().__init__(unix_socket=lease.gdb_endpoint, resume_on_connect=False)
        self._endpoint_identity = self._endpoint_metadata()

    def _endpoint_metadata(self):
        import os
        if os.name == "nt":
            from gnwmanager.session_client import _directory, _private_file
            _directory(self.unix_socket.parent)
            info = _private_file(self.unix_socket, socket_file=True)
            return info.st_dev, info.st_ino

        directory = self.unix_socket.parent.lstat()
        if (
            not stat.S_ISDIR(directory.st_mode)
            or directory.st_uid != os.getuid()
            or stat.S_IMODE(directory.st_mode) != 0o700
        ):
            raise SessionError("STALE_SESSION", "Managed GDB directory is no longer private")
        info = self.unix_socket.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise SessionError("STALE_SESSION", "Managed GDB socket is no longer private")
        return info.st_dev, info.st_ino

    def _check_endpoint_identity(self):
        if self._endpoint_metadata() != self._endpoint_identity:
            raise SessionError("STALE_SESSION", "Managed GDB socket changed during connection")

    def open(self):
        self.close()
        self.session_lease.check()
        if self._endpoint_metadata() != self._endpoint_identity:
            raise SessionError("STALE_SESSION", "Managed GDB socket changed")
        try:
            # Unlike standalone connect, managed admission is bounded by the
            # lease's remaining budget even when a Unix listen backlog is full.
            from gnwmanager.windows_transport import connect_endpoint
            remaining = self.session_lease.deadline - time.monotonic()
            self._socket = connect_endpoint(self.unix_socket, min(5.0, max(0.001, remaining)))
        except OSError as error:
            self.close()
            raise DebugProbeConnectionError("Could not connect to the managed GDB proxy") from error
        try:
            self.session_lease.check()
            self._check_endpoint_identity()
            supported = self._send_command(b"qSupported:multiprocess+;xmlRegisters=arm;qRelocInsn+")
            if b"qXfer:features:read+" in supported.split(b";"):
                self._load_register_description()
        except BaseException:
            self.close()
            raise
        return self

    def _send_command(self, cmd):
        self.session_lease.check()
        result = super()._send_command(cmd)
        self.session_lease.check()
        return result

    def _set_remaining_timeout(self):
        self.session_lease.check()
        super()._set_remaining_timeout()
        remaining = self.session_lease.deadline - time.monotonic()
        self._socket.settimeout(min(self._socket.gettimeout(), max(0.001, remaining)))

    def read_memory(self, addr, size):
        self.session_lease.check()
        return super().read_memory(addr, size)

    def read_register(self, name):
        self.session_lease.check()
        return super().read_register(name)

    def write_memory(self, addr, data):
        if data:
            self.session_lease.mark(memory_written=True)
        return super().write_memory(addr, data)

    def write_register(self, name, val):
        self.session_lease.mark(execution_changed=True)
        return super().write_register(name, val)

    def reset(self):
        self.session_lease.mark(execution_changed=True)
        return super().reset()

    def reset_and_halt(self):
        self.session_lease.mark(execution_changed=True)
        return super().reset_and_halt()

    def resume(self):
        self.session_lease.mark(execution_changed=True)
        result = super().resume()
        self.session_lease.check()
        return result

    def before_manager_upload(self):
        self.session_lease.mark(manager_uploaded=True)

    def debugger_endpoint(self):
        if self.session_owner._gnw is not None:
            # External GDB may replace PC/RAM. Invalidate even when admission
            # fails so a later command cannot trust an earlier manager phase.
            self.session_owner._gnw.invalidate_manager_state()
        self.session_lease.mark(execution_changed=True)
        self.close()
        return self.session_lease.gdb_endpoint

    def cold_reconnect(self, *, expected_rdp=None):
        """Latch option bytes via desktop cold-start and reconnect the same lease."""
        self.close()
        try:
            self.session_lease.control("cold-start")
            self.open()
            if expected_rdp is not None:
                self.verify_rdp(expected_rdp)
        except BaseException:
            self.session_owner.failed = True
            raise
        finally:
            if self.session_owner._gnw is not None:
                self.session_owner._gnw.invalidate_manager_state()

    def verify_rdp(self, expected):
        """Verify both the latched register and its actual debug-read effect."""
        rdp = (self.read_uint32(0x5200201C) >> 8) & 0xFF
        if rdp != expected:
            raise SessionError("UNCERTAIN", f"Cold-start RDP latch is 0x{rdp:02x}, expected 0x{expected:02x}")
        if expected == 0x55:
            try:
                self.read_memory(0x08000000, 4)
            except GDBError as error:
                if "GDB error response: 14" not in str(error):
                    raise
            else:
                raise SessionError("UNCERTAIN", "RDP1 did not protect internal Flash debug reads")
        elif expected == 0xAA:
            self.read_memory(0x08000000, 4)

    def unlock_payload(self, device, *, timeout=30.0):
        """Wait for the blue payload and a hash-verified SRAM Flash copy.

        The native cold-start already issues its POWER pulse. Polling reconnects
        the same proxy; incomplete payload work is continued through marked GDB,
        never by injecting a second POWER press or starting manager firmware.
        """
        from gnwmanager.cli.devices import HashMismatchError

        self.close()
        self.session_lease.control("cold-start")
        until = min(time.monotonic() + timeout, self.session_lease.deadline)
        while time.monotonic() < until:
            self.session_lease.check()
            time.sleep(min(0.05, max(0, until - time.monotonic())))
            self.open()
            if self.read_uint32(0x5000109C) == 0xFF0000FF:
                try:
                    data = device.read_internal_from_ram()
                except HashMismatchError:
                    pass
                else:
                    return data
            self.resume()
            self.close()
        self.session_owner.failed = True
        raise SessionError("UNCERTAIN", "Unlock payload did not produce blue state and verified SRAM data")

    @property
    def probe_name(self):
        return "Desktop gwemu session"


class SessionRoute:
    """Keep discovery/acquisition lazy and share the owner across commands/shell."""

    def __init__(self, *, session_id=None, directory=None, timeout_ms=300000, heartbeat_interval=10.0):
        self.session_id = session_id
        self.directory = directory
        self.timeout_ms = timeout_ms
        self.heartbeat_interval = heartbeat_interval
        self.client = None
        self._lease = None
        self._backend = None
        self._gnw = None
        self.failed = False
        self._closed = False

    def sessions(self):
        return discover_sessions(directory=self.directory)

    def lease(self, *, operation="manage"):
        if self._closed:
            raise SessionError("NOT_OWNER", "CLI session owner is closed")
        if self._lease is not None:
            self._lease.check()
            return self._lease
        found = self.sessions()
        if not found:
            raise SessionError("NOT_FOUND", "No active gwemu session; start the desktop UI and load a ROM")
        selected = select_session(found, self.session_id)
        self.client = SessionClient(selected.descriptor, directory=self.directory)
        try:
            self.client.open()
            self._lease = self.client.acquire(
                selected.session["sessionId"],
                operation=operation,
                timeout_ms=self.timeout_ms,
                heartbeat_interval=self.heartbeat_interval,
            )
        except BaseException:
            self.client.close()
            self.client = None
            raise
        else:
            return self._lease

    def backend(self, *, operation="manage"):
        lease = self.lease(operation=operation)
        if self._backend is None:
            self._backend = SessionGDBBackend(lease, self)
        if self._backend._socket is None:
            self._backend.open()
        return self._backend

    def gnw(self, *, operation="manage"):
        backend = self.backend(operation=operation)
        if self._gnw is None:
            self._gnw = GnW(backend)
        return self._gnw

    @contextmanager
    def borrow_backend(self):
        try:
            yield self.backend()
        except BaseException:
            self.failed = True
            raise
        finally:
            if self._gnw is not None:
                self._gnw.invalidate_manager_state()

    def close(self):
        self._closed = True
        try:
            if self._backend is not None:
                self._backend.close()
            if self._lease is not None:
                self._lease.release(success=not self.failed)
        finally:
            if self.client is not None:
                self.client.close()
            self._lease = None
            self.client = None
