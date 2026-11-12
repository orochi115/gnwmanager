import contextlib
import socket
from time import monotonic
from xml.etree import ElementTree

from gnwmanager.exceptions import DebugProbeConnectionError
from gnwmanager.ocdbackend.base import OCDBackend, TransferErrors


class GDBError(DebugProbeConnectionError):
    pass


TransferErrors.add(GDBError)


def _checksum(data: bytes) -> bytes:
    c = sum(data) % 256
    return f"{c:02x}".encode("ascii")


_CORE_REGISTERS = {"sp": 13, "lr": 14, "pc": 15, "xpsr": 25}


class GDBBackend(OCDBackend):
    def __init__(self, host: str = "localhost", port: int = 1234):
        super().__init__()
        self.version = (0, 0, 0)
        self.host = host
        self.port = port
        self._socket = None
        self._sock_file = None
        self._is_running = False
        self._deadline = None
        # ARM M-profile core numbering, including the legacy FPA gap. MSP is
        # deliberately absent: r13 is the active SP, which may instead be PSP.
        self._registers = dict(_CORE_REGISTERS)
        self._msp_alias_safe = False

    def open(self) -> OCDBackend:
        # A new peer must never inherit the previous target's system indices,
        # including when the last description was only partially received.
        self.close()
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.settimeout(5.0)
        # The GDB remote protocol here is dominated by tiny packets waiting
        # on each other's replies (a single-byte '+' ack, a short "m<addr>,4"
        # read). Without this, Nagle's algorithm on this socket combines with
        # the peer's delayed-ACK timer to add a fixed ~40ms stall to every
        # single request/response round trip -- measured directly against
        # qemu-gnw's gdbstub (a `gnwmanager --backend gdb info` call went from ~6.7s,
        # matching real hardware over OpenOCD, to ~39s with this unset).
        self._socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            self._socket.connect((self.host, self.port))
            self._sock_file = self._socket.makefile("rb", buffering=8192)
        except OSError as e:
            self.close()
            raise DebugProbeConnectionError(
                f"Could not connect to QEMU GDB server at {self.host}:{self.port}. "
                f"Is QEMU running with '-gdb tcp::{self.port}'?"
            ) from e

        try:
            # Some simple stubs do not support XML. Their MSP alias can only
            # be used while no guest instruction has run after reset-and-halt.
            # An unsupported qSupported has a normal empty reply. Protocol or
            # connection failures must propagate before any continue command.
            supported = self._send_command(b"qSupported:multiprocess+;xmlRegisters=arm;qRelocInsn+")
            if b"qXfer:features:read+" in supported.split(b";"):
                self._load_register_description()
            # QEMU halts on client connection; retain physical-probe behavior.
            self.resume()
        except BaseException:
            self.close()
            raise

        return self

    def close(self):
        if self._socket:
            if hasattr(self, "_sock_file") and self._sock_file:
                self._sock_file.close()
            with contextlib.suppress(OSError):
                self._socket.close()
            self._socket = None
        self._is_running = False
        self._msp_alias_safe = False
        self._deadline = None
        self._registers = dict(_CORE_REGISTERS)
        self._sock_file = None

    def _read_feature(self, name):
        data = bytearray()
        while len(data) < 65536:
            reply = self._send_command(f"qXfer:features:read:{name}:{len(data):x},fff".encode("ascii"))
            if reply[:1] not in (b"m", b"l") or (reply[:1] == b"m" and len(reply) == 1):
                raise GDBError(f"Malformed target description response for {name}")
            data.extend(reply[1:])
            if reply[:1] == b"l":
                # QEMU's generated target.xml omits the namespace declaration
                # understood implicitly by GDB's target-description reader.
                if name == "target.xml" and b"xmlns:xi=" not in data:
                    data = data.replace(b"<target>", b'<target xmlns:xi="http://www.w3.org/2001/XInclude">', 1)
                try:
                    return ElementTree.fromstring(data)
                except ElementTree.ParseError as error:
                    raise GDBError(f"Malformed target description XML for {name}") from error
        raise GDBError(f"Target description too large: {name}")

    def _load_register_description(self):
        """Read just the two features needed by this Cortex-M backend."""
        target = self._read_feature("target.xml")
        features = [element.get("href") for element in target.iter()
                    if element.tag.rsplit("}", 1)[-1] == "include"]
        if "arm-m-profile.xml" not in features:
            raise GDBError("GDB backend requires an ARM M-profile target")
        for name in ("arm-m-profile.xml", "arm-m-system.xml"):
            if name not in features:
                continue
            feature = self._read_feature(name)
            number = 0
            for register in feature.findall("reg"):
                try:
                    number = int(register.get("regnum", number))
                    if int(register.get("bitsize", "0")) != 32:
                        raise ValueError("not a 32-bit register")
                except ValueError as error:
                    raise GDBError(f"Invalid register description in {name}") from error
                self._registers[register.get("name")] = number
                number += 1

    def _read(self, n: int) -> bytes:
        """Read exactly ``n`` bytes, translating socket failures into GDBError.

        The socket carries a 5s timeout (see open()); without this translation a
        raw socket.timeout would escape past TransferErrors' retry machinery and
        main.py's DebugProbeConnectionError handling.
        """
        if self._deadline is not None and monotonic() >= self._deadline:
            raise GDBError("Timed out waiting for the GDB command to complete")
        try:
            data = self._sock_file.read(n)
        except socket.timeout as e:
            raise GDBError(f"Timed out waiting for {n} byte(s) from the GDB stub") from e
        except OSError as e:
            raise GDBError(f"Socket error while reading from the GDB stub: {e}") from e
        if not data:
            raise GDBError("Connection closed by remote")
        if len(data) != n:
            raise GDBError(f"Short packet read: expected {n} byte(s), got {len(data)}")
        return data

    def _write(self, data: bytes):
        """Send all of ``data``, translating socket failures into GDBError."""
        if not self._socket:
            raise GDBError("Socket is not open")
        try:
            self._socket.sendall(data)
        except socket.timeout as e:
            raise GDBError("Timed out sending to the GDB stub") from e
        except OSError as e:
            raise GDBError(f"Socket error while writing to the GDB stub: {e}") from e

    def _send_command(self, cmd: bytes) -> bytes:
        if not self._socket:
            raise GDBError("Socket is not open")

        self._deadline = monotonic() + 5
        try:
            packet = b"$" + cmd + b"#" + _checksum(cmd)
            self._write(packet)
            self._wait_for_ack(packet)

            # Unrequested asynchronous stop notifications are consumed within
            # the same total command deadline, never extending it.
            while True:
                reply = self._wait_for_packet()
                if cmd == b"?" or not reply.startswith((b"T", b"S", b"W", b"X")):
                    break
            if reply.startswith(b"E"):
                err_code = reply[1:].decode("ascii", errors="replace")
                raise GDBError(f"GDB error response: {err_code} for command {cmd.decode('ascii', errors='ignore')}")
            return reply
        finally:
            self._deadline = None

    def _wait_for_ack(self, packet):
        retries = 0
        while True:
            c = self._read(1)
            if c == b"+":
                return
            elif c == b"-":
                retries += 1
                if retries >= 3:
                    raise GDBError("Too many negative acknowledgements from the GDB stub")
                self._write(packet)
            elif c == b"$":
                # We got a packet instead of an ack. It's likely an asynchronous stop reply.
                # We need to read it, ack it, and then keep waiting for our ack or response.
                self._read_packet_data()

    def _read_packet_data(self) -> bytes:
        # Assuming '$' was just read
        reply = bytearray()
        encoded = bytearray()
        while True:
            c = self._read(1)
            if c == b"#":
                break
            encoded.extend(c)
            if len(encoded) > 131104:
                raise GDBError("GDB reply packet too large")
            if c == b"}":
                escaped = self._read(1)
                encoded.extend(escaped)
                reply.append(escaped[0] ^ 0x20)
                continue
            if c == b"*":
                # Run-length encoding: the previous byte repeats an additional
                # (count_char - 29) times. QEMU's gdbstub does not currently
                # emit this on replies (gdb_put_packet_binary() copies the
                # payload verbatim; its RLE handling is receive-side only), but
                # the remote protocol permits any stub to, so decode it.
                if not reply:
                    raise GDBError("Malformed packet: RLE marker with no preceding byte")
                count = self._read(1)
                encoded.extend(count)
                repeat = count[0] - 29
                if repeat < 0:
                    raise GDBError("Malformed packet: invalid RLE repeat count")
                reply.extend(reply[-1:] * repeat)
                continue
            reply.extend(c)
        checksum = self._read(2)
        if checksum.lower() != _checksum(encoded):
            self._write(b"-")
            raise GDBError("GDB reply packet checksum mismatch")
        # Send ack
        self._write(b"+")
        return bytes(reply)

    def _wait_for_packet(self) -> bytes:
        while True:
            c = self._read(1)
            if c == b"$":
                return self._read_packet_data()
            # Ignore anything else before '$'

    def read_memory(self, addr: int, size: int) -> bytes:
        if size == 0:
            return b""

        # Deliberately does NOT halt/resume around this like the other accessors
        # below. Plain 'm'/'M' memory access is serviced by QEMU's gdbstub via
        # cpu_memory_rw_debug(), which is exactly as safe to call against a
        # running VM as a halted one. Halting/resuming around every single read
        # added two full GDB round-trips (each bounded by this socket's 5s
        # timeout) to every poll of a status flag, which under a heavily-loaded
        # vCPU turned runs that should take seconds into minutes.
        chunk_size_max = 4096
        result = bytearray()

        for offset in range(0, size, chunk_size_max):
            chunk_size = min(chunk_size_max, size - offset)
            cmd = f"m{(addr + offset):x},{chunk_size:x}".encode("ascii")
            reply = self._send_command(cmd)
            chunk = self._decode_hex(reply, cmd)
            # A stub is permitted to return fewer bytes than requested; without
            # this check that would silently yield truncated data to callers.
            if len(chunk) != chunk_size:
                raise GDBError(f"Short read at 0x{addr + offset:08x}: requested {chunk_size} bytes, got {len(chunk)}")
            result.extend(chunk)

        return bytes(result)

    @staticmethod
    def _decode_hex(reply: bytes, cmd: bytes) -> bytes:
        """Decode a hex-string reply, raising GDBError rather than ValueError."""
        try:
            return bytes.fromhex(reply.decode("ascii"))
        except (ValueError, UnicodeDecodeError) as e:
            raise GDBError(f"Malformed hex reply {reply!r} for command {cmd.decode('ascii', errors='ignore')}") from e

    def write_memory(self, addr: int, data: bytes):
        if not data:
            return

        # See read_memory()'s comment: 'M' goes through the same
        # cpu_memory_rw_debug() path, so no halt/resume is needed here either.
        chunk_size_max = 4096
        for offset in range(0, len(data), chunk_size_max):
            chunk = data[offset : offset + chunk_size_max]
            hex_data = chunk.hex()
            cmd = f"M{(addr + offset):x},{len(chunk):x}:{hex_data}".encode("ascii")
            reply = self._send_command(cmd)

            if reply != b"OK":
                raise GDBError(f"Failed to write memory, expected OK got {reply}")

    def _get_reg_idx(self, name: str) -> int:
        name = name.lower()
        if name in self._registers:
            return self._registers[name]
        if name == "msp":
            return 13
        if name.startswith("r"):
            try:
                index = int(name[1:])
                if 0 <= index <= 15:
                    return index
            except ValueError:
                pass
        raise ValueError(f"Unknown register {name}")

    def read_register(self, name: str) -> int:
        idx = self._get_reg_idx(name)
        was_running = self._is_running
        if was_running:
            self.halt()

        if name.lower() == "msp" and "msp" not in self._registers and not self._msp_alias_safe:
            raise GDBError("Target does not describe MSP; r13 aliases MSP only immediately after reset-and-halt")
        value = self._read_register_value(idx)
        if was_running:
            self.resume()
        return value

    def _read_register_value(self, idx):
        cmd = f"p{idx:x}".encode("ascii")
        reply = self._send_command(cmd)
        data = self._decode_hex(reply, cmd)
        if len(data) != 4:
            raise GDBError(f"Short register reply for {cmd.decode()}: expected 4 bytes, got {len(data)}")
        return int.from_bytes(data, byteorder="little")

    def write_register(self, name: str, val: int):
        idx = self._get_reg_idx(name)
        hex_val = val.to_bytes(4, byteorder="little").hex()
        was_running = self._is_running
        if was_running:
            self.halt()

        if name.lower() == "msp":
            # QEMU exposes real MSP for reads but does not implement writes
            # through its M-system feature. Core r13 is writable only when
            # MSP is selected; writing it in PSP Thread mode corrupts PSP.
            if "control" in self._registers:
                control = self._read_register_value(self._registers["control"])
                handler = control & 2 and self._read_register_value(self._registers["xpsr"]) & 0x1FF
                if control & 2 and not handler:
                    raise GDBError("Cannot write inactive MSP through QEMU's read-only M-system registers")
            elif not self._msp_alias_safe:
                raise GDBError("Target does not describe MSP; write it only immediately after reset-and-halt")
            idx = 13
        # 32-bit registers, little-endian hex string
        cmd = f"P{idx:x}={hex_val}".encode("ascii")
        reply = self._send_command(cmd)

        if reply != b"OK":
            raise GDBError(f"Failed to write register, expected OK got {reply}")
        if was_running:
            self.resume()

    def set_frequency(self, freq: int):
        # Ignored for emulated environment
        pass

    def reset(self):
        if self._is_running:
            self.halt()

        # 'monitor system_reset'. Failures propagate: silently suppressing them
        # would report a successful reset having reset nothing.
        cmd = b"qRcmd," + b"system_reset".hex().encode("ascii")
        self._send_command(cmd)

        # Matches OpenOCDBackend/PyOCDBackend, whose reset() unconditionally
        # leaves the target running regardless of its prior state.
        self.resume()

    def halt(self):
        # Send Ctrl-C to interrupt
        self._write(b"\x03")
        # Try to query the current state instead of waiting blindly for an out-of-band stop reply
        self._send_command(b"?")
        self._is_running = False

    def reset_and_halt(self):
        if self._is_running:
            self.halt()
        self._send_command(b"qRcmd," + b"system_reset".hex().encode("ascii"))
        self._msp_alias_safe = True

    # Override resume specifically for the blocking nature
    def resume(self):
        if not self._socket:
            raise GDBError("Socket is not open")
        cmd = b"c"
        packet = b"$" + cmd + b"#" + _checksum(cmd)
        self._deadline = monotonic() + 5
        self._msp_alias_safe = False
        try:
            self._write(packet)
            self._wait_for_ack(packet)
        finally:
            self._deadline = None
        # Do NOT wait for '$' here because 'c' replies only when target stops.
        self._is_running = True

    def start_gdbserver(self, port, logging=True, blocking=True):
        # QEMU is itself the GDB server, and its stub accepts only a single
        # client -- which this backend is already occupying. Returning silently
        # would leave `gnwmanager gdbserver` exiting instantly and `gnwmanager
        # gdb` launching gdb against a port nothing is listening on.
        raise NotImplementedError(
            f"QEMU is already the GDB server on port {self.port}. Connect gdb to it directly with "
            f"'target extended-remote {self.host}:{self.port}' (without a concurrent gnwmanager session, "
            f"since QEMU's gdbstub accepts only one client)."
        )

    @property
    def probe_name(self) -> str:
        return "QEMU Emulator"
