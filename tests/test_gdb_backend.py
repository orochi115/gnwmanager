import socket

import pytest

from gnwmanager.ocdbackend.gdb_backend import GDBBackend, GDBError, _checksum


class FakeSockFile:
    """Stands in for the socket's buffered file object."""

    def __init__(self, data: bytes, raise_timeout: bool = False):
        self.data = data
        self.pos = 0
        self.raise_timeout = raise_timeout

    def read(self, n: int) -> bytes:
        if self.raise_timeout:
            raise socket.timeout
        chunk = self.data[self.pos : self.pos + n]
        self.pos += len(chunk)
        return chunk

    def close(self):
        pass


class FakeSocket:
    def __init__(self):
        self.sent = bytearray()

    def sendall(self, data: bytes):
        self.sent.extend(data)

    def close(self):
        pass


def make_backend(reply_stream: bytes, raise_timeout: bool = False) -> GDBBackend:
    backend = GDBBackend()
    backend._socket = FakeSocket()
    backend._sock_file = FakeSockFile(reply_stream, raise_timeout=raise_timeout)
    return backend


def packet(payload: bytes) -> bytes:
    """Wrap a raw (already-encoded) payload as an acked reply packet."""
    return b"+$" + payload + b"#" + _checksum(payload)


def test_rle_is_expanded():
    # RLE repeats the preceding *character* of the packet stream, i.e. a hex
    # nibble. "ff*!" -> 'f' plus 4 more (ord('!') - 29) -> "ffffff" -> 3 bytes.
    backend = make_backend(packet(b"ff*!"))
    assert backend.read_memory(0x2000_0000, 3) == b"\xff\xff\xff"


def test_rle_without_preceding_byte_is_an_error():
    backend = make_backend(packet(b"* "))
    with pytest.raises(GDBError, match="RLE marker with no preceding byte"):
        backend.read_memory(0x2000_0000, 1)


def test_rle_invalid_repeat_count_is_an_error():
    backend = make_backend(packet(b"ff*\x01"))
    with pytest.raises(GDBError, match="invalid RLE repeat count"):
        backend.read_memory(0x2000_0000, 1)


def test_short_read_is_detected():
    # Asked for 4 bytes, stub returns 2.
    backend = make_backend(packet(b"deadbeef"[:4]))
    with pytest.raises(GDBError, match="Short read"):
        backend.read_memory(0x2000_0000, 4)


def test_read_memory_happy_path():
    backend = make_backend(packet(b"deadbeef"))
    assert backend.read_memory(0x2000_0000, 4) == b"\xde\xad\xbe\xef"


def test_malformed_hex_raises_gdb_error_not_value_error():
    backend = make_backend(packet(b"zzzz"))
    with pytest.raises(GDBError, match="Malformed hex reply"):
        backend.read_memory(0x2000_0000, 2)


def test_timeout_is_translated_to_gdb_error():
    backend = make_backend(b"", raise_timeout=True)
    with pytest.raises(GDBError, match="Timed out"):
        backend.read_memory(0x2000_0000, 4)


def test_closed_connection_is_translated_to_gdb_error():
    backend = make_backend(b"")
    with pytest.raises(GDBError, match="Connection closed by remote"):
        backend.read_memory(0x2000_0000, 4)


def test_error_reply_raises_gdb_error():
    backend = make_backend(packet(b"E01"))
    with pytest.raises(GDBError, match="GDB error response"):
        backend.read_memory(0x2000_0000, 4)


def test_reset_leaves_target_running():
    # Reply to the halt '?' query, then to qRcmd. resume() only needs an ack.
    backend = make_backend(packet(b"T05") + packet(b"OK") + b"+")
    backend._is_running = True
    backend.reset()
    assert backend._is_running is True


def test_reset_propagates_failure():
    backend = make_backend(packet(b"E01"))
    with pytest.raises(GDBError):
        backend.reset()


def test_start_gdbserver_raises_with_actionable_message():
    backend = GDBBackend(port=1234)
    with pytest.raises(NotImplementedError, match="already the GDB server on port 1234"):
        backend.start_gdbserver(3333)


def test_close_resets_running_state():
    backend = make_backend(b"")
    backend._is_running = True
    backend.close()
    assert backend._is_running is False


def test_xpsr_uses_arm_m_profile_register_number():
    backend = make_backend(packet(b"00000041"))
    assert backend.read_register("xpsr") == 0x41000000
    assert b"$p19#" in backend._socket.sent


@pytest.mark.parametrize("name", ["r-1", "r16", "r99"])
def test_invalid_core_register_does_not_halt_or_send(name):
    backend = make_backend(packet(b"T05") + packet(b"00000000") + b"+")
    backend._is_running = True
    with pytest.raises(ValueError, match="Unknown register"):
        backend.read_register(name)
    assert backend._socket.sent == b""
    assert backend._is_running is True


@pytest.mark.parametrize("payload", [b"zzzzzzzz", b"0000", b""])
def test_bad_register_read_leaves_target_halted(payload):
    backend = make_backend(packet(b"T05") + packet(payload) + b"+")
    backend._is_running = True
    with pytest.raises(GDBError):
        backend.read_register("r0")
    assert b"$c#" not in backend._socket.sent
    assert backend._is_running is False


def test_failed_register_write_leaves_target_halted():
    backend = make_backend(packet(b"T05") + packet(b"unsupported") + b"+")
    backend._is_running = True
    with pytest.raises(GDBError, match="expected OK"):
        backend.write_register("r0", 7)
    assert b"$c#" not in backend._socket.sent
    assert backend._is_running is False


@pytest.mark.parametrize("checksum", [b"00", b"zz", b"a"])
def test_bad_packet_checksum_is_not_accepted(checksum):
    backend = make_backend(b"+$deadbeef#" + checksum)
    with pytest.raises(GDBError):
        backend.read_memory(0x20000000, 4)
    assert not backend._socket.sent.endswith(b"+")


@pytest.mark.parametrize("operation", ["read", "resume"])
def test_repeated_negative_acknowledgements_are_bounded(operation):
    backend = make_backend(b"-" * 20)
    with pytest.raises(GDBError, match="negative acknowledgements"):
        (backend.read_memory(0x20000000, 4) if operation == "read" else backend.resume())
    assert backend._socket.sent.count(b"$") <= 4
    assert backend._is_running is False


def test_failed_open_closes_created_socket(monkeypatch):
    class FailedSocket(FakeSocket):
        closed = False

        def settimeout(self, _timeout):
            pass

        def setsockopt(self, *_args):
            pass

        def connect(self, _address):
            raise ConnectionRefusedError("refused")

        def close(self):
            self.closed = True

    sock = FailedSocket()
    monkeypatch.setattr(socket, "socket", lambda *_args: sock)
    backend = GDBBackend()
    with pytest.raises(GDBError.__bases__[0], match="Could not connect"):
        backend.open()
    assert sock.closed
    assert backend._socket is None


def described_backend(monkeypatch):
    """Use actual wire packets for QEMU's two relevant M-profile features."""
    target = b'<target xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="arm-m-profile.xml"/><xi:include href="arm-m-system.xml"/></target>'
    core = b'<feature><reg name="sp" bitsize="32" regnum="13"/><reg name="xpsr" bitsize="32" regnum="25"/></feature>'
    system = b'<feature><reg name="msp" bitsize="32" regnum="43"/><reg name="psp" bitsize="32" regnum="44"/><reg name="control" bitsize="32" regnum="46"/></feature>'

    class ConnectedSocket(FakeSocket):
        def settimeout(self, _timeout):
            pass

        def setsockopt(self, *_args):
            pass

        def connect(self, _address):
            pass

        def makefile(self, *_args, **_kwargs):
            return self.stream

    sock = ConnectedSocket()
    sock.stream = FakeSockFile(packet(b"PacketSize=20020;qXfer:features:read+")
                              + packet(b"l" + target) + packet(b"l" + core)
                              + packet(b"l" + system) + b"+")
    monkeypatch.setattr(socket, "socket", lambda *_args: sock)
    backend = GDBBackend()
    backend.open()
    backend._is_running = False
    return backend


def test_msp_read_uses_target_description_not_active_sp(monkeypatch):
    backend = described_backend(monkeypatch)
    backend._sock_file = FakeSockFile(packet(b"00000120"))
    assert backend.read_register("msp") == 0x20010000
    assert b"xmlRegisters=arm" in backend._socket.sent
    assert b"$p2b#" in backend._socket.sent


def test_inactive_msp_write_is_rejected_without_changing_active_psp(monkeypatch):
    backend = described_backend(monkeypatch)
    # CONTROL.SPSEL selects PSP in Thread mode (IPSR=0 in XPSR).
    backend._sock_file = FakeSockFile(packet(b"02000000") + packet(b"00000001") + packet(b"OK"))
    with pytest.raises(GDBError, match="inactive MSP"):
        backend.write_register("msp", 0x2000F000)
    assert b"$Pd=" not in backend._socket.sent
    assert b"$P2b=" not in backend._socket.sent


def test_active_msp_write_uses_writable_core_stack_pointer(monkeypatch):
    backend = described_backend(monkeypatch)
    backend._sock_file = FakeSockFile(packet(b"00000000") + packet(b"OK"))
    backend.write_register("msp", 0x2000F000)
    assert b"$Pd=00f00020#" in backend._socket.sent
    assert b"$P2b=" not in backend._socket.sent


def test_packet_checksum_covers_encoded_escape_bytes():
    backend = make_backend(packet(b"a}\x03"))  # Encoded '#' is '}' followed by 0x03.
    assert backend._send_command(b"qXfer:features:read:target.xml:0,fff") == b"a#"


def test_continuing_ack_noise_cannot_extend_command_deadline(monkeypatch):
    from gnwmanager.ocdbackend import gdb_backend

    ticks = iter(range(100))
    monkeypatch.setattr(gdb_backend, "monotonic", lambda: next(ticks), raising=False)
    backend = make_backend(b"!" * 20)
    with pytest.raises(GDBError, match="Timed out.*command"):
        backend.read_memory(0x20000000, 4)
    assert backend._sock_file.pos < 20


def test_handler_mode_can_write_selected_msp_despite_thread_spsel(monkeypatch):
    backend = described_backend(monkeypatch)
    backend._sock_file = FakeSockFile(packet(b"02000000") + packet(b"10000001") + packet(b"OK"))
    backend.write_register("msp", 0x2000F000)
    assert b"$Pd=00f00020#" in backend._socket.sent


def test_reset_and_halt_never_continues_guest_before_stack_initialization():
    backend = make_backend(packet(b"T05") + packet(b"OK"))
    backend._is_running = True
    backend.reset_and_halt()
    assert backend._is_running is False
    assert b"$c#" not in backend._socket.sent
    assert backend._msp_alias_safe


def test_simple_stub_msp_alias_is_refused_outside_reset_window():
    backend = make_backend(packet(b"00000120"))
    with pytest.raises(GDBError, match="immediately after reset-and-halt"):
        backend.read_register("msp")
    assert backend._socket.sent == b""


def test_corrupt_handshake_does_not_continue_target(monkeypatch):
    class ConnectedSocket(FakeSocket):
        def settimeout(self, _timeout):
            pass

        def setsockopt(self, *_args):
            pass

        def connect(self, _address):
            pass

        def makefile(self, *_args, **_kwargs):
            return FakeSockFile(b"+$PacketSize=20020#00+")

    sock = ConnectedSocket()
    monkeypatch.setattr(socket, "socket", lambda *_args: sock)
    backend = GDBBackend()
    with pytest.raises(GDBError, match="checksum"):
        backend.open()
    assert b"$c#" not in sock.sent
    assert backend._socket is None


@pytest.mark.parametrize("feature_mode", ["no-xml", "core-only", "broken-system"])
@pytest.mark.parametrize("close_first", [True, False])
def test_new_connection_does_not_inherit_system_register_identities(monkeypatch, feature_mode, close_first):
    backend = described_backend(monkeypatch)
    assert backend._registers["msp"] == 43
    if close_first:
        backend.close()

    class ConnectedSocket(FakeSocket):
        def settimeout(self, _timeout):
            pass

        def setsockopt(self, *_args):
            pass

        def connect(self, _address):
            pass

        def makefile(self, *_args, **_kwargs):
            return self.stream

    sock = ConnectedSocket()
    if feature_mode == "no-xml":
        replies = packet(b"PacketSize=20020") + b"+"
    else:
        includes = b'<xi:include href="arm-m-profile.xml"/>'
        if feature_mode == "broken-system":
            includes += b'<xi:include href="arm-m-system.xml"/>'
        target = b'<target xmlns:xi="http://www.w3.org/2001/XInclude">' + includes + b'</target>'
        core = b'<feature><reg name="xpsr" bitsize="32" regnum="25"/></feature>'
        replies = packet(b"PacketSize=20020;qXfer:features:read+") + packet(b"l" + target) + packet(b"l" + core)
        replies += packet(b"l<feature") if feature_mode == "broken-system" else b"+"
    sock.stream = FakeSockFile(replies)
    monkeypatch.setattr(socket, "socket", lambda *_args: sock)
    if feature_mode == "broken-system":
        with pytest.raises(GDBError, match="Malformed target description XML"):
            backend.open()
        assert backend._socket is None
    else:
        backend.open()
    assert "msp" not in backend._registers
    assert "control" not in backend._registers
    assert "psp" not in backend._registers
    assert backend._msp_alias_safe is False
    backend._is_running = False
    before = bytes(sock.sent)
    with pytest.raises(GDBError, match="immediately after reset-and-halt"):
        backend.read_register("msp")
    assert bytes(sock.sent) == before, "missing MSP identity must fail before reading an old index"
