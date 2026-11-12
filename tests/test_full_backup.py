import hashlib
import json
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from gnwmanager.full_backup import (
    EXTRAS,
    REGIONS,
    BackupError,
    capture_backup,
    fetch_backup,
    restore_backup,
    verify_archive,
)
from gnwmanager.gnw import GnW


class Backend:
    def __init__(self):
        self.events = []
        self.rdp = 0xAA
        self.bad_read = False
        self.data = {a: bytes([i + 17]) * s for i, (a, s) in enumerate([*REGIONS.values(), *EXTRAS.values()])}
        self.data[0x90000000] = b"x" * (1 << 20)

    def __enter__(self):
        self.events.append("open")
        return self

    def __exit__(self, *_):
        self.events.append("close")

    def halt(self):
        self.events.append("halt")

    def resume(self):
        self.events.append("resume")

    def read_uint32(self, a):
        assert a == 0x5200201C
        return self.rdp << 8

    def read_memory(self, a, s):
        self.events.append(("read", a, s))
        for base, data in self.data.items():
            if base <= a and a + s <= base + len(data):
                result = data[a - base : a - base + s]
                return result[:-1] if self.bad_read else result
        raise AssertionError(hex(a))


class FakeGnW(GnW):
    def __init__(self, b):
        super().__init__(b)
        self._external_flash_size = 1 << 20
        self.writes = []
        self.corrupt_readback = False

    def start_gnwmanager(self):
        self.backend.events.append("manager")
        self.backend.data[0] = b"z" * 65536

    def read_memory(self, a, s):
        assert "manager" in self.backend.events
        data = self.backend.read_memory(a, s)
        return bytes([data[0] ^ 1]) + data[1:] if self.corrupt_readback else data

    def flash(self, bank, offset, data):
        self.writes.append((bank, offset, data))
        self.backend.data[{0: 0x90000000, 1: 0x08000000, 2: 0x08100000}[bank]] = data


@pytest.fixture
def archive(tmp_path):
    out = tmp_path / "archive"
    capture_backup(FakeGnW(Backend()), out)
    return out


def test_raw_capture_precedes_manager_without_reset_resume(tmp_path):
    b = Backend()
    before = dict(b.data)
    out = tmp_path / "capture"
    man = capture_backup(FakeGnW(b), out)
    assert (out / "itcm.bin").read_bytes() == before[0] and b.data[0] != before[0]
    prefix = b.events[: b.events.index("manager")]
    assert "halt" in prefix and "resume" not in b.events
    assert sum(isinstance(e, tuple) and e[1] == 0 for e in prefix) == 2
    assert verify_archive(out) == man


def test_partial_and_existing_output(tmp_path):
    b = Backend()
    out = tmp_path / "partial"
    man = capture_backup(FakeGnW(b), out, skip_ext=True, resume=True)
    assert "manager" not in b.events and b.events[-1] == "resume" and man["coverage"] == "partial"
    assert "ext.bin" not in man["files"]
    verify_archive(out)
    with pytest.raises(BackupError, match="exists"):
        capture_backup(FakeGnW(Backend()), out)


@pytest.mark.parametrize("interrupt", [False, KeyboardInterrupt, SystemExit])
def test_failed_capture_pauses_even_when_diagnostics_fail(tmp_path, monkeypatch, interrupt):
    backend = Backend()
    gnw = FakeGnW(backend)
    original_start = gnw.start_gnwmanager

    def start():
        original_start()
        backend.resume()

    def failed_read(*_args):
        if interrupt:
            raise interrupt("capture cancelled")
        raise OSError("original capture disk full")

    original_write = Path.write_text

    def failed_diagnostic(path, *args, **kwargs):
        if path.name == "failure.json":
            raise OSError("diagnostic disk full")
        return original_write(path, *args, **kwargs)

    gnw.start_gnwmanager = start
    gnw.read_memory = failed_read
    monkeypatch.setattr(Path, "write_text", failed_diagnostic)
    expected = interrupt or BackupError
    with pytest.raises(
        expected,
        match="capture cancelled" if interrupt else "original capture disk full",
    ) as failure:
        capture_backup(gnw, tmp_path / "capture")
    if not interrupt:
        assert isinstance(failure.value.__cause__, OSError)
        assert str(failure.value.__cause__) == "original capture disk full"
    assert backend.events[-1] == "halt"
    assert not (tmp_path / "capture/manifest.json").exists()


def test_fetch_diagnostic_failure_preserves_original_error(tmp_path, monkeypatch):
    def fail_transfer(*_args, **_kwargs):
        raise BackupError("original transfer failure")

    def fail_diagnostic(*_args, **_kwargs):
        raise OSError("diagnostic disk full")

    monkeypatch.setattr(Path, "write_text", fail_diagnostic)
    with pytest.raises(BackupError, match="original transfer failure"):
        fetch_backup("host:backup", tmp_path / "fetched", runner=fail_transfer)
    assert not (tmp_path / "fetched").exists()


@pytest.mark.parametrize("borrowed", [False, True])
@pytest.mark.parametrize("command", ["backup", "restore-backup"])
def test_chained_cli_reuses_exclusive_backend(archive, tmp_path, monkeypatch, borrowed, command):
    import importlib

    main = importlib.import_module("gnwmanager.cli.main")
    state = {"active": 0, "opens": 0, "writes": 0}

    class ExclusiveBackend(Backend):
        def open(self):
            if state["active"]:
                raise RuntimeError("second simultaneous connection")
            state["active"] += 1
            state["opens"] += 1
            return self

        def close(self):
            state["active"] -= 1

        def __enter__(self):
            return self.open()

        def __exit__(self, *_args):
            self.close()

    class ChainGnW(FakeGnW):
        def write_uint32(self, *_args):
            state["writes"] += 1

    monkeypatch.setattr(main, "OCDBackend", {"gdb": lambda **_kwargs: ExclusiveBackend()})
    monkeypatch.setattr(main, "GnW", ChainGnW)
    monkeypatch.setattr("gnwmanager.cli._backup.GnW", ChainGnW)
    monkeypatch.setattr("gnwmanager.full_backup.GnW", ChainGnW)
    supplied = None
    if borrowed:
        backend = ExclusiveBackend().open()
        supplied = ChainGnW(backend)
    action = (
        ["backup", "--out", str(tmp_path / "new"), "--skip-ext"]
        if command == "backup"
        else ["restore-backup", str(archive), "--only", "bank2", "--yes"]
    )
    try:
        main.main(
            "disable-debug",
            "--",
            *action,
            "--",
            "disable-debug",
            backend="gdb",
            gnw=supplied,
            exit_on_error=False,
        )
        assert state == {"active": int(borrowed), "opens": 1, "writes": 2}
        if command == "backup":
            assert verify_archive(tmp_path / "new")["coverage"] == "partial"
    finally:
        if supplied is not None:
            supplied.backend.close()


@pytest.mark.parametrize("injected", [False, True])
@pytest.mark.parametrize("operation", ["partial", "complete", "restore"])
def test_backup_chain_restarts_manager_before_following_flash(archive, tmp_path, monkeypatch, injected, operation):
    import importlib

    main = importlib.import_module("gnwmanager.cli.main")
    devices = []
    instances = []

    class StatefulBackend(Backend):
        def __init__(self):
            super().__init__()
            self.running = False
            self.active = False
            self.opens = 0

        def open(self):
            assert not self.active
            self.active = True
            self.opens += 1
            return self

        def close(self):
            self.active = False

        def halt(self):
            super().halt()
            self.running = False

        def resume(self):
            super().resume()
            self.running = True

        def reset_and_halt(self):
            self.events.append("reset")
            self.running = False

        def write_memory(self, address, data):
            self.events.append(("write", address, len(data)))

        def write_uint32(self, address, value):
            self.events.append(("write32", address, value))

        def write_register(self, name, value):
            self.events.append(("register", name, value))

    class StatefulGnW(GnW):
        def __init__(self, backend):
            super().__init__(backend)
            instances.append(self)

        @property
        def external_flash_size(self):
            return 1 << 20

        def wait_for_idle(self):
            assert self.backend.running

        def read_memory(self, address, size):
            assert self.backend.running
            return self.backend.read_memory(address, size)

        def flash(self, bank, offset, data, **_kwargs):
            assert self.backend.running, "manager-dependent flash attempted while CPU halted"
            assert self.context_counter == 1
            assert self._in_flight_retry == [None, None]
            address = {0: 0x90000000, 1: 0x08000000, 2: 0x08100000}[bank]
            original = self.backend.data[address]
            self.backend.data[address] = original[:offset] + data + original[offset + len(data) :]
            self.backend.events.append(("flash", bank, bytes(data)))

    def factory(**_kwargs):
        backend = StatefulBackend()
        devices.append(backend)
        return backend

    monkeypatch.setattr(main, "OCDBackend", {"gdb": factory})
    monkeypatch.setattr(main, "GnW", StatefulGnW)
    monkeypatch.setattr("gnwmanager.cli._backup.GnW", StatefulGnW)
    monkeypatch.setattr("gnwmanager.full_backup.GnW", StatefulGnW)
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"new flash bytes" * 2)
    supplied = None
    if injected:
        supplied = StatefulGnW(factory().open())
    # The first actual CLI flash loads the manager through the real startup
    # method. Seed old communication state to detect stale cache/retry reuse.
    from gnwmanager.cli.main import app

    @app.command(name="seed-backup-test-state", show=False)
    def seed_state(*, gnw: main.GnWType):
        gnw.context_counter = 91
        gnw._in_flight_retry = [{"attempts": 2}, None]

    action = (
        ["restore-backup", str(archive), "--only", "bank2", "--yes"]
        if operation == "restore"
        else [
            "backup",
            "--out",
            str(tmp_path / "new"),
            *(["--skip-ext"] if operation == "partial" else []),
        ]
    )
    try:
        main.main(
            "flash",
            "bank2",
            str(payload),
            "--",
            "seed-backup-test-state",
            "--",
            *action,
            "--",
            "flash",
            "bank2",
            str(payload),
            backend="gdb",
            gnw=supplied,
            exit_on_error=False,
        )
        backend = devices[0]
        assert len(devices) == 1 and backend.opens == 1
        assert backend.active == injected
        assert backend.data[0x08100000][: payload.stat().st_size] == payload.read_bytes()
        assert sum(e == "reset" for e in backend.events) == (2 if operation == "partial" else 3)
        owner = supplied or instances[0]
        assert owner._gnwmanager_started and owner.context_counter == 1
        assert owner._in_flight_retry == [None, None]
    finally:
        # Registration is local to this test; never leave it in the app registry.
        del app["seed-backup-test-state"]
        if supplied is not None:
            supplied.backend.close()


def test_manager_cache_invalidation_is_host_only():
    backend = Backend()
    owner = GnW(backend)
    owner._gnwmanager_started = True
    owner.context_counter = 99
    owner._in_flight_retry = [{"attempts": 1}, None]
    owner._external_flash_size = 1 << 20
    owner._external_flash_block_size = 4096
    owner.default_filesystem_offset = 1234
    owner.invalidate_manager_state()
    assert not owner._gnwmanager_started
    assert owner.context_counter == 1 and owner._in_flight_retry == [None, None]
    assert owner._external_flash_size == owner._external_flash_block_size == 0
    assert owner.default_filesystem_offset == 1234
    assert backend.events == []


@pytest.mark.parametrize("cancelled", [False, True])
def test_failed_borrowed_capture_invalidates_host_state_without_resuming(tmp_path, cancelled):
    import importlib

    main = importlib.import_module("gnwmanager.cli.main")
    backend = Backend()
    owner = GnW(backend)
    owner._gnwmanager_started = True
    owner.context_counter = 71
    owner._in_flight_retry = [{"attempts": 1}, None]
    if cancelled:

        def interrupt(*_args):
            raise KeyboardInterrupt("cancel borrowed capture")

        backend.read_memory = interrupt
    else:
        backend.bad_read = True
    tokens = ("backup", "--out", str(tmp_path / "failed"), "--skip-ext")
    if cancelled:
        with pytest.raises(KeyboardInterrupt, match="cancel borrowed capture"):
            main.main(*tokens, backend="gdb", gnw=owner, exit_on_error=False)
    else:
        main.main(*tokens, backend="gdb", gnw=owner, exit_on_error=False)
    assert not owner._gnwmanager_started
    assert owner.context_counter == 1 and owner._in_flight_retry == [None, None]
    assert "resume" not in backend.events and "close" not in backend.events
    assert backend.events[-1] == "halt"


@pytest.mark.parametrize("invalid", [True, False])
def test_borrowed_restore_rejects_before_open_and_leaves_caller_connected(archive, monkeypatch, invalid):
    import importlib

    main = importlib.import_module("gnwmanager.cli.main")
    backend = Backend()
    gnw = FakeGnW(backend)
    gnw.write_uint32 = lambda *_args: None
    gnw._gnwmanager_started = True
    gnw.context_counter = 77
    gnw._in_flight_retry = [{"attempts": 3}, None]
    backend.close = lambda: pytest.fail("caller-owned backend closed")

    def forbidden(**_kwargs):
        pytest.fail("new backend constructed")

    monkeypatch.setattr(main, "OCDBackend", {"gdb": forbidden})
    if invalid:
        (archive / "bank1.bin").write_bytes(b"damaged")
    else:
        monkeypatch.setattr("builtins.input", lambda *_args: "NO")
    main.main(
        "disable-debug",
        "--",
        "restore-backup",
        str(archive),
        backend="gdb",
        gnw=gnw,
        exit_on_error=False,
    )
    assert backend.events == []
    assert gnw._gnwmanager_started and gnw.context_counter == 77
    assert gnw._in_flight_retry == [{"attempts": 3}, None]


@pytest.mark.parametrize("command", ["verify-backup", "fetch-backup"])
def test_offline_commands_preserve_injected_manager_cache(archive, tmp_path, monkeypatch, command):
    import importlib

    main = importlib.import_module("gnwmanager.cli.main")
    backend = Backend()
    owner = GnW(backend)
    owner._gnwmanager_started = True
    owner.context_counter = 31
    owner._in_flight_retry = [{"attempts": 1}, None]
    monkeypatch.setattr("gnwmanager.cli._backup.fetch_backup", lambda *_args, **_kwargs: None)
    tokens = (
        [command, str(archive)]
        if command == "verify-backup"
        else [command, "host:archive", "--dest", str(tmp_path / "fetched")]
    )
    main.main(*tokens, backend="gdb", gnw=owner, exit_on_error=False)
    assert owner._gnwmanager_started and owner.context_counter == 31
    assert owner._in_flight_retry == [{"attempts": 1}, None]
    assert backend.events == []


def test_short_read_and_locked_capture_fail_before_manager(tmp_path):
    b = Backend()
    b.bad_read = True
    out = tmp_path / "bad"
    with pytest.raises(BackupError, match="Short"):
        capture_backup(FakeGnW(b), out)
    assert not (out / "manifest.json").exists() and (out / "failure.json").exists() and "manager" not in b.events
    b = Backend()
    b.rdp = 0x55
    with pytest.raises(BackupError, match="RDP"):
        capture_backup(FakeGnW(b), tmp_path / "locked")


def test_double_read_difference_fails(tmp_path):
    b = Backend()
    original = b.read_memory
    calls = 0

    def changed(a, s):
        nonlocal calls
        calls += 1
        data = original(a, s)
        return bytes([data[0] ^ 1]) + data[1:] if calls == 2 else data

    b.read_memory = changed
    with pytest.raises(BackupError, match="differ"):
        capture_backup(FakeGnW(b), tmp_path / "bad", skip_ext=True)


def test_legacy_manifest(archive):
    p = archive / "manifest.json"
    m = json.loads(p.read_text())
    for k in ("format", "version", "coverage"):
        m.pop(k)
    p.write_text(json.dumps(m))
    assert verify_archive(archive)["files"] == m["files"]


@pytest.mark.parametrize(
    "kind",
    [
        "empty",
        "path",
        "unknown",
        "size",
        "hash",
        "capacity",
        "version",
        "coverage",
        "address",
        "boolean",
    ],
)
def test_bad_manifest(archive, kind):
    p = archive / "manifest.json"
    m = json.loads(p.read_text())
    if kind == "empty":
        m["files"] = {}
    elif kind == "path":
        m["files"]["../bank1.bin"] = m["files"].pop("bank1.bin")
    elif kind == "unknown":
        m["files"]["other.bin"] = m["files"]["bank1.bin"]
    elif kind == "size":
        m["files"]["bank1.bin"]["size"] -= 1
    elif kind == "hash":
        m["files"]["bank1.bin"]["sha256"] = "0" * 64
    elif kind == "capacity":
        m["ext_size"] = 12345
    elif kind == "version":
        m["version"] = 999
    elif kind == "coverage":
        m["coverage"] = "partial"
    elif kind == "address":
        m["regions"]["bank1"]["addr"] = "0x20000000"
    else:
        m["files"]["bank1.bin"]["size"] = True
    p.write_text(json.dumps(m))
    with pytest.raises(BackupError):
        verify_archive(archive)


def test_missing_and_symlink(archive, tmp_path):
    p = archive / "bank1.bin"
    data = p.read_bytes()
    p.unlink()
    with pytest.raises(BackupError):
        verify_archive(archive)
    target = tmp_path / "target"
    target.write_bytes(data)
    p.symlink_to(target)
    with pytest.raises(BackupError, match="link|regular"):
        verify_archive(archive)


def test_selected_flash_restore(archive, monkeypatch):
    b = Backend()
    g = FakeGnW(b)
    monkeypatch.setattr("gnwmanager.full_backup.GnW", lambda _: g)
    result = restore_backup(archive, lambda: b, only=["bank2"], confirm=lambda: True)
    assert result["completed"] == ["bank2"] and [(bank, offset) for bank, offset, _ in g.writes] == [(2, 0)]


@pytest.mark.parametrize("only", [["itcm"], ["unknown"], []])
def test_invalid_selection_never_connects(archive, only):
    def forbidden():
        raise AssertionError("connected")

    with pytest.raises(BackupError):
        restore_backup(archive, forbidden, only=only, confirm=lambda: True)


def test_corrupt_or_abort_never_connects(archive):
    def forbidden():
        raise AssertionError("connected")

    with pytest.raises(BackupError, match="abort"):
        restore_backup(archive, forbidden, confirm=lambda: False)
    (archive / "bank1.bin").write_bytes(b"bad")
    with pytest.raises(BackupError):
        restore_backup(archive, forbidden, confirm=lambda: True)


def test_factory_mutation_cannot_replace_verified_payload(archive, monkeypatch):
    b = Backend()
    g = FakeGnW(b)
    expected = (archive / "bank1.bin").read_bytes()

    def factory():
        (archive / "bank1.bin").write_bytes(b"evil" * 65536)
        return b

    monkeypatch.setattr("gnwmanager.full_backup.GnW", lambda _: g)
    restore_backup(archive, factory, only=["bank1"], confirm=lambda: True)
    assert g.writes[0][2] == expected


def test_capacity_and_readback_failures(archive, monkeypatch):
    b = Backend()
    g = FakeGnW(b)
    monkeypatch.setattr("gnwmanager.full_backup.GnW", lambda _: g)
    g._external_flash_size = 4 << 20
    with pytest.raises(BackupError, match="capacity"):
        restore_backup(archive, lambda: b, only=["ext"], confirm=lambda: True)
    assert not g.writes
    g._external_flash_size = 1 << 20
    g.corrupt_readback = True
    with pytest.raises(BackupError, match="readback|Readback"):
        restore_backup(archive, lambda: b, only=["bank1"], confirm=lambda: True)


def test_http_actual_fetch_and_corruption(archive, tmp_path):
    class Quiet(SimpleHTTPRequestHandler):
        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Quiet, directory=str(archive)))
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        src = f"http://127.0.0.1:{server.server_port}/"
        dest = tmp_path / "fetched"
        fetch_backup(src, dest)
        assert verify_archive(dest) == verify_archive(archive)
        with pytest.raises(BackupError, match="exists"):
            fetch_backup(src, dest)
        (archive / "bank1.bin").write_bytes(b"bad")
        failed = tmp_path / "bad-fetch"
        with pytest.raises(BackupError):
            fetch_backup(src, failed)
        assert not failed.exists()
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


@pytest.mark.parametrize("remote", ["user@host:/remote/backup", "user@host:backups/full_20261104_1021"])
def test_scp_manifest_first_allowlist(archive, tmp_path, remote):
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        name = argv[-2].split("/")[-1]
        Path(argv[-1]).write_bytes((archive / name).read_bytes())

    dest = tmp_path / "fetched"
    fetch_backup(remote, dest, runner=runner)
    assert calls[0][0][-2].endswith("/manifest.json") and len(calls) == 7
    assert all("*" not in " ".join(argv) and kw["timeout"] > 0 for argv, kw in calls)
    assert verify_archive(dest)


@pytest.mark.parametrize("src", ["-oProxyCommand=x:/foo", "host:../escape", "host:/foo;touch-x"])
def test_bad_scp_input(tmp_path, src):
    def forbidden(*_, **kw):
        raise AssertionError("called")

    with pytest.raises(BackupError):
        fetch_backup(src, tmp_path / "dest", runner=forbidden)


def test_cli_offline_and_corrupt_restore_never_create_backend(archive, tmp_path, monkeypatch):
    import importlib

    main = importlib.import_module("gnwmanager.cli.main")

    def forbidden(**_):
        raise AssertionError("backend created")

    monkeypatch.setattr(main, "OCDBackend", {"gdb": forbidden})
    main.main("verify-backup", str(archive), backend="gdb", exit_on_error=False)
    calls = []
    monkeypatch.setattr(
        "gnwmanager.cli._backup.fetch_backup",
        lambda src, dest: calls.append((src, dest)),
    )
    main.main(
        "fetch-backup",
        "host:/backup",
        "--dest",
        str(tmp_path / "dest"),
        backend="gdb",
        exit_on_error=False,
    )
    assert calls == [("host:/backup", tmp_path / "dest")]
    (archive / "bank1.bin").write_bytes(b"bad")
    main.main("restore-backup", str(archive), "--yes", backend="gdb", exit_on_error=False)


def test_cli_backup_selects_raw_gdb_and_resume(tmp_path, monkeypatch):
    import importlib

    main = importlib.import_module("gnwmanager.cli.main")
    b = Backend()
    g = FakeGnW(b)
    kwargs = []
    monkeypatch.setattr(main, "OCDBackend", {"gdb": lambda **kw: kwargs.append(kw) or b})
    monkeypatch.setattr("gnwmanager.cli._backup.GnW", lambda backend: g)
    main.main(
        "backup",
        "--out",
        str(tmp_path / "out"),
        "--skip-ext",
        "--resume",
        backend="gdb",
        gdb_host="test",
        gdb_port=4567,
    )
    assert kwargs == [{"host": "test", "port": 4567, "resume_on_connect": False}]
    assert "resume" in b.events
    assert b.events[-1] == "close"


def test_readonly_extra_corruption_blocks_selected_restore(archive):
    (archive / "rtc_bkp.bin").write_bytes(b"bad")

    def forbidden():
        raise AssertionError("connected")

    with pytest.raises(BackupError):
        restore_backup(archive, forbidden, only=["bank1"], confirm=lambda: True)


def test_legacy_partial_archive_is_valid(tmp_path):
    out = tmp_path / "partial"
    man = capture_backup(FakeGnW(Backend()), out, skip_ext=True)
    for key in ("format", "version", "coverage"):
        man.pop(key)
    (out / "manifest.json").write_text(json.dumps(man))
    assert "ext.bin" not in verify_archive(out)["files"]


def test_restore_failure_reports_verified_completed_regions(archive, monkeypatch):
    b = Backend()
    g = FakeGnW(b)
    original = g.flash

    def flash(bank, offset, data):
        original(bank, offset, data)
        if bank == 2:
            g.corrupt_readback = True

    g.flash = flash
    monkeypatch.setattr("gnwmanager.full_backup.GnW", lambda _: g)
    with pytest.raises(BackupError) as error:
        restore_backup(archive, lambda: b, only=["bank1", "bank2"], confirm=lambda: True)
    assert error.value.completed == ["bank1"]
    assert "completed=" in str(error.value)


def test_fifo_payload_is_rejected_without_open_blocking(archive):
    import os

    p = archive / "bank1.bin"
    p.unlink()
    os.mkfifo(p)
    # A FIFO open must include O_NONBLOCK so even a malicious archive cannot hang.
    import gnwmanager.full_backup as module

    original = module.os.open
    seen = []

    def checking(path, flags):
        seen.append(flags)
        assert flags & os.O_NONBLOCK
        return original(path, flags)

    from unittest.mock import patch

    with patch.object(module.os, "open", checking), pytest.raises(BackupError):
        verify_archive(archive)
    assert seen


def test_scp_corruption_and_collision_keep_destination_unpublished(archive, tmp_path):
    dest = tmp_path / "fetched"

    def runner(argv, **kwargs):
        name = argv[-2].split("/")[-1]
        Path(argv[-1]).write_bytes((archive / name).read_bytes() if name != "bank1.bin" else b"bad")

    with pytest.raises(BackupError):
        fetch_backup("host:/backup", dest, runner=runner)
    assert not dest.exists() and list(tmp_path.glob(".fetched.fetch-*"))


def test_schema_duplicate_fields_and_bad_types(archive):
    p = archive / "manifest.json"
    man = json.loads(p.read_text())
    p.write_text(p.read_text().replace('"version": 1', '"version": 1, "version": 1'))
    with pytest.raises(BackupError, match="Duplicate"):
        verify_archive(archive)
    man["files"]["bank1.bin"] = []
    p.write_text(json.dumps(man))
    with pytest.raises(BackupError):
        verify_archive(archive)


@pytest.mark.parametrize("phase", ["headers", "body"])
def test_http_dribble_obeys_total_deadline(tmp_path, monkeypatch, phase):
    import time
    from http.server import BaseHTTPRequestHandler

    import gnwmanager.full_backup as module

    stopped = threading.Event()
    entered = threading.Event()
    sent = []
    children = []
    original_popen = module.subprocess.Popen

    def record_child(*args, **kwargs):
        child = original_popen(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(module.subprocess, "Popen", record_child)

    class Dribble(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            entered.set()
            body = b'{"not":"a manifest"}' + b" " * 300
            header = f"HTTP/1.0 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode()
            parts = header + body if phase == "headers" else body
            try:
                if phase == "body":
                    self.wfile.write(header)
                    self.wfile.flush()
                for value in parts:
                    if stopped.wait(0.025):
                        return
                    self.wfile.write(bytes([value]))
                    self.wfile.flush()
                    sent.append(value)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Dribble)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(module, "FETCH_TIMEOUT", 0.75, raising=False)
    dest = tmp_path / "dribbled"
    started = time.monotonic()
    try:
        with pytest.raises(BackupError, match="deadline"):
            fetch_backup(f"http://127.0.0.1:{server.server_port}/backup", dest)
        assert time.monotonic() - started < 2
        assert entered.is_set() and len(sent) >= 2, "deadline must exercise actual dribbled HTTP data"
        assert len(children) == 1 and children[0].poll() is not None
        import os

        with pytest.raises(ProcessLookupError):
            os.kill(children[0].pid, 0)
        assert not dest.exists()
        stages = list(tmp_path.glob(".dribbled.fetch-*"))
        assert len(stages) == 1 and (stages[0] / "failure.json").is_file()
    finally:
        stopped.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_fetch_atomic_publication_preserves_racing_empty_destination(archive, tmp_path, monkeypatch):
    import ctypes
    import os
    import sys
    from types import SimpleNamespace

    import gnwmanager.full_backup as module

    dest = tmp_path / "race"
    collision = {}

    def occupy():
        dest.mkdir()
        collision["inode"] = dest.stat().st_ino

    if os.name == "nt":
        original = os.rename

        def raced_rename(source, destination):
            occupy()
            return original(source, destination)

        monkeypatch.setattr(module.os, "rename", raced_rename)
    else:
        library = ctypes.CDLL(None, use_errno=True)
        if sys.platform == "darwin":
            symbol = "renamex_np"
            real = library.renamex_np
            real.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        elif sys.platform.startswith("linux"):
            symbol = "renameat2"
            real = library.renameat2
            real.argtypes = (
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            )
        else:
            pytest.skip("platform does not offer an atomic no-replace rename")
        real.restype = ctypes.c_int

        def raced_rename(*args):
            occupy()
            return real(*args)

        setattr(library, symbol, raced_rename)
        proxy = SimpleNamespace(
            CDLL=lambda *_args, **_kwargs: library,
            c_char_p=ctypes.c_char_p,
            c_uint=ctypes.c_uint,
            c_int=ctypes.c_int,
            get_errno=ctypes.get_errno,
        )
        monkeypatch.setattr(module, "ctypes", proxy, raising=False)

    def runner(argv, **_kwargs):
        name = argv[-2].rsplit("/", 1)[-1]
        Path(argv[-1]).write_bytes((archive / name).read_bytes())

    with pytest.raises(BackupError, match="exists"):
        fetch_backup("host:backups/complete", dest, runner=runner)
    assert dest.stat().st_ino == collision["inode"]
    assert list(dest.iterdir()) == []
    stages = list(tmp_path.glob(".race.fetch-*"))
    assert len(stages) == 1 and (stages[0] / "failure.json").is_file()
    assert verify_archive(stages[0]) == verify_archive(archive)
