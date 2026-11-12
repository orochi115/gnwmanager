"""Complete Flash archives, with raw capture before manager firmware upload."""

import ctypes
import datetime as dt
import errno
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import suppress
from pathlib import Path
from urllib.parse import urlsplit

from gnwmanager.exceptions import DataError
from gnwmanager.gnw import GnW

REGIONS = {"bank1": (0x08000000, 256 * 1024), "bank2": (0x08100000, 256 * 1024), "ext": (0x90000000, 0)}
EXTRAS = {"optbytes": (0x52002000, 256), "itcm": (0, 65536), "rtc_bkp": (0x58004500, 128)}
_ALLOWED = {f"{name}.bin": spec for name, spec in {**REGIONS, **EXTRAS}.items()}
_FORMAT = "gnwmanager-full-backup"
_MANIFEST_LIMIT = 65536
_CHUNK = 1 << 20
FETCH_TIMEOUT = 300


class BackupError(DataError):
    """An archive or transfer failed; completed lists verified restored regions."""

    def __init__(self, message, *, completed=()):
        super().__init__(message)
        self.completed = list(completed)


def _capacity(size):
    if type(size) is not int or not (1 << 20) <= size <= (256 << 20) or size & (size - 1):
        raise BackupError("Invalid external Flash capacity")
    return size


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BackupError(f"Duplicate manifest field: {key}")
        result[key] = value
    return result


def _regular_open(path, limit):
    # O_NOFOLLOW and fstat validate the opened object, avoiding a symlink race.
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            os.close(fd)
            raise BackupError(f"Not a bounded regular file: {path.name}")
        if path.is_symlink():
            os.close(fd)
            raise BackupError(f"Symbolic link rejected: {path.name}")
        return os.fdopen(fd, "rb")
    except OSError as error:
        raise BackupError(f"Missing or non-regular/link file: {path.name}") from error


def _schema(man):
    if not isinstance(man, dict) or not isinstance(man.get("created"), str):
        raise BackupError("Invalid manifest")
    modern = any(key in man for key in ("format", "version", "coverage"))
    if modern and (man.get("format") != _FORMAT or type(man.get("version")) is not int or man["version"] != 1):
        raise BackupError("Unsupported backup format/version")
    files = man.get("files")
    if not isinstance(files, dict) or not files or not set(files) <= set(_ALLOWED):
        raise BackupError("Empty or unknown backup files")
    regions = man.get("regions")
    if not isinstance(regions, dict) or set(regions) != set(REGIONS):
        raise BackupError("Invalid regions")
    for name, (addr, _) in REGIONS.items():
        spec = regions[name]
        if not isinstance(spec, dict) or spec.get("addr") != hex(addr):
            raise BackupError(f"Invalid address for {name}")
    has_ext = "ext.bin" in files
    if has_ext:
        _capacity(man.get("ext_size"))
    elif "ext_size" in man:
        raise BackupError("External capacity without external payload")
    if modern:
        complete = set(files) == set(_ALLOWED)
        partial = set(files) == set(_ALLOWED) - {"ext.bin"}
        if not ((man.get("coverage") == "complete" and complete) or (man.get("coverage") == "partial" and partial)):
            raise BackupError("Invalid backup coverage")
    for name, metadata in files.items():
        size = man["ext_size"] if name == "ext.bin" else _ALLOWED[name][1]
        if not isinstance(metadata, dict) or type(metadata.get("size")) is not int or metadata["size"] != size:
            raise BackupError(f"Invalid size: {name}")
        for algorithm, length in (("sha1", 40), ("sha256", 64)):
            digest = metadata.get(algorithm)
            if not isinstance(digest, str) or re.fullmatch(f"[0-9a-f]{{{length}}}", digest) is None:
                raise BackupError(f"Invalid {algorithm}: {name}")
    return man


def _manifest(directory):
    try:
        with _regular_open(directory / "manifest.json", _MANIFEST_LIMIT) as stream:
            data = stream.read(_MANIFEST_LIMIT + 1)
            if len(data) > _MANIFEST_LIMIT:
                raise BackupError("Manifest exceeds size limit")
            return _schema(json.loads(data, object_pairs_hook=_pairs))
    except (ValueError, UnicodeError) as error:
        raise BackupError("Invalid manifest JSON") from error


def _hash_stream(stream, *, collect=False, limit=None):
    s1, s256 = hashlib.sha1(), hashlib.sha256()
    size = 0
    payload = bytearray() if collect else None
    while True:
        chunk = stream.read(_CHUNK if limit is None else min(_CHUNK, limit - size + 1))
        if not chunk:
            break
        size += len(chunk)
        if limit is not None and size > limit:
            raise BackupError("Backup file exceeds size limit")
        s1.update(chunk)
        s256.update(chunk)
        if payload is not None:
            payload.extend(chunk)
    return {"size": size, "sha1": s1.hexdigest(), "sha256": s256.hexdigest()}, bytes(payload) if collect else None


def _verify(directory, collect=False):
    directory = Path(directory)
    man = _manifest(directory)
    payloads = {}
    for name, expected in man["files"].items():
        with _regular_open(directory / name, expected["size"]) as stream:
            actual, payload = _hash_stream(stream, collect=collect and name[:-4] in REGIONS, limit=expected["size"])
        if actual != {key: expected[key] for key in ("size", "sha1", "sha256")}:
            raise BackupError(f"Backup hash/size mismatch: {name}")
        if payload is not None:
            payloads[name[:-4]] = payload
    return man, payloads


def verify_archive(directory):
    """Validate every declared file, including read-only extras, without a backend."""
    return _verify(directory)[0]


def _double_read(read, address, size, path):
    # Keep each pass on failure for diagnostics; only promote identical passes.
    first, second = path.with_suffix(".pass1.bin"), path.with_suffix(".pass2.bin")
    for destination in (first, second):
        with destination.open("xb") as stream:
            for offset in range(0, size, _CHUNK):
                count = min(_CHUNK, size - offset)
                data = read(address + offset, count)
                stream.write(data)
                if len(data) != count:
                    raise BackupError(f"Short read: {path.name} at {offset:#x}")
    with first.open("rb") as a, second.open("rb") as b:
        while True:
            chunk = a.read(_CHUNK)
            if chunk != b.read(_CHUNK):
                raise BackupError(f"Two reads differ: {path.name}")
            if not chunk:
                break
    first.rename(path)
    second.unlink()
    with path.open("rb") as stream:
        return _hash_stream(stream)[0]


def _rdp(backend):
    if (backend.read_uint32(0x5200201C) >> 8) & 255 != 0xAA:
        raise BackupError("RDP0 required; backup never unlocks a device")


def _record_failure(directory, error):
    """Retain diagnostics when possible without replacing the original error."""
    with suppress(Exception):
        (directory / "failure.json").write_text(json.dumps({"error": str(error)}), encoding="utf-8")


def capture_backup(gnw, out, *, skip_ext=False, resume=False):
    """Capture raw banks/extras first; default leaves the target halted."""
    out = Path(out)
    try:
        out.mkdir(parents=True)
    except FileExistsError as error:
        raise BackupError("Backup output already exists") from error
    try:
        gnw.backend.halt()
        _rdp(gnw.backend)
        files = {}
        for name, (address, size) in {**{k: v for k, v in REGIONS.items() if k != "ext"}, **EXTRAS}.items():
            files[f"{name}.bin"] = _double_read(gnw.backend.read_memory, address, size, out / f"{name}.bin")
        man = {
            "format": _FORMAT,
            "version": 1,
            "coverage": "partial" if skip_ext else "complete",
            "created": dt.datetime.now(dt.timezone.utc).isoformat(),
            "regions": {name: {"addr": hex(address)} for name, (address, _) in REGIONS.items()},
            "files": files,
        }
        if not skip_ext:
            gnw.start_gnwmanager()
            size = _capacity(gnw.external_flash_size)
            files["ext.bin"] = _double_read(gnw.read_memory, REGIONS["ext"][0], size, out / "ext.bin")
            man["ext_size"] = size
        _schema(man)
        # Halt/resume must succeed before publishing a completed manifest.
        gnw.backend.resume() if resume else gnw.backend.halt()
        (out / "manifest.pending.json").write_text(json.dumps(man, indent=2), encoding="utf-8")
        (out / "manifest.pending.json").rename(out / "manifest.json")
    except BaseException as error:
        with suppress(Exception):
            gnw.backend.halt()
        _record_failure(out, error)
        if not isinstance(error, Exception) or isinstance(error, BackupError):
            raise
        raise BackupError(f"Capture failed: {error}") from error
    else:
        return man


def restore_backup(directory, factory, *, only=None, confirm=lambda: False, frequency=None):
    """Verify and confirm before connection; flash only immutable verified bytes."""
    man, payloads = _verify(directory, collect=True)
    selected = list(payloads) if only is None else list(only)
    if not selected or len(set(selected)) != len(selected) or any(name not in payloads for name in selected):
        raise BackupError("Invalid or unavailable restore selection")
    if not confirm():
        raise BackupError("Restore aborted")
    completed = []
    try:
        with factory() as backend:
            if frequency is not None:
                backend.set_frequency(frequency)
            backend.halt()
            _rdp(backend)
            gnw = GnW(backend)
            try:
                gnw.start_gnwmanager()
                capacity = _capacity(gnw.external_flash_size)
                if "ext" in selected and capacity != man["ext_size"]:
                    raise BackupError("External Flash capacity mismatch")
                for name in selected:
                    payload = payloads[name]
                    gnw.flash({"ext": 0, "bank1": 1, "bank2": 2}[name], 0, payload)
                    digest = hashlib.sha256()
                    for offset in range(0, len(payload), _CHUNK):
                        count = min(_CHUNK, len(payload) - offset)
                        data = gnw.read_memory(REGIONS[name][0] + offset, count)
                        if len(data) != count:
                            raise BackupError(f"Short readback: {name}")
                        digest.update(data)
                    if digest.hexdigest() != man["files"][f"{name}.bin"]["sha256"]:
                        raise BackupError(f"Readback mismatch: {name}")
                    completed.append(name)
            finally:
                backend.halt()
    except Exception as error:
        raise BackupError(f"Restore failed; completed={completed}: {error}", completed=completed) from error
    return {"completed": completed}


def _scp_runner(argv, *, timeout, max_bytes):
    # Enforce the file limit in the transfer process, not merely after download.
    try:
        import resource
    except ImportError as error:
        raise BackupError("Bounded SCP fetch requires POSIX; use HTTP(S) on this platform") from error

    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (max_bytes, max_bytes))

    return subprocess.run(
        argv, check=True, timeout=timeout, preexec_fn=limits, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )


def _publish_archive(stage, destination):
    """Atomically publish a directory without replacing any existing entry."""
    if os.name == "nt":
        # Unlike POSIX rename(), Windows rename refuses an existing target.
        try:
            stage.rename(destination)
        except FileExistsError as error:
            raise BackupError("Fetch destination already exists") from error
        return
    library = ctypes.CDLL(None, use_errno=True)
    source, target = os.fsencode(stage), os.fsencode(destination)
    if sys.platform == "darwin" and hasattr(library, "renamex_np"):
        rename = library.renamex_np
        rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        result = rename(source, target, 0x00000004)  # RENAME_EXCL
    elif sys.platform.startswith("linux") and hasattr(library, "renameat2"):
        rename = library.renameat2
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        result = rename(-100, source, -100, target, 1)  # AT_FDCWD, RENAME_NOREPLACE
    else:
        raise BackupError("Atomic no-replace archive publication is unsupported on this platform")
    if result:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise BackupError("Fetch destination already exists")
        raise OSError(code, os.strerror(code))


def fetch_backup(source, dest, *, runner=None, timeout=None):
    """Fetch a manifest first, then bounded allowlisted files into a new archive."""
    timeout = FETCH_TIMEOUT if timeout is None else timeout
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
        raise BackupError("Invalid fetch timeout")
    deadline = time.monotonic() + timeout
    dest = Path(dest)
    if dest.exists() or dest.is_symlink():
        raise BackupError("Fetch destination already exists")
    http = source.startswith(("http://", "https://"))
    if http:
        parsed = urlsplit(source)
        if not parsed.hostname or parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise BackupError("Invalid HTTP backup source")
    elif re.fullmatch(
        r"(?:[A-Za-z0-9_][A-Za-z0-9_.-]*@)?[A-Za-z0-9_][A-Za-z0-9_.-]*:(?!-)[A-Za-z0-9_./-]+", source
    ) is None or ".." in source.split(":", 1)[-1].split("/"):
        raise BackupError("Invalid SCP backup source")
    dest.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{dest.name}.fetch-", dir=dest.parent))

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise BackupError("Fetch total deadline exceeded")
        return value

    def download(name, limit):
        path = stage / name
        if http:
            # A process deadline also bounds urllib's DNS and buffered header
            # parsing. A per-recv socket timeout alone cannot stop a dribbler.
            try:
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "gnwmanager.backup_transfer",
                        source.rstrip("/") + "/" + name,
                        str(path),
                        str(limit),
                    ],
                    timeout=remaining(),
                    capture_output=True,
                    check=False,
                )
            except subprocess.TimeoutExpired as error:
                raise BackupError("Fetch total deadline exceeded") from error
            if result.returncode:
                message = result.stderr.decode("utf-8", errors="replace").strip()[:1024]
                raise BackupError(f"HTTP transfer failed: {name}: {message}")
        else:
            (runner or _scp_runner)(
                ["scp", "--", source.rstrip("/") + "/" + name, str(path)],
                timeout=min(120, remaining()),
                max_bytes=limit,
            )
            with _regular_open(path, limit):
                pass
        remaining()

    try:
        download("manifest.json", _MANIFEST_LIMIT)
        man = _manifest(stage)
        for name, metadata in man["files"].items():
            download(name, metadata["size"])
        verify_archive(stage)
        remaining()
        _publish_archive(stage, dest)
    except BaseException as error:
        _record_failure(stage, error)
        if not isinstance(error, Exception) or isinstance(error, BackupError):
            raise
        raise BackupError(f"Fetch failed; staging retained at {stage}: {error}") from error
    else:
        return man
