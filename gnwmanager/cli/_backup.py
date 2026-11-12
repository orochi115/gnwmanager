"""Full backup commands; archive validation is independent of the backend."""

import datetime as dt
from pathlib import Path
from typing import Annotated, Any, Callable, Optional

from cyclopts import Parameter

from gnwmanager.cli.main import app
from gnwmanager.full_backup import BackupError, capture_backup, fetch_backup, restore_backup, verify_archive
from gnwmanager.gnw import GnW

_BackendFactory = Annotated[Callable[[], dict[str, Any]], Parameter(parse=False)]


@app.command(group="Storage")
def backup(
    *,
    out: Optional[Path] = None,
    skip_ext: bool = False,
    resume: bool = False,
    backend_factory: _BackendFactory,
):
    """Double-read both internal banks, original extras, and the external chip.

    Parameters
    ----------
    out
        New output directory. Existing directories are never overwritten.
    skip_ext
        Capture a partial archive without uploading manager firmware.
    resume
        Resume the target after a successful capture; otherwise leave it halted.
    """
    out = out or Path("backups") / dt.datetime.now().strftime("full_%Y%m%d_%H%M%S")
    if out.exists() or out.is_symlink():
        raise BackupError("Backup output already exists")
    options = backend_factory()
    with options["factory"]() as backend:
        if options["frequency"] is not None:
            backend.set_frequency(options["frequency"])
        man = capture_backup(GnW(backend), out, skip_ext=skip_ext, resume=resume)
    print(f"Backup verified ({man['coverage']}): {out}")


@app.command(group="Storage")
def verify_backup(directory: Path):
    """Verify all archive files without connecting to a device."""
    man = verify_archive(directory)
    print(f"Backup verified: {directory} ({len(man['files'])} files)")


@app.command(name="restore-backup", group="Storage")
def restore_backup_command(
    directory: Path,
    *,
    only: Optional[str] = None,
    yes: bool = False,
    backend_factory: _BackendFactory,
):
    """Verify, confirm, then restore selected complete Flash regions.

    Parameters
    ----------
    only
        Comma-separated Flash regions: bank1, bank2, ext. Default restores all present.
    yes
        Explicitly authorize restore without the interactive YES prompt.
    """
    selected = None if only is None else [name.strip() for name in only.split(",")]
    options = backend_factory()
    result = restore_backup(
        directory,
        options["factory"],
        only=selected,
        confirm=lambda: yes or input("Restore Flash from verified archive? Type YES: ").strip() == "YES",
        frequency=options["frequency"],
    )
    print("Restore verified: " + ", ".join(result["completed"]))


@app.command(name="fetch-backup", group="Storage")
def fetch_backup_command(source: str, *, dest: Path):
    """Fetch an HTTP(S) or HOST:REMOTE_DIR archive into a new verified directory."""
    fetch_backup(source, dest)
    print(f"Fetched and verified: {dest}")
