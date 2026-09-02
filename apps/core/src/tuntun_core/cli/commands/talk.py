from __future__ import annotations

import asyncio
import os
import stat
from pathlib import Path
from typing import Annotated

import typer
from tuntun_core.workflows.conversation import LinearConversationEngine, TurnRequest, WorkflowPorts

_MAX_SYNTHETIC_WAV_BYTES = 8_388_608
_READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)


def run_synthetic_turn(ports: WorkflowPorts, turn: TurnRequest) -> bool:
    return asyncio.run(LinearConversationEngine(ports).run(turn)).spoken


def read_synthetic_wav(path: Path) -> bytes:
    absolute = Path(path).absolute()
    parent_fd = os.open(absolute.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    fd: int | None = None
    primary: BaseException | None = None
    try:
        before_name = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
        fd = os.open(absolute.name, _READ_FLAGS, dir_fd=parent_fd)
        before = os.fstat(fd)
        _require_safe_wav(before, before_name)
        if not 1 <= before.st_size <= _MAX_SYNTHETIC_WAV_BYTES:
            raise ValueError("synthetic WAV outside turn bounds")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65_536, _MAX_SYNTHETIC_WAV_BYTES + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_SYNTHETIC_WAV_BYTES:
                raise ValueError("synthetic WAV outside turn bounds")
            chunks.append(chunk)
        after = os.fstat(fd)
        after_name = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
        _require_safe_wav(after, after_name)
        if total != before.st_size or _identity(before) != _identity(after):
            raise PermissionError("unsafe synthetic WAV")
        if (after.st_dev, after.st_ino) != (after_name.st_dev, after_name.st_ino):
            raise PermissionError("unsafe synthetic WAV")
        return b"".join(chunks)
    except OSError as error:
        primary = PermissionError("unsafe synthetic WAV")
        raise primary from error
    except BaseException as error:
        primary = error
        raise
    finally:
        if fd is not None:
            _close_fd(fd, primary)
        _close_fd(parent_fd, primary)


def _require_safe_wav(opened: os.stat_result, named: os.stat_result) -> None:
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        or opened.st_nlink != 1
    ):
        raise PermissionError("unsafe synthetic WAV")


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _close_fd(fd: int, primary: BaseException | None) -> None:
    try:
        os.close(fd)
    except OSError as error:
        if primary is None:
            raise PermissionError("unsafe synthetic WAV") from error
        primary.add_note(f"additional synthetic WAV cleanup failure: {type(error).__name__}")


def talk(
    wav: Annotated[
        Path,
        typer.Argument(
            help="Path to the completed synthetic WAV turn audio.",
            exists=False,
            file_okay=True,
            dir_okay=False,
            readable=False,
        ),
    ],
) -> None:
    """Load a local synthetic WAV for the Phase 1 talk flow."""

    data = read_synthetic_wav(wav)
    typer.echo(f"loaded synthetic WAV: {len(data)} bytes")
