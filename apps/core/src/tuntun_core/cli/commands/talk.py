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
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)


def run_synthetic_turn(ports: WorkflowPorts, turn: TurnRequest) -> bool:
    return asyncio.run(LinearConversationEngine(ports).run(turn)).spoken


def read_synthetic_wav(path: Path) -> bytes:
    requested = Path(path)
    parent_fd: int | None = None
    fd: int | None = None
    primary: BaseException | None = None
    try:
        parent_fd, file_name = _open_parent_directory(requested)
        before_name = os.stat(file_name, dir_fd=parent_fd, follow_symlinks=False)
        fd = os.open(file_name, _READ_FLAGS, dir_fd=parent_fd)
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
        after_name = os.stat(file_name, dir_fd=parent_fd, follow_symlinks=False)
        _require_safe_wav(after, after_name)
        if total != before.st_size or _identity(before) != _identity(after):
            raise PermissionError("unsafe synthetic WAV")
        if (after.st_dev, after.st_ino) != (after_name.st_dev, after_name.st_ino):
            raise PermissionError("unsafe synthetic WAV")
        return b"".join(chunks)
    except OSError:
        primary = PermissionError("unsafe synthetic WAV")
        raise primary from None
    except BaseException as error:
        primary = error
        raise
    finally:
        if fd is not None:
            _close_fd(fd, primary)
        if parent_fd is not None:
            _close_fd(parent_fd, primary)


def _open_parent_directory(path: Path) -> tuple[int, str]:
    if path.name in {"", ".", ".."}:
        raise PermissionError("unsafe synthetic WAV")
    root_fd: int | None = None
    current_fd: int | None = None
    primary: BaseException | None = None
    try:
        if path.is_absolute():
            current_fd = os.open(os.sep, _DIR_FLAGS)
            parent_parts = path.parts[1:-1]
        else:
            current_fd = os.open(".", _DIR_FLAGS)
            parent_parts = path.parts[:-1]
        for part in parent_parts:
            if part in {"", ".", ".."}:
                raise PermissionError("unsafe synthetic WAV")
            next_fd = os.open(part, _DIR_FLAGS, dir_fd=current_fd)
            next_stat = os.fstat(next_fd)
            if not stat.S_ISDIR(next_stat.st_mode):
                raise PermissionError("unsafe synthetic WAV")
            root_fd = current_fd
            current_fd = next_fd
            _close_fd(root_fd, None)
            root_fd = None
        return current_fd, path.name
    except OSError:
        primary = PermissionError("unsafe synthetic WAV")
        raise primary from None
    except BaseException as error:
        primary = error
        raise
    finally:
        if root_fd is not None:
            _close_fd(root_fd, primary)
        if primary is not None and current_fd is not None:
            _close_fd(current_fd, primary)


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
