from __future__ import annotations

import asyncio
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any

import typer
from tuntun_contracts.poc.framing import PttInputMode
from tuntun_core.adapters.poc.fake_voice import FakeVoiceScript, run_fake_simulated_turn
from tuntun_core.workflows.conversation import (
    SYNTHETIC_NO_PROVIDER_TRANSPORT,
    ContextWorkflowPorts,
    LinearConversationEngine,
    TurnRequest,
    WorkflowPorts,
)

_MAX_SYNTHETIC_WAV_BYTES = 8_388_608
_READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
_MODE_MATRIX: dict[tuple[str, str], dict[str, Any]] = {
    ("fake", "simulated"): {
        "available": True,
        "input_mode": PttInputMode.CORE_TERMINAL_TOGGLE.value,
        "status": "task5_fake_simulated_only",
    },
    ("fake", "ssh"): {
        "available": False,
        "input_mode": None,
        "status": "reachy_hardware_deferred_to_task7",
    },
    ("live-cloud", "simulated"): {
        "available": False,
        "input_mode": None,
        "status": "cloud_gate_deferred_to_task6",
    },
    ("live-cloud", "ssh"): {
        "available": False,
        "input_mode": None,
        "status": "cloud_and_hardware_deferred",
    },
}


class TalkModeError(PermissionError):
    def __init__(self) -> None:
        super().__init__("unsupported-talk-mode")


@dataclass(frozen=True, slots=True)
class TalkModeSelection:
    mode: str
    transport: str
    input_mode: PttInputMode
    status: str


def run_synthetic_turn(
    ports: WorkflowPorts | ContextWorkflowPorts,
    turn: TurnRequest,
    context_provider: object,
) -> bool:
    return asyncio.run(
        LinearConversationEngine(
            ports,
            context_provider=context_provider,
            provider_egress=SYNTHETIC_NO_PROVIDER_TRANSPORT,
        ).run(turn)
    ).spoken


def read_synthetic_wav(path: Path) -> bytes:
    requested = Path(path)
    parent_fd: int | None = None
    fd: int | None = None
    primary: BaseException | None = None
    buffer = bytearray()
    try:
        parent_fd, file_name = _open_parent_directory(requested)
        before_name = os.stat(file_name, dir_fd=parent_fd, follow_symlinks=False)
        fd = os.open(file_name, _READ_FLAGS, dir_fd=parent_fd)
        before = os.fstat(fd)
        _require_safe_wav(before, before_name)
        if not 1 <= before.st_size <= _MAX_SYNTHETIC_WAV_BYTES:
            raise ValueError("synthetic WAV outside turn bounds")
        total = 0
        while True:
            chunk = os.read(fd, min(65_536, _MAX_SYNTHETIC_WAV_BYTES + 1 - total))
            try:
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_SYNTHETIC_WAV_BYTES:
                    raise ValueError("synthetic WAV outside turn bounds")
                buffer.extend(chunk)
            finally:
                del chunk
        after = os.fstat(fd)
        after_name = os.stat(file_name, dir_fd=parent_fd, follow_symlinks=False)
        _require_safe_wav(after, after_name)
        if total != before.st_size or _identity(before) != _identity(after):
            raise PermissionError("unsafe synthetic WAV")
        if (after.st_dev, after.st_ino) != (after_name.st_dev, after_name.st_ino):
            raise PermissionError("unsafe synthetic WAV")
        return bytes(buffer)
    except OSError:
        primary = PermissionError("unsafe synthetic WAV")
        raise primary from None
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            buffer[:] = b"\x00" * len(buffer)
            buffer.clear()
        finally:
            _close_descriptors(fd, parent_fd, primary)


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


def _close_descriptors(
    fd: int | None,
    parent_fd: int | None,
    primary: BaseException | None,
) -> None:
    close_primary = primary
    deferred_close: BaseException | None = None
    if fd is not None:
        try:
            _close_fd(fd, close_primary)
        except BaseException as error:
            deferred_close = error
            close_primary = error
            del error
    if parent_fd is not None:
        try:
            _close_fd(parent_fd, close_primary)
        except BaseException as error:
            if deferred_close is None:
                deferred_close = error
            del error
    if primary is None and deferred_close is not None:
        raise deferred_close


def _close_fd(fd: int, primary: BaseException | None) -> None:
    close_error_type: str | None = None
    try:
        os.close(fd)
    except OSError as error:
        close_error_type = type(error).__name__
        del error
    if close_error_type is None:
        return
    if primary is None:
        raise PermissionError("unsafe synthetic WAV") from None
    primary.add_note(f"additional synthetic WAV cleanup failure: {close_error_type}")


def exact_mode_matrix() -> dict[tuple[str, str], dict[str, Any]]:
    return {key: dict(value) for key, value in _MODE_MATRIX.items()}


def validate_talk_mode(
    mode: str,
    transport: str,
    *,
    before_keychain: Callable[[], None] | None = None,
    before_budget: Callable[[], None] | None = None,
    before_audio: Callable[[], None] | None = None,
    before_network: Callable[[], None] | None = None,
    before_ssh: Callable[[], None] | None = None,
) -> TalkModeSelection:
    del before_keychain, before_budget, before_network, before_ssh
    cell = _MODE_MATRIX.get((mode, transport))
    if cell is None or cell["available"] is not True:
        raise TalkModeError
    if before_audio is not None:
        before_audio()
    input_mode = PttInputMode(cell["input_mode"])
    return TalkModeSelection(
        mode=mode,
        transport=transport,
        input_mode=input_mode,
        status=str(cell["status"]),
    )


def talk(
    wav: Annotated[
        Path | None,
        typer.Argument(
            help="Optional legacy path to a completed synthetic WAV turn audio.",
            exists=False,
            file_okay=True,
            dir_okay=False,
            readable=False,
        ),
    ] = None,
    mode: Annotated[str, typer.Option("--mode", help="PTT runtime mode.")] = "fake",
    transport: Annotated[
        str,
        typer.Option("--transport", help="PTT transport boundary."),
    ] = "simulated",
    turns: Annotated[
        int,
        typer.Option("--turns", min=1, max=50, help="Number of fake simulated turns."),
    ] = 1,
) -> None:
    """Run the Phase 1 synthetic WAV or Task 5 fake simulated talk flow."""

    if wav is not None:
        data = read_synthetic_wav(wav)
        typer.echo(f"loaded synthetic WAV: {len(data)} bytes")
        return
    try:
        validate_talk_mode(mode, transport)
    except TalkModeError:
        typer.echo("unsupported-talk-mode", err=True)
        raise typer.Exit(code=65) from None
    outcomes = [asyncio.run(run_fake_simulated_turn(FakeVoiceScript())) for _index in range(turns)]
    final = (
        "completed"
        if all(outcome.value == "completed" for outcome in outcomes)
        else "cleanup_incomplete"
    )
    typer.echo(f"turns={turns}")
    typer.echo(f"outcome={final}")
