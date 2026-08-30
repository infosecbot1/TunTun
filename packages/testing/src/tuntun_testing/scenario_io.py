from __future__ import annotations

import errno
import os
import stat
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from itertools import islice
from pathlib import Path, PurePosixPath

MAX_SCENARIO_BYTES = 65_536
MAX_SCENARIOS = 32


class ScenarioInputError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ScenarioInput:
    normalized_name: str
    raw: bytes
    device: int
    inode: int


_StableIdentity = tuple[int, int, int, int, int, int]


@dataclass(frozen=True, slots=True)
class _DirectorySnapshot:
    identity: _StableIdentity
    entries: tuple[tuple[str, _StableIdentity], ...]


def _fail() -> ScenarioInputError:
    return ScenarioInputError("invalid-scenario-input")


def _validate_part(part: str) -> str:
    if (
        not part
        or part in {".", ".."}
        or part != unicodedata.normalize("NFC", part)
        or len(part.encode("utf-8")) > 255
        or any(ord(character) < 32 or ord(character) == 127 for character in part)
    ):
        raise _fail()
    return part


def _relative_parts(path: Path, trusted_root: Path) -> tuple[str, ...]:
    if not trusted_root.is_absolute():
        raise _fail()
    if path.is_absolute():
        try:
            relative = path.relative_to(trusted_root)
        except ValueError as error:
            raise _fail() from error
    else:
        relative = path
    parts = tuple(_validate_part(part) for part in relative.parts)
    if not parts:
        raise _fail()
    return parts


def _open_root(trusted_root: Path) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for part in trusted_root.parts[1:]:
            validated = _validate_part(part)
            next_descriptor = os.open(validated, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_parent(trusted_root: Path, parts: tuple[str, ...]) -> tuple[int, str]:
    descriptor = _open_root(trusted_root)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        for part in parts[:-1]:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor, parts[-1]
    except BaseException:
        os.close(descriptor)
        raise


def _stable_identity(value: os.stat_result) -> _StableIdentity:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_exact(descriptor: int, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        try:
            chunk = os.read(descriptor, min(remaining, 65_536))
        except OSError as error:
            if error.errno == errno.EINTR:
                continue
            raise
        if not chunk:
            raise _fail()
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise _fail()
    return b"".join(chunks)


def _read_scenario_child(
    parent_descriptor: int,
    name: str,
    normalized_name: str,
    *,
    max_bytes: int,
    expected_identity: _StableIdentity | None = None,
) -> ScenarioInput:
    descriptor = -1
    try:
        if (
            max_bytes < 1
            or max_bytes > MAX_SCENARIO_BYTES
            or _validate_part(name) != name
            or not name.endswith(".yaml")
        ):
            raise _fail()
        before_path = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if expected_identity is not None and _stable_identity(before_path) != expected_identity:
            raise _fail()
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=parent_descriptor,
        )
        before_fd = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before_fd.st_mode)
            or before_fd.st_nlink != 1
            or before_fd.st_size < 1
            or before_fd.st_size > max_bytes
            or _stable_identity(before_path) != _stable_identity(before_fd)
        ):
            raise _fail()
        raw = _read_exact(descriptor, before_fd.st_size)
        after_fd = os.fstat(descriptor)
        after_path = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            _stable_identity(before_fd) != _stable_identity(after_fd)
            or _stable_identity(before_fd) != _stable_identity(after_path)
            or after_fd.st_nlink != 1
        ):
            raise _fail()
        return ScenarioInput(
            normalized_name=normalized_name,
            raw=raw,
            device=after_fd.st_dev,
            inode=after_fd.st_ino,
        )
    except (OSError, UnicodeError) as error:
        raise _fail() from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def read_scenario_input(
    path: Path,
    *,
    trusted_root: Path,
    max_bytes: int = MAX_SCENARIO_BYTES,
) -> ScenarioInput:
    parent_descriptor = -1
    try:
        parts = _relative_parts(path, trusted_root)
        parent_descriptor, name = _open_parent(trusted_root, parts)
        return _read_scenario_child(
            parent_descriptor,
            name,
            PurePosixPath(*parts).as_posix(),
            max_bytes=max_bytes,
        )
    except (OSError, UnicodeError) as error:
        raise _fail() from error
    finally:
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def _open_directory_descriptor(directory: Path, trusted_root: Path) -> int:
    descriptor = -1
    try:
        parts = _relative_parts(directory, trusted_root)
        descriptor = _open_root(trusted_root)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        for part in parts:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except (OSError, UnicodeError) as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise _fail() from error


def _directory_snapshot(descriptor: int) -> _DirectorySnapshot:
    scan_descriptor = -1
    try:
        before = _stable_identity(os.fstat(descriptor))
        scan_descriptor = os.open(
            ".",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=descriptor,
        )
        collected: list[str] = []
        with os.scandir(scan_descriptor) as entries:
            for entry in entries:
                if len(collected) == MAX_SCENARIOS:
                    raise _fail()
                collected.append(entry.name)
        names = tuple(sorted(collected, key=lambda item: item.encode("utf-8")))
        if not names or any(
            _validate_part(name) != name or not name.endswith(".yaml") for name in names
        ):
            raise _fail()
        frozen_entries = tuple(
            (
                name,
                _stable_identity(os.stat(name, dir_fd=descriptor, follow_symlinks=False)),
            )
            for name in names
        )
        after = _stable_identity(os.fstat(descriptor))
        if after != before:
            raise _fail()
        return _DirectorySnapshot(identity=after, entries=frozen_entries)
    except (OSError, UnicodeError) as error:
        raise _fail() from error
    finally:
        if scan_descriptor >= 0:
            os.close(scan_descriptor)


def _directory_inventory(directory: Path, trusted_root: Path) -> tuple[str, ...]:
    descriptor = -1
    try:
        descriptor = _open_directory_descriptor(directory, trusted_root)
        return tuple(name for name, _identity in _directory_snapshot(descriptor).entries)
    except (OSError, UnicodeError) as error:
        raise _fail() from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _load_default_inputs(
    *,
    trusted_root: Path,
    default_directory: Path,
) -> tuple[ScenarioInput, ...]:
    descriptor = -1
    rebound_descriptor = -1
    try:
        parts = _relative_parts(default_directory, trusted_root)
        descriptor = _open_directory_descriptor(default_directory, trusted_root)
        before = _directory_snapshot(descriptor)
        loaded = tuple(
            _read_scenario_child(
                descriptor,
                name,
                PurePosixPath(*parts, name).as_posix(),
                max_bytes=MAX_SCENARIO_BYTES,
                expected_identity=identity,
            )
            for name, identity in before.entries
        )
        after = _directory_snapshot(descriptor)
        rebound_descriptor = _open_directory_descriptor(default_directory, trusted_root)
        rebound_identity = _stable_identity(os.fstat(rebound_descriptor))
        if after != before or rebound_identity != before.identity:
            raise _fail()
        return loaded
    except (OSError, UnicodeError) as error:
        raise _fail() from error
    finally:
        if rebound_descriptor >= 0:
            os.close(rebound_descriptor)
        if descriptor >= 0:
            os.close(descriptor)


def load_scenario_inputs(
    paths: Iterable[Path],
    *,
    trusted_root: Path,
    default_directory: Path,
) -> tuple[ScenarioInput, ...]:
    requested = tuple(islice(paths, MAX_SCENARIOS + 1))
    if len(requested) > MAX_SCENARIOS:
        raise _fail()
    if requested:
        loaded = tuple(read_scenario_input(path, trusted_root=trusted_root) for path in requested)
    else:
        loaded = _load_default_inputs(
            trusted_root=trusted_root,
            default_directory=default_directory,
        )
    names = [item.normalized_name for item in loaded]
    folded_names = [unicodedata.normalize("NFC", name).casefold() for name in names]
    logical_names = [name.rsplit("/", 1)[-1].removesuffix(".yaml") for name in names]
    folded_logical_names = [name.casefold() for name in logical_names]
    identities = [(item.device, item.inode) for item in loaded]
    if (
        len(names) != len(set(names))
        or len(folded_names) != len(set(folded_names))
        or len(logical_names) != len(set(logical_names))
        or len(folded_logical_names) != len(set(folded_logical_names))
    ):
        raise _fail()
    if len(identities) != len(set(identities)):
        raise _fail()
    return tuple(sorted(loaded, key=lambda item: item.normalized_name.encode("utf-8")))
