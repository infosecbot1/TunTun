"""Core-side read-only access to Reachy's accepted operator projection.

This reader treats the owner-only operator-state file as the current-active trust boundary.
Edge is responsible for atomically clearing ``accepted_capability`` before recommission,
revoke, or any generation change; Core rejects cleared projections and never imports Edge
commissioning internals, opens sockets, shells out, resolves DNS, or writes companion state.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Self

from pydantic import ValidationError
from tuntun_contracts.base import ContractParseError, canonical_bytes, parse_bounded_json_value
from tuntun_contracts.reachy_operator import ReachyAcceptedCapabilityV1, ReachyOperatorStateV1

OPERATOR_STATE_PATH: Final = Path("/private/var/lib/tuntun/reachy/operator-state.json")
MAX_OPERATOR_STATE_BYTES: Final = 32_768
MAX_OPERATOR_JSON_DEPTH: Final = 4
MAX_OPERATOR_JSON_CONTAINERS: Final = 4
MAX_OPERATOR_JSON_STRUCTURE_TOKENS: Final = 128

_OPERATOR_ERROR_MESSAGE: Final = "unsafe Reachy operator state"
_OPERATOR_STATE_FILENAME: Final = "operator-state.json"
_SYSTEM_COMPONENT_COUNT: Final = 3
_READ_CHUNK_BYTES: Final = 4096


class ReachyOperatorStateUnavailable(PermissionError):
    """The local Reachy operator projection is absent, stale, or unsafe."""


@dataclass(frozen=True, slots=True)
class _PathPolicy:
    state_path: Path
    trusted_root: Path
    system_component_count: int
    trusted_root_owner_uid: int
    system_owner_uid: int
    app_owner_uid: int


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    device: int
    inode: int
    owner: int
    mode: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> Self:
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            owner=value.st_uid,
            mode=value.st_mode,
            links=value.st_nlink,
            size=value.st_size,
            modified_ns=value.st_mtime_ns,
            changed_ns=value.st_ctime_ns,
        )


class ReachyOperatorReader:
    __slots__ = ("_policy",)

    def __init__(self, policy: _PathPolicy) -> None:
        self._policy = policy

    @classmethod
    def from_fixed_owner_file(cls) -> Self:
        return cls(
            _PathPolicy(
                state_path=OPERATOR_STATE_PATH,
                trusted_root=Path("/"),
                system_component_count=_SYSTEM_COMPONENT_COUNT,
                trusted_root_owner_uid=0,
                system_owner_uid=0,
                app_owner_uid=os.geteuid(),
            )
        )

    def compatibility_field(self, field: str) -> str:
        accepted = self._accepted_capability()
        values: dict[str, str] = {
            "sdk": accepted.sdk_version,
            "daemon": accepted.daemon_version,
            "python-version": accepted.python_version,
            "python-abi": accepted.python_abi,
            "wheel-platform": accepted.selected_wheel_tag,
            "selected-wheel-tag": accepted.selected_wheel_tag,
            "python-executable": accepted.python_executable,
        }
        try:
            return values[field]
        except KeyError:
            raise ReachyOperatorStateUnavailable(_OPERATOR_ERROR_MESSAGE) from None

    def commissioned_numeric_ssh_target(self) -> str:
        state = self._read_current_operator_state()
        accepted = _require_accepted_capability(state)
        return f"{accepted.ssh_username}@{state.reachy_ipv4}"

    def _accepted_capability(self) -> ReachyAcceptedCapabilityV1:
        return _require_accepted_capability(self._read_current_operator_state())

    def _read_current_operator_state(self) -> ReachyOperatorStateV1:
        directory_fd: int | None = None
        try:
            directory_fd, file_name = _open_operator_directory(self._policy)
            raw = _read_owner_state_bytes(directory_fd, file_name)
            state = _parse_operator_state(raw)
            _require_accepted_capability(state)
            return state
        except ReachyOperatorStateUnavailable:
            raise
        except (
            ContractParseError,
            OSError,
            PermissionError,
            RecursionError,
            TypeError,
            ValueError,
            ValidationError,
        ):
            raise ReachyOperatorStateUnavailable(_OPERATOR_ERROR_MESSAGE) from None
        finally:
            if directory_fd is not None:
                _close_fd(directory_fd)


def _absolute_lexical_path(path: Path, *, allow_root: bool = False) -> Path:
    try:
        raw = os.fspath(path)
        if (
            type(raw) is not str
            or not raw
            or "\x00" in raw
            or raw.startswith(os.sep * 2)
            or any(component in {".", ".."} for component in raw.split(os.sep))
        ):
            raise ReachyOperatorStateUnavailable(_OPERATOR_ERROR_MESSAGE)
        absolute = Path(os.path.abspath(raw))
        if absolute == Path("/") and not allow_root:
            raise ReachyOperatorStateUnavailable(_OPERATOR_ERROR_MESSAGE)
        return absolute
    except OSError:
        raise ReachyOperatorStateUnavailable(_OPERATOR_ERROR_MESSAGE) from None


def _relative_state_parts(policy: _PathPolicy) -> tuple[tuple[str, ...], str]:
    state_path = _absolute_lexical_path(policy.state_path)
    trusted_root = _absolute_lexical_path(policy.trusted_root, allow_root=True)
    try:
        relative_parts = state_path.relative_to(trusted_root).parts
    except ValueError:
        raise ReachyOperatorStateUnavailable(_OPERATOR_ERROR_MESSAGE) from None
    if (
        len(relative_parts) < policy.system_component_count + 2
        or relative_parts[-1] != _OPERATOR_STATE_FILENAME
        or any(part in {"", ".", ".."} for part in relative_parts)
    ):
        raise ReachyOperatorStateUnavailable(_OPERATOR_ERROR_MESSAGE)
    return relative_parts[:-1], relative_parts[-1]


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | _required_open_flag("O_CLOEXEC")
        | _required_open_flag("O_DIRECTORY")
        | _required_open_flag("O_NOFOLLOW")
    )


def _file_flags() -> int:
    return os.O_RDONLY | _required_open_flag("O_CLOEXEC") | _required_open_flag("O_NOFOLLOW")


def _required_open_flag(name: str) -> int:
    value = getattr(os, name, 0)
    if type(value) is not int or value == 0:
        raise ReachyOperatorStateUnavailable(_OPERATOR_ERROR_MESSAGE)
    return value


def _open_operator_directory(policy: _PathPolicy) -> tuple[int, str]:
    directory_parts, file_name = _relative_state_parts(policy)
    current_fd: int | None = None
    try:
        trusted_root = _absolute_lexical_path(policy.trusted_root, allow_root=True)
        current_fd = os.open(os.fspath(trusted_root), _directory_flags())
        trusted_opened = os.fstat(current_fd)
        trusted_named = os.stat(trusted_root, follow_symlinks=False)
        _require_trusted_root_directory(
            trusted_opened,
            trusted_named,
            owner_uid=policy.trusted_root_owner_uid,
        )

        for index, part in enumerate(directory_parts):
            named = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
            next_fd = _open_child_directory(current_fd, part)
            try:
                opened = os.fstat(next_fd)
                if index < policy.system_component_count:
                    _require_system_directory(opened, named, owner_uid=policy.system_owner_uid)
                else:
                    _require_app_directory(opened, named, owner_uid=policy.app_owner_uid)
            except BaseException:
                _close_fd(next_fd)
                raise
            previous_fd = current_fd
            current_fd = next_fd
            _close_fd(previous_fd)
        result = current_fd
        current_fd = None
        return result, file_name
    except ReachyOperatorStateUnavailable:
        raise
    except OSError:
        raise ReachyOperatorStateUnavailable(_OPERATOR_ERROR_MESSAGE) from None
    finally:
        if current_fd is not None:
            _close_fd(current_fd)


def _open_child_directory(parent_fd: int, part: str) -> int:
    if part in {"", ".", ".."}:
        raise ReachyOperatorStateUnavailable(_OPERATOR_ERROR_MESSAGE)
    return os.open(part, _directory_flags(), dir_fd=parent_fd)


def _require_directory_identity(opened: os.stat_result, named: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(named.st_mode)
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
    ):
        raise ReachyOperatorStateUnavailable(_OPERATOR_ERROR_MESSAGE)


def _require_trusted_root_directory(
    opened: os.stat_result,
    named: os.stat_result,
    *,
    owner_uid: int,
) -> None:
    _require_directory_identity(opened, named)
    permissions = stat.S_IMODE(opened.st_mode)
    if opened.st_uid != owner_uid or permissions & 0o022:
        raise ReachyOperatorStateUnavailable(_OPERATOR_ERROR_MESSAGE)


def _require_system_directory(
    opened: os.stat_result,
    named: os.stat_result,
    *,
    owner_uid: int,
) -> None:
    _require_directory_identity(opened, named)
    permissions = stat.S_IMODE(opened.st_mode)
    if opened.st_uid != owner_uid or permissions & 0o022:
        raise ReachyOperatorStateUnavailable(_OPERATOR_ERROR_MESSAGE)


def _require_app_directory(
    opened: os.stat_result,
    named: os.stat_result,
    *,
    owner_uid: int,
) -> None:
    _require_directory_identity(opened, named)
    if opened.st_uid != owner_uid or stat.S_IMODE(opened.st_mode) != 0o700:
        raise ReachyOperatorStateUnavailable(_OPERATOR_ERROR_MESSAGE)


def _read_owner_state_bytes(directory_fd: int, file_name: str) -> bytes:
    descriptor: int | None = None
    try:
        named = os.stat(file_name, dir_fd=directory_fd, follow_symlinks=False)
        directory_stat = os.fstat(directory_fd)
        _require_state_file(named, directory_device=directory_stat.st_dev)
        descriptor = os.open(file_name, _file_flags(), dir_fd=directory_fd)
        opened = os.fstat(descriptor)
        _require_state_file(opened, directory_device=directory_stat.st_dev)
        expected = _FileIdentity.from_stat(named)
        if _FileIdentity.from_stat(opened) != expected:
            raise ReachyOperatorStateUnavailable(_OPERATOR_ERROR_MESSAGE)

        remaining = opened.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, remaining))
            if not chunk:
                raise ReachyOperatorStateUnavailable(_OPERATOR_ERROR_MESSAGE)
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ReachyOperatorStateUnavailable(_OPERATOR_ERROR_MESSAGE)

        after = os.fstat(descriptor)
        named_after = os.stat(file_name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            _FileIdentity.from_stat(after) != expected
            or _FileIdentity.from_stat(named_after) != expected
        ):
            raise ReachyOperatorStateUnavailable(_OPERATOR_ERROR_MESSAGE)
        return b"".join(chunks)
    except ReachyOperatorStateUnavailable:
        raise
    except OSError:
        raise ReachyOperatorStateUnavailable(_OPERATOR_ERROR_MESSAGE) from None
    finally:
        if descriptor is not None:
            _close_fd(descriptor)


def _require_state_file(value: os.stat_result, *, directory_device: int) -> None:
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_uid != os.geteuid()
        or stat.S_IMODE(value.st_mode) != 0o600
        or value.st_nlink != 1
        or value.st_dev != directory_device
        or not 1 <= value.st_size <= MAX_OPERATOR_STATE_BYTES
    ):
        raise ReachyOperatorStateUnavailable(_OPERATOR_ERROR_MESSAGE)


def _parse_operator_state(raw: bytes) -> ReachyOperatorStateV1:
    parse_bounded_json_value(
        raw,
        max_bytes=MAX_OPERATOR_STATE_BYTES,
        max_depth=MAX_OPERATOR_JSON_DEPTH,
        max_containers=MAX_OPERATOR_JSON_CONTAINERS,
        max_structure_tokens=MAX_OPERATOR_JSON_STRUCTURE_TOKENS,
    )
    state = ReachyOperatorStateV1.model_validate_json(raw, strict=True)
    if canonical_bytes(state) != raw:
        raise ReachyOperatorStateUnavailable(_OPERATOR_ERROR_MESSAGE)
    return state


def _require_accepted_capability(state: ReachyOperatorStateV1) -> ReachyAcceptedCapabilityV1:
    accepted = state.accepted_capability
    if accepted is None or accepted.ssh_username != state.ssh_username:
        raise ReachyOperatorStateUnavailable(_OPERATOR_ERROR_MESSAGE)
    return accepted


def _close_fd(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        raise ReachyOperatorStateUnavailable(_OPERATOR_ERROR_MESSAGE) from None
