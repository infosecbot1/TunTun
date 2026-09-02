from __future__ import annotations

import contextlib
import errno
import fcntl
import hashlib
import hmac
import os
import re
import stat
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Final, Literal, Self
from uuid import uuid4

from tuntun_contracts.base import canonical_bytes, parse_contract_json
from tuntun_contracts.reachy_operator import ReachyOperatorStateV1

from .commissioning import (
    CommissioningAssuranceV1,
    CommissioningStateV1,
    ReachyCoreEndpointV1,
    _commissioning_assurance_kind,
)

MAX_COMMISSIONING_STATE_BYTES: Final = 65_536
MAX_COMMISSIONING_ASSURANCE_BYTES: Final = 4_096
MAX_OPERATOR_STATE_BYTES: Final = 65_536
COMMISSIONING_STATE_NAME: Final = "commissioning-state.json"
COMMISSIONING_ASSURANCE_NAME: Final = "commissioning-assurance.json"
COMMISSIONING_LOCK_NAME: Final = ".commissioning-state.lock"
OPERATOR_STATE_NAME: Final = "operator-state.json"
OPERATOR_LOCK_NAME: Final = ".operator-state.lock"
COMMISSIONING_PUBLISH_FAULT_STAGES: Final = (
    "before_temp_open",
    "after_temp_open",
    "after_temp_write",
    "after_file_fsync",
    "before_parent_fsync",
    "after_parent_fsync_before_replace",
    "after_replace_before_parent_fsync",
    "after_parent_fsync",
    "after_final_verify",
)

_CLOEXEC: Final = getattr(os, "O_CLOEXEC", 0)
_NOFOLLOW: Final = getattr(os, "O_NOFOLLOW", 0)
_NONBLOCK: Final = getattr(os, "O_NONBLOCK", 0)
_DIRECTORY: Final = getattr(os, "O_DIRECTORY", 0)
_READ_FLAGS: Final = os.O_RDONLY | _CLOEXEC | _NOFOLLOW | _NONBLOCK
_DIRECTORY_FLAGS: Final = os.O_RDONLY | _DIRECTORY | _CLOEXEC | _NOFOLLOW
_LOCK_FLAGS: Final = os.O_RDWR | os.O_CREAT | _CLOEXEC | _NOFOLLOW | _NONBLOCK
_WRITE_FLAGS: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _CLOEXEC | _NOFOLLOW
_READ_CHUNK_BYTES: Final = 64
_LOCK_TIMEOUT_SECONDS: Final = 5.0
_ARTIFACT_NAME_PATTERN: Final = re.compile(r"[A-Za-z0-9_.-]+")

OS_MODULE: Final = os


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    nlink: int
    size: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> _FileIdentity:
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            mode=stat.S_IMODE(value.st_mode),
            uid=value.st_uid,
            nlink=value.st_nlink,
            size=value.st_size,
        )

    def same_file(self, value: os.stat_result) -> bool:
        return (self.device, self.inode) == (value.st_dev, value.st_ino)

    def same_file_and_size(self, value: os.stat_result) -> bool:
        return self == type(self).from_stat(value)


@dataclass(frozen=True, slots=True)
class _DirectoryIdentity:
    device: int
    inode: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> _DirectoryIdentity:
        return cls(value.st_dev, value.st_ino)


class _OwnedDirectory:
    def __init__(self, path: Path, *, create: bool) -> None:
        self.path = _absolute_lexical_path(path)
        self._fd = _open_private_directory(self.path, create=create)
        identity = os.fstat(self._fd)
        _require_private_directory(identity)
        self.identity = _DirectoryIdentity.from_stat(identity)

    @property
    def fd(self) -> int:
        if self._fd < 0:
            raise OSError(errno.EBADF, os.strerror(errno.EBADF))
        return self._fd

    def close(self) -> None:
        descriptor = self._fd
        self._fd = -1
        if descriptor >= 0:
            os.close(descriptor)

    def fsync(self) -> None:
        os.fsync(self.fd)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        _error_type: type[BaseException] | None,
        _error: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close()


class CommissioningRepository:
    def __init__(self, root: Path) -> None:
        self._directory = _OwnedDirectory(root, create=True)
        self.root = self._directory.path
        self.path = self.root / COMMISSIONING_STATE_NAME
        self._fault_stage: str | None = None

    @property
    def directory_fd(self) -> int:
        return self._directory.fd

    @property
    def mode(self) -> int:
        identity = os.stat(
            COMMISSIONING_STATE_NAME,
            dir_fd=self.directory_fd,
            follow_symlinks=False,
        )
        return stat.S_IMODE(identity.st_mode)

    def close(self) -> None:
        self._directory.close()

    def reopen(self) -> CommissioningRepository:
        return CommissioningRepository(self.root)

    def inject_crash_at(self, stage: str) -> None:
        if stage not in COMMISSIONING_PUBLISH_FAULT_STAGES:
            raise ValueError("unknown commissioning publish fault stage")
        self._fault_stage = stage

    def has_current(self) -> bool:
        try:
            identity = _stat_owner_file(
                self._directory,
                COMMISSIONING_STATE_NAME,
                max_bytes=MAX_COMMISSIONING_STATE_BYTES,
            )
        except FileNotFoundError:
            return False
        _require_owner_regular(
            identity,
            expected_mode=0o600,
            require_single_link=True,
            directory_device=self._directory.identity.device,
        )
        return True

    def require_current(self) -> CommissioningStateV1:
        return parse_contract_json(
            CommissioningStateV1,
            _read_owner_file(
                self._directory,
                COMMISSIONING_STATE_NAME,
                max_bytes=MAX_COMMISSIONING_STATE_BYTES,
            ),
            max_bytes=MAX_COMMISSIONING_STATE_BYTES,
            require_canonical=True,
        )

    def replace_atomic(
        self,
        state: CommissioningStateV1,
        *,
        expected_generation: int | None = None,
        expected_current: CommissioningStateV1 | None = None,
        assurance: object | None = None,
    ) -> None:
        payload = canonical_bytes(state)
        if not 1 <= len(payload) <= MAX_COMMISSIONING_STATE_BYTES:
            raise ValueError("commissioning state size invalid")
        assurance_kind = None if assurance is None else _commissioning_assurance_kind(assurance)
        with _exclusive_lock(self._directory, COMMISSIONING_LOCK_NAME):
            _require_expected_generation(
                self,
                state,
                _infer_expected_generation(state)
                if expected_generation is None
                else expected_generation,
                expected_current,
            )
            self._atomic_write(COMMISSIONING_STATE_NAME, payload, MAX_COMMISSIONING_STATE_BYTES)
            if assurance_kind is not None:
                assurance = _commissioning_assurance(state, source=assurance_kind)
                self._atomic_write(
                    COMMISSIONING_ASSURANCE_NAME,
                    canonical_bytes(assurance),
                    MAX_COMMISSIONING_ASSURANCE_BYTES,
                )

    def is_key_revoked(self, identifier: str) -> bool:
        return identifier in self.require_current().revoked_key_ids

    def is_certificate_revoked(self, digest: str) -> bool:
        return digest in self.require_current().revoked_certificate_sha256

    def require_usable(self, endpoint: ReachyCoreEndpointV1) -> ReachyCoreEndpointV1:
        with _exclusive_lock(self._directory, COMMISSIONING_LOCK_NAME):
            state = self.require_current()
            if state.status != "active":
                raise PermissionError("commissioning_material_revoked")
            if endpoint != state.endpoint:
                raise PermissionError("commissioning_material_revoked")
            if any(
                identifier in state.revoked_key_ids for identifier in _endpoint_key_ids(endpoint)
            ):
                raise PermissionError("commissioning_material_revoked")
            if any(
                digest in state.revoked_certificate_sha256
                for digest in _endpoint_certificate_digests(endpoint)
            ):
                raise PermissionError("commissioning_material_revoked")
            assurance = self._require_assurance(endpoint)
            if assurance.source != "hardware":
                raise PermissionError("commissioning_assurance_not_runtime_usable")
            return endpoint

    def _require_assurance(self, endpoint: ReachyCoreEndpointV1) -> CommissioningAssuranceV1:
        try:
            raw = _read_owner_file(
                self._directory,
                COMMISSIONING_ASSURANCE_NAME,
                max_bytes=MAX_COMMISSIONING_ASSURANCE_BYTES,
            )
        except FileNotFoundError as error:
            raise PermissionError("commissioning_assurance_not_runtime_usable") from error
        assurance = parse_contract_json(
            CommissioningAssuranceV1,
            raw,
            max_bytes=MAX_COMMISSIONING_ASSURANCE_BYTES,
            require_canonical=True,
        )
        if assurance.generation != endpoint.generation or not hmac.compare_digest(
            assurance.endpoint_sha256,
            hashlib.sha256(canonical_bytes(endpoint)).hexdigest(),
        ):
            raise PermissionError("commissioning_assurance_not_runtime_usable")
        return assurance

    def _atomic_write(self, target_name: str, payload: bytes, max_bytes: int) -> None:
        temp_name = f".commissioning-state.{os.getpid()}.{uuid4().hex}.tmp"
        descriptor = -1
        replaced = False
        temp_identity: _FileIdentity | None = None
        try:
            self._fault("before_temp_open")
            descriptor = os.open(temp_name, _WRITE_FLAGS, 0o600, dir_fd=self.directory_fd)
            self._fault("after_temp_open")
            os.fchmod(descriptor, 0o600)
            _write_all(descriptor, payload)
            self._fault("after_temp_write")
            written = os.fstat(descriptor)
            _require_owner_regular(
                written,
                expected_mode=0o600,
                require_single_link=True,
                expected_size=len(payload),
                directory_device=self._directory.identity.device,
            )
            os.fsync(descriptor)
            temp_identity = _FileIdentity.from_stat(written)
            self._fault("after_file_fsync")
            os.close(descriptor)
            descriptor = -1
            named_temp = os.stat(temp_name, dir_fd=self.directory_fd, follow_symlinks=False)
            if not temp_identity.same_file_and_size(named_temp):
                raise PermissionError("commissioning temporary file changed before publish")
            self._fault("before_parent_fsync")
            self._directory.fsync()
            self._fault("after_parent_fsync_before_replace")
            os.replace(
                temp_name,
                target_name,
                src_dir_fd=self.directory_fd,
                dst_dir_fd=self.directory_fd,
            )
            replaced = True
            self._fault("after_replace_before_parent_fsync")
            self._directory.fsync()
            self._fault("after_parent_fsync")
            published = os.stat(target_name, dir_fd=self.directory_fd, follow_symlinks=False)
            if not temp_identity.same_file_and_size(published):
                raise PermissionError("commissioning published identity mismatch")
            if _read_owner_file(self._directory, target_name, max_bytes=max_bytes) != payload:
                raise PermissionError("commissioning final byte verification failed")
            self._fault("after_final_verify")
        finally:
            if descriptor >= 0 and temp_identity is None:
                with contextlib.suppress(OSError):
                    temp_identity = _FileIdentity.from_stat(os.fstat(descriptor))
            if descriptor >= 0:
                os.close(descriptor)
            if not replaced and temp_identity is not None:
                _unlink_if_identity_matches(self._directory, temp_name, temp_identity)

    def _fault(self, stage: str) -> None:
        if self._fault_stage == stage:
            self._fault_stage = None
            raise OSError(f"scripted commissioning publish fault at {stage}")


class OwnerOnlyArtifactStore:
    def __init__(self, root: Path, *, max_bytes: int = 16_384) -> None:
        if not 1 <= max_bytes <= 1_048_576:
            raise ValueError("artifact size bound invalid")
        self._directory = _OwnedDirectory(root, create=True)
        self.root = self._directory.path
        self.max_bytes = max_bytes

    @property
    def directory_fd(self) -> int:
        return self._directory.fd

    def close(self) -> None:
        self._directory.close()

    def write(self, identifier: str, value: bytes) -> None:
        name = _artifact_name(identifier)
        if type(value) is not bytes or not 1 <= len(value) <= self.max_bytes:
            raise ValueError("commissioning artifact size invalid")
        _atomic_write_artifact(self._directory, name, value, self.max_bytes)

    def read(self, identifier: str) -> bytes:
        return _read_owner_file(
            self._directory,
            _artifact_name(identifier),
            max_bytes=self.max_bytes,
        )

    def delete(self, identifier: str) -> None:
        name = _artifact_name(identifier)
        try:
            identity = _stat_owner_file(self._directory, name, max_bytes=self.max_bytes)
        except FileNotFoundError:
            return
        _require_owner_regular(
            identity,
            expected_mode=0o600,
            require_single_link=True,
            directory_device=self._directory.identity.device,
        )
        os.unlink(name, dir_fd=self.directory_fd)
        self._directory.fsync()


class ReachyOperatorStateRepository:
    def __init__(self, root: Path) -> None:
        self._directory = _OwnedDirectory(root, create=True)
        self.root = self._directory.path
        self.path = self.root / OPERATOR_STATE_NAME

    @property
    def directory_fd(self) -> int:
        return self._directory.fd

    @property
    def mode(self) -> int:
        identity = os.stat(OPERATOR_STATE_NAME, dir_fd=self.directory_fd, follow_symlinks=False)
        return stat.S_IMODE(identity.st_mode)

    def close(self) -> None:
        self._directory.close()

    def reopen(self) -> ReachyOperatorStateRepository:
        return ReachyOperatorStateRepository(self.root)

    def require_current(self) -> ReachyOperatorStateV1:
        return parse_contract_json(
            ReachyOperatorStateV1,
            _read_owner_file(
                self._directory,
                OPERATOR_STATE_NAME,
                max_bytes=MAX_OPERATOR_STATE_BYTES,
            ),
            max_bytes=MAX_OPERATOR_STATE_BYTES,
            require_canonical=True,
        )

    def replace_atomic(
        self,
        state: ReachyOperatorStateV1,
        *,
        expected_current: ReachyOperatorStateV1 | None = None,
    ) -> None:
        payload = canonical_bytes(state)
        if not 1 <= len(payload) <= MAX_OPERATOR_STATE_BYTES:
            raise ValueError("operator state size invalid")
        with _exclusive_lock(self._directory, OPERATOR_LOCK_NAME):
            try:
                current = self.require_current()
            except FileNotFoundError:
                current = None
            if expected_current is None:
                if current is not None:
                    raise PermissionError("operator_state_current_cas_required")
            elif current != expected_current:
                raise PermissionError("operator_state_current_cas_failed")
            _atomic_write_artifact(
                self._directory,
                OPERATOR_STATE_NAME,
                payload,
                MAX_OPERATOR_STATE_BYTES,
            )

    def clear_accepted_capability(
        self,
        *,
        commissioning_generation: int,
        commissioning_state_sha256: str,
    ) -> ReachyOperatorStateV1:
        with _exclusive_lock(self._directory, OPERATOR_LOCK_NAME):
            current = self.require_current()
            if current.commissioning_generation != commissioning_generation or (
                not hmac.compare_digest(
                    current.commissioning_state_sha256,
                    commissioning_state_sha256,
                )
            ):
                raise PermissionError("operator_state_commissioning_cas_failed")
            if current.accepted_capability is None:
                return current
            cleared = current.model_copy(update={"accepted_capability": None})
            _atomic_write_artifact(
                self._directory,
                OPERATOR_STATE_NAME,
                canonical_bytes(cleared),
                MAX_OPERATOR_STATE_BYTES,
            )
            return cleared


class ReachyOperatorAcceptancePublisher:
    def __init__(self, operator_state_repository: ReachyOperatorStateRepository) -> None:
        self._operator_state_repository = operator_state_repository

    def clear_before_recommission(self, state: CommissioningStateV1) -> None:
        self._clear(state)

    def clear_before_revoke(self, state: CommissioningStateV1) -> None:
        self._clear(state)

    def _clear(self, state: CommissioningStateV1) -> None:
        self._operator_state_repository.clear_accepted_capability(
            commissioning_generation=state.endpoint.generation,
            commissioning_state_sha256=hashlib.sha256(canonical_bytes(state)).hexdigest(),
        )


def _absolute_lexical_path(path: Path) -> Path:
    raw = os.fspath(path)
    if type(raw) is not str or "\x00" in raw or raw == "":
        raise PermissionError("unsafe commissioning filesystem path")
    if any(part in {".", ".."} for part in raw.split(os.sep)):
        raise PermissionError("unsafe commissioning filesystem path")
    absolute = Path(os.path.abspath(raw))
    if absolute == Path("/") or any(part in {".", ".."} for part in absolute.parts):
        raise PermissionError("unsafe commissioning filesystem path")
    return absolute


def _open_private_directory(path: Path, *, create: bool) -> int:
    parts = path.parts
    descriptor = os.open("/", _DIRECTORY_FLAGS & ~_NOFOLLOW)
    try:
        for index, component in enumerate(parts[1:]):
            if not _safe_component(component):
                raise PermissionError("unsafe commissioning filesystem path")
            final = index == len(parts[1:]) - 1
            if create and final:
                with contextlib.suppress(FileExistsError):
                    os.mkdir(component, 0o700, dir_fd=descriptor)
            named = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISDIR(named.st_mode):
                raise PermissionError("unsafe commissioning filesystem path")
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            try:
                opened = os.fstat(child)
                if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                    raise PermissionError("unsafe commissioning filesystem path")
                if final:
                    _require_private_directory(opened)
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _safe_component(value: str) -> bool:
    return (
        type(value) is str
        and value not in {"", ".", ".."}
        and "/" not in value
        and "\x00" not in value
    )


def _artifact_name(identifier: str) -> str:
    if (
        type(identifier) is not str
        or not 8 <= len(identifier) <= 128
        or _ARTIFACT_NAME_PATTERN.fullmatch(identifier) is None
    ):
        raise ValueError("invalid commissioning artifact identifier")
    return identifier


def _require_private_directory(identity: os.stat_result) -> None:
    if not stat.S_ISDIR(identity.st_mode):
        raise PermissionError("commissioning directory is not a directory")
    if identity.st_uid != os.geteuid() or stat.S_IMODE(identity.st_mode) != 0o700:
        raise PermissionError("commissioning directory is not owner-only")


def _stat_owner_file(
    directory: _OwnedDirectory,
    name: str,
    *,
    max_bytes: int,
) -> os.stat_result:
    if not _safe_component(name):
        raise PermissionError("unsafe commissioning filesystem path")
    identity = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
    _require_owner_regular(
        identity,
        expected_mode=0o600,
        require_single_link=True,
        max_bytes=max_bytes,
        directory_device=directory.identity.device,
    )
    return identity


def _read_owner_file(directory: _OwnedDirectory, name: str, *, max_bytes: int) -> bytes:
    before = _stat_owner_file(directory, name, max_bytes=max_bytes)
    expected = _FileIdentity.from_stat(before)
    descriptor = os.open(name, _READ_FLAGS, dir_fd=directory.fd)
    try:
        opened = os.fstat(descriptor)
        _require_owner_regular(
            opened,
            expected_mode=0o600,
            require_single_link=True,
            max_bytes=max_bytes,
            directory_device=directory.identity.device,
        )
        if not expected.same_file_and_size(opened):
            raise PermissionError("commissioning owner file changed during read")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining > 0:
            chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, remaining))
            if not chunk:
                raise ValueError("commissioning owner file changed during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError("commissioning owner file changed during read")
        after = os.fstat(descriptor)
        named_after = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
        for candidate in (after, named_after):
            _require_owner_regular(
                candidate,
                expected_mode=0o600,
                require_single_link=True,
                max_bytes=max_bytes,
                directory_device=directory.identity.device,
            )
        if not expected.same_file_and_size(after) or not expected.same_file_and_size(named_after):
            raise PermissionError("commissioning owner file changed during read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _require_owner_regular(
    identity: os.stat_result,
    *,
    expected_mode: int,
    require_single_link: bool,
    max_bytes: int | None = None,
    expected_size: int | None = None,
    directory_device: int | None = None,
) -> None:
    if not stat.S_ISREG(identity.st_mode):
        raise PermissionError("commissioning owner file is not regular")
    if identity.st_uid != os.geteuid() or stat.S_IMODE(identity.st_mode) != expected_mode:
        raise PermissionError("commissioning owner file is not owner-only")
    if require_single_link and identity.st_nlink != 1:
        raise PermissionError("commissioning owner file must have one link")
    if directory_device is not None and identity.st_dev != directory_device:
        raise PermissionError("commissioning owner file must stay on one device")
    if max_bytes is not None and not 1 <= identity.st_size <= max_bytes:
        raise ValueError("commissioning owner file size invalid")
    if expected_size is not None and identity.st_size != expected_size:
        raise ValueError("commissioning owner file size invalid")


@contextlib.contextmanager
def _exclusive_lock(directory: _OwnedDirectory, name: str) -> Iterator[None]:
    descriptor = os.open(name, _LOCK_FLAGS, 0o600, dir_fd=directory.fd)
    try:
        identity = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
        _require_owner_regular(
            identity,
            expected_mode=0o600,
            require_single_link=True,
            directory_device=directory.identity.device,
        )
        if (identity.st_dev, identity.st_ino) != (named.st_dev, named.st_ino):
            raise PermissionError("commissioning lock identity changed")
        expected = _FileIdentity.from_stat(identity)
        deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("commissioning repository lock deadline") from None
                time.sleep(0.01)
        locked = os.fstat(descriptor)
        named_locked = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
        for candidate in (locked, named_locked):
            _require_owner_regular(
                candidate,
                expected_mode=0o600,
                require_single_link=True,
                directory_device=directory.identity.device,
            )
        if expected != _FileIdentity.from_stat(locked) or expected != _FileIdentity.from_stat(
            named_locked
        ):
            raise PermissionError("commissioning lock identity changed")
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _require_expected_generation(
    repository: CommissioningRepository,
    state: CommissioningStateV1,
    expected_generation: int | None,
    expected_current: CommissioningStateV1 | None,
) -> None:
    try:
        current = repository.require_current()
    except FileNotFoundError:
        current = None
    if expected_current is not None:
        _require_exact_expected_current(current, expected_current)
        _require_valid_transition_from_current(state, expected_current)
        return
    if current is not None:
        raise PermissionError("commissioning_current_endpoint_cas_required")
    if expected_generation is not None:
        raise PermissionError("commissioning_generation_cas_failed")
    if state.status != "active" or state.endpoint.generation != 1:
        raise PermissionError("commissioning_generation_cas_failed")


def _require_exact_expected_current(
    current: CommissioningStateV1 | None,
    expected_current: CommissioningStateV1,
) -> None:
    if current is None or current != expected_current:
        raise PermissionError("commissioning_current_endpoint_cas_failed")


def _require_valid_transition_from_current(
    state: CommissioningStateV1,
    current: CommissioningStateV1,
) -> None:
    if state.status == "active":
        if state.endpoint.generation != current.endpoint.generation + 1:
            raise PermissionError("commissioning_generation_cas_failed")
        if state.revoked_key_ids != _endpoint_key_ids(
            current.endpoint
        ) or state.revoked_certificate_sha256 != _endpoint_certificate_digests(current.endpoint):
            raise PermissionError("commissioning_revocation_inventory_mismatch")
        return
    if state.endpoint != current.endpoint:
        raise PermissionError("commissioning_revocation_endpoint_mismatch")
    if state.revoked_key_ids != _endpoint_key_ids(
        current.endpoint
    ) or state.revoked_certificate_sha256 != _endpoint_certificate_digests(current.endpoint):
        raise PermissionError("commissioning_revocation_inventory_mismatch")


def _infer_expected_generation(state: CommissioningStateV1) -> int | None:
    if state.status == "active" and state.endpoint.generation == 1:
        return None
    if state.status == "revoked":
        return state.endpoint.generation
    return state.endpoint.generation - 1


def _commissioning_assurance(
    state: CommissioningStateV1,
    *,
    source: Literal["synthetic", "hardware"],
) -> CommissioningAssuranceV1:
    return CommissioningAssuranceV1(
        schema_version="tuntun.reachy-commissioning-assurance.v1",
        source=source,
        generation=state.endpoint.generation,
        endpoint_sha256=hashlib.sha256(canonical_bytes(state.endpoint)).hexdigest(),
    )


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    total = 0
    while total < len(payload):
        written = os.write(descriptor, view[total:])
        if written <= 0:
            raise OSError("short commissioning owner-file write")
        total += written


def _atomic_write_artifact(
    directory: _OwnedDirectory,
    target_name: str,
    payload: bytes,
    max_bytes: int,
) -> None:
    if not 1 <= len(payload) <= max_bytes:
        raise ValueError("commissioning artifact size invalid")
    temp_name = f".commissioning-artifact.{os.getpid()}.{uuid4().hex}.tmp"
    descriptor = -1
    replaced = False
    temp_identity: _FileIdentity | None = None
    try:
        descriptor = os.open(temp_name, _WRITE_FLAGS, 0o600, dir_fd=directory.fd)
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, payload)
        written = os.fstat(descriptor)
        _require_owner_regular(
            written,
            expected_mode=0o600,
            require_single_link=True,
            expected_size=len(payload),
            directory_device=directory.identity.device,
        )
        os.fsync(descriptor)
        temp_identity = _FileIdentity.from_stat(written)
        os.close(descriptor)
        descriptor = -1
        named_temp = os.stat(temp_name, dir_fd=directory.fd, follow_symlinks=False)
        if not temp_identity.same_file_and_size(named_temp):
            raise PermissionError("commissioning artifact changed before publish")
        directory.fsync()
        os.replace(temp_name, target_name, src_dir_fd=directory.fd, dst_dir_fd=directory.fd)
        replaced = True
        directory.fsync()
        published = os.stat(target_name, dir_fd=directory.fd, follow_symlinks=False)
        if not temp_identity.same_file_and_size(published):
            raise PermissionError("commissioning artifact published identity mismatch")
        if _read_owner_file(directory, target_name, max_bytes=max_bytes) != payload:
            raise PermissionError("commissioning artifact final byte verification failed")
    finally:
        if descriptor >= 0 and temp_identity is None:
            with contextlib.suppress(OSError):
                temp_identity = _FileIdentity.from_stat(os.fstat(descriptor))
        if descriptor >= 0:
            os.close(descriptor)
        if not replaced and temp_identity is not None:
            _unlink_if_identity_matches(directory, temp_name, temp_identity)


def _unlink_if_identity_matches(
    directory: _OwnedDirectory,
    name: str,
    identity: _FileIdentity,
) -> None:
    try:
        candidate = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if identity.same_file_and_size(candidate):
        os.unlink(name, dir_fd=directory.fd)
        directory.fsync()


def _endpoint_key_ids(endpoint: ReachyCoreEndpointV1) -> tuple[str, str, str, str]:
    return (
        endpoint.server_key_id,
        endpoint.client_tls_key_id,
        endpoint.device_signing_key_id,
        endpoint.hmac_key_id,
    )


def _endpoint_certificate_digests(endpoint: ReachyCoreEndpointV1) -> tuple[str, str]:
    return (endpoint.server_leaf_sha256, endpoint.client_certificate_sha256)
