from __future__ import annotations

import contextlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from uuid import uuid4

_KEY_ID_CHARS: Final = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
_NOFOLLOW: Final = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY: Final = getattr(os, "O_DIRECTORY", 0)
_CLOEXEC: Final = getattr(os, "O_CLOEXEC", 0)
_ROOT_FLAGS: Final = os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC
_KEY_CREATE_FLAGS: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC
_KEY_READ_FLAGS: Final = os.O_RDONLY | _NOFOLLOW | _CLOEXEC
_KEY_FILE_MODE: Final = 0o600
_KEY_ROOT_MODE: Final = 0o700
_MIN_KEY_BYTES: Final = 32
_MAX_KEY_BYTES: Final = 4096


@dataclass(frozen=True, slots=True)
class _KeyIdentity:
    device: int
    inode: int
    size: int
    uid: int
    mode: int
    nlink: int
    mtime_ns: int
    ctime_ns: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> _KeyIdentity:
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            size=value.st_size,
            uid=value.st_uid,
            mode=value.st_mode,
            nlink=value.st_nlink,
            mtime_ns=getattr(value, "st_mtime_ns", int(value.st_mtime * 1_000_000_000)),
            ctime_ns=getattr(value, "st_ctime_ns", int(value.st_ctime * 1_000_000_000)),
        )

    def same_inode(self, value: os.stat_result | _KeyIdentity) -> bool:
        if isinstance(value, _KeyIdentity):
            return self.device == value.device and self.inode == value.inode
        return self.device == value.st_dev and self.inode == value.st_ino

    def same_security_identity(self, value: os.stat_result | _KeyIdentity) -> bool:
        other = value if isinstance(value, _KeyIdentity) else _KeyIdentity.from_stat(value)
        return (
            self.device == other.device
            and self.inode == other.inode
            and self.size == other.size
            and self.uid == other.uid
            and self.mode == other.mode
            and self.nlink == other.nlink
            and self.mtime_ns == other.mtime_ns
            and self.ctime_ns == other.ctime_ns
        )


class EdgeKeyStore:
    """Owner-only directory-fd key custody for edge-local secrets."""

    def __init__(self, root: Path, *, expected_owner_uid: int | None = None) -> None:
        if not isinstance(root, Path):
            raise TypeError("edge key root must be a Path")
        _validate_root_path(root)
        self.root = root
        self._expected_owner_uid = (
            os.geteuid() if expected_owner_uid is None else expected_owner_uid
        )
        self._ensure_root_directory()

    def write(self, key_id: str, value: bytes) -> None:
        key_name = self._key_name(key_id)
        key_bytes = self._key_bytes(value)
        marker_name = _publication_marker_name(key_name)
        temporary_name = f".{key_name}.{uuid4().hex}.tmp"
        root_fd = self._open_root_fd()
        descriptor: int | None = None
        marker_descriptor: int | None = None
        marker_committed = False
        marker_created = False
        committed = False
        try:
            self._require_no_publication_marker(root_fd, marker_name)
            self._require_new_key_target_absent(root_fd, key_name)
            descriptor = os.open(
                temporary_name,
                _KEY_CREATE_FLAGS,
                _KEY_FILE_MODE,
                dir_fd=root_fd,
            )
            os.fchmod(descriptor, _KEY_FILE_MODE)
            _write_all(descriptor, key_bytes)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            marker_descriptor = os.open(
                marker_name,
                _KEY_CREATE_FLAGS,
                _KEY_FILE_MODE,
                dir_fd=root_fd,
            )
            marker_created = True
            os.fchmod(marker_descriptor, _KEY_FILE_MODE)
            _write_all(marker_descriptor, b"tuntun-edge-key-publication-v1\n")
            os.fsync(marker_descriptor)
            os.close(marker_descriptor)
            marker_descriptor = None
            os.fsync(root_fd)
            marker_committed = True
            self._require_new_key_target_absent(root_fd, key_name)
            os.link(
                temporary_name,
                key_name,
                src_dir_fd=root_fd,
                dst_dir_fd=root_fd,
                follow_symlinks=False,
            )
            os.fsync(root_fd)
            os.unlink(temporary_name, dir_fd=root_fd)
            os.fsync(root_fd)
            self._remove_publication_marker_or_quarantine(root_fd, marker_name, key_name)
            committed = True
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if marker_descriptor is not None:
                os.close(marker_descriptor)
            if not committed:
                if marker_committed:
                    with contextlib.suppress(FileNotFoundError, PermissionError):
                        os.unlink(temporary_name, dir_fd=root_fd)
                else:
                    with contextlib.suppress(FileNotFoundError, PermissionError):
                        os.unlink(temporary_name, dir_fd=root_fd)
                    if marker_created:
                        with contextlib.suppress(FileNotFoundError, PermissionError):
                            os.unlink(marker_name, dir_fd=root_fd)
                with contextlib.suppress(OSError):
                    os.fsync(root_fd)
            os.close(root_fd)

    def read(self, key_id: str) -> bytes:
        key_name = self._key_name(key_id)
        marker_name = _publication_marker_name(key_name)
        root_fd = self._open_root_fd()
        descriptor: int | None = None
        try:
            self._require_no_publication_marker(root_fd, marker_name)
            before = self._stat_key_name(root_fd, key_name)
            self._require_safe_key_identity(before)
            try:
                descriptor = os.open(key_name, _KEY_READ_FLAGS, dir_fd=root_fd)
            except OSError as error:
                raise PermissionError("edge_key_file_unsafe") from error
            opened = os.fstat(descriptor)
            if not before.same_security_identity(opened):
                raise PermissionError("edge_key_identity_changed")
            self._require_safe_key_identity(_KeyIdentity.from_stat(opened))
            value = _read_exact_with_growth_check(descriptor, before.size)
            after = self._stat_key_name(root_fd, key_name)
            if not before.same_security_identity(after):
                raise PermissionError("edge_key_identity_changed")
            self._require_safe_key_identity(after)
            self._require_no_publication_marker(root_fd, marker_name)
            return self._key_bytes(value)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(root_fd)

    def delete(self, key_id: str) -> None:
        key_name = self._key_name(key_id)
        marker_name = _publication_marker_name(key_name)
        root_fd = self._open_root_fd()
        try:
            self._require_no_publication_marker(root_fd, marker_name)
            try:
                before = self._stat_key_name(root_fd, key_name)
            except FileNotFoundError:
                return
            self._require_safe_key_identity(before)
            after = self._stat_key_name(root_fd, key_name)
            if not before.same_inode(after):
                raise PermissionError("edge_key_identity_changed")
            os.unlink(key_name, dir_fd=root_fd)
            os.fsync(root_fd)
        finally:
            os.close(root_fd)

    def _require_root_directory(self) -> None:
        root_fd = self._open_root_fd()
        try:
            self._require_root_metadata(root_fd)
        finally:
            os.close(root_fd)

    def _ensure_root_directory(self) -> None:
        current_fd: int | None = None
        try:
            current_fd = os.open(self.root.anchor, os.O_RDONLY | _DIRECTORY | _CLOEXEC)
            path_parts = [part for part in self.root.parts if part != self.root.anchor]
            for index, part in enumerate(path_parts):
                is_final = index == len(path_parts) - 1
                created = False
                try:
                    os.mkdir(part, _KEY_ROOT_MODE, dir_fd=current_fd)
                    created = True
                    os.fsync(current_fd)
                except FileExistsError:
                    pass
                except OSError as error:
                    raise PermissionError("edge_key_root_unsafe") from error
                try:
                    next_fd = os.open(part, _ROOT_FLAGS, dir_fd=current_fd)
                except OSError as error:
                    raise PermissionError("edge_key_root_unsafe") from error
                os.close(current_fd)
                current_fd = next_fd
                if is_final:
                    self._require_root_metadata(current_fd)
                elif created:
                    metadata = os.fstat(current_fd)
                    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_nlink < 1:
                        raise PermissionError("edge_key_root_unsafe")
                    if stat.S_IMODE(metadata.st_mode) != _KEY_ROOT_MODE:
                        os.fchmod(current_fd, _KEY_ROOT_MODE)
                        os.fsync(current_fd)
            if not path_parts:
                raise PermissionError("edge_key_root_unsafe")
        finally:
            if current_fd is not None:
                os.close(current_fd)

    def _require_root_metadata(self, root_fd: int) -> None:
        metadata = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != self._expected_owner_uid
            or metadata.st_nlink < 1
        ):
            raise PermissionError("edge_key_root_unsafe")
        current_mode = stat.S_IMODE(metadata.st_mode)
        if current_mode != _KEY_ROOT_MODE:
            os.fchmod(root_fd, _KEY_ROOT_MODE)
            os.fsync(root_fd)

    def _open_root_fd(self) -> int:
        try:
            return os.open(self.root, _ROOT_FLAGS)
        except OSError as error:
            raise PermissionError("edge_key_root_unsafe") from error

    def _stat_key_name(self, root_fd: int, key_name: str) -> _KeyIdentity:
        return _KeyIdentity.from_stat(os.stat(key_name, dir_fd=root_fd, follow_symlinks=False))

    def _require_no_publication_marker(self, root_fd: int, marker_name: str) -> None:
        for blocker_name in (marker_name, _publication_quarantine_name(marker_name)):
            try:
                os.stat(blocker_name, dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise PermissionError("edge_key_publication_uncommitted")
        return

    def _remove_publication_marker_or_quarantine(
        self,
        root_fd: int,
        marker_name: str,
        key_name: str,
    ) -> None:
        try:
            os.unlink(marker_name, dir_fd=root_fd)
            os.fsync(root_fd)
        except OSError:
            self._fail_closed_uncommitted_publication(root_fd, marker_name, key_name)
            raise PermissionError("edge_key_publication_uncommitted") from None

    def _fail_closed_uncommitted_publication(
        self,
        root_fd: int,
        marker_name: str,
        key_name: str,
    ) -> None:
        if self._try_restore_publication_marker(root_fd, marker_name):
            return
        if self._try_restore_publication_marker(
            root_fd,
            _publication_quarantine_name(marker_name),
        ):
            return
        self._make_key_name_unclaimable(root_fd, key_name)

    def _try_restore_publication_marker(self, root_fd: int, marker_name: str) -> bool:
        try:
            self._restore_publication_marker(root_fd, marker_name)
        except OSError:
            return False
        return True

    @staticmethod
    def _make_key_name_unclaimable(root_fd: int, key_name: str) -> None:
        descriptor: int | None = None
        try:
            descriptor = os.open(key_name, _KEY_READ_FLAGS, dir_fd=root_fd)
            os.fchmod(descriptor, 0)
            os.fsync(descriptor)
        except OSError:
            pass
        finally:
            if descriptor is not None:
                os.close(descriptor)
        with contextlib.suppress(OSError):
            os.unlink(key_name, dir_fd=root_fd)
        with contextlib.suppress(OSError):
            os.fsync(root_fd)

    @staticmethod
    def _restore_publication_marker(root_fd: int, marker_name: str) -> None:
        descriptor: int | None = None
        try:
            descriptor = os.open(marker_name, _KEY_CREATE_FLAGS, _KEY_FILE_MODE, dir_fd=root_fd)
            os.fchmod(descriptor, _KEY_FILE_MODE)
            _write_all(descriptor, b"tuntun-edge-key-publication-v1\n")
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
        except FileExistsError:
            pass
        finally:
            if descriptor is not None:
                os.close(descriptor)
        os.fsync(root_fd)

    def _require_new_key_target_absent(self, root_fd: int, key_name: str) -> None:
        try:
            metadata = os.stat(key_name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        identity = _KeyIdentity.from_stat(metadata)
        if (
            not stat.S_ISREG(identity.mode)
            or identity.uid != self._expected_owner_uid
            or stat.S_IMODE(identity.mode) != _KEY_FILE_MODE
            or identity.nlink != 1
        ):
            raise PermissionError("edge_key_file_unsafe")
        raise FileExistsError("edge_key_already_exists")

    def _require_safe_key_identity(self, identity: _KeyIdentity) -> None:
        if (
            not stat.S_ISREG(identity.mode)
            or identity.uid != self._expected_owner_uid
            or stat.S_IMODE(identity.mode) != _KEY_FILE_MODE
            or identity.nlink != 1
            or not _MIN_KEY_BYTES <= identity.size <= _MAX_KEY_BYTES
        ):
            raise PermissionError("edge_key_file_unsafe")

    @staticmethod
    def _key_name(key_id: str) -> str:
        if (
            type(key_id) is not str
            or not key_id
            or key_id in {".", ".."}
            or any(character not in _KEY_ID_CHARS for character in key_id)
        ):
            raise ValueError("invalid edge key identifier")
        return f"{key_id}.key"

    @staticmethod
    def _key_bytes(value: bytes) -> bytes:
        if type(value) is not bytes or not _MIN_KEY_BYTES <= len(value) <= _MAX_KEY_BYTES:
            raise ValueError("edge key material outside strict byte bound")
        return bytes(value)


def _write_all(descriptor: int, value: bytes) -> None:
    offset = 0
    while offset < len(value):
        written = os.write(descriptor, value[offset:])
        if written <= 0:
            raise OSError("edge_key_write_incomplete")
        offset += written


def _publication_marker_name(key_name: str) -> str:
    return f".{key_name}.publish"


def _publication_quarantine_name(marker_name: str) -> str:
    return f"{marker_name}.quarantine"


def _read_exact_with_growth_check(descriptor: int, expected_size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = expected_size
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            raise PermissionError("edge_key_short_read")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise PermissionError("edge_key_identity_changed")
    return b"".join(chunks)


def _validate_root_path(root: Path) -> None:
    parts = tuple(root.parts)
    leaf_parts = tuple(part for part in parts if part != root.anchor)
    if (
        not root.is_absolute()
        or len(leaf_parts) < 2
        or any(part in {"", ".", ".."} or "\x00" in part for part in parts)
    ):
        raise PermissionError("edge_key_root_unsafe")
