from __future__ import annotations

import contextlib
import ctypes
import errno
import fcntl
import hashlib
import os
import stat
import sys
import time
from collections.abc import Callable, Hashable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from yaml.events import AliasEvent, CollectionEndEvent, CollectionStartEvent
from yaml.nodes import MappingNode

MAX_MANIFEST_BYTES = 1_048_576
MAX_MANIFEST_EVENTS = 16_384
MAX_MANIFEST_DEPTH = 32
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_DESCRIPTOR_CLEANUP_NOTE = "additional descriptor cleanup failure"


def close_preserving_primary[T](
    resource: T,
    closer: Callable[[T], None],
    primary_error: BaseException,
) -> None:
    """Attempt one ownership release without replacing an active failure."""
    try:
        closer(resource)
    except BaseException:
        primary_error.add_note(_DESCRIPTOR_CLEANUP_NOTE)


def recovery_pending_name(revision: str) -> str:
    name = f".recovery-pending-{revision}"
    if not _safe_component(name):
        raise PermissionError("unsafe model filesystem path")
    return name


def model_install_lock_name(model_id: str) -> str:
    name = f".model-install-{model_id}.lock"
    if not _safe_component(name):
        raise PermissionError("unsafe model filesystem path")
    return name


def publication_commit_name(revision: str) -> str:
    name = f".publication-verified-{revision}"
    if not _safe_component(name):
        raise PermissionError("unsafe model filesystem path")
    return name


def require_publication_commit(
    model: OwnedDirectory,
    revision: str,
    descriptor: int,
    *,
    expected_mode: int,
    require_read_only: bool,
) -> None:
    name = publication_commit_name(revision)
    identity = os.fstat(descriptor)
    named = os.stat(name, dir_fd=model.fd, follow_symlinks=False)
    if (
        not stat.S_ISREG(identity.st_mode)
        or identity.st_uid != _effective_user_id()
        or stat.S_IMODE(identity.st_mode) != expected_mode
        or identity.st_nlink != 1
        or identity.st_size != 0
        or (identity.st_dev, identity.st_ino) != (named.st_dev, named.st_ino)
        or (
            require_read_only
            and fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
        )
    ):
        raise PermissionError("unsafe model publication commit")


def open_publication_commit(
    model: OwnedDirectory,
    revision: str,
    owner_slot: _FileDescriptorOwnerSlot,
) -> None:
    open_regular_at(
        model,
        publication_commit_name(revision),
        os.O_RDONLY,
        owner_slot,
        mode=0o400,
        expected_mode=0o400,
    )
    owner = owner_slot.owner
    if owner is None:
        raise RuntimeError("publication commit acquisition missing")
    try:
        require_publication_commit(
            model,
            revision,
            owner.fileno(),
            expected_mode=0o400,
            require_read_only=True,
        )
    except BaseException as error:
        close_preserving_primary(owner, _FileDescriptorOwner.close, error)
        owner_slot.owner = None
        raise


def entry_exists_at(directory: OwnedDirectory, name: str) -> bool:
    if not _safe_component(name):
        raise PermissionError("unsafe model filesystem path")
    try:
        os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise PermissionError("unsafe model filesystem path") from error
    return True


def _effective_user_id() -> int:
    return os.geteuid()


def _safe_component(value: str) -> bool:
    return (
        isinstance(value, str)
        and value not in {"", ".", ".."}
        and "/" not in value
        and "\x00" not in value
    )


def _require_private_directory(identity: os.stat_result, *, mode: int | None = None) -> None:
    if (
        not stat.S_ISDIR(identity.st_mode)
        or identity.st_uid != _effective_user_id()
        or identity.st_mode & 0o077
        or (mode is not None and stat.S_IMODE(identity.st_mode) != mode)
    ):
        raise PermissionError("unsafe model filesystem directory")


def _require_regular_file(
    identity: os.stat_result,
    *,
    expected_mode: int | None = None,
    require_single_link: bool = True,
) -> None:
    if (
        not stat.S_ISREG(identity.st_mode)
        or identity.st_uid != _effective_user_id()
        or identity.st_mode & 0o022
        or (expected_mode is not None and stat.S_IMODE(identity.st_mode) != expected_mode)
        or (require_single_link and identity.st_nlink != 1)
    ):
        raise PermissionError("unsafe model filesystem file")


class StrictSafeLoader(yaml.SafeLoader):
    def construct_mapping(self, node: yaml.Node, deep: bool = False) -> dict[Hashable, Any]:
        if not isinstance(node, MappingNode):
            raise ValueError("invalid model manifest")
        result: dict[Hashable, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValueError("invalid model manifest")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def parse_yaml_no_duplicates_aliases_tags(
    data: bytes, *, max_events: int = MAX_MANIFEST_EVENTS, max_depth: int = MAX_MANIFEST_DEPTH
) -> object:
    try:
        depth = 0
        for count, event in enumerate(yaml.parse(data), start=1):
            if count > max_events or isinstance(event, AliasEvent):
                raise ValueError("invalid model manifest")
            if getattr(event, "tag", None) is not None:
                raise ValueError("invalid model manifest")
            if isinstance(event, CollectionStartEvent):
                depth += 1
                if depth > max_depth:
                    raise ValueError("invalid model manifest")
            elif isinstance(event, CollectionEndEvent):
                depth -= 1
        if depth != 0:
            raise ValueError("invalid model manifest")
        return yaml.load(data, Loader=StrictSafeLoader)
    except (UnicodeDecodeError, yaml.YAMLError, ValueError) as error:
        raise ValueError("invalid model manifest") from error


def read_bounded_strict_yaml(path: Path) -> object:
    """Read a strict YAML document once through one stable no-follow descriptor."""
    descriptor_owner = _FileDescriptorOwner()
    primary_error: BaseException | None = None
    try:
        try:
            descriptor_owner.open_at(
                path,
                path,
                os.O_RDONLY | _CLOEXEC | _NOFOLLOW | _NONBLOCK,
                0,
            )
        except OSError as error:
            raise ValueError("invalid model manifest") from error
        descriptor = descriptor_owner.fileno()
        before = os.fstat(descriptor)
        _require_regular_file(before, require_single_link=False)
        current_flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        if _NONBLOCK and current_flags & _NONBLOCK:
            fcntl.fcntl(descriptor, fcntl.F_SETFL, current_flags & ~_NONBLOCK)
        if before.st_size > MAX_MANIFEST_BYTES:
            raise ValueError("invalid model manifest")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, MAX_MANIFEST_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_MANIFEST_BYTES:
                raise ValueError("invalid model manifest")
        after = os.fstat(descriptor)
        named = os.lstat(path)
        if (
            (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
            or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)
            or total != after.st_size
        ):
            raise ValueError("invalid model manifest")
        return parse_yaml_no_duplicates_aliases_tags(b"".join(chunks))
    except (OSError, PermissionError) as error:
        primary_error = ValueError("invalid model manifest")
        raise primary_error from error
    except BaseException as error:
        primary_error = error
        raise
    finally:
        if primary_error is None:
            descriptor_owner.close()
        else:
            close_preserving_primary(
                descriptor_owner,
                _FileDescriptorOwner.close,
                primary_error,
            )


@dataclass(frozen=True, slots=True)
class DirectoryIdentity:
    device: int
    inode: int


@dataclass(slots=True)
class AtomicPublishWitness:
    committed: bool = False


class _FileDescriptorOwner:
    """Idempotent ownership for one raw descriptor; integer access is borrowed."""

    __slots__ = ("fd",)

    def __init__(self) -> None:
        self.fd = -1

    def open_at(
        self,
        directory: int | str | bytes | os.PathLike[str] | os.PathLike[bytes],
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int,
    ) -> None:
        if self.fd >= 0:
            raise ValueError("descriptor owner already populated")
        if isinstance(directory, int):
            self.fd = os.open(path, flags, mode, dir_fd=directory)
        else:
            self.fd = os.open(path, flags, mode)

    def duplicate(self, descriptor: int) -> None:
        if self.fd >= 0:
            raise ValueError("descriptor owner already populated")
        self.fd = os.dup(descriptor)

    def fileno(self) -> int:
        if self.fd < 0:
            raise OSError(errno.EBADF, os.strerror(errno.EBADF))
        return self.fd

    def close(self) -> None:
        descriptor = self.fd
        if descriptor >= 0:
            # Consume ownership in the same traced line as the terminal close attempt.
            os.close(descriptor if setattr(self, "fd", -1) is None else descriptor)  # type: ignore[func-returns-value]


class _FileDescriptorOwnerSlot:
    """Caller-visible ownership populated before an acquiring helper returns."""

    __slots__ = ("owner",)

    def __init__(self) -> None:
        self.owner: _FileDescriptorOwner | None = None


class _OwnedDirectoryOwnerSlot:
    """Caller-visible ownership for one acquired directory descriptor."""

    __slots__ = ("owner",)

    def __init__(self) -> None:
        self.owner: OwnedDirectory | None = None


class OwnedDirectory:
    def __init__(self, descriptor_owner: _FileDescriptorOwner) -> None:
        self._descriptor_owner = descriptor_owner
        identity = os.fstat(descriptor_owner.fileno())
        _require_private_directory(identity)
        self.identity = DirectoryIdentity(identity.st_dev, identity.st_ino)

    @property
    def fd(self) -> int:
        return self._descriptor_owner.fileno()

    @classmethod
    def _walk(
        cls,
        path: Path,
        owner_slot: _OwnedDirectoryOwnerSlot,
        *,
        create: bool,
    ) -> None:
        if owner_slot.owner is not None:
            raise ValueError("directory owner slot already populated")
        absolute = path.absolute()
        parts = absolute.parts
        descriptor_slot = _FileDescriptorOwnerSlot()
        next_slot = _FileDescriptorOwnerSlot()
        descriptor_slot.owner = _FileDescriptorOwner()
        try:
            descriptor_slot.owner.open_at(
                "/",
                "/",
                os.O_RDONLY | _DIRECTORY | _CLOEXEC,
                0,
            )
            for component in parts[1:]:
                if not _safe_component(component):
                    raise PermissionError("unsafe model filesystem path")
                descriptor_owner = descriptor_slot.owner
                if descriptor_owner is None:
                    raise RuntimeError("directory walk descriptor ownership missing")
                if create:
                    with contextlib.suppress(FileExistsError):
                        os.mkdir(component, 0o700, dir_fd=descriptor_owner.fileno())
                next_slot = _FileDescriptorOwnerSlot()
                next_slot.owner = _FileDescriptorOwner()
                next_slot.owner.open_at(
                    descriptor_owner.fileno(),
                    component,
                    os.O_RDONLY | _DIRECTORY | _CLOEXEC | _NOFOLLOW,
                    0,
                )
                next_owner = next_slot.owner
                if next_owner is None or not stat.S_ISDIR(os.fstat(next_owner.fileno()).st_mode):
                    raise PermissionError("unsafe model filesystem path")
                descriptor_owner.close()
                descriptor_slot.owner = next_owner
                next_slot.owner = None
            descriptor_owner = descriptor_slot.owner
            if descriptor_owner is None:
                raise RuntimeError("directory walk descriptor ownership missing")
            owner_slot.owner = cls(descriptor_owner)
            descriptor_slot.owner = None
        except BaseException as error:
            if owner_slot.owner is not None:
                close_preserving_primary(owner_slot.owner, OwnedDirectory.close, error)
            if next_slot.owner is not None:
                close_preserving_primary(next_slot.owner, _FileDescriptorOwner.close, error)
            if descriptor_slot.owner is not None:
                close_preserving_primary(
                    descriptor_slot.owner,
                    _FileDescriptorOwner.close,
                    error,
                )
            raise

    @classmethod
    def open(cls, path: Path, owner_slot: _OwnedDirectoryOwnerSlot) -> None:
        try:
            cls._walk(path, owner_slot, create=False)
        except OSError as error:
            raise PermissionError("unsafe model filesystem path") from error

    @classmethod
    def open_or_create(cls, path: Path, owner_slot: _OwnedDirectoryOwnerSlot) -> None:
        try:
            cls._walk(path, owner_slot, create=True)
        except OSError as error:
            raise PermissionError("unsafe model filesystem path") from error

    def close(self) -> None:
        self._descriptor_owner.close()

    def __enter__(self) -> OwnedDirectory:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def child(
        self,
        name: str,
        owner_slot: _OwnedDirectoryOwnerSlot,
        *,
        create: bool = False,
        exist_ok: bool = False,
        mode: int | None = None,
    ) -> None:
        if owner_slot.owner is not None:
            raise ValueError("directory owner slot already populated")
        if not _safe_component(name):
            raise PermissionError("unsafe model filesystem path")
        if create:
            try:
                os.mkdir(name, mode or 0o700, dir_fd=self.fd)
            except FileExistsError:
                if not exist_ok:
                    raise
        descriptor_slot = _FileDescriptorOwnerSlot()
        descriptor_slot.owner = _FileDescriptorOwner()
        try:
            descriptor_slot.owner.open_at(
                self.fd,
                name,
                os.O_RDONLY | _DIRECTORY | _CLOEXEC | _NOFOLLOW,
                0,
            )
            descriptor_owner = descriptor_slot.owner
            if descriptor_owner is None:
                raise RuntimeError("child directory descriptor ownership missing")
            _require_private_directory(
                os.fstat(descriptor_owner.fileno()),
                mode=mode if not create else None,
            )
            owner_slot.owner = OwnedDirectory(descriptor_owner)
            descriptor_slot.owner = None
        except BaseException as error:
            if owner_slot.owner is not None:
                close_preserving_primary(owner_slot.owner, OwnedDirectory.close, error)
            if descriptor_slot.owner is not None:
                close_preserving_primary(
                    descriptor_slot.owner,
                    _FileDescriptorOwner.close,
                    error,
                )
            raise

    def has_child(self, name: str) -> bool:
        if not _safe_component(name):
            return False
        try:
            identity = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        _require_private_directory(identity, mode=0o500)
        return True

    def chmod(self, mode: int) -> None:
        os.fchmod(self.fd, mode)
        _require_private_directory(os.fstat(self.fd), mode=mode)

    def fsync(self) -> None:
        os.fsync(self.fd)

    @contextlib.contextmanager
    def lock(
        self,
        name: str,
        owner_slot: _FileDescriptorOwnerSlot,
        *,
        timeout_seconds: float,
        shared: bool = False,
    ) -> Iterator[None]:
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                open_regular_at(
                    self,
                    name,
                    os.O_RDWR | os.O_CREAT,
                    owner_slot,
                    mode=0o600,
                    expected_mode=0o600,
                )
                break
            except FileNotFoundError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("model install lock deadline") from None
                time.sleep(0.01)
        descriptor_owner = owner_slot.owner
        if descriptor_owner is None:
            raise RuntimeError("model lock descriptor acquisition missing")
        descriptor = descriptor_owner.fileno()
        primary_error: BaseException | None = None
        locked = False
        try:
            operation = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
            while True:
                try:
                    fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
                    locked = True
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("model install lock deadline") from None
                    time.sleep(0.01)
            try:
                yield
            except BaseException as error:
                primary_error = error
                raise
        except BaseException as error:
            if primary_error is None:
                primary_error = error
            raise
        finally:
            release_error: BaseException | None = None
            if locked:
                if primary_error is None:
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                    except BaseException as error:
                        primary_error = error
                        release_error = error
                else:
                    close_preserving_primary(
                        descriptor,
                        lambda value: fcntl.flock(value, fcntl.LOCK_UN),
                        primary_error,
                    )
            if primary_error is None:
                descriptor_owner.close()
            else:
                close_preserving_primary(
                    descriptor_owner,
                    _FileDescriptorOwner.close,
                    primary_error,
                )
            if release_error is not None:
                raise release_error

    def remove_private_stages(self, prefix: str) -> None:
        for name in os.listdir(self.fd):
            if name.startswith(prefix):
                child_slot = _OwnedDirectoryOwnerSlot()
                primary_error: BaseException | None = None
                try:
                    try:
                        self.child(name, child_slot)
                    except (FileNotFoundError, PermissionError):
                        raise PermissionError("unsafe model filesystem stage") from None
                    child = child_slot.owner
                    if child is None:
                        raise RuntimeError("model stage directory acquisition missing")
                    identity = child.identity
                except BaseException as error:
                    primary_error = error
                    raise
                finally:
                    if child_slot.owner is not None:
                        if primary_error is None:
                            child_slot.owner.close()
                        else:
                            close_preserving_primary(
                                child_slot.owner,
                                OwnedDirectory.close,
                                primary_error,
                            )
                self.remove_private_stage(name, identity)

    def remove_private_stage(self, name: str, expected: DirectoryIdentity) -> None:
        stage_slot = _OwnedDirectoryOwnerSlot()
        primary_error: BaseException | None = None
        try:
            self.child(name, stage_slot)
            stage = stage_slot.owner
            if stage is None:
                raise RuntimeError("model stage directory acquisition missing")
            if stage.identity != expected:
                raise PermissionError("unsafe model filesystem stage")
            stage.chmod(0o700)
            _remove_tree_contents(stage)
        except BaseException as error:
            primary_error = error
            raise
        finally:
            if stage_slot.owner is not None:
                if primary_error is None:
                    stage_slot.owner.close()
                else:
                    close_preserving_primary(
                        stage_slot.owner,
                        OwnedDirectory.close,
                        primary_error,
                    )
        os.rmdir(name, dir_fd=self.fd)


def _remove_tree_contents(directory: OwnedDirectory) -> None:
    for name in os.listdir(directory.fd):
        identity = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
        if stat.S_ISDIR(identity.st_mode):
            child_slot = _OwnedDirectoryOwnerSlot()
            primary_error: BaseException | None = None
            try:
                directory.child(name, child_slot)
                child = child_slot.owner
                if child is None:
                    raise RuntimeError("model stage child acquisition missing")
                _remove_tree_contents(child)
            except BaseException as error:
                primary_error = error
                raise
            finally:
                if child_slot.owner is not None:
                    if primary_error is None:
                        child_slot.owner.close()
                    else:
                        close_preserving_primary(
                            child_slot.owner,
                            OwnedDirectory.close,
                            primary_error,
                        )
            os.rmdir(name, dir_fd=directory.fd)
        elif stat.S_ISREG(identity.st_mode) and identity.st_uid == _effective_user_id():
            os.unlink(name, dir_fd=directory.fd)
        else:
            raise PermissionError("unsafe model filesystem stage")


def open_regular_at(
    directory: OwnedDirectory,
    name: str,
    flags: int,
    owner_slot: _FileDescriptorOwnerSlot,
    *,
    mode: int = 0o600,
    expected_mode: int | None = None,
) -> None:
    if owner_slot.owner is not None:
        raise ValueError("descriptor owner slot already populated")
    if not _safe_component(name):
        raise PermissionError("unsafe model filesystem path")
    owner_slot.owner = _FileDescriptorOwner()
    owner = owner_slot.owner
    try:
        owner.open_at(
            directory.fd,
            name,
            flags | _CLOEXEC | _NOFOLLOW | _NONBLOCK,
            mode,
        )
        descriptor = owner.fileno()
        identity = os.fstat(descriptor)
        _require_regular_file(identity, expected_mode=expected_mode)
        current_flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        if _NONBLOCK and current_flags & _NONBLOCK:
            fcntl.fcntl(descriptor, fcntl.F_SETFL, current_flags & ~_NONBLOCK)
        named = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
        if (identity.st_dev, identity.st_ino) != (named.st_dev, named.st_ino):
            raise PermissionError("unsafe model filesystem identity")
    except BaseException as error:
        close_preserving_primary(owner, _FileDescriptorOwner.close, error)
        owner_slot.owner = None
        raise


def hash_exact_fd(descriptor: int, size: int, expected_sha256: str) -> str:
    identity = os.fstat(descriptor)
    _require_regular_file(identity, expected_mode=0o400, require_single_link=False)
    if fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
        raise PermissionError("model descriptor is not read-only")
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        chunk = os.pread(descriptor, min(65_536, size - offset), offset)
        if not chunk:
            raise ValueError("model size/hash mismatch")
        digest.update(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, size) or identity.st_size != size:
        raise ValueError("model size/hash mismatch")
    actual = digest.hexdigest()
    if actual != expected_sha256:
        raise ValueError("model size/hash mismatch")
    return actual


def atomic_publish_dir_noreplace(
    parent: OwnedDirectory,
    source: str,
    target: str,
    *,
    expected_source_fd: int | None = None,
    expected_source_identity: tuple[int, int] | None = None,
    witness: AtomicPublishWitness | None = None,
) -> None:
    if not _safe_component(source) or not _safe_component(target):
        raise PermissionError("unsafe model filesystem path")
    if witness is not None and witness.committed:
        raise ValueError("atomic publication witness already committed")
    if (expected_source_fd is None) != (expected_source_identity is None):
        raise ValueError("atomic publication source identity is incomplete")
    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    target_bytes = os.fsencode(target)
    if sys.platform == "darwin":
        if not hasattr(libc, "renameatx_np"):
            raise OSError(errno.ENOTSUP, "exclusive directory publication unsupported")
        native_rename = libc.renameatx_np
        flags = 0x00000004
    elif sys.platform.startswith("linux"):
        if not hasattr(libc, "renameat2"):
            raise OSError(errno.ENOTSUP, "exclusive directory publication unsupported")
        native_rename = libc.renameat2
        flags = 1
    else:
        raise OSError(errno.ENOTSUP, "exclusive directory publication unsupported")
    if expected_source_fd is not None and expected_source_identity is not None:
        retained = os.fstat(expected_source_fd)
        named = os.stat(source, dir_fd=parent.fd, follow_symlinks=False)
        if any(
            not stat.S_ISREG(candidate.st_mode)
            or candidate.st_uid != _effective_user_id()
            or stat.S_IMODE(candidate.st_mode) != 0o400
            or candidate.st_nlink != 1
            or candidate.st_size != 0
            or (candidate.st_dev, candidate.st_ino) != expected_source_identity
            for candidate in (retained, named)
        ):
            raise PermissionError("atomic publication source changed")
    result = native_rename(parent.fd, source_bytes, parent.fd, target_bytes, flags)
    if result != 0:
        value = ctypes.get_errno()
        raise OSError(value, os.strerror(value), target)
    if witness is not None:
        witness.committed = True
