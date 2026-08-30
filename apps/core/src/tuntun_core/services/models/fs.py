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
from collections.abc import Hashable, Iterator
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
    try:
        descriptor = os.open(path, os.O_RDONLY | _CLOEXEC | _NOFOLLOW | _NONBLOCK)
    except OSError as error:
        raise ValueError("invalid model manifest") from error
    try:
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
        raise ValueError("invalid model manifest") from error
    finally:
        os.close(descriptor)


@dataclass(frozen=True, slots=True)
class DirectoryIdentity:
    device: int
    inode: int


class OwnedDirectory:
    def __init__(self, descriptor: int) -> None:
        self.fd = descriptor
        identity = os.fstat(descriptor)
        _require_private_directory(identity)
        self.identity = DirectoryIdentity(identity.st_dev, identity.st_ino)

    @classmethod
    def _walk(cls, path: Path, *, create: bool) -> OwnedDirectory:
        absolute = path.absolute()
        parts = absolute.parts
        descriptor = os.open("/", os.O_RDONLY | _DIRECTORY | _CLOEXEC)
        try:
            for component in parts[1:]:
                if not _safe_component(component):
                    raise PermissionError("unsafe model filesystem path")
                if create:
                    with contextlib.suppress(FileExistsError):
                        os.mkdir(component, 0o700, dir_fd=descriptor)
                next_descriptor = os.open(
                    component,
                    os.O_RDONLY | _DIRECTORY | _CLOEXEC | _NOFOLLOW,
                    dir_fd=descriptor,
                )
                try:
                    if not stat.S_ISDIR(os.fstat(next_descriptor).st_mode):
                        raise PermissionError("unsafe model filesystem path")
                except BaseException:
                    os.close(next_descriptor)
                    raise
                os.close(descriptor)
                descriptor = next_descriptor
            return cls(descriptor)
        except BaseException:
            os.close(descriptor)
            raise

    @classmethod
    def open(cls, path: Path) -> OwnedDirectory:
        try:
            return cls._walk(path, create=False)
        except OSError as error:
            raise PermissionError("unsafe model filesystem path") from error

    @classmethod
    def open_or_create(cls, path: Path) -> OwnedDirectory:
        try:
            return cls._walk(path, create=True)
        except OSError as error:
            raise PermissionError("unsafe model filesystem path") from error

    def close(self) -> None:
        if self.fd >= 0:
            descriptor = self.fd
            self.fd = -1
            os.close(descriptor)

    def __enter__(self) -> OwnedDirectory:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def child(
        self,
        name: str,
        *,
        create: bool = False,
        exist_ok: bool = False,
        mode: int | None = None,
    ) -> OwnedDirectory:
        if not _safe_component(name):
            raise PermissionError("unsafe model filesystem path")
        if create:
            try:
                os.mkdir(name, mode or 0o700, dir_fd=self.fd)
            except FileExistsError:
                if not exist_ok:
                    raise
        descriptor = os.open(
            name,
            os.O_RDONLY | _DIRECTORY | _CLOEXEC | _NOFOLLOW,
            dir_fd=self.fd,
        )
        try:
            _require_private_directory(os.fstat(descriptor), mode=mode if not create else None)
            return OwnedDirectory(descriptor)
        except BaseException:
            os.close(descriptor)
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
    def lock(self, name: str, *, timeout_seconds: float) -> Iterator[None]:
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                descriptor = open_regular_at(
                    self,
                    name,
                    os.O_RDWR | os.O_CREAT,
                    mode=0o600,
                    expected_mode=0o600,
                )
                break
            except FileNotFoundError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("model install lock deadline") from None
                time.sleep(0.01)
        try:
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("model install lock deadline") from None
                    time.sleep(0.01)
            try:
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def remove_private_stages(self, prefix: str) -> None:
        for name in os.listdir(self.fd):
            if name.startswith(prefix):
                try:
                    child = self.child(name)
                except (FileNotFoundError, PermissionError):
                    raise PermissionError("unsafe model filesystem stage") from None
                identity = child.identity
                child.close()
                self.remove_private_stage(name, identity)

    def remove_private_stage(self, name: str, expected: DirectoryIdentity) -> None:
        stage = self.child(name)
        try:
            if stage.identity != expected:
                raise PermissionError("unsafe model filesystem stage")
            stage.chmod(0o700)
            _remove_tree_contents(stage)
        finally:
            stage.close()
        os.rmdir(name, dir_fd=self.fd)


def _remove_tree_contents(directory: OwnedDirectory) -> None:
    for name in os.listdir(directory.fd):
        identity = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
        if stat.S_ISDIR(identity.st_mode):
            child = directory.child(name)
            try:
                _remove_tree_contents(child)
            finally:
                child.close()
            os.rmdir(name, dir_fd=directory.fd)
        elif stat.S_ISREG(identity.st_mode) and identity.st_uid == _effective_user_id():
            os.unlink(name, dir_fd=directory.fd)
        else:
            raise PermissionError("unsafe model filesystem stage")


def open_regular_at(
    directory: OwnedDirectory,
    name: str,
    flags: int,
    *,
    mode: int = 0o600,
    expected_mode: int | None = None,
) -> int:
    if not _safe_component(name):
        raise PermissionError("unsafe model filesystem path")
    descriptor = os.open(name, flags | _CLOEXEC | _NOFOLLOW | _NONBLOCK, mode, dir_fd=directory.fd)
    try:
        identity = os.fstat(descriptor)
        _require_regular_file(identity, expected_mode=expected_mode)
        current_flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        if _NONBLOCK and current_flags & _NONBLOCK:
            fcntl.fcntl(descriptor, fcntl.F_SETFL, current_flags & ~_NONBLOCK)
        named = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
        if (identity.st_dev, identity.st_ino) != (named.st_dev, named.st_ino):
            raise PermissionError("unsafe model filesystem identity")
        return descriptor
    except BaseException:
        os.close(descriptor)
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


def atomic_publish_dir_noreplace(parent: OwnedDirectory, source: str, target: str) -> None:
    if not _safe_component(source) or not _safe_component(target):
        raise PermissionError("unsafe model filesystem path")
    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    target_bytes = os.fsencode(target)
    if sys.platform == "darwin" and hasattr(libc, "renameatx_np"):
        result = libc.renameatx_np(parent.fd, source_bytes, parent.fd, target_bytes, 0x00000004)
    elif hasattr(libc, "renameat2"):
        result = libc.renameat2(parent.fd, source_bytes, parent.fd, target_bytes, 1)
    else:
        raise OSError(errno.ENOTSUP, "exclusive directory publication unsupported")
    if result != 0:
        value = ctypes.get_errno()
        raise OSError(value, os.strerror(value), target)
