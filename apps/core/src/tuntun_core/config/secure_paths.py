from __future__ import annotations

import ctypes
import errno
import os
import stat
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from types import TracebackType
from typing import Literal

OPEN_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
MAX_LINUX_XATTR_LIST_BYTES = 64 * 1024
LINUX_POSIX_ACL_FILESYSTEM_MAGICS = frozenset(
    {
        0xEF53,  # ext2/ext3/ext4
        0x58465342,  # XFS
        0x9123683E,  # Btrfs
        0x01021994,  # tmpfs
        0x794C7630,  # overlayfs
        0xF2F52010,  # F2FS
    }
)
LINUX_POSIX_ACL_ATTRIBUTES = frozenset({b"system.posix_acl_access", b"system.posix_acl_default"})
DARWIN_ACL_TYPE_EXTENDED = 0x00000100
DARWIN_ACL_FIRST_ENTRY = 0
DARWIN_ACL_NEXT_ENTRY = -1
DARWIN_ACL_EXTENDED_ALLOW = 1
DARWIN_ACL_EXTENDED_DENY = 2
MAX_DARWIN_ACL_ENTRIES = 128
_DESCRIPTOR_CLEANUP_NOTE = "additional descriptor cleanup failure"
_ACL_RELEASE_CLEANUP_NOTE = "additional ACL release failure"


class _AclInspectionError(ValueError):
    pass


@dataclass(slots=True)
class _OwnedDescriptor:
    _value: int | None

    def borrow(self) -> int:
        if self._value is None:
            raise PermissionError("descriptor is no longer owned")
        return self._value

    def detach(self) -> int:
        descriptor = self.borrow()
        self._value = None
        return descriptor

    def close(self, closer: Callable[[int], None]) -> None:
        if self._value is None:
            return
        descriptor = self.detach()
        closer(descriptor)


def _acquire_owned_descriptor(
    opener: Callable[[], int],
    closer: Callable[[int], None],
) -> _OwnedDescriptor:
    descriptor = opener()
    try:
        return _OwnedDescriptor(descriptor)
    except BaseException as error:
        try:
            closer(descriptor)
        except BaseException:
            error.add_note(_DESCRIPTOR_CLEANUP_NOTE)
        raise


def _close_preserving_primary(
    owner: _OwnedDescriptor,
    closer: Callable[[int], None],
    primary_error: BaseException | None,
) -> None:
    try:
        owner.close(closer)
    except BaseException:
        if primary_error is None:
            raise
        primary_error.add_note(_DESCRIPTOR_CLEANUP_NOTE)


def absolute_lexical_path(
    path: Path,
    *,
    allow_root: bool = False,
) -> Path:
    raw = os.fspath(path)
    if (
        type(raw) is not str
        or not raw
        or "\x00" in raw
        or raw.startswith(os.sep * 2)
        or any(component in {".", ".."} for component in raw.split(os.sep))
    ):
        raise PermissionError("unsafe application path")
    absolute = Path(os.path.abspath(raw))
    if absolute == Path("/") and not allow_root:
        raise PermissionError("unsafe application path")
    return absolute


def _reported_owner(value: os.stat_result) -> int:
    return value.st_uid


def _open_root() -> int:
    return os.open("/", OPEN_FLAGS)


def _open_directory_at(name: str, parent_fd: int) -> int:
    return os.open(name, OPEN_FLAGS, dir_fd=parent_fd)


def _stat_directory_at(name: str, parent_fd: int) -> os.stat_result:
    return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)


def _mkdir_directory_at(name: str, parent_fd: int) -> None:
    os.mkdir(name, 0o700, dir_fd=parent_fd)


def _close_fd(fd: int) -> None:
    os.close(fd)


def _require_supported_linux_acl_filesystem_magic(magic: int) -> None:
    if magic not in LINUX_POSIX_ACL_FILESYSTEM_MAGICS:
        raise _AclInspectionError(f"unsupported Linux filesystem ACL semantics: 0x{magic:x}")


def _classify_linux_acl_attribute(attribute: bytes) -> Literal["posix", "other"]:
    if attribute in LINUX_POSIX_ACL_ATTRIBUTES:
        return "posix"
    normalized = attribute.lower()
    if normalized.startswith((b"system.", b"security.", b"trusted.")) and b"acl" in normalized:
        raise _AclInspectionError(
            f"unsupported Linux discretionary ACL attribute: {attribute.decode('ascii', 'replace')}"
        )
    return "other"


def _linux_filesystem_magic(library: ctypes.CDLL, descriptor: int) -> int:
    filesystem_words = (ctypes.c_long * 32)()
    inspector = library.fstatfs
    inspector.argtypes = [ctypes.c_int, ctypes.c_void_p]
    inspector.restype = ctypes.c_int
    ctypes.set_errno(0)
    if inspector(descriptor, ctypes.byref(filesystem_words)) != 0:
        error_number = ctypes.get_errno()
        raise _AclInspectionError(f"filesystem ACL inspection failed: {os.strerror(error_number)}")
    word_bits = ctypes.sizeof(ctypes.c_long) * 8
    return int(filesystem_words[0]) & ((1 << word_bits) - 1)


def _linux_extended_attribute_names(
    library: ctypes.CDLL,
    descriptor: int,
) -> tuple[bytes, ...]:
    lister = library.flistxattr
    lister.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]
    lister.restype = ctypes.c_ssize_t
    for _ in range(4):
        ctypes.set_errno(0)
        required = lister(descriptor, None, 0)
        if required < 0:
            error_number = ctypes.get_errno()
            raise _AclInspectionError(f"ACL inspection failed: {os.strerror(error_number)}")
        if required == 0:
            return ()
        if required > MAX_LINUX_XATTR_LIST_BYTES:
            raise _AclInspectionError("extended-attribute inventory is too large")
        buffer = ctypes.create_string_buffer(required)
        ctypes.set_errno(0)
        actual = lister(descriptor, buffer, required)
        if actual < 0:
            error_number = ctypes.get_errno()
            if error_number == errno.ERANGE:
                continue
            raise _AclInspectionError(f"ACL inspection failed: {os.strerror(error_number)}")
        if actual == 0 or actual > required:
            raise _AclInspectionError("ACL inventory changed during inspection")
        raw_names = buffer.raw[:actual]
        if not raw_names.endswith(b"\0"):
            raise _AclInspectionError("ACL inventory is malformed")
        names = tuple(raw_names[:-1].split(b"\0"))
        if not names or any(not name for name in names):
            raise _AclInspectionError("ACL inventory is malformed")
        return names
    raise _AclInspectionError("ACL inventory changed during inspection")


def _darwin_descriptor_has_unsafe_acl(
    library: ctypes.CDLL,
    descriptor: int,
) -> bool:
    getter = library.acl_get_fd_np
    getter.argtypes = [ctypes.c_int, ctypes.c_int]
    getter.restype = ctypes.c_void_p
    iterator = library.acl_get_entry
    iterator.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    iterator.restype = ctypes.c_int
    tag_getter = library.acl_get_tag_type
    tag_getter.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    tag_getter.restype = ctypes.c_int
    freer = library.acl_free
    freer.argtypes = [ctypes.c_void_p]
    freer.restype = ctypes.c_int
    ctypes.set_errno(0)
    acl_pointer = getter(descriptor, DARWIN_ACL_TYPE_EXTENDED)
    if acl_pointer is None:
        error_number = ctypes.get_errno()
        if error_number == errno.ENOENT:
            return False
        raise _AclInspectionError(f"ACL inspection failed: {os.strerror(error_number)}")
    primary_error: BaseException | None = None
    unsafe = False
    try:
        entry = ctypes.c_void_p()
        entry_id = DARWIN_ACL_FIRST_ENTRY
        for index in range(MAX_DARWIN_ACL_ENTRIES + 1):
            ctypes.set_errno(0)
            result = iterator(acl_pointer, entry_id, ctypes.byref(entry))
            error_number = ctypes.get_errno()
            if result == -1 and entry_id == DARWIN_ACL_NEXT_ENTRY and error_number == errno.EINVAL:
                break
            if result != 0:
                raise _AclInspectionError(
                    f"ACL entry inspection failed: {os.strerror(error_number)}"
                )
            if index >= MAX_DARWIN_ACL_ENTRIES:
                raise _AclInspectionError("Darwin ACL entry inventory is too large")
            tag = ctypes.c_int()
            ctypes.set_errno(0)
            if tag_getter(entry, ctypes.byref(tag)) != 0:
                error_number = ctypes.get_errno()
                raise _AclInspectionError(f"ACL tag inspection failed: {os.strerror(error_number)}")
            if tag.value == DARWIN_ACL_EXTENDED_ALLOW:
                unsafe = True
                break
            if tag.value != DARWIN_ACL_EXTENDED_DENY:
                raise _AclInspectionError(f"unsupported Darwin ACL entry type: {tag.value}")
            entry_id = DARWIN_ACL_NEXT_ENTRY
        else:
            raise _AclInspectionError("Darwin ACL entry inventory is too large")
    except BaseException as error:
        primary_error = error

    ctypes.set_errno(0)
    release_error: BaseException | None = None
    try:
        if freer(acl_pointer) != 0:
            error_number = ctypes.get_errno()
            release_error = _AclInspectionError(f"ACL release failed: {os.strerror(error_number)}")
    except BaseException:
        release_error = _AclInspectionError("ACL release failed")
    if release_error is not None:
        if primary_error is None:
            primary_error = release_error
        else:
            primary_error.add_note(_ACL_RELEASE_CLEANUP_NOTE)
    if primary_error is not None:
        raise primary_error
    return unsafe


def _linux_descriptor_has_unsafe_acl(
    library: ctypes.CDLL,
    descriptor: int,
) -> bool:
    magic = _linux_filesystem_magic(library, descriptor)
    _require_supported_linux_acl_filesystem_magic(magic)
    return any(
        _classify_linux_acl_attribute(attribute) == "posix"
        for attribute in _linux_extended_attribute_names(library, descriptor)
    )


def _descriptor_has_unsafe_acl(descriptor: int) -> bool:
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        return _darwin_descriptor_has_unsafe_acl(library, descriptor)
    if sys.platform.startswith("linux"):
        return _linux_descriptor_has_unsafe_acl(library, descriptor)
    raise _AclInspectionError("ACL inspection is unsupported")


def _require_no_unsafe_acl(descriptor: int, message: str) -> None:
    try:
        has_unsafe_acl = _descriptor_has_unsafe_acl(descriptor)
    except Exception:
        raise PermissionError(message) from None
    if has_unsafe_acl:
        raise PermissionError(message)


def _ancestor_mode_is_safe(owner: int, mode: int) -> bool:
    permissions = stat.S_IMODE(mode)
    if owner == 0:
        return not permissions & 0o022 or bool(mode & stat.S_ISVTX)
    return owner == os.geteuid() and not permissions & 0o022


def _require_directory(
    descriptor: int,
    opened: os.stat_result,
    named: os.stat_result,
    *,
    leaf_private: bool,
) -> None:
    owner = _reported_owner(opened)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(named.st_mode)
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        or not _ancestor_mode_is_safe(owner, opened.st_mode)
        or (leaf_private and (owner != os.geteuid() or stat.S_IMODE(opened.st_mode) != 0o700))
    ):
        raise PermissionError("unsafe application path")
    _require_no_unsafe_acl(descriptor, "unsafe application path")


@dataclass(slots=True)
class OwnedDirectory:
    path: Path
    _descriptor: _OwnedDescriptor
    device: int
    inode: int
    _leaf_private: bool = field(repr=False)

    @property
    def fd(self) -> int:
        return self._descriptor.borrow()

    def revalidate(self) -> None:
        try:
            held = os.fstat(self.fd)
        except (OSError, PermissionError) as error:
            raise PermissionError("unsafe application path") from error
        with _walk_directory(
            self.path,
            create=False,
            leaf_private=self._leaf_private,
        ) as fresh:
            if (held.st_dev, held.st_ino) != (self.device, self.inode) or (
                fresh.device,
                fresh.inode,
            ) != (self.device, self.inode):
                raise PermissionError("unsafe application path")

    def close(self) -> None:
        try:
            self._descriptor.close(_close_fd)
        except Exception:
            raise PermissionError("unsafe application path") from None

    def __enter__(self) -> OwnedDirectory:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, traceback
        if exc is None:
            self.close()
        else:
            _close_preserving_primary(self._descriptor, _close_fd, exc)


@dataclass(frozen=True, slots=True)
class OwnedPath:
    path: Path
    device: int
    inode: int

    def revalidate(self) -> None:
        with open_owned_directory(self.path) as fresh:
            if (fresh.device, fresh.inode) != (self.device, self.inode):
                raise PermissionError("unsafe application path")


def _walk_directory(
    path: Path,
    *,
    create: bool,
    leaf_private: bool,
) -> OwnedDirectory:
    allow_root = not create and not leaf_private
    absolute = absolute_lexical_path(path, allow_root=allow_root)
    parts = absolute.parts[1:]
    parent = _acquire_owned_descriptor(_open_root, _close_fd)
    primary_error: BaseException | None = None
    try:
        parent_fd = parent.borrow()
        root = os.fstat(parent_fd)
        _require_directory(
            parent_fd,
            root,
            os.stat("/", follow_symlinks=False),
            leaf_private=not parts and leaf_private,
        )
        for index, part in enumerate(parts):
            parent_fd = parent.borrow()
            is_leaf = index == len(parts) - 1
            try:
                child = _acquire_owned_descriptor(
                    partial(_open_directory_at, part, parent_fd),
                    _close_fd,
                )
            except FileNotFoundError:
                if not create:
                    raise
                _mkdir_directory_at(part, parent_fd)
                child = _acquire_owned_descriptor(
                    partial(_open_directory_at, part, parent_fd),
                    _close_fd,
                )
            try:
                child_fd = child.borrow()
                opened = os.fstat(child_fd)
                named = _stat_directory_at(part, parent_fd)
                _require_directory(
                    child_fd,
                    opened,
                    named,
                    leaf_private=is_leaf and leaf_private,
                )
            except BaseException as error:
                _close_preserving_primary(child, _close_fd, error)
                raise
            previous_parent = parent
            parent = child
            previous_parent.close(_close_fd)
        parent_fd = parent.borrow()
        leaf_value = os.fstat(parent_fd)
        result = OwnedDirectory(
            absolute,
            parent,
            leaf_value.st_dev,
            leaf_value.st_ino,
            leaf_private,
        )
        parent = _OwnedDescriptor(None)
        return result
    except PermissionError as error:
        primary_error = error
        raise
    except OSError:
        mapped_error = PermissionError("unsafe application path")
        primary_error = mapped_error
        raise mapped_error from None
    except BaseException as error:
        primary_error = error
        raise
    finally:
        _close_preserving_primary(parent, _close_fd, primary_error)


def open_trusted_directory(path: Path) -> OwnedDirectory:
    return _walk_directory(path, create=False, leaf_private=False)


def open_owned_directory(path: Path) -> OwnedDirectory:
    return _walk_directory(path, create=False, leaf_private=True)


def ensure_private_directory(path: Path) -> OwnedPath:
    with _walk_directory(path, create=True, leaf_private=True) as opened:
        result = OwnedPath(
            opened.path,
            opened.device,
            opened.inode,
        )
    result.revalidate()
    return result
