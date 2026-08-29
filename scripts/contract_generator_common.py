from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory, gettempdir
from typing import TYPE_CHECKING, Literal, TypeAlias

from tuntun_contracts.base import ContractModel

if TYPE_CHECKING:
    from scripts.assurance_common import (
        AssuranceInputError,
        FrozenRegularFile,
        lexical_path,
        read_regular_file,
        validate_root,
        walk_regular_files,
    )
elif __package__:
    from .assurance_common import (
        AssuranceInputError,
        FrozenRegularFile,
        lexical_path,
        read_regular_file,
        validate_root,
        walk_regular_files,
    )
else:
    from assurance_common import (
        AssuranceInputError,
        FrozenRegularFile,
        lexical_path,
        read_regular_file,
        validate_root,
        walk_regular_files,
    )

MAX_GENERATED_BYTES = 4 * 1024 * 1024
MAX_PARENT_FILES = 3
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
GeneratorMode: TypeAlias = Literal["check", "write"]  # noqa: UP040
Renderer: TypeAlias = Callable[[], bytes]  # noqa: UP040


@dataclass(frozen=True)
class OutputParent:
    """Open output-parent descriptor and the directory identity it captured."""

    path: Path
    descriptor: int
    device: int
    inode: int


@dataclass(frozen=True)
class OutputBaseline:
    """Exact sole-output snapshot retained for descriptor-relative rollback."""

    snapshot: tuple[FrozenRegularFile, ...]
    mode: int | None


class GeneratorError(RuntimeError):
    """Generation, inventory, determinism, or publication failed closed."""


def _json_pointer_escape(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _rewrite_local_ref(value: object, *, model_pointer: str) -> str:
    if not isinstance(value, str):
        raise GeneratorError("generated schema reference is not a string")
    if not value.startswith("#/$defs/"):
        raise GeneratorError(f"unsupported generated schema reference: {value}")
    return f"{model_pointer}/$defs/{value.removeprefix('#/$defs/')}"


def _registered_model_map(
    models: Sequence[type[ContractModel]],
) -> dict[str, type[ContractModel]]:
    result: dict[str, type[ContractModel]] = {}
    for model in models:
        name = f"{model.__module__}.{model.__qualname__}"
        if name in result:
            raise GeneratorError(f"duplicate fully qualified contract model: {name}")
        result[name] = model
    if not result:
        raise GeneratorError("contract registry must not be empty")
    return dict(sorted(result.items()))


def _rewrite_local_refs(value: object, *, model_pointer: str) -> object:
    if isinstance(value, dict):
        is_discriminator = "propertyName" in value and "mapping" in value
        if is_discriminator:
            if not isinstance(value["propertyName"], str):
                raise GeneratorError("generated discriminator propertyName is not a string")
            if not isinstance(value["mapping"], dict):
                raise GeneratorError("generated discriminator mapping is not an object")
        result: dict[str, object] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise GeneratorError("generated schema key is not a string")
            if key == "$ref":
                result[key] = _rewrite_local_ref(child, model_pointer=model_pointer)
            elif is_discriminator and key == "mapping":
                mapping: dict[str, object] = {}
                for discriminator_value, reference in child.items():
                    if not isinstance(discriminator_value, str):
                        raise GeneratorError("generated discriminator value is not a string")
                    mapping[discriminator_value] = _rewrite_local_ref(
                        reference,
                        model_pointer=model_pointer,
                    )
                result[key] = mapping
            else:
                result[key] = _rewrite_local_refs(child, model_pointer=model_pointer)
        return result
    if isinstance(value, list):
        return [_rewrite_local_refs(child, model_pointer=model_pointer) for child in value]
    return value


def build_model_schemas(
    models: Sequence[type[ContractModel]],
    *,
    container_pointer: str,
) -> dict[str, object]:
    if not container_pointer.startswith("/") or container_pointer.endswith("/"):
        raise ValueError("container_pointer must be one nonempty absolute JSON Pointer")
    result: dict[str, object] = {}
    for name, model in _registered_model_map(models).items():
        model_pointer = f"#{container_pointer}/{_json_pointer_escape(name)}"
        raw_schema = model.model_json_schema(
            mode="validation",
            ref_template="#/$defs/{model}",
        )
        result[name] = _rewrite_local_refs(raw_schema, model_pointer=model_pointer)
    return result


def render_json_document(document: Mapping[str, object]) -> bytes:
    return (
        json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
        )
        + "\n"
    ).encode("utf-8")


def _require_rendered_bytes(value: object) -> bytes:
    if type(value) is not bytes:
        raise GeneratorError("renderer must return bytes")
    rendered = value
    if not 1 <= len(rendered) <= MAX_GENERATED_BYTES:
        raise GeneratorError("rendered artifact byte limit exceeded")
    return rendered


def _write_all(descriptor: int, value: bytes) -> None:
    view = memoryview(value)
    offset = 0
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        if written <= 0:
            raise OSError("short generated-artifact write")
        offset += written


def _render_twice_in_private_tree(renderer: Renderer, filename: str) -> bytes:
    first = _require_rendered_bytes(renderer())
    second = _require_rendered_bytes(renderer())
    if first != second:
        raise GeneratorError("nondeterministic generator render")
    system_temporary_root = validate_root(Path(os.path.realpath(gettempdir())))
    with TemporaryDirectory(
        prefix="tuntun-contract-generator-",
        dir=system_temporary_root,
    ) as temporary:
        candidate = Path(temporary) / filename
        descriptor = os.open(
            candidate,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            _write_all(descriptor, first)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if read_regular_file(candidate, max_bytes=MAX_GENERATED_BYTES) != first:
            raise GeneratorError("private render verification failed")
    return first


def _scan_parent(parent: Path) -> tuple[FrozenRegularFile, ...]:
    return tuple(
        sorted(
            walk_regular_files(
                (parent,),
                max_files=MAX_PARENT_FILES,
                max_total_bytes=MAX_GENERATED_BYTES * MAX_PARENT_FILES,
            ),
            key=lambda item: item.path.as_posix(),
        )
    )


def _output_parent_is_current(output_parent: OutputParent) -> bool:
    try:
        named = os.stat(output_parent.path, follow_symlinks=False)
        opened = os.fstat(output_parent.descriptor)
    except OSError:
        return False
    return (
        stat.S_ISDIR(named.st_mode)
        and stat.S_ISDIR(opened.st_mode)
        and named.st_dev == output_parent.device == opened.st_dev
        and named.st_ino == output_parent.inode == opened.st_ino
    )


def _owned_snapshot(
    output_path: Path,
    *,
    allow_missing: bool,
    output_parent: OutputParent | None = None,
) -> tuple[FrozenRegularFile, ...]:
    expected = lexical_path(output_path)
    if output_parent is not None and (
        expected.parent != output_parent.path or not _output_parent_is_current(output_parent)
    ):
        raise GeneratorError("output parent changed during generation")
    files = _scan_parent(expected.parent)
    if output_parent is not None and not _output_parent_is_current(output_parent):
        raise GeneratorError("output parent changed during generation")
    if not files and allow_missing:
        return ()
    if len(files) != 1 or files[0].path != expected:
        raise GeneratorError("owned output inventory is not exact")
    if read_regular_file(expected, max_bytes=MAX_GENERATED_BYTES) != files[0].raw:
        raise AssuranceInputError(expected, "input-changed-during-scan")
    if output_parent is not None and not _output_parent_is_current(output_parent):
        raise GeneratorError("output parent changed during generation")
    return files


def _capture_output_baseline(output: Path, output_parent: OutputParent) -> OutputBaseline:
    snapshot = _owned_snapshot(
        output,
        allow_missing=True,
        output_parent=output_parent,
    )
    if not snapshot:
        return OutputBaseline(snapshot=(), mode=None)
    metadata = os.stat(
        output.name,
        dir_fd=output_parent.descriptor,
        follow_symlinks=False,
    )
    frozen = snapshot[0]
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_dev != frozen.device
        or metadata.st_ino != frozen.inode
        or metadata.st_size != frozen.size
        or metadata.st_mtime_ns != frozen.modified_ns
        or metadata.st_ctime_ns != frozen.changed_ns
    ):
        raise AssuranceInputError(output, "input-changed-during-scan")
    return OutputBaseline(snapshot=snapshot, mode=stat.S_IMODE(metadata.st_mode))


def _bind_output_parent(
    output_path: Path,
    *,
    create_missing: bool,
) -> OutputParent:
    parent = lexical_path(output_path).parent
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    current_fd = os.open(os.path.sep, flags)
    keep_descriptor = False
    try:
        for index, part in enumerate(parent.parts[1:]):
            display = Path(os.path.sep).joinpath(*parent.parts[1 : index + 2])
            try:
                before = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
            except FileNotFoundError:
                if not create_missing:
                    raise AssuranceInputError(display, "missing-input") from None
                _require_owner_controlled_creation_parent(current_fd)
                _require_supported_private_directory_umask(current_fd)
                os.mkdir(part, mode=0o700, dir_fd=current_fd)
                child_fd, opened = _open_created_private_directory(current_fd, part)
            else:
                if stat.S_ISLNK(before.st_mode):
                    raise AssuranceInputError(display, "symlink-input")
                if not stat.S_ISDIR(before.st_mode):
                    raise AssuranceInputError(display, "not-directory")
                child_fd = os.open(part, flags, dir_fd=current_fd)
                opened = os.fstat(child_fd)
                if before.st_dev != opened.st_dev or before.st_ino != opened.st_ino:
                    os.close(child_fd)
                    raise AssuranceInputError(display, "input-changed-during-scan")
            os.close(current_fd)
            current_fd = child_fd
        validated = validate_root(parent)
        opened = os.fstat(current_fd)
        output_parent = OutputParent(
            path=validated,
            descriptor=current_fd,
            device=opened.st_dev,
            inode=opened.st_ino,
        )
        if not _output_parent_is_current(output_parent):
            raise GeneratorError("output parent changed during generation")
        keep_descriptor = True
        return output_parent
    finally:
        if not keep_descriptor:
            os.close(current_fd)


def _ensure_output_parent(output_path: Path) -> OutputParent:
    return _bind_output_parent(output_path, create_missing=True)


def _open_existing_output_parent(output_path: Path) -> OutputParent:
    return _bind_output_parent(output_path, create_missing=False)


def _atomic_replace(source_name: str, destination_name: str, parent_fd: int) -> None:
    os.replace(
        source_name,
        destination_name,
        src_dir_fd=parent_fd,
        dst_dir_fd=parent_fd,
    )


def _rollback_replace(source_name: str, destination_name: str, parent_fd: int) -> None:
    os.replace(
        source_name,
        destination_name,
        src_dir_fd=parent_fd,
        dst_dir_fd=parent_fd,
    )


def _rollback_unlink(destination_name: str, parent_fd: int) -> None:
    os.unlink(destination_name, dir_fd=parent_fd)


def _rollback_publication(
    output_name: str,
    baseline: OutputBaseline,
    parent_fd: int,
) -> None:
    rollback_name: str | None = None
    rollback_fd: int | None = None
    try:
        if baseline.snapshot:
            if baseline.mode is None:
                raise GeneratorError("existing baseline is missing its mode")
            rollback_name = f".{output_name}.{secrets.token_hex(16)}.rollback"
            rollback_fd = os.open(
                rollback_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent_fd,
            )
            _write_all(rollback_fd, baseline.snapshot[0].raw)
            os.fchmod(rollback_fd, baseline.mode)
            os.fsync(rollback_fd)
            os.close(rollback_fd)
            rollback_fd = None
            _rollback_replace(rollback_name, output_name, parent_fd)
            rollback_name = None
        else:
            if baseline.mode is not None:
                raise GeneratorError("missing baseline unexpectedly has a mode")
            with suppress(FileNotFoundError):
                _rollback_unlink(output_name, parent_fd)
        os.fsync(parent_fd)
    finally:
        if rollback_fd is not None:
            os.close(rollback_fd)
        try:
            if rollback_name is not None:
                with suppress(FileNotFoundError):
                    os.unlink(rollback_name, dir_fd=parent_fd)
        finally:
            os.fsync(parent_fd)


def _write_atomically(output_path: Path, rendered: bytes) -> None:
    output = lexical_path(output_path)
    output_parent = _ensure_output_parent(output)
    temporary_name = f".{output.name}.{secrets.token_hex(16)}.tmp"
    temporary_path = output_parent.path / temporary_name
    temporary_fd: int | None = None
    published = False
    try:
        baseline = _capture_output_baseline(output, output_parent)
        if not _output_parent_is_current(output_parent):
            raise GeneratorError("output parent changed during generation")
        temporary_fd = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=output_parent.descriptor,
        )
        os.fchmod(temporary_fd, 0o600)
        _write_all(temporary_fd, rendered)
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = None

        current = _scan_parent(output_parent.path)
        temporary_entries = tuple(
            item for item in current if item.path == lexical_path(temporary_path)
        )
        remaining = tuple(item for item in current if item.path != lexical_path(temporary_path))
        if (
            len(temporary_entries) != 1
            or temporary_entries[0].raw != rendered
            or stat.S_IMODE(os.stat(temporary_path, follow_symlinks=False).st_mode) != 0o600
        ):
            raise GeneratorError("private publication file verification failed")
        if remaining != baseline.snapshot or not _output_parent_is_current(output_parent):
            raise GeneratorError("output changed during generation")

        _atomic_replace(temporary_name, output.name, output_parent.descriptor)
        published = True
        try:
            if not _output_parent_is_current(output_parent):
                raise GeneratorError("output parent changed during publication")
            os.fsync(output_parent.descriptor)
            final = _owned_snapshot(
                output,
                allow_missing=False,
                output_parent=output_parent,
            )
            if final[0].raw != rendered:
                raise GeneratorError("published generated artifact verification failed")
            if not _output_parent_is_current(output_parent):
                raise GeneratorError("output parent changed at final postcondition")
        except Exception as publication_error:
            try:
                _rollback_publication(
                    output.name,
                    baseline,
                    output_parent.descriptor,
                )
            except Exception as rollback_error:
                raise GeneratorError("publication failed and rollback failed") from rollback_error
            raise GeneratorError(
                "publication failed and baseline was restored"
            ) from publication_error
    finally:
        if temporary_fd is not None:
            os.close(temporary_fd)
        if not published:
            try:
                os.unlink(temporary_name, dir_fd=output_parent.descriptor)
                os.fsync(output_parent.descriptor)
            except FileNotFoundError:
                pass
        os.close(output_parent.descriptor)


def _check_current_output(output_path: Path, rendered: bytes) -> bool:
    output = lexical_path(output_path)
    output_parent = _open_existing_output_parent(output)
    try:
        initial = _owned_snapshot(
            output,
            allow_missing=False,
            output_parent=output_parent,
        )
        final = _owned_snapshot(
            output,
            allow_missing=False,
            output_parent=output_parent,
        )
        matches = initial == final and final[0].raw == rendered
        if not _output_parent_is_current(output_parent):
            raise GeneratorError("output parent changed at check postcondition")
        return matches
    finally:
        os.close(output_parent.descriptor)


def _parse_mode(argv: Sequence[str] | None) -> GeneratorMode:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    if arguments == ("--check",):
        return "check"
    if arguments == ("--write",):
        return "write"
    raise ValueError("exactly one of --check or --write is required")


def run_generator(
    *,
    output_path: Path,
    renderer: Renderer,
    argv: Sequence[str] | None,
) -> int:
    try:
        mode = _parse_mode(argv)
        rendered = _render_twice_in_private_tree(renderer, output_path.name)
        if mode == "check":
            return 0 if _check_current_output(output_path, rendered) else 1
        _write_atomically(output_path, rendered)
        return 0
    except Exception:
        return 1


MAX_GENERATED_DIRECTORY_FILES = 32
MAX_GENERATED_DIRECTORY_BYTES = MAX_GENERATED_BYTES * MAX_GENERATED_DIRECTORY_FILES
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
INTENT_VERSION = 1
INTENT_NAME = "intent.json"
INTENT_TEMP_NAME = ".intent.tmp"
STAGE_NAME = "stage"
DARWIN_RENAME_SWAP = 0x00000002
DARWIN_RENAME_EXCL = 0x00000004
LINUX_RENAME_NOREPLACE = 1
LINUX_RENAME_EXCHANGE = 2
DirectoryRenderer: TypeAlias = Callable[[], Mapping[str, bytes]]  # noqa: UP040


@dataclass(frozen=True)
class GeneratedDirectoryEntry:
    name: str
    raw: bytes
    sha256: str
    mode: int
    device: int
    inode: int
    owner: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass
class GeneratedDirectoryHandle:
    name: str
    descriptor: int
    device: int
    inode: int


@dataclass(frozen=True)
class GeneratedDirectoryReceipt:
    device: int
    inode: int
    owner: int
    mode: int
    tree_sha256: str
    entries: tuple[GeneratedDirectoryEntry, ...]


@dataclass(frozen=True)
class GeneratedDirectoryIntent:
    output_name: str
    expected_names: tuple[str, ...]
    baseline: GeneratedDirectoryReceipt | None
    candidate: GeneratedDirectoryReceipt


@dataclass
class GeneratedDirectorySnapshot:
    """One lock-held, immutable view of a generated directory generation."""

    _parent: OutputParent
    _directory: GeneratedDirectoryHandle
    _entries: tuple[GeneratedDirectoryEntry, ...]
    _closed: bool = False
    _directory_disposed: bool = False
    _parent_disposed: bool = False

    @property
    def names(self) -> tuple[str, ...]:
        self._require_open()
        return tuple(entry.name for entry in self._entries)

    def read_bytes(self, name: str) -> bytes:
        self._require_open()
        for entry in self._entries:
            if entry.name == name:
                return entry.raw
        raise KeyError(name)

    def _require_open(self) -> None:
        if self._closed:
            raise GeneratorError("generated directory snapshot is closed")

    def close(self) -> None:
        if self._directory_disposed and self._parent_disposed:
            return
        self._closed = True
        cleanup_errors: list[BaseException] = []
        if not self._directory_disposed:
            self._directory_disposed = True
            try:
                os.close(self._directory.descriptor)
            except BaseException as error:
                cleanup_errors.append(error)
        if not self._parent_disposed:
            try:
                fcntl.flock(self._parent.descriptor, fcntl.LOCK_UN)
            except BaseException as error:
                cleanup_errors.append(error)
            self._parent_disposed = True
            try:
                os.close(self._parent.descriptor)
            except BaseException as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            primary_error, *additional_errors = cleanup_errors
            for cleanup_error in additional_errors:
                primary_error.add_note(f"additional snapshot cleanup failure: {cleanup_error}")
            raise primary_error

    def __enter__(self) -> GeneratedDirectorySnapshot:
        self._require_open()
        return self

    def __exit__(
        self,
        exception_type: object,
        exception: object,
        traceback: object,
    ) -> None:
        del exception_type, traceback
        if isinstance(exception, BaseException):
            try:
                self.close()
            except BaseException as cleanup_error:
                exception.add_note(f"generated snapshot cleanup failure: {cleanup_error}")
            return
        self.close()


def _closed_generated_names(names: Sequence[str]) -> tuple[str, ...]:
    result = tuple(names)
    if (
        not result
        or len(result) > MAX_GENERATED_DIRECTORY_FILES
        or len(set(result)) != len(result)
        or result != tuple(sorted(result))
    ):
        raise GeneratorError("generated directory names must be unique, sorted, and bounded")
    for name in result:
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,127}", name):
            raise GeneratorError("generated directory contains an unsafe artifact name")
        if Path(name).name != name or "\\" in name:
            raise GeneratorError("generated directory artifact must be one basename")
    return result


def _validated_directory_render(
    rendered: Mapping[str, bytes],
    expected_names: tuple[str, ...],
) -> dict[str, bytes]:
    if tuple(sorted(rendered)) != expected_names:
        raise GeneratorError("generated directory render inventory is not exact")
    result: dict[str, bytes] = {}
    total_bytes = 0
    for name in expected_names:
        value = rendered[name]
        if type(value) is not bytes or not 1 <= len(value) <= MAX_GENERATED_BYTES:
            raise GeneratorError("generated directory artifact byte limit exceeded")
        total_bytes += len(value)
        if total_bytes > MAX_GENERATED_DIRECTORY_BYTES:
            raise GeneratorError("generated directory total byte limit exceeded")
        result[name] = value
    return result


def _render_directory_twice(
    renderer: DirectoryRenderer,
    expected_names: tuple[str, ...],
) -> dict[str, bytes]:
    first = _validated_directory_render(renderer(), expected_names)
    second = _validated_directory_render(renderer(), expected_names)
    if first != second:
        raise GeneratorError("nondeterministic generated directory render")
    return first


def _native_function(name: str) -> ctypes._CFuncPtr:  # type: ignore[name-defined]
    function = getattr(ctypes.CDLL(None, use_errno=True), name, None)
    if function is None:
        raise GeneratorError(f"required atomic directory primitive is unavailable: {name}")
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    return function


def _require_directory_transaction_platform() -> None:
    if not hasattr(fcntl, "flock"):
        raise GeneratorError("directory flock is unavailable")
    if sys.platform == "darwin":
        _native_function("renameatx_np")
    elif sys.platform.startswith("linux"):
        _native_function("renameat2")
    else:
        raise GeneratorError("atomic generated-directory publication is unsupported")


def _require_supported_private_directory_umask(parent_fd: int) -> None:
    """Probe mkdir permission semantics on the exact bound creation parent."""

    flags = (
        os.O_RDONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor: int | None = None
    probe_name = ""
    for _ in range(8):
        probe_name = f".tuntun-directory-mode-probe.{secrets.token_hex(16)}"
        try:
            descriptor = os.open(probe_name, flags, stat.S_IRUSR, dir_fd=parent_fd)
        except FileExistsError:
            continue
        break
    if descriptor is None:
        raise GeneratorError("could not reserve a private directory-mode probe")

    primary_error: BaseException | None = None
    try:
        os.unlink(probe_name, dir_fd=parent_fd)
    except BaseException as error:
        primary_error = error

    if primary_error is None:
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 0
                or stat.S_IMODE(metadata.st_mode) != stat.S_IRUSR
                or _directory_has_extended_acl(descriptor)
            ):
                raise GeneratorError(
                    "process umask and creation-parent ACLs must preserve an owner-only "
                    "readable probe"
                )
        except BaseException as error:
            primary_error = error

    cleanup_errors: list[BaseException] = []
    try:
        os.close(descriptor)
    except BaseException as error:
        cleanup_errors.append(error)

    if primary_error is not None:
        for cleanup_error in cleanup_errors:
            primary_error.add_note(f"directory-mode probe cleanup failure: {cleanup_error}")
        raise primary_error
    if cleanup_errors:
        cleanup_error, *additional_errors = cleanup_errors
        for additional_error in additional_errors:
            cleanup_error.add_note(
                f"additional directory-mode probe cleanup failure: {additional_error}"
            )
        raise cleanup_error


def _require_supported_linux_acl_filesystem_magic(magic: int) -> None:
    if magic not in LINUX_POSIX_ACL_FILESYSTEM_MAGICS:
        raise GeneratorError(f"unsupported Linux filesystem ACL semantics: 0x{magic:x}")


def _classify_linux_acl_attribute(attribute: bytes) -> Literal["posix", "other"]:
    if attribute in LINUX_POSIX_ACL_ATTRIBUTES:
        return "posix"
    normalized = attribute.lower()
    if normalized.startswith((b"system.", b"security.", b"trusted.")) and b"acl" in normalized:
        raise GeneratorError(
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
        raise GeneratorError(
            f"creation-parent filesystem inspection failed: {os.strerror(error_number)}"
        )
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
            raise GeneratorError(
                f"creation-parent ACL inspection failed: {os.strerror(error_number)}"
            )
        if required == 0:
            return ()
        if required > MAX_LINUX_XATTR_LIST_BYTES:
            raise GeneratorError("creation-parent extended-attribute inventory is too large")
        buffer = ctypes.create_string_buffer(required)
        ctypes.set_errno(0)
        actual = lister(descriptor, buffer, required)
        if actual < 0:
            error_number = ctypes.get_errno()
            if error_number == errno.ERANGE:
                continue
            raise GeneratorError(
                f"creation-parent ACL inspection failed: {os.strerror(error_number)}"
            )
        if actual == 0 or actual > required:
            raise GeneratorError("creation-parent ACL inventory changed during inspection")
        raw_names = buffer.raw[:actual]
        if not raw_names.endswith(b"\0"):
            raise GeneratorError("creation-parent ACL inventory is malformed")
        names = tuple(raw_names[:-1].split(b"\0"))
        if not names or any(not name for name in names):
            raise GeneratorError("creation-parent ACL inventory is malformed")
        return names
    raise GeneratorError("creation-parent ACL inventory changed during inspection")


def _directory_has_extended_acl(descriptor: int) -> bool:
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        getter = library.acl_get_fd_np
        getter.argtypes = [ctypes.c_int, ctypes.c_int]
        getter.restype = ctypes.c_void_p
        ctypes.set_errno(0)
        acl_pointer = getter(descriptor, 0x00000100)
        if acl_pointer is None:
            error_number = ctypes.get_errno()
            if error_number == errno.ENOENT:
                return False
            raise GeneratorError(
                f"creation-parent ACL inspection failed: {os.strerror(error_number)}"
            )
        freer = library.acl_free
        freer.argtypes = [ctypes.c_void_p]
        freer.restype = ctypes.c_int
        if freer(acl_pointer) != 0:
            error_number = ctypes.get_errno()
            raise GeneratorError(f"creation-parent ACL release failed: {os.strerror(error_number)}")
        return True
    if sys.platform.startswith("linux"):
        magic = _linux_filesystem_magic(library, descriptor)
        _require_supported_linux_acl_filesystem_magic(magic)
        for attribute in _linux_extended_attribute_names(library, descriptor):
            if _classify_linux_acl_attribute(attribute) == "posix":
                return True
        return False
    raise GeneratorError("directory ACL inspection is unsupported")


def _require_owner_controlled_creation_parent(parent_fd: int) -> None:
    metadata = os.fstat(parent_fd)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or _directory_has_extended_acl(parent_fd)
    ):
        raise GeneratorError(
            "private directory creation parent must be owner-controlled, ACL-free, and not "
            "shared-writable"
        )


def _native_rename(
    source_parent_fd: int,
    source_name: str,
    destination_parent_fd: int,
    destination_name: str,
    *,
    exchange: bool,
) -> None:
    if sys.platform == "darwin":
        function = _native_function("renameatx_np")
        flag = DARWIN_RENAME_SWAP if exchange else DARWIN_RENAME_EXCL
    elif sys.platform.startswith("linux"):
        function = _native_function("renameat2")
        flag = LINUX_RENAME_EXCHANGE if exchange else LINUX_RENAME_NOREPLACE
    else:
        raise GeneratorError("atomic generated-directory publication is unsupported")
    result = function(
        source_parent_fd,
        os.fsencode(source_name),
        destination_parent_fd,
        os.fsencode(destination_name),
        flag,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        unsupported = {
            errno.EINVAL,
            errno.ENOSYS,
            getattr(errno, "ENOTSUP", errno.EINVAL),
            getattr(errno, "EOPNOTSUPP", errno.EINVAL),
        }
        if error_number in unsupported:
            raise GeneratorError("filesystem lacks required atomic directory semantics")
        raise OSError(error_number, os.strerror(error_number))


def _atomic_exchange(
    source_parent_fd: int,
    source_name: str,
    destination_parent_fd: int,
    destination_name: str,
) -> None:
    _native_rename(
        source_parent_fd,
        source_name,
        destination_parent_fd,
        destination_name,
        exchange=True,
    )


def _atomic_noreplace(
    source_parent_fd: int,
    source_name: str,
    destination_parent_fd: int,
    destination_name: str,
) -> None:
    _native_rename(
        source_parent_fd,
        source_name,
        destination_parent_fd,
        destination_name,
        exchange=False,
    )


def _transaction_checkpoint(name: str) -> None:
    """Deterministic failure-injection seam; production deliberately does nothing."""

    del name


def _lock_output_parent(parent: OutputParent, *, exclusive: bool) -> None:
    operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    try:
        fcntl.flock(parent.descriptor, operation)
    except OSError as error:
        raise GeneratorError("generated output parent cannot be locked") from error
    if not _output_parent_is_current(parent):
        raise GeneratorError("generated output parent changed while locking")


def _require_output_parent_current(parent: OutputParent) -> None:
    if not _output_parent_is_current(parent):
        raise GeneratorError("generated output parent changed during transaction")


def _close_output_parent(parent: OutputParent) -> None:
    try:
        fcntl.flock(parent.descriptor, fcntl.LOCK_UN)
    finally:
        os.close(parent.descriptor)


def _validate_directory_metadata(metadata: os.stat_result, *, private: bool) -> None:
    mode = stat.S_IMODE(metadata.st_mode)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
        raise GeneratorError("generated directory has an unsafe type or owner")
    if private:
        if mode != PRIVATE_DIRECTORY_MODE:
            raise GeneratorError("private generated directory mode is not 0700")
        return
    if mode & 0o7022 or not mode & stat.S_IXUSR:
        raise GeneratorError("published generated directory mode is unsafe")


def _validate_file_metadata(metadata: os.stat_result, *, private: bool) -> None:
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
    ):
        raise GeneratorError("generated entry has an unsafe type, owner, or link count")
    if private:
        if mode != PRIVATE_FILE_MODE:
            raise GeneratorError("private generated entry mode is not 0600")
        return
    if mode & 0o7111 or mode & 0o022 or not mode & stat.S_IRUSR:
        raise GeneratorError("published generated entry mode is unsafe")


def _descriptor_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _open_created_private_directory(
    parent_fd: int,
    name: str,
) -> tuple[int, os.stat_result]:
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (
        not stat.S_ISDIR(before.st_mode)
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) & ~PRIVATE_DIRECTORY_MODE
    ):
        raise GeneratorError("new private directory has an unsafe type, owner, or mode")
    descriptor = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent_fd,
    )
    try:
        opened = os.fstat(descriptor)
        if (
            _descriptor_identity(before) != _descriptor_identity(opened)
            or not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) & ~PRIVATE_DIRECTORY_MODE
        ):
            raise GeneratorError("new private directory changed during open")
        os.fchmod(descriptor, PRIVATE_DIRECTORY_MODE)
        normalized = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _validate_directory_metadata(normalized, private=True)
        _validate_directory_metadata(named, private=True)
        if _directory_has_extended_acl(descriptor):
            raise GeneratorError("new private directory inherited a discretionary ACL")
        if not (
            _descriptor_identity(before)
            == _descriptor_identity(opened)
            == _descriptor_identity(normalized)
            == _descriptor_identity(named)
        ):
            raise GeneratorError("new private directory changed during normalization")
    except BaseException as validation_error:
        try:
            os.close(descriptor)
        except BaseException as cleanup_error:
            validation_error.add_note(
                f"created-directory validation cleanup failure: {cleanup_error}"
            )
        raise
    return descriptor, normalized


def _open_generated_directory(
    parent_fd: int,
    name: str,
    *,
    private: bool,
) -> GeneratedDirectoryHandle:
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    _validate_directory_metadata(before, private=private)
    descriptor = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent_fd,
    )
    opened = os.fstat(descriptor)
    try:
        _validate_directory_metadata(opened, private=private)
        if _directory_has_extended_acl(descriptor):
            raise GeneratorError("generated directory has a discretionary ACL")
        if _descriptor_identity(before) != _descriptor_identity(opened):
            raise GeneratorError("generated directory changed during open")
    except BaseException as validation_error:
        try:
            os.close(descriptor)
        except BaseException as cleanup_error:
            validation_error.add_note(
                f"generated-directory validation cleanup failure: {cleanup_error}"
            )
        raise
    return GeneratedDirectoryHandle(
        name=name,
        descriptor=descriptor,
        device=opened.st_dev,
        inode=opened.st_ino,
    )


def _open_optional_generated_directory(
    parent_fd: int,
    name: str,
    *,
    private: bool,
) -> GeneratedDirectoryHandle | None:
    try:
        return _open_generated_directory(parent_fd, name, private=private)
    except FileNotFoundError:
        return None


def _create_generated_directory(
    parent_fd: int,
    name: str,
) -> GeneratedDirectoryHandle:
    _require_owner_controlled_creation_parent(parent_fd)
    _require_supported_private_directory_umask(parent_fd)
    os.mkdir(name, mode=PRIVATE_DIRECTORY_MODE, dir_fd=parent_fd)
    descriptor, opened = _open_created_private_directory(parent_fd, name)
    return GeneratedDirectoryHandle(
        name=name,
        descriptor=descriptor,
        device=opened.st_dev,
        inode=opened.st_ino,
    )


def _directory_is_named(
    parent_fd: int,
    name: str,
    handle: GeneratedDirectoryHandle,
) -> bool:
    try:
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        opened = os.fstat(handle.descriptor)
    except OSError:
        return False
    return (
        stat.S_ISDIR(named.st_mode)
        and _descriptor_identity(named) == (handle.device, handle.inode)
        and _descriptor_identity(opened) == (handle.device, handle.inode)
    )


def _read_generated_entry(
    handle: GeneratedDirectoryHandle,
    name: str,
    *,
    private: bool,
) -> GeneratedDirectoryEntry:
    before = os.stat(name, dir_fd=handle.descriptor, follow_symlinks=False)
    _validate_file_metadata(before, private=private)
    descriptor = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0),
        dir_fd=handle.descriptor,
    )
    try:
        opened = os.fstat(descriptor)
        _validate_file_metadata(opened, private=private)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            stat.S_IMODE(before.st_mode),
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        opened_identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_uid,
            stat.S_IMODE(opened.st_mode),
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        if before_identity != opened_identity or opened.st_size > MAX_GENERATED_BYTES:
            raise GeneratorError("generated entry changed during open")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise GeneratorError("generated entry was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise GeneratorError("generated entry grew during read")
        final = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    named = os.stat(name, dir_fd=handle.descriptor, follow_symlinks=False)
    identity = (
        opened.st_dev,
        opened.st_ino,
        opened.st_uid,
        stat.S_IMODE(opened.st_mode),
        opened.st_nlink,
        opened.st_size,
        opened.st_mtime_ns,
        opened.st_ctime_ns,
    )
    if identity != (
        final.st_dev,
        final.st_ino,
        final.st_uid,
        stat.S_IMODE(final.st_mode),
        final.st_nlink,
        final.st_size,
        final.st_mtime_ns,
        final.st_ctime_ns,
    ) or identity != (
        named.st_dev,
        named.st_ino,
        named.st_uid,
        stat.S_IMODE(named.st_mode),
        named.st_nlink,
        named.st_size,
        named.st_mtime_ns,
        named.st_ctime_ns,
    ):
        raise GeneratorError("generated entry changed during read")
    raw = b"".join(chunks)
    return GeneratedDirectoryEntry(
        name=name,
        raw=raw,
        sha256=hashlib.sha256(raw).hexdigest(),
        mode=stat.S_IMODE(opened.st_mode),
        device=opened.st_dev,
        inode=opened.st_ino,
        owner=opened.st_uid,
        links=opened.st_nlink,
        size=opened.st_size,
        modified_ns=opened.st_mtime_ns,
        changed_ns=opened.st_ctime_ns,
    )


def _snapshot_generated_directory(
    handle: GeneratedDirectoryHandle,
    expected_names: tuple[str, ...],
    *,
    require_exact: bool,
    private: bool,
) -> tuple[GeneratedDirectoryEntry, ...]:
    before = os.fstat(handle.descriptor)
    _validate_directory_metadata(before, private=private)
    if _descriptor_identity(before) != (handle.device, handle.inode):
        raise GeneratorError("generated directory descriptor changed")
    names = tuple(sorted(os.listdir(handle.descriptor)))
    if len(names) > MAX_GENERATED_DIRECTORY_FILES or not set(names) <= set(expected_names):
        raise GeneratorError("generated directory contains an unexpected entry")
    if require_exact and names != expected_names:
        raise GeneratorError("generated directory inventory is incomplete")
    result = tuple(_read_generated_entry(handle, name, private=private) for name in names)
    if tuple(sorted(os.listdir(handle.descriptor))) != names:
        raise GeneratorError("generated directory changed during scan")
    final = os.fstat(handle.descriptor)
    _validate_directory_metadata(final, private=private)
    if _descriptor_identity(final) != (handle.device, handle.inode):
        raise GeneratorError("generated directory changed during scan")
    if sum(entry.size for entry in result) > MAX_GENERATED_DIRECTORY_BYTES:
        raise GeneratorError("generated directory total byte limit exceeded")
    return result


def _tree_digest(
    directory_metadata: tuple[int, int, int, int],
    entries: tuple[GeneratedDirectoryEntry, ...],
) -> str:
    document = {
        "directory": list(directory_metadata),
        "entries": [
            {
                "device": entry.device,
                "changed_ns": entry.changed_ns,
                "inode": entry.inode,
                "links": entry.links,
                "mode": entry.mode,
                "modified_ns": entry.modified_ns,
                "name": entry.name,
                "owner": entry.owner,
                "sha256": entry.sha256,
                "size": entry.size,
            }
            for entry in entries
        ],
    }
    raw = json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _receipt_for(
    handle: GeneratedDirectoryHandle,
    entries: tuple[GeneratedDirectoryEntry, ...],
) -> GeneratedDirectoryReceipt:
    metadata = os.fstat(handle.descriptor)
    directory_metadata = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
    )
    return GeneratedDirectoryReceipt(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        owner=metadata.st_uid,
        mode=stat.S_IMODE(metadata.st_mode),
        tree_sha256=_tree_digest(directory_metadata, entries),
        entries=entries,
    )


def _entry_identity(entry: GeneratedDirectoryEntry) -> tuple[object, ...]:
    return (
        entry.name,
        entry.sha256,
        entry.mode,
        entry.device,
        entry.inode,
        entry.owner,
        entry.links,
        entry.size,
        entry.modified_ns,
        entry.changed_ns,
    )


def _receipt_matches(
    handle: GeneratedDirectoryHandle,
    entries: tuple[GeneratedDirectoryEntry, ...],
    receipt: GeneratedDirectoryReceipt,
    *,
    allow_subset: bool,
) -> bool:
    metadata = os.fstat(handle.descriptor)
    if (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
    ) != (receipt.device, receipt.inode, receipt.owner, receipt.mode):
        return False
    expected = {entry.name: entry for entry in receipt.entries}
    if (allow_subset and not set(entry.name for entry in entries) <= set(expected)) or (
        not allow_subset and tuple(entry.name for entry in entries) != tuple(expected)
    ):
        return False
    if any(_entry_identity(entry) != _entry_identity(expected[entry.name]) for entry in entries):
        return False
    if allow_subset and len(entries) != len(receipt.entries):
        return True
    return receipt.tree_sha256 == _tree_digest(
        (receipt.device, receipt.inode, receipt.owner, receipt.mode),
        entries,
    )


def _write_generated_entry(
    handle: GeneratedDirectoryHandle,
    name: str,
    raw: bytes,
) -> None:
    descriptor = os.open(
        name,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        PRIVATE_FILE_MODE,
        dir_fd=handle.descriptor,
    )
    try:
        os.fchmod(descriptor, PRIVATE_FILE_MODE)
        _transaction_checkpoint(
            "intent-file-opened" if name == INTENT_TEMP_NAME else "stage-file-opened"
        )
        _write_all(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _populate_generated_directory(
    handle: GeneratedDirectoryHandle,
    rendered: Mapping[str, bytes],
) -> None:
    for name in sorted(rendered):
        _write_generated_entry(handle, name, rendered[name])
        _transaction_checkpoint("stage-entry")
    os.fsync(handle.descriptor)


def _receipt_json(receipt: GeneratedDirectoryReceipt) -> dict[str, object]:
    return {
        "device": receipt.device,
        "entries": [
            {
                "device": entry.device,
                "changed_ns": entry.changed_ns,
                "inode": entry.inode,
                "links": entry.links,
                "mode": entry.mode,
                "modified_ns": entry.modified_ns,
                "name": entry.name,
                "owner": entry.owner,
                "sha256": entry.sha256,
                "size": entry.size,
            }
            for entry in receipt.entries
        ],
        "inode": receipt.inode,
        "mode": receipt.mode,
        "owner": receipt.owner,
        "tree_sha256": receipt.tree_sha256,
    }


def _intent_bytes(intent: GeneratedDirectoryIntent) -> bytes:
    document = {
        "baseline": None if intent.baseline is None else _receipt_json(intent.baseline),
        "candidate": _receipt_json(intent.candidate),
        "expected_names": list(intent.expected_names),
        "output_name": intent.output_name,
        "version": INTENT_VERSION,
    }
    return (
        json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")


def _exact_mapping(value: object, keys: frozenset[str], label: str) -> dict[str, object]:
    if (
        not isinstance(value, dict)
        or set(value) != keys
        or not all(isinstance(key, str) for key in value)
    ):
        raise GeneratorError(f"transaction {label} is malformed")
    return value


def _exact_int(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise GeneratorError(f"transaction {label} is malformed")
    return value


def _receipt_from_json(value: object) -> GeneratedDirectoryReceipt:
    document = _exact_mapping(
        value,
        frozenset({"device", "entries", "inode", "mode", "owner", "tree_sha256"}),
        "receipt",
    )
    raw_entries = document["entries"]
    if not isinstance(raw_entries, list):
        raise GeneratorError("transaction receipt entries are malformed")
    entries: list[GeneratedDirectoryEntry] = []
    for raw_entry in raw_entries:
        entry = _exact_mapping(
            raw_entry,
            frozenset(
                {
                    "changed_ns",
                    "device",
                    "inode",
                    "links",
                    "mode",
                    "modified_ns",
                    "name",
                    "owner",
                    "sha256",
                    "size",
                }
            ),
            "entry receipt",
        )
        name = entry["name"]
        digest = entry["sha256"]
        if (
            not isinstance(name, str)
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise GeneratorError("transaction entry receipt is malformed")
        entries.append(
            GeneratedDirectoryEntry(
                name=name,
                raw=b"",
                sha256=digest,
                mode=_exact_int(entry["mode"], "entry mode"),
                device=_exact_int(entry["device"], "entry device"),
                inode=_exact_int(entry["inode"], "entry inode"),
                owner=_exact_int(entry["owner"], "entry owner"),
                links=_exact_int(entry["links"], "entry links"),
                size=_exact_int(entry["size"], "entry size"),
                modified_ns=_exact_int(entry["modified_ns"], "entry modified time"),
                changed_ns=_exact_int(entry["changed_ns"], "entry changed time"),
            )
        )
    names = tuple(item.name for item in entries)
    if names != tuple(sorted(names)) or len(names) != len(set(names)):
        raise GeneratorError("transaction receipt inventory is malformed")
    tree_digest = document["tree_sha256"]
    if not isinstance(tree_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", tree_digest):
        raise GeneratorError("transaction tree digest is malformed")
    return GeneratedDirectoryReceipt(
        device=_exact_int(document["device"], "directory device"),
        inode=_exact_int(document["inode"], "directory inode"),
        owner=_exact_int(document["owner"], "directory owner"),
        mode=_exact_int(document["mode"], "directory mode"),
        tree_sha256=tree_digest,
        entries=tuple(entries),
    )


def _reject_duplicate_json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GeneratorError("transaction intent contains a duplicate key")
        result[key] = value
    return result


def _intent_from_bytes(raw: bytes) -> GeneratedDirectoryIntent:
    try:
        parsed = json.loads(raw, object_pairs_hook=_reject_duplicate_json_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GeneratorError("transaction intent is not strict JSON") from error
    document = _exact_mapping(
        parsed,
        frozenset({"baseline", "candidate", "expected_names", "output_name", "version"}),
        "intent",
    )
    if document["version"] != INTENT_VERSION or not isinstance(document["output_name"], str):
        raise GeneratorError("transaction intent version or output is malformed")
    names_value = document["expected_names"]
    if not isinstance(names_value, list) or not all(isinstance(name, str) for name in names_value):
        raise GeneratorError("transaction intent names are malformed")
    intent = GeneratedDirectoryIntent(
        output_name=document["output_name"],
        expected_names=_closed_generated_names(names_value),
        baseline=(
            None if document["baseline"] is None else _receipt_from_json(document["baseline"])
        ),
        candidate=_receipt_from_json(document["candidate"]),
    )
    if _intent_bytes(intent) != raw:
        raise GeneratorError("transaction intent is not canonical")
    return intent


def _write_transaction_intent(
    transaction: GeneratedDirectoryHandle,
    intent: GeneratedDirectoryIntent,
) -> None:
    _write_generated_entry(transaction, INTENT_TEMP_NAME, _intent_bytes(intent))
    os.fsync(transaction.descriptor)
    _transaction_checkpoint("intent-temporary")
    _atomic_noreplace(
        transaction.descriptor,
        INTENT_TEMP_NAME,
        transaction.descriptor,
        INTENT_NAME,
    )
    os.fsync(transaction.descriptor)


def _rendered_entries_are_authorized_prefixes(
    entries: tuple[GeneratedDirectoryEntry, ...],
    rendered: Mapping[str, bytes],
) -> bool:
    return all(
        entry.mode == PRIVATE_FILE_MODE
        and rendered[entry.name].startswith(entry.raw)
        and entry.sha256 == hashlib.sha256(entry.raw).hexdigest()
        for entry in entries
    )


def _unlink_exact_entry(
    parent_fd: int,
    entry: GeneratedDirectoryEntry,
) -> None:
    current = os.stat(entry.name, dir_fd=parent_fd, follow_symlinks=False)
    current_identity = (
        current.st_dev,
        current.st_ino,
        current.st_uid,
        stat.S_IMODE(current.st_mode),
        current.st_nlink,
        current.st_size,
        current.st_mtime_ns,
        current.st_ctime_ns,
    )
    expected_identity = (
        entry.device,
        entry.inode,
        entry.owner,
        entry.mode,
        entry.links,
        entry.size,
        entry.modified_ns,
        entry.changed_ns,
    )
    if current_identity != expected_identity:
        raise GeneratorError("transaction entry changed before cleanup")
    os.unlink(entry.name, dir_fd=parent_fd)


def _remove_empty_directory(
    parent_fd: int,
    name: str,
    handle: GeneratedDirectoryHandle,
) -> None:
    if os.listdir(handle.descriptor):
        raise GeneratorError("transaction directory is not empty")
    if not _directory_is_named(parent_fd, name, handle):
        raise GeneratorError("transaction directory changed before cleanup")
    os.rmdir(name, dir_fd=parent_fd)
    os.fsync(parent_fd)


def _remove_receipted_directory(
    parent_fd: int,
    name: str,
    handle: GeneratedDirectoryHandle,
    receipt: GeneratedDirectoryReceipt,
) -> None:
    expected_names = tuple(entry.name for entry in receipt.entries)
    private = receipt.mode == PRIVATE_DIRECTORY_MODE and all(
        entry.mode == PRIVATE_FILE_MODE for entry in receipt.entries
    )
    entries = _snapshot_generated_directory(
        handle,
        expected_names,
        require_exact=False,
        private=private,
    )
    if not _receipt_matches(handle, entries, receipt, allow_subset=True):
        raise GeneratorError("transaction cleanup receipt no longer matches")
    for entry in entries:
        _unlink_exact_entry(handle.descriptor, entry)
        os.fsync(handle.descriptor)
        _transaction_checkpoint("cleanup-entry")
    _remove_empty_directory(parent_fd, name, handle)


def _transaction_name(output_name: str) -> str:
    return f".{output_name}.transaction"


def _open_transaction(parent: OutputParent, output_name: str) -> GeneratedDirectoryHandle | None:
    return _open_optional_generated_directory(
        parent.descriptor,
        _transaction_name(output_name),
        private=True,
    )


def _open_output(
    parent: OutputParent,
    output_name: str,
) -> GeneratedDirectoryHandle | None:
    return _open_optional_generated_directory(parent.descriptor, output_name, private=False)


def _public_receipt(
    parent: OutputParent,
    output_name: str,
    expected_names: tuple[str, ...],
) -> tuple[GeneratedDirectoryHandle, GeneratedDirectoryReceipt] | None:
    handle = _open_output(parent, output_name)
    if handle is None:
        return None
    try:
        entries = _snapshot_generated_directory(
            handle,
            expected_names,
            require_exact=True,
            private=False,
        )
        if not _directory_is_named(parent.descriptor, output_name, handle):
            raise GeneratorError("published generated directory changed during scan")
        return handle, _receipt_for(handle, entries)
    except Exception:
        os.close(handle.descriptor)
        raise


def _remove_unjournaled_transaction(
    parent: OutputParent,
    transaction: GeneratedDirectoryHandle,
    output_name: str,
    expected_names: tuple[str, ...],
    rendered: Mapping[str, bytes],
) -> None:
    root_names = tuple(sorted(os.listdir(transaction.descriptor)))
    if not set(root_names) <= {INTENT_TEMP_NAME, STAGE_NAME}:
        raise GeneratorError("unjournaled transaction inventory is ambiguous")
    stage = _open_optional_generated_directory(
        transaction.descriptor,
        STAGE_NAME,
        private=True,
    )
    entries: tuple[GeneratedDirectoryEntry, ...] = ()
    temporary: GeneratedDirectoryEntry | None = None
    try:
        if stage is not None:
            entries = _snapshot_generated_directory(
                stage,
                expected_names,
                require_exact=INTENT_TEMP_NAME in root_names,
                private=True,
            )
            if not _rendered_entries_are_authorized_prefixes(entries, rendered):
                raise GeneratorError("unjournaled transaction candidate is ambiguous")
        if INTENT_TEMP_NAME in root_names:
            if stage is None:
                raise GeneratorError("unjournaled intent has no exact candidate")
            temporary = _read_generated_entry(
                transaction,
                INTENT_TEMP_NAME,
                private=True,
            )
            baseline_pair = _public_receipt(parent, output_name, expected_names)
            try:
                baseline_receipt = None if baseline_pair is None else baseline_pair[1]
                expected_intent = _intent_bytes(
                    GeneratedDirectoryIntent(
                        output_name=output_name,
                        expected_names=expected_names,
                        baseline=baseline_receipt,
                        candidate=_receipt_for(stage, entries),
                    )
                )
                if not expected_intent.startswith(temporary.raw):
                    raise GeneratorError("unjournaled intent prefix is ambiguous")
            finally:
                if baseline_pair is not None:
                    os.close(baseline_pair[0].descriptor)
        if stage is not None:
            for entry in entries:
                _unlink_exact_entry(stage.descriptor, entry)
            os.fsync(stage.descriptor)
            _remove_empty_directory(transaction.descriptor, STAGE_NAME, stage)
        if temporary is not None:
            _unlink_exact_entry(transaction.descriptor, temporary)
            os.fsync(transaction.descriptor)
        _remove_empty_directory(
            parent.descriptor,
            transaction.name,
            transaction,
        )
    finally:
        if stage is not None:
            os.close(stage.descriptor)


def _read_transaction_intent(
    transaction: GeneratedDirectoryHandle,
) -> tuple[GeneratedDirectoryIntent | None, GeneratedDirectoryEntry | None]:
    names = tuple(sorted(os.listdir(transaction.descriptor)))
    if INTENT_NAME not in names:
        return None, None
    entry = _read_generated_entry(transaction, INTENT_NAME, private=True)
    return _intent_from_bytes(entry.raw), entry


def _reconcile_transaction_locked(
    parent: OutputParent,
    output_name: str,
    expected_names: tuple[str, ...],
    rendered: Mapping[str, bytes],
) -> str:
    transaction = _open_transaction(parent, output_name)
    if transaction is None:
        return "none"
    output: GeneratedDirectoryHandle | None = None
    stage: GeneratedDirectoryHandle | None = None
    try:
        intent, intent_entry = _read_transaction_intent(transaction)
        if intent is None:
            _remove_unjournaled_transaction(
                parent,
                transaction,
                output_name,
                expected_names,
                rendered,
            )
            return "pre"
        if intent.output_name != output_name or intent.expected_names != expected_names:
            raise GeneratorError("transaction intent targets a different output")
        root_names = tuple(sorted(os.listdir(transaction.descriptor)))
        if not set(root_names) <= {INTENT_NAME, STAGE_NAME}:
            raise GeneratorError("journaled transaction inventory is ambiguous")
        output = _open_output(parent, output_name)
        output_entries: tuple[GeneratedDirectoryEntry, ...] | None = None
        if output is not None:
            output_entries = _snapshot_generated_directory(
                output,
                expected_names,
                require_exact=True,
                private=False,
            )
            if not _directory_is_named(parent.descriptor, output_name, output):
                raise GeneratorError("transaction output changed during recovery")
        stage = _open_optional_generated_directory(
            transaction.descriptor,
            STAGE_NAME,
            private=False,
        )
        stage_entries: tuple[GeneratedDirectoryEntry, ...] | None = None
        if stage is not None:
            expected_stage_names = tuple(
                entry.name
                for entry in (
                    intent.candidate.entries
                    if intent.baseline is None
                    else (intent.candidate.entries + intent.baseline.entries)
                )
            )
            expected_stage_names = tuple(sorted(set(expected_stage_names)))
            stage_entries = _snapshot_generated_directory(
                stage,
                expected_stage_names,
                require_exact=False,
                private=False,
            )

        baseline_output = (intent.baseline is None and output is None) or (
            intent.baseline is not None
            and output is not None
            and output_entries is not None
            and _receipt_matches(output, output_entries, intent.baseline, allow_subset=False)
        )
        candidate_stage = stage is None or (
            stage_entries is not None
            and _receipt_matches(stage, stage_entries, intent.candidate, allow_subset=True)
        )
        candidate_output = (
            output is not None
            and output_entries is not None
            and _receipt_matches(output, output_entries, intent.candidate, allow_subset=False)
        )
        baseline_stage = stage is None or (
            intent.baseline is not None
            and stage is not None
            and stage_entries is not None
            and _receipt_matches(stage, stage_entries, intent.baseline, allow_subset=True)
        )
        cleanup_receipt: GeneratedDirectoryReceipt | None
        if baseline_output and candidate_stage:
            state = "pre"
            cleanup_receipt = intent.candidate
        elif candidate_output and baseline_stage:
            state = "post"
            cleanup_receipt = intent.baseline
        else:
            raise GeneratorError("transaction state is ambiguous")

        if stage is not None:
            if cleanup_receipt is None:
                raise GeneratorError("transaction stage has no cleanup authority")
            _remove_receipted_directory(
                transaction.descriptor,
                STAGE_NAME,
                stage,
                cleanup_receipt,
            )
            os.close(stage.descriptor)
            stage = None
        if intent_entry is None:
            raise GeneratorError("transaction intent identity is unavailable")
        _unlink_exact_entry(transaction.descriptor, intent_entry)
        os.fsync(transaction.descriptor)
        _remove_empty_directory(
            parent.descriptor,
            _transaction_name(output_name),
            transaction,
        )
        return state
    finally:
        if stage is not None:
            os.close(stage.descriptor)
        if output is not None:
            os.close(output.descriptor)
        os.close(transaction.descriptor)


def _write_generated_directory(
    output_directory: Path,
    expected_names: tuple[str, ...],
    rendered: Mapping[str, bytes],
) -> None:
    _require_directory_transaction_platform()
    output = lexical_path(output_directory)
    parent = _bind_output_parent(output, create_missing=True)
    baseline_handle: GeneratedDirectoryHandle | None = None
    transaction: GeneratedDirectoryHandle | None = None
    stage: GeneratedDirectoryHandle | None = None
    candidate_receipt: GeneratedDirectoryReceipt | None = None
    exclusive_lock_acquired = False
    try:
        _require_owner_controlled_creation_parent(parent.descriptor)
        _lock_output_parent(parent, exclusive=True)
        exclusive_lock_acquired = True
        _reconcile_transaction_locked(parent, output.name, expected_names, rendered)
        baseline_pair = _public_receipt(parent, output.name, expected_names)
        baseline_receipt: GeneratedDirectoryReceipt | None = None
        if baseline_pair is not None:
            baseline_handle, baseline_receipt = baseline_pair
        transaction = _create_generated_directory(
            parent.descriptor,
            _transaction_name(output.name),
        )
        transaction.name = _transaction_name(output.name)
        _transaction_checkpoint("transaction-created")
        stage = _create_generated_directory(transaction.descriptor, STAGE_NAME)
        _transaction_checkpoint("stage-created")
        _populate_generated_directory(stage, rendered)
        stage_entries = _snapshot_generated_directory(
            stage,
            expected_names,
            require_exact=True,
            private=True,
        )
        if any(entry.raw != rendered[entry.name] for entry in stage_entries):
            raise GeneratorError("private generated directory verification failed")
        candidate_receipt = _receipt_for(stage, stage_entries)
        intent = GeneratedDirectoryIntent(
            output_name=output.name,
            expected_names=expected_names,
            baseline=baseline_receipt,
            candidate=candidate_receipt,
        )
        _write_transaction_intent(transaction, intent)
        os.fsync(transaction.descriptor)
        os.fsync(parent.descriptor)
        _transaction_checkpoint("prepared")
        current_baseline = _public_receipt(parent, output.name, expected_names)
        try:
            if baseline_receipt is None:
                if current_baseline is not None:
                    raise GeneratorError("absent output appeared before publication")
            else:
                if current_baseline is None or not _receipt_matches(
                    current_baseline[0],
                    _snapshot_generated_directory(
                        current_baseline[0],
                        expected_names,
                        require_exact=True,
                        private=False,
                    ),
                    baseline_receipt,
                    allow_subset=False,
                ):
                    raise GeneratorError("published baseline changed before publication")
        finally:
            if current_baseline is not None:
                os.close(current_baseline[0].descriptor)
        if not _directory_is_named(transaction.descriptor, STAGE_NAME, stage):
            raise GeneratorError("candidate stage changed before publication")
        _require_output_parent_current(parent)
        if baseline_receipt is None:
            _atomic_noreplace(
                transaction.descriptor,
                STAGE_NAME,
                parent.descriptor,
                output.name,
            )
        else:
            _atomic_exchange(
                transaction.descriptor,
                STAGE_NAME,
                parent.descriptor,
                output.name,
            )
        _transaction_checkpoint("committed")
        os.fsync(transaction.descriptor)
        os.fsync(parent.descriptor)
        if (
            _reconcile_transaction_locked(
                parent,
                output.name,
                expected_names,
                rendered,
            )
            != "post"
        ):
            raise GeneratorError("committed transaction did not reconcile as POST")
        _transaction_checkpoint("cleanup-complete")
        _require_output_parent_current(parent)
        final = _public_receipt(parent, output.name, expected_names)
        if final is None or candidate_receipt is None:
            raise GeneratorError("published generated directory is missing")
        try:
            final_entries = _snapshot_generated_directory(
                final[0],
                expected_names,
                require_exact=True,
                private=False,
            )
            if not _receipt_matches(
                final[0],
                final_entries,
                candidate_receipt,
                allow_subset=False,
            ):
                raise GeneratorError("published generated directory changed after commit")
            _require_output_parent_current(parent)
        finally:
            os.close(final[0].descriptor)
    except BaseException as publication_error:
        if exclusive_lock_acquired:
            try:
                _reconcile_transaction_locked(parent, output.name, expected_names, rendered)
            except BaseException as recovery_error:
                publication_error.add_note(f"transaction recovery retained state: {recovery_error}")
        raise
    finally:
        for handle in (stage, transaction, baseline_handle):
            if handle is not None:
                with suppress(OSError):
                    os.close(handle.descriptor)
        if exclusive_lock_acquired:
            _close_output_parent(parent)
        else:
            os.close(parent.descriptor)


def open_generated_directory_snapshot(
    output_directory: Path,
    expected_names: Sequence[str],
) -> GeneratedDirectorySnapshot:
    _require_directory_transaction_platform()
    names = _closed_generated_names(expected_names)
    output = lexical_path(output_directory)
    parent = _bind_output_parent(output, create_missing=False)
    directory: GeneratedDirectoryHandle | None = None
    parent_lock_acquired = False
    try:
        _lock_output_parent(parent, exclusive=False)
        parent_lock_acquired = True
        try:
            os.stat(
                _transaction_name(output.name),
                dir_fd=parent.descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise GeneratorError("generated directory recovery is pending")
        directory = _open_generated_directory(parent.descriptor, output.name, private=False)
        entries = _snapshot_generated_directory(
            directory,
            names,
            require_exact=True,
            private=False,
        )
        if not _directory_is_named(parent.descriptor, output.name, directory):
            raise GeneratorError("published generated directory changed during snapshot")
        _require_output_parent_current(parent)
        return GeneratedDirectorySnapshot(parent, directory, entries)
    except BaseException as snapshot_error:
        cleanup_errors: list[BaseException] = []
        if directory is not None:
            try:
                os.close(directory.descriptor)
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
        if parent_lock_acquired:
            try:
                fcntl.flock(parent.descriptor, fcntl.LOCK_UN)
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
        try:
            os.close(parent.descriptor)
        except BaseException as cleanup_error:
            cleanup_errors.append(cleanup_error)
        for recorded_cleanup_error in cleanup_errors:
            snapshot_error.add_note(f"generated snapshot cleanup failure: {recorded_cleanup_error}")
        raise


def _check_generated_directory(
    output_directory: Path,
    expected_names: tuple[str, ...],
    rendered: Mapping[str, bytes],
) -> bool:
    with open_generated_directory_snapshot(output_directory, expected_names) as snapshot:
        return snapshot.names == expected_names and all(
            snapshot.read_bytes(name) == rendered[name] for name in expected_names
        )


def run_directory_generator(
    *,
    output_directory: Path,
    expected_names: Sequence[str],
    renderer: DirectoryRenderer,
    argv: Sequence[str] | None,
) -> int:
    """Run the maintainer-only fixture writer or its nonmutating check.

    Write mode requires a stable process umask and owner-controlled creation
    parents. Same-EUID local writers are trusted to honor the parent flock.
    """

    try:
        names = _closed_generated_names(expected_names)
        rendered = _render_directory_twice(renderer, names)
        mode = _parse_mode(argv)
        if mode == "check":
            return 0 if _check_generated_directory(output_directory, names, rendered) else 1
        _write_generated_directory(output_directory, names, rendered)
        return 0
    except Exception:
        return 1
