from __future__ import annotations

import json
import os
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
                os.mkdir(part, mode=0o700, dir_fd=current_fd)
                before = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
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
