from __future__ import annotations

import argparse
import importlib
import json
import os
import stat
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn, TypeVar, overload

_Namespace = TypeVar("_Namespace")

MAX_REGULAR_FILE_BYTES = 4 * 1024 * 1024
MAX_WALK_FILES = 4096
MAX_WALK_TOTAL_BYTES = 128 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_CONTAINERS = 100_000
MAX_JSON_TOKENS = 1_000_000
READ_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True, order=True)
class AssuranceFinding:
    path: Path
    code: str
    detail: str | None = None


@dataclass(frozen=True)
class AssuranceResult:
    tool: str
    complete: bool
    findings: tuple[AssuranceFinding, ...]

    def exit_code(self) -> int:
        if not self.complete:
            return 2
        return 1 if self.findings else 0


@dataclass(frozen=True)
class FrozenRegularFile:
    path: Path
    raw: bytes
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


class AssuranceInputError(RuntimeError):
    def __init__(self, path: Path, code: str, detail: str | None = None) -> None:
        super().__init__(code)
        self.path = path
        self.code = code
        self.detail = detail

    def finding(self) -> AssuranceFinding:
        return AssuranceFinding(self.path, self.code, self.detail)


class CsvSet:
    @staticmethod
    def parse(value: str) -> tuple[str, ...]:
        if not value:
            raise argparse.ArgumentTypeError("CSV value must not be empty")
        values = value.split(",")
        if any(not item or item != item.strip() for item in values):
            raise argparse.ArgumentTypeError("CSV values must be nonempty and canonical")
        if len(set(values)) != len(values):
            raise argparse.ArgumentTypeError("CSV values must be unique")
        return tuple(values)


class ClosedArgumentParser(argparse.ArgumentParser):
    def __init__(self, *, prog: str) -> None:
        super().__init__(prog=prog, allow_abbrev=False, add_help=False, exit_on_error=False)

    def error(self, message: str) -> NoReturn:
        raise ValueError(message)

    @overload
    def parse_args(
        self,
        args: Sequence[str] | None = ...,
        namespace: None = ...,
    ) -> argparse.Namespace: ...

    @overload
    def parse_args(
        self,
        args: Sequence[str] | None,
        namespace: _Namespace,
    ) -> _Namespace: ...

    @overload
    def parse_args(self, *, namespace: _Namespace) -> _Namespace: ...

    def parse_args(
        self,
        args: Sequence[str] | None = None,
        namespace: Any = None,
    ) -> Any:
        try:
            return super().parse_args(args, namespace)
        except (argparse.ArgumentError, argparse.ArgumentTypeError) as error:
            raise ValueError(str(error)) from error


def finish(result: AssuranceResult) -> int:
    for finding in sorted(result.findings):
        suffix = "" if finding.detail is None else f": {finding.detail}"
        print(f"{finding.path}: {finding.code}{suffix}")
    if result.complete and not result.findings:
        print(f"{result.tool}: PASS")
    elif not result.complete:
        print(f"{result.tool}: INCOMPLETE")
    return result.exit_code()


def lexical_path(value: str | Path) -> Path:
    return Path(os.path.abspath(os.fspath(value)))


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _raise(path: Path, code: str, detail: str | None = None) -> NoReturn:
    raise AssuranceInputError(path, code, detail)


def _open_directory(path: Path) -> tuple[int, os.stat_result]:
    absolute = lexical_path(path)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    current = os.open(os.path.sep, flags)
    try:
        for index, part in enumerate(absolute.parts[1:]):
            display = Path(os.path.sep).joinpath(*absolute.parts[1 : index + 2])
            before = os.stat(part, dir_fd=current, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode):
                _raise(display, "symlink-input")
            if not stat.S_ISDIR(before.st_mode):
                _raise(display, "not-directory")
            child = os.open(part, flags, dir_fd=current)
            opened = os.fstat(child)
            if _identity(before) != _identity(opened):
                os.close(child)
                _raise(display, "input-changed-during-scan")
            os.close(current)
            current = child
        return current, os.fstat(current)
    except OSError as error:
        os.close(current)
        _raise(absolute, "unreadable-input", error.strerror)
    except BaseException:
        os.close(current)
        raise


@dataclass(slots=True)
class BoundDirectory:
    path: Path
    descriptor: int
    identity: tuple[int, int, int, int, int, int]

    @classmethod
    def open(cls, path: Path) -> BoundDirectory:
        root = lexical_path(path)
        descriptor, opened = _open_directory(root)
        try:
            named = os.stat(root, follow_symlinks=False)
            if not stat.S_ISDIR(named.st_mode) or _identity(named) != _identity(opened):
                _raise(root, "input-changed-during-scan")
            return cls(root, descriptor, _identity(opened))
        except BaseException:
            os.close(descriptor)
            raise

    def revalidate(self) -> None:
        try:
            opened = os.fstat(self.descriptor)
            named = os.stat(self.path, follow_symlinks=False)
        except OSError as error:
            _raise(self.path, "input-changed-during-scan", error.strerror)
        if not stat.S_ISDIR(named.st_mode) or (
            _identity(opened) != self.identity or _identity(named) != self.identity
        ):
            _raise(self.path, "input-changed-during-scan")

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


def validate_root(path: Path) -> Path:
    root = lexical_path(path)
    binding: BoundDirectory | None = None
    try:
        binding = BoundDirectory.open(root)
    except FileNotFoundError:
        _raise(root, "missing-input")
    finally:
        if binding is not None:
            binding.close()
    return root


def _read_named_file(parent_fd: int, name: str, path: Path, *, max_bytes: int) -> FrozenRegularFile:
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode):
            _raise(path, "symlink-input")
        if not stat.S_ISREG(before.st_mode):
            _raise(path, "special-input")
        if before.st_size > max_bytes:
            _raise(path, "byte-limit", f"{before.st_size}>{max_bytes}")
        descriptor = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        try:
            opened = os.fstat(descriptor)
            if _identity(opened) != _identity(before):
                _raise(path, "input-changed-during-scan")
            chunks: list[bytes] = []
            total = 0
            while total < opened.st_size:
                chunk = os.read(descriptor, min(READ_CHUNK_BYTES, opened.st_size - total))
                if not chunk:
                    _raise(path, "input-changed-during-scan")
                chunks.append(chunk)
                total += len(chunk)
            if os.read(descriptor, 1):
                _raise(path, "input-changed-during-scan")
            final = os.fstat(descriptor)
            renamed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if _identity(final) != _identity(opened) or _identity(renamed) != _identity(opened):
                _raise(path, "input-changed-during-scan")
            return FrozenRegularFile(
                path=path,
                raw=b"".join(chunks),
                device=opened.st_dev,
                inode=opened.st_ino,
                size=opened.st_size,
                modified_ns=opened.st_mtime_ns,
                changed_ns=opened.st_ctime_ns,
            )
        finally:
            os.close(descriptor)
    except FileNotFoundError:
        _raise(path, "missing-input")
    except AssuranceInputError:
        raise
    except OSError as error:
        _raise(path, "unreadable-input", error.strerror)


def read_regular_file(path: Path, *, max_bytes: int) -> bytes:
    lexical = lexical_path(path)
    if max_bytes < 0:
        _raise(lexical, "invalid-byte-limit")
    try:
        parent_fd, _ = _open_directory(lexical.parent)
        try:
            return _read_named_file(parent_fd, lexical.name, lexical, max_bytes=max_bytes).raw
        finally:
            os.close(parent_fd)
    except FileNotFoundError:
        _raise(lexical, "missing-input")


def _source_scanner_module() -> Any:
    module_name = f"{__package__}.verify_private_data" if __package__ else "verify_private_data"
    return importlib.import_module(module_name)


def _read_frozen_regular_file(path: Path, *, max_bytes: int) -> FrozenRegularFile:
    lexical = lexical_path(path)
    parent_fd, _ = _open_directory(lexical.parent)
    try:
        return _read_named_file(parent_fd, lexical.name, lexical, max_bytes=max_bytes)
    finally:
        os.close(parent_fd)


def _git_source_regular_files(
    root: Path,
    *,
    max_files: int,
    max_total_bytes: int,
) -> tuple[FrozenRegularFile, ...] | None:
    scanner = _source_scanner_module()
    binding = None
    classification = None
    try:
        binding = scanner.RootBinding.open(root)
        if not binding.directory:
            return None
        classification = scanner._classify_root(binding)
        if not classification.source:
            return None
        repository = classification.repository
        scope = classification.scope
        assert repository is not None and scope is not None
        first = scanner._capture_source_snapshot(repository, scope)
        snapshot = scanner._capture_source_snapshot(repository, scope)
        if first != snapshot:
            _raise(root, "source-inventory-drift")
        scanner._supplement_source_inventory(
            binding,
            classification,
            snapshot,
            scanner.ScanBudget(),
        )
        working = dict(snapshot.working)
        result: list[FrozenRegularFile] = []
        total_bytes = 0
        for relative in (
            *(entry.path for entry in snapshot.index),
            *snapshot.untracked,
        ):
            expected = working[relative.as_posix()]
            if expected is None:
                continue
            path = repository.path / Path(relative.as_posix())
            frozen = _read_frozen_regular_file(path, max_bytes=MAX_REGULAR_FILE_BYTES)
            actual = (
                frozen.device,
                frozen.inode,
                frozen.size,
                frozen.modified_ns,
                frozen.changed_ns,
            )
            captured = (expected[0], expected[1], expected[3], expected[4], expected[5])
            if actual != captured:
                _raise(path, "input-changed-during-scan")
            result.append(frozen)
            if len(result) > max_files:
                _raise(path, "file-count-limit")
            total_bytes += frozen.size
            if total_bytes > max_total_bytes:
                _raise(path, "total-byte-limit")
        final = scanner._capture_source_snapshot(repository, scope)
        binding.revalidate()
        repository.revalidate()
        if final != snapshot:
            _raise(root, "source-inventory-drift")
        return tuple(result)
    except AssuranceInputError:
        raise
    except scanner.ScanLimit as error:
        _raise(Path(error.path), str(error.reason))
    except (FileNotFoundError, OSError) as error:
        _raise(root, "unreadable-input", str(error))
    finally:
        if classification is not None and classification.repository is not None:
            classification.repository.close()
        if binding is not None:
            binding.close()


def _preflight_json(text: str, *, max_depth: int, max_containers: int, max_tokens: int) -> None:
    containers = 0
    tokens = 0
    stack: list[str] = []

    def token() -> None:
        nonlocal tokens
        tokens += 1
        if tokens > max_tokens:
            raise ValueError("json-token-limit")

    index = 0
    while index < len(text):
        character = text[index]
        if character.isspace() or character in {",", ":"}:
            index += 1
            continue
        if character == '"':
            token()
            index += 1
            while index < len(text):
                if text[index] == "\\":
                    index += 2
                    continue
                if text[index] == '"':
                    index += 1
                    break
                index += 1
            else:
                raise ValueError("invalid-json")
            continue
        if character in {"{", "["}:
            token()
            containers += 1
            if containers > max_containers:
                raise ValueError("json-container-limit")
            stack.append(character)
            if len(stack) > max_depth:
                raise ValueError("json-depth-limit")
            index += 1
            continue
        if character in {"}", "]"}:
            expected = "{" if character == "}" else "["
            if not stack or stack.pop() != expected:
                raise ValueError("invalid-json")
            index += 1
            continue
        token()
        index += 1
        while index < len(text) and not (text[index].isspace() or text[index] in '{}[],:"'):
            index += 1
    if stack:
        raise ValueError("invalid-json")


def parse_json_object(
    raw: bytes, *, max_depth: int, max_containers: int, max_tokens: int
) -> Mapping[str, object]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("invalid-utf8") from error
    _preflight_json(
        text,
        max_depth=max_depth,
        max_containers=max_containers,
        max_tokens=max_tokens,
    )

    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise ValueError(f"duplicate-json-key:{key}")
            result[key] = value
        return result

    try:
        parsed = json.loads(text, object_pairs_hook=pairs)
    except (json.JSONDecodeError, RecursionError) as error:
        raise ValueError("invalid-json") from error
    if not isinstance(parsed, dict):
        raise ValueError("json-root-not-object")
    containers = 0
    tokens = 0
    stack: list[tuple[object, int]] = [(parsed, 1)]
    while stack:
        value, depth = stack.pop()
        tokens += 1
        if tokens > max_tokens:
            raise ValueError("json-token-limit")
        if isinstance(value, dict):
            containers += 1
            if depth > max_depth:
                raise ValueError("json-depth-limit")
            for key, child in value.items():
                tokens += 1
                if tokens > max_tokens:
                    raise ValueError("json-token-limit")
                if not isinstance(key, str):
                    raise ValueError("json-key-not-string")
                stack.append((child, depth + 1))
        elif isinstance(value, list):
            containers += 1
            if depth > max_depth:
                raise ValueError("json-depth-limit")
            stack.extend((child, depth + 1) for child in value)
        if containers > max_containers:
            raise ValueError("json-container-limit")
    return parsed


def read_json_object(
    path: Path,
    *,
    max_bytes: int = MAX_REGULAR_FILE_BYTES,
    max_depth: int = MAX_JSON_DEPTH,
    max_containers: int = MAX_JSON_CONTAINERS,
    max_tokens: int = MAX_JSON_TOKENS,
) -> Mapping[str, object]:
    raw = read_regular_file(path, max_bytes=max_bytes)
    try:
        return parse_json_object(
            raw,
            max_depth=max_depth,
            max_containers=max_containers,
            max_tokens=max_tokens,
        )
    except ValueError as error:
        _raise(lexical_path(path), str(error))


def walk_regular_files(
    roots: Sequence[Path], *, max_files: int, max_total_bytes: int
) -> Iterator[FrozenRegularFile]:
    if not roots:
        _raise(Path("."), "missing-input")
    files = 0
    total_bytes = 0

    def walk(directory: Path, directory_fd: int, depth: int) -> Iterator[FrozenRegularFile]:
        nonlocal files, total_bytes
        if depth > 64:
            _raise(directory, "directory-depth-limit")
        try:
            with os.scandir(directory_fd) as entries:
                for entry in entries:
                    path = directory / entry.name
                    before = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
                    if stat.S_ISLNK(before.st_mode):
                        _raise(path, "symlink-input")
                    if stat.S_ISDIR(before.st_mode):
                        child = os.open(
                            entry.name,
                            os.O_RDONLY
                            | getattr(os, "O_DIRECTORY", 0)
                            | getattr(os, "O_NOFOLLOW", 0),
                            dir_fd=directory_fd,
                        )
                        opened = os.fstat(child)
                        if _identity(opened) != _identity(before):
                            os.close(child)
                            _raise(path, "input-changed-during-scan")
                        try:
                            yield from walk(path, child, depth + 1)
                            renamed = os.stat(
                                entry.name, dir_fd=directory_fd, follow_symlinks=False
                            )
                            if _identity(renamed) != _identity(opened):
                                _raise(path, "input-changed-during-scan")
                        finally:
                            os.close(child)
                        continue
                    if not stat.S_ISREG(before.st_mode):
                        _raise(path, "special-input")
                    files += 1
                    if files > max_files:
                        _raise(path, "file-count-limit")
                    total_bytes += before.st_size
                    if total_bytes > max_total_bytes:
                        _raise(path, "total-byte-limit")
                    yield _read_named_file(
                        directory_fd, entry.name, path, max_bytes=MAX_REGULAR_FILE_BYTES
                    )
        except AssuranceInputError:
            raise
        except OSError as error:
            _raise(directory, "unreadable-input", error.strerror)

    for requested in roots:
        root = lexical_path(requested)
        try:
            metadata = os.stat(root, follow_symlinks=False)
        except FileNotFoundError:
            _raise(root, "missing-input")
        if stat.S_ISLNK(metadata.st_mode):
            _raise(root, "symlink-input")
        if stat.S_ISREG(metadata.st_mode):
            parent_fd, _ = _open_directory(root.parent)
            try:
                files += 1
                if files > max_files:
                    _raise(root, "file-count-limit")
                total_bytes += metadata.st_size
                if total_bytes > max_total_bytes:
                    _raise(root, "total-byte-limit")
                yield _read_named_file(parent_fd, root.name, root, max_bytes=MAX_REGULAR_FILE_BYTES)
            finally:
                os.close(parent_fd)
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            _raise(root, "special-input")
        source_files = _git_source_regular_files(
            root,
            max_files=max_files - files,
            max_total_bytes=max_total_bytes - total_bytes,
        )
        if source_files is not None:
            for frozen in source_files:
                files += 1
                total_bytes += frozen.size
                yield frozen
            continue
        descriptor, opened = _open_directory(root)
        try:
            yield from walk(root, descriptor, 0)
            renamed = os.stat(root, follow_symlinks=False)
            if _identity(renamed) != _identity(opened):
                _raise(root, "input-changed-during-scan")
        finally:
            os.close(descriptor)


def incomplete(tool: str, error: AssuranceInputError) -> AssuranceResult:
    return AssuranceResult(tool=tool, complete=False, findings=(error.finding(),))
