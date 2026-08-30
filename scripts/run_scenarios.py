from __future__ import annotations

import argparse
import asyncio
import base64
import errno
import gc
import inspect
import json
import os
import re
import secrets
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from hashlib import sha256
from itertools import islice
from pathlib import Path, PurePosixPath
from typing import Any, Never

MIN_TURNS = 1
MAX_TURNS = 10_000
MAX_TOTAL_TURNS = 10_000
_CHILD_TIMEOUT_SECONDS = 120.0
_CHILD_CLEANUP_SECONDS = 5.0
_CHILD_POLL_SECONDS = 0.01
_MAX_CHILD_OUTPUT_BYTES = 65_536
# Includes base64 plus canonical metadata for all 32 maximum-size scenario inputs.
_MAX_CHILD_CONFIGURATION_BYTES = 4_194_304
_MAX_SCENARIO_BYTES = 65_536
_MAX_SCENARIOS = 32
_SCENARIO_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_CHILD_BOOTSTRAP = """
from __future__ import annotations

import base64
import importlib.util
import json
import os
import resource
import select
import signal
import socket
import stat
import sys
import time
import types


class _NetworkDeniedError(RuntimeError):
    pass


def _deny(*_args: object, **_kwargs: object) -> None:
    raise _NetworkDeniedError("network access denied")


_original_socket = socket.socket


class _GuardedSocket(_original_socket):
    def __new__(
        cls,
        family: int = socket.AF_INET,
        type: int = socket.SOCK_STREAM,
        proto: int = 0,
        fileno: int | None = None,
    ) -> object:
        if family != socket.AF_UNIX:
            raise _NetworkDeniedError("network access denied")
        return _original_socket.__new__(cls, family, type, proto, fileno)


_worker_process_guard = False


def _audit_hook(event: str, args: tuple[object, ...]) -> None:
    if event in {
        "socket.bind",
        "socket.connect",
        "socket.getaddrinfo",
        "socket.gethostbyaddr",
        "socket.gethostbyname",
        "socket.gethostbyname_ex",
        "socket.getnameinfo",
        "socket.sendto",
    }:
        raise _NetworkDeniedError("network access denied")
    if event == "socket.__new__" and len(args) >= 2 and args[1] != socket.AF_UNIX:
        raise _NetworkDeniedError("network access denied")
    if _worker_process_guard and event in {
        "os.exec",
        "os.fork",
        "os.forkpty",
        "os.posix_spawn",
        "os.spawn",
        "os.system",
        "subprocess.Popen",
    }:
        raise PermissionError("worker process operation denied")


socket.socket = _GuardedSocket
for _name in (
    "create_connection",
    "getaddrinfo",
    "getfqdn",
    "gethostbyaddr",
    "gethostbyname",
    "gethostbyname_ex",
    "gethostname",
    "getnameinfo",
):
    setattr(socket, _name, _deny)
sys.addaudithook(_audit_hook)

def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _line(value: object) -> bytes:
    return _canonical(value) + b"\\n"


def _write_all(descriptor: int, value: bytes) -> None:
    view = memoryview(value)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise RuntimeError("control-write-failed")
        view = view[written:]


def _manifest(value: str) -> dict[str, object]:
    raw = base64.b64decode(value, validate=True)
    parsed = json.loads(raw)
    if type(parsed) is not dict or _canonical(parsed) != raw:
        raise ValueError("invalid-runtime-layout")
    return parsed


nonce, limit_text, manifest_text, shutdown_text, acknowledgement_text = sys.argv[1:]
limit = int(limit_text)
shutdown_fd = int(shutdown_text)
acknowledgement_fd = int(acknowledgement_text)
runtime_manifest = _manifest(manifest_text)
if (
    limit != 65536
    or len(nonce) != 64
    or any(character not in "0123456789abcdef" for character in nonce)
    or shutdown_fd <= 2
    or acknowledgement_fd <= 2
    or shutdown_fd == acknowledgement_fd
):
    raise SystemExit(97)

worker_pid = os.fork()
_worker_process_guard = True
if worker_pid:
    runtime_fds: set[int] = set()
    try:
        manifest_items = [
            runtime_manifest["root"],
            runtime_manifest["site_packages"],
            runtime_manifest["script"],
            *runtime_manifest["workspace"],
        ]
        for item in manifest_items:
            if type(item) is dict and type(item.get("fd")) is int:
                runtime_fds.add(item["fd"])
    except BaseException:
        pass
    for descriptor in runtime_fds:
        if descriptor not in {shutdown_fd, acknowledgement_fd}:
            try:
                os.close(descriptor)
            except OSError:
                pass
    _write_all(
        acknowledgement_fd,
        _line({"event": "ready", "nonce": nonce, "worker_pid": worker_pid}),
    )
    worker_reaped = False
    worker_status = 1
    reported = False
    os.set_blocking(shutdown_fd, False)
    control = bytearray()
    while True:
        if not worker_reaped:
            waited_pid, status_value = os.waitpid(worker_pid, os.WNOHANG)
            if waited_pid:
                worker_reaped = True
                worker_status = os.waitstatus_to_exitcode(status_value)
        if worker_reaped and not reported:
            message = (
                "scenario-gate: invalid-input\\n"
                if worker_status == 2
                else "scenario-gate: failed\\n"
            )
            sys.stderr.write(message)
            sys.stderr.flush()
            reported = True
        readable, _writable, _exceptional = select.select([shutdown_fd], [], [], 0.01)
        if not readable:
            continue
        chunk = os.read(shutdown_fd, 1025 - len(control))
        if chunk:
            control.extend(chunk)
            if len(control) > 1024:
                raise SystemExit(97)
            continue
        expected = _line(
            {"event": "shutdown", "nonce": nonce, "worker_pid": worker_pid}
        )
        if bytes(control) != expected:
            if not worker_reaped:
                os.kill(worker_pid, signal.SIGKILL)
            raise SystemExit(97)
        if not worker_reaped:
            os.kill(worker_pid, signal.SIGKILL)
            stop_deadline = time.monotonic() + 4.0
            while True:
                waited_pid, status_value = os.waitpid(worker_pid, os.WNOHANG)
                if waited_pid:
                    worker_reaped = True
                    worker_status = os.waitstatus_to_exitcode(status_value)
                    break
                if time.monotonic() >= stop_deadline:
                    raise SystemExit(97)
                time.sleep(0.01)
        _write_all(
            acknowledgement_fd,
            _line({"event": "stopped", "nonce": nonce, "worker_pid": worker_pid}),
        )
        os.close(acknowledgement_fd)
        raise SystemExit(0)

os.close(shutdown_fd)
os.close(acknowledgement_fd)


def _deny_process(*_args: object, **_kwargs: object) -> None:
    raise PermissionError("worker process operation denied")


for _process_name in (
    "execv",
    "execve",
    "execl",
    "execle",
    "execlp",
    "execlpe",
    "execvp",
    "execvpe",
    "fork",
    "forkpty",
    "posix_spawn",
    "posix_spawnp",
    "setsid",
    "setpgid",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnlpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "system",
):
    if hasattr(os, _process_name):
        setattr(os, _process_name, _deny_process)

_worker_guard_installed = True


def _identity(value: os.stat_result) -> list[int]:
    return [value.st_dev, value.st_ino, value.st_mode, value.st_uid]


def _runtime_item(value: object, *, directory: bool, keys: set[str]) -> int:
    if type(value) is not dict or set(value) != keys:
        raise ValueError("invalid-runtime-layout")
    descriptor = value["fd"]
    expected = value["identity"]
    if (
        type(descriptor) is not int
        or descriptor <= 2
        or type(expected) is not list
        or len(expected) != 4
        or any(type(item) is not int for item in expected)
    ):
        raise ValueError("invalid-runtime-layout")
    actual = os.fstat(descriptor)
    valid_type = stat.S_ISDIR(actual.st_mode) if directory else stat.S_ISREG(actual.st_mode)
    if (
        not valid_type
        or actual.st_uid != os.geteuid()
        or actual.st_mode & 0o022
        or _identity(actual) != expected
    ):
        raise ValueError("invalid-runtime-layout")
    return descriptor


if set(runtime_manifest) != {
    "root",
    "schema_version",
    "script",
    "site_packages",
    "workspace",
} or runtime_manifest["schema_version"] != "runtime_layout.v1":
    raise SystemExit(97)
root_fd = _runtime_item(runtime_manifest["root"], directory=True, keys={"fd", "identity"})
site_fd = _runtime_item(
    runtime_manifest["site_packages"], directory=True, keys={"fd", "identity"}
)
script_fd = _runtime_item(
    runtime_manifest["script"], directory=False, keys={"fd", "identity"}
)
workspace_values = runtime_manifest["workspace"]
if type(workspace_values) is not list or len(workspace_values) != 3:
    raise SystemExit(97)
workspace: dict[str, int] = {}
for item, expected_package in zip(
    workspace_values,
    ("tuntun_testing", "tuntun_contracts", "tuntun_core"),
    strict=True,
):
    descriptor = _runtime_item(
        item,
        directory=True,
        keys={"fd", "identity", "package"},
    )
    if item["package"] != expected_package:
        raise SystemExit(97)
    workspace[expected_package] = descriptor
all_runtime_fds = (root_fd, site_fd, script_fd, *workspace.values())
if len(set(all_runtime_fds)) != len(all_runtime_fds):
    raise SystemExit(97)

os.fchdir(site_fd)
site_path = os.getcwd()
if _identity(os.stat(site_path, follow_symlinks=False)) != _identity(os.fstat(site_fd)):
    raise SystemExit(97)
# Keep the retained directory as cwd so the import entry cannot be rebound by
# renaming and replacing its former lexical path after validation.
sys.path.append(".")


def _read_source(descriptor: int, maximum: int = 1_048_576) -> bytes:
    value = os.fstat(descriptor)
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_uid != os.geteuid()
        or value.st_mode & 0o022
        or not 1 <= value.st_size <= maximum
    ):
        raise ImportError("workspace source rejected")
    before = _identity(value)
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = value.st_size
    while remaining:
        chunk = os.read(descriptor, min(remaining, 65536))
        if not chunk:
            raise ImportError("workspace source truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1) or _identity(os.fstat(descriptor)) != before:
        raise ImportError("workspace source changed")
    return b"".join(chunks)


def _open_directory(parent: int, name: str) -> int:
    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    value = os.fstat(descriptor)
    if value.st_uid != os.geteuid() or value.st_mode & 0o022:
        os.close(descriptor)
        raise ImportError("workspace directory rejected")
    return descriptor


def _workspace_source(fullname: str) -> tuple[bytes, str, bool]:
    top = fullname.partition(".")[0]
    if top not in workspace:
        raise ModuleNotFoundError(fullname)
    parts = fullname.split(".")
    if any(not part.isidentifier() for part in parts):
        raise ModuleNotFoundError(fullname)
    directory = os.dup(workspace[top])
    try:
        for part in parts[:-1]:
            next_directory = _open_directory(directory, part)
            os.close(directory)
            directory = next_directory
        try:
            package_directory = _open_directory(directory, parts[-1])
        except FileNotFoundError:
            source_fd = os.open(
                parts[-1] + ".py",
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=directory,
            )
            try:
                return _read_source(source_fd), "workspace:/" + "/".join(parts) + ".py", False
            finally:
                os.close(source_fd)
        try:
            source_fd = os.open(
                "__init__.py", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=package_directory
            )
            try:
                return (
                    _read_source(source_fd),
                    "workspace:/" + "/".join(parts) + "/__init__.py",
                    True,
                )
            finally:
                os.close(source_fd)
        finally:
            os.close(package_directory)
    finally:
        os.close(directory)


class _WorkspaceLoader:
    def __init__(self, source: bytes, label: str, package: bool) -> None:
        self.source = source
        self.label = label
        self.package = package

    def create_module(self, _spec: object) -> None:
        return None

    def exec_module(self, module: object) -> None:
        module.__file__ = self.label
        if self.package:
            module.__path__ = []
        exec(compile(self.source, self.label, "exec"), module.__dict__)


class _WorkspaceFinder:
    def find_spec(
        self,
        fullname: str,
        _path: object = None,
        _target: object = None,
    ) -> object:
        if fullname.partition(".")[0] not in workspace:
            return None
        source, label, package = _workspace_source(fullname)
        return importlib.util.spec_from_loader(
            fullname,
            _WorkspaceLoader(source, label, package),
            is_package=package,
        )


sys.meta_path.insert(0, _WorkspaceFinder())

_soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
bounded = limit if hard == resource.RLIM_INFINITY else min(limit, hard)
resource.setrlimit(resource.RLIMIT_FSIZE, (bounded, bounded))
source = _read_source(script_fd)
child_module = types.ModuleType("_tuntun_scenario_child")
child_module.__file__ = "scripts/run_scenarios.py"
child_module.__package__ = None
sys.modules[child_module.__name__] = child_module
namespace = child_module.__dict__
exec(compile(source, "scripts/run_scenarios.py", "exec"), namespace)
raise SystemExit(namespace["_child_main_from_stdin"](nonce))
"""


@dataclass(frozen=True, slots=True)
class _PreparedGateInvocation:
    values: argparse.Namespace
    inputs: tuple[Any, ...]
    input_references: tuple[dict[str, str], ...]
    input_reference_set_commitment: str
    invocation: dict[str, Any]
    invocation_commitment: str


@dataclass(frozen=True, slots=True)
class _SnapshotInput:
    normalized_name: str
    raw: bytes
    device: int
    inode: int


_StableIdentity = tuple[int, int, int, int, int, int]


@dataclass(frozen=True, slots=True)
class _DirectorySnapshot:
    identity: _StableIdentity
    entries: tuple[tuple[str, _StableIdentity], ...]


_RuntimeIdentity = tuple[int, int, int, int]


@dataclass(frozen=True, slots=True)
class _RuntimeLayout:
    root_descriptor: int
    workspace_descriptors: tuple[int, ...]
    site_packages_descriptor: int
    script_descriptor: int | None
    descriptors: tuple[int, ...]
    manifest_b64: str
    executable: Path
    executable_identity: _StableIdentity


class _InputFailure(ValueError):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        raise _InputFailure("invalid-input")


def _arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = _Parser(prog="run_scenarios.py", add_help=True)
    parser.add_argument("--scenario", action="append", default=[])
    parser.add_argument("--turns", type=int, required=True)
    parser.add_argument("--assert-resource-bounds", action="store_true")
    parser.add_argument("--json", action="store_true")
    values = parser.parse_args(argv)
    if not MIN_TURNS <= values.turns <= MAX_TURNS:
        raise _InputFailure("invalid-input")
    return values


def _fd_count() -> int:
    directory = next((path for path in ("/proc/self/fd", "/dev/fd") if os.path.isdir(path)), None)
    if directory is None:
        raise RuntimeError("fd-measurement-unavailable")
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        entries = tuple(name for name in os.listdir(descriptor) if name.isdecimal())
        return len(entries) - (1 if str(descriptor) in entries else 0)
    finally:
        os.close(descriptor)


def _pending_task_count() -> int:
    current = asyncio.current_task()
    return sum(1 for task in asyncio.all_tasks() if task is not current and not task.done())


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate-json-key")
        result[key] = value
    return result


def _reject_json_number(_value: str) -> Never:
    raise ValueError("invalid-json-number")


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _canonical_json_object(
    raw: bytes,
    *,
    maximum: int = _MAX_CHILD_OUTPUT_BYTES,
) -> dict[str, Any]:
    if not 2 <= len(raw) <= maximum or not raw.endswith(b"\n"):
        raise ValueError("invalid-child-output")
    payload = raw[:-1]
    value = json.loads(
        payload.decode("utf-8", errors="strict"),
        object_pairs_hook=_unique_json_object,
        parse_float=_reject_json_number,
        parse_constant=_reject_json_number,
    )
    if type(value) is not dict:
        raise ValueError("invalid-child-output")
    if _canonical_bytes(value) != payload:
        raise ValueError("invalid-child-output")
    return value


def _snapshot_fail() -> _InputFailure:
    return _InputFailure("invalid-input")


def _validate_snapshot_part(part: str) -> str:
    if (
        not part
        or part in {".", ".."}
        or part != unicodedata.normalize("NFC", part)
        or len(part.encode("utf-8")) > 255
        or any(ord(character) < 32 or ord(character) == 127 for character in part)
    ):
        raise _snapshot_fail()
    return part


def _snapshot_relative_parts(path: Path, trusted_root: Path) -> tuple[str, ...]:
    if not trusted_root.is_absolute():
        raise _snapshot_fail()
    if path.is_absolute():
        try:
            relative = path.relative_to(trusted_root)
        except ValueError as error:
            raise _snapshot_fail() from error
    else:
        relative = path
    parts = tuple(_validate_snapshot_part(part) for part in relative.parts)
    if not parts or len(PurePosixPath(*parts).as_posix().encode("utf-8")) > 4_096:
        raise _snapshot_fail()
    return parts


def _open_snapshot_root(trusted_root: Path) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for part in trusted_root.parts[1:]:
            next_descriptor = os.open(
                _validate_snapshot_part(part),
                flags,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_snapshot_parent(trusted_root: Path, parts: tuple[str, ...]) -> tuple[int, str]:
    descriptor = _open_snapshot_root(trusted_root)
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


def _snapshot_identity(value: os.stat_result) -> _StableIdentity:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _snapshot_read_exact(descriptor: int, size: int) -> bytes:
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
            raise _snapshot_fail()
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise _snapshot_fail()
    return b"".join(chunks)


def _read_snapshot_child(
    parent_descriptor: int,
    name: str,
    normalized_name: str,
    *,
    expected_identity: _StableIdentity | None = None,
) -> _SnapshotInput:
    descriptor = -1
    try:
        if _validate_snapshot_part(name) != name or not name.endswith(".yaml"):
            raise _snapshot_fail()
        before_path = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if expected_identity is not None and _snapshot_identity(before_path) != expected_identity:
            raise _snapshot_fail()
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=parent_descriptor,
        )
        before_fd = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before_fd.st_mode)
            or before_fd.st_nlink != 1
            or not 1 <= before_fd.st_size <= _MAX_SCENARIO_BYTES
            or _snapshot_identity(before_path) != _snapshot_identity(before_fd)
        ):
            raise _snapshot_fail()
        raw = _snapshot_read_exact(descriptor, before_fd.st_size)
        after_fd = os.fstat(descriptor)
        after_path = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            _snapshot_identity(before_fd) != _snapshot_identity(after_fd)
            or _snapshot_identity(before_fd) != _snapshot_identity(after_path)
            or after_fd.st_nlink != 1
        ):
            raise _snapshot_fail()
        return _SnapshotInput(normalized_name, raw, after_fd.st_dev, after_fd.st_ino)
    except (OSError, UnicodeError) as error:
        raise _snapshot_fail() from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_snapshot_input(path: Path, trusted_root: Path) -> _SnapshotInput:
    parent_descriptor = -1
    try:
        parts = _snapshot_relative_parts(path, trusted_root)
        parent_descriptor, name = _open_snapshot_parent(trusted_root, parts)
        return _read_snapshot_child(
            parent_descriptor,
            name,
            PurePosixPath(*parts).as_posix(),
        )
    except (OSError, UnicodeError) as error:
        raise _snapshot_fail() from error
    finally:
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def _open_snapshot_directory(directory: Path, trusted_root: Path) -> int:
    descriptor = -1
    try:
        parts = _snapshot_relative_parts(directory, trusted_root)
        descriptor = _open_snapshot_root(trusted_root)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        for part in parts:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except (OSError, UnicodeError) as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise _snapshot_fail() from error


def _snapshot_directory(descriptor: int) -> _DirectorySnapshot:
    scan_descriptor = -1
    try:
        before = _snapshot_identity(os.fstat(descriptor))
        scan_descriptor = os.open(
            ".",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=descriptor,
        )
        collected: list[str] = []
        with os.scandir(scan_descriptor) as entries:
            for entry in entries:
                if len(collected) == _MAX_SCENARIOS:
                    raise _snapshot_fail()
                collected.append(entry.name)
        names = tuple(sorted(collected, key=lambda item: item.encode("utf-8")))
        if not names or any(
            _validate_snapshot_part(name) != name or not name.endswith(".yaml") for name in names
        ):
            raise _snapshot_fail()
        frozen_entries = tuple(
            (
                name,
                _snapshot_identity(os.stat(name, dir_fd=descriptor, follow_symlinks=False)),
            )
            for name in names
        )
        after = _snapshot_identity(os.fstat(descriptor))
        if after != before:
            raise _snapshot_fail()
        return _DirectorySnapshot(after, frozen_entries)
    except (OSError, UnicodeError) as error:
        raise _snapshot_fail() from error
    finally:
        if scan_descriptor >= 0:
            os.close(scan_descriptor)


def _load_default_snapshot_inputs(
    trusted_root: Path,
    default_directory: Path,
) -> tuple[_SnapshotInput, ...]:
    descriptor = -1
    rebound_descriptor = -1
    try:
        parts = _snapshot_relative_parts(default_directory, trusted_root)
        descriptor = _open_snapshot_directory(default_directory, trusted_root)
        before = _snapshot_directory(descriptor)
        loaded = tuple(
            _read_snapshot_child(
                descriptor,
                name,
                PurePosixPath(*parts, name).as_posix(),
                expected_identity=identity,
            )
            for name, identity in before.entries
        )
        after = _snapshot_directory(descriptor)
        rebound_descriptor = _open_snapshot_directory(default_directory, trusted_root)
        if after != before or _snapshot_identity(os.fstat(rebound_descriptor)) != before.identity:
            raise _snapshot_fail()
        return loaded
    except (OSError, UnicodeError) as error:
        raise _snapshot_fail() from error
    finally:
        if rebound_descriptor >= 0:
            os.close(rebound_descriptor)
        if descriptor >= 0:
            os.close(descriptor)


def _snapshot_scenario_inputs(
    paths: Sequence[Path],
    *,
    trusted_root: Path,
    default_directory: Path,
) -> tuple[_SnapshotInput, ...]:
    requested = tuple(islice(paths, _MAX_SCENARIOS + 1))
    if len(requested) > _MAX_SCENARIOS:
        raise _snapshot_fail()
    loaded = (
        tuple(_read_snapshot_input(path, trusted_root) for path in requested)
        if requested
        else _load_default_snapshot_inputs(trusted_root, default_directory)
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
        or len(identities) != len(set(identities))
    ):
        raise _snapshot_fail()
    return tuple(sorted(loaded, key=lambda item: item.normalized_name.encode("utf-8")))


def _runtime_identity(value: os.stat_result) -> _RuntimeIdentity:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid)


def _require_runtime_node(
    value: os.stat_result,
    *,
    directory: bool,
) -> None:
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(value.st_mode) or value.st_uid != os.geteuid() or value.st_mode & 0o022:
        raise ValueError("invalid-runtime-path")


def _open_runtime_relative(
    root_descriptor: int,
    relative: str,
    *,
    directory: bool,
) -> int:
    parts = tuple(_validate_snapshot_part(part) for part in PurePosixPath(relative).parts)
    if not parts or PurePosixPath(*parts).as_posix() != relative:
        raise ValueError("invalid-runtime-path")
    descriptor = os.dup(root_descriptor)
    try:
        for index, part in enumerate(parts):
            terminal = index == len(parts) - 1
            flags = os.O_RDONLY | os.O_NOFOLLOW
            if not terminal or directory:
                flags |= os.O_DIRECTORY
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            _require_runtime_node(
                os.fstat(next_descriptor),
                directory=not terminal or directory,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _validate_runtime_executable(code_root: Path, executable: str) -> tuple[Path, _StableIdentity]:
    executable_path = Path(executable).absolute()
    expected_parent = code_root / ".venv/bin"
    if executable_path.parent != expected_parent or executable_path.name not in {
        "python",
        "python3",
        f"python{sys.version_info.major}.{sys.version_info.minor}",
    }:
        raise ValueError("invalid-runtime-path")
    lexical = os.lstat(executable_path)
    if lexical.st_uid != os.geteuid() or not (
        stat.S_ISLNK(lexical.st_mode) or stat.S_ISREG(lexical.st_mode)
    ):
        raise ValueError("invalid-runtime-path")
    resolved = executable_path.resolve(strict=True)
    resolved_stat = resolved.stat()
    if (
        not stat.S_ISREG(resolved_stat.st_mode)
        or resolved_stat.st_uid not in {0, os.geteuid()}
        or resolved_stat.st_mode & 0o022
        or not resolved_stat.st_mode & 0o111
    ):
        raise ValueError("invalid-runtime-path")
    return executable_path, _snapshot_identity(resolved_stat)


def _open_runtime_layout(
    code_root: Path,
    executable: str,
    *,
    script_relative: str | None,
) -> _RuntimeLayout:
    descriptors: list[int] = []
    try:
        if not code_root.is_absolute():
            raise ValueError("invalid-runtime-path")
        root_descriptor = _open_snapshot_root(code_root)
        descriptors.append(root_descriptor)
        _require_runtime_node(os.fstat(root_descriptor), directory=True)
        executable_path, executable_identity = _validate_runtime_executable(
            code_root,
            executable,
        )
        workspace_relative = (
            "packages/testing/src",
            "packages/contracts/src",
            "apps/core/src",
        )
        workspace_descriptors = tuple(
            _open_runtime_relative(root_descriptor, relative, directory=True)
            for relative in workspace_relative
        )
        descriptors.extend(workspace_descriptors)
        site_relative = (
            f".venv/lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages"
        )
        site_packages_descriptor = _open_runtime_relative(
            root_descriptor,
            site_relative,
            directory=True,
        )
        descriptors.append(site_packages_descriptor)
        script_descriptor = (
            None
            if script_relative is None
            else _open_runtime_relative(root_descriptor, script_relative, directory=False)
        )
        if script_descriptor is not None:
            descriptors.append(script_descriptor)
        manifest: dict[str, Any] = {
            "root": {
                "fd": root_descriptor,
                "identity": list(_runtime_identity(os.fstat(root_descriptor))),
            },
            "schema_version": "runtime_layout.v1",
            "script": (
                None
                if script_descriptor is None
                else {
                    "fd": script_descriptor,
                    "identity": list(_runtime_identity(os.fstat(script_descriptor))),
                }
            ),
            "site_packages": {
                "fd": site_packages_descriptor,
                "identity": list(_runtime_identity(os.fstat(site_packages_descriptor))),
            },
            "workspace": [
                {
                    "fd": descriptor,
                    "identity": list(_runtime_identity(os.fstat(descriptor))),
                    "package": package,
                }
                for descriptor, package in zip(
                    workspace_descriptors,
                    ("tuntun_testing", "tuntun_contracts", "tuntun_core"),
                    strict=True,
                )
            ],
        }
        return _RuntimeLayout(
            root_descriptor=root_descriptor,
            workspace_descriptors=workspace_descriptors,
            site_packages_descriptor=site_packages_descriptor,
            script_descriptor=script_descriptor,
            descriptors=tuple(descriptors),
            manifest_b64=base64.b64encode(_canonical_bytes(manifest)).decode("ascii"),
            executable=executable_path,
            executable_identity=executable_identity,
        )
    except (OSError, UnicodeError) as error:
        for descriptor in reversed(descriptors):
            with suppress(OSError):
                os.close(descriptor)
        raise ValueError("invalid-runtime-path") from error
    except BaseException:
        for descriptor in reversed(descriptors):
            with suppress(OSError):
                os.close(descriptor)
        raise


def _close_runtime_layout(layout: _RuntimeLayout) -> None:
    for descriptor in reversed(layout.descriptors):
        os.close(descriptor)


def _revalidate_runtime_executable(layout: _RuntimeLayout) -> None:
    _path, identity = _validate_runtime_executable(
        layout.executable.parents[2],
        str(layout.executable),
    )
    if identity != layout.executable_identity:
        raise ValueError("invalid-runtime-path")


def _prepare_gate_invocation(
    argv: Sequence[str],
    repository_root: Path,
) -> _PreparedGateInvocation:
    values = _arguments(argv)
    inputs = _snapshot_scenario_inputs(
        tuple(Path(item) for item in values.scenario),
        trusted_root=repository_root,
        default_directory=Path("tests/fixtures/scenarios"),
    )
    if len(inputs) * values.turns > MAX_TOTAL_TURNS:
        raise _InputFailure("invalid-input")
    references: list[dict[str, str]] = []
    for value in inputs:
        normalized_path = value.normalized_name
        scenario = normalized_path.rsplit("/", 1)[-1].removesuffix(".yaml")
        if _SCENARIO_NAME_PATTERN.fullmatch(scenario) is None:
            raise _InputFailure("invalid-input")
        references.append(
            {
                "content_sha256": sha256(value.raw).hexdigest(),
                "path": normalized_path,
                "scenario": scenario,
            }
        )
    reference_set_commitment = _reference_set_commitment(tuple(references))
    invocation: dict[str, Any] = {
        "assert_resource_bounds": values.assert_resource_bounds,
        "input_reference_set_sha256": reference_set_commitment,
        "json_output": values.json,
        "schema_version": "scenario_invocation.v1",
        "turns": values.turns,
    }
    return _PreparedGateInvocation(
        values=values,
        inputs=inputs,
        input_references=tuple(references),
        input_reference_set_commitment=reference_set_commitment,
        invocation=invocation,
        invocation_commitment=sha256(_canonical_bytes(invocation)).hexdigest(),
    )


def _reference_set_commitment(references: tuple[dict[str, str], ...]) -> str:
    return sha256(_canonical_bytes(list(references))).hexdigest()


def _valid_b2(value: Any) -> bool:
    keys = {
        "duplicate_effect_count",
        "peak_rss_growth_bytes",
        "privacy_block_p95_ms",
        "private_sentinel_count",
        "status",
        "terminal_rss_growth_bytes",
        "warmup_turns",
    }
    if type(value) is not dict or set(value) != keys:
        return False
    metrics = tuple(value[key] for key in keys - {"status"})
    if value["status"] == "not_measured":
        return all(item is None for item in metrics)
    return (
        value["status"] == "pass"
        and value["warmup_turns"] == 50
        and all(type(item) is int and item >= 0 for item in metrics)
    )


def _valid_foundation_resources(value: Any, *, measured: bool) -> bool:
    keys = {
        "fd_after",
        "fd_baseline",
        "fd_delta",
        "pending_tasks_after",
        "pending_tasks_baseline",
        "pending_tasks_delta",
        "status",
    }
    if type(value) is not dict or set(value) != keys:
        return False
    metrics = tuple(value[key] for key in keys - {"status"})
    if not measured:
        return value["status"] == "not_measured" and all(item is None for item in metrics)
    return (
        value["status"] == "pass"
        and all(type(item) is int and item >= 0 for item in metrics)
        and value["fd_delta"] == 0
        and value["pending_tasks_delta"] == 0
        and value["fd_after"] == value["fd_baseline"]
        and value["pending_tasks_after"] == value["pending_tasks_baseline"]
    )


def _valid_scenario_records(
    value: Any,
    *,
    turns: int,
    input_references: tuple[dict[str, str], ...],
) -> bool:
    if type(value) is not list or len(value) != len(input_references):
        return False
    for item, reference in zip(value, input_references, strict=True):
        if type(item) is not dict or set(item) != {"name", "result_chain_sha256", "turns"}:
            return False
        name = item["name"]
        digest = item["result_chain_sha256"]
        if (
            type(name) is not str
            or _SCENARIO_NAME_PATTERN.fullmatch(name) is None
            or name != reference["scenario"]
            or type(digest) is not str
            or _DIGEST_PATTERN.fullmatch(digest) is None
            or type(item["turns"]) is not int
            or item["turns"] != turns
        ):
            return False
    return True


def _valid_gate_document(value: Any, prepared: _PreparedGateInvocation) -> bool:
    if type(value) is not dict:
        return False
    return not (
        set(value) != {"b2", "foundation_resources", "scenarios", "schema_version", "status"}
        or value["schema_version"] != "scenario_gate.v1"
        or value["status"] != "pass"
        or not _valid_b2(value["b2"])
        or not _valid_foundation_resources(
            value["foundation_resources"],
            measured=prepared.values.assert_resource_bounds,
        )
        or not _valid_scenario_records(
            value["scenarios"],
            turns=prepared.values.turns,
            input_references=prepared.input_references,
        )
    )


def _validated_gate_envelope(
    raw: bytes,
    prepared: _PreparedGateInvocation,
    nonce: str,
) -> bytes:
    envelope = _canonical_json_object(raw)
    if (
        set(envelope)
        != {
            "document",
            "input_reference_set_sha256",
            "invocation_commitment",
            "nonce",
            "schema_version",
        }
        or envelope["schema_version"] != "scenario_supervisor_envelope.v1"
        or envelope["nonce"] != nonce
        or envelope["invocation_commitment"] != prepared.invocation_commitment
        or envelope["input_reference_set_sha256"] != prepared.input_reference_set_commitment
        or not _valid_gate_document(envelope["document"], prepared)
    ):
        raise ValueError("invalid-child-output")
    if prepared.values.json:
        return _canonical_bytes(envelope["document"]) + b"\n"
    return b"scenario-gate: PASS\n"


def _write_descriptor(descriptor: int, value: bytes) -> None:
    view = memoryview(value)
    while view:
        try:
            written = os.write(descriptor, view)
        except InterruptedError:
            continue
        if written <= 0:
            raise RuntimeError("control-write-failed")
        view = view[written:]


def _read_control_line(
    descriptor: int,
    buffer: bytearray,
    *,
    deadline: float,
) -> bytes:
    while True:
        newline = buffer.find(b"\n")
        if newline >= 0:
            result = bytes(buffer[: newline + 1])
            del buffer[: newline + 1]
            return result
        if len(buffer) > 1_024:
            raise ValueError("invalid-control-frame")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("control-frame-timeout")
        readable, _writable, _exceptional = select.select(
            [descriptor],
            [],
            [],
            remaining,
        )
        if not readable:
            raise TimeoutError("control-frame-timeout")
        chunk = os.read(descriptor, 1_025 - len(buffer))
        if not chunk:
            raise ValueError("incomplete-control-frame")
        buffer.extend(chunk)


def _read_control_to_eof(
    descriptor: int,
    buffer: bytearray,
    *,
    deadline: float,
) -> bytes:
    while True:
        if len(buffer) > 1_024:
            raise ValueError("invalid-control-frame")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("control-frame-timeout")
        readable, _writable, _exceptional = select.select(
            [descriptor],
            [],
            [],
            remaining,
        )
        if not readable:
            raise TimeoutError("control-frame-timeout")
        chunk = os.read(descriptor, 1_025 - len(buffer))
        if not chunk:
            return bytes(buffer)
        buffer.extend(chunk)


def _force_process_group_cleanup(
    process: subprocess.Popen[bytes],
    *,
    deadline: float,
) -> None:
    permission_failure = False
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        permission_failure = True
        process.kill()
    except OSError:
        process.kill()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("child-cleanup-timeout")
    try:
        process.wait(timeout=remaining)
    except subprocess.TimeoutExpired as error:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            permission_failure = True
            process.kill()
        except OSError:
            process.kill()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("child-cleanup-timeout") from error
        process.wait(timeout=remaining)
    if permission_failure:
        raise RuntimeError("process-group-cleanup-permission-denied")


def _shutdown_supervised_process(
    process: subprocess.Popen[bytes],
    *,
    nonce: str,
    worker_pid: int,
    shutdown_descriptor: int,
    acknowledgement_descriptor: int,
    acknowledgement_buffer: bytearray,
    deadline: float,
) -> int:
    request = (
        _canonical_bytes({"event": "shutdown", "nonce": nonce, "worker_pid": worker_pid}) + b"\n"
    )
    _write_descriptor(shutdown_descriptor, request)
    os.close(shutdown_descriptor)
    acknowledgement = _read_control_to_eof(
        acknowledgement_descriptor,
        acknowledgement_buffer,
        deadline=deadline,
    )
    expected = (
        _canonical_bytes({"event": "stopped", "nonce": nonce, "worker_pid": worker_pid}) + b"\n"
    )
    if acknowledgement != expected:
        raise ValueError("invalid-shutdown-acknowledgement")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("child-cleanup-timeout")
    return process.wait(timeout=remaining)


def _run_bounded_process(
    command: Sequence[str],
    *,
    payload: bytes,
    cwd: Path,
    environment: dict[str, str],
    supervision_nonce: str,
    inherited_descriptors: tuple[int, ...],
) -> subprocess.CompletedProcess[bytes]:
    with (
        tempfile.TemporaryFile(mode="w+b") as stdin_file,
        tempfile.TemporaryFile(mode="w+b") as stdout_file,
        tempfile.TemporaryFile(mode="w+b") as stderr_file,
    ):
        if len(payload) > _MAX_CHILD_CONFIGURATION_BYTES:
            raise ValueError("child-configuration-limit-exceeded")
        stdin_file.write(payload + b"\n")
        stdin_file.seek(0)
        shutdown_read, shutdown_write = os.pipe()
        try:
            acknowledgement_read, acknowledgement_write = os.pipe()
        except BaseException:
            os.close(shutdown_read)
            os.close(shutdown_write)
            raise
        process: subprocess.Popen[bytes] | None = None
        try:
            process = subprocess.Popen(
                (*command, str(shutdown_read), str(acknowledgement_write)),
                stdin=stdin_file,
                stdout=stdout_file,
                stderr=stderr_file,
                cwd=cwd,
                env=environment,
                close_fds=True,
                pass_fds=(*inherited_descriptors, shutdown_read, acknowledgement_write),
                start_new_session=True,
            )
        except BaseException:
            os.close(shutdown_write)
            os.close(acknowledgement_read)
            raise
        finally:
            os.close(shutdown_read)
            os.close(acknowledgement_write)
        if process is None:
            os.close(shutdown_write)
            os.close(acknowledgement_read)
            raise RuntimeError("child-start-failed")
        runtime_deadline = time.monotonic() + _CHILD_TIMEOUT_SECONDS
        completed_frame = False
        acknowledgement_buffer = bytearray()
        worker_pid: int | None = None
        supervisor_returncode: int | None = None
        try:
            ready_raw = _read_control_line(
                acknowledgement_read,
                acknowledgement_buffer,
                deadline=runtime_deadline,
            )
            ready = _canonical_json_object(ready_raw, maximum=1_024)
            ready_worker_pid = ready.get("worker_pid")
            if (
                set(ready) != {"event", "nonce", "worker_pid"}
                or ready["event"] != "ready"
                or ready["nonce"] != supervision_nonce
                or type(ready_worker_pid) is not int
                or ready_worker_pid <= 0
                or acknowledgement_buffer
            ):
                raise ValueError("invalid-ready-acknowledgement")
            worker_pid = ready_worker_pid
            while True:
                stdout_size = os.fstat(stdout_file.fileno()).st_size
                stderr_size = os.fstat(stderr_file.fileno()).st_size
                if stdout_size > _MAX_CHILD_OUTPUT_BYTES or stderr_size > _MAX_CHILD_OUTPUT_BYTES:
                    break
                if stdout_size:
                    stdout_file.seek(stdout_size - 1)
                    if stdout_file.read(1) == b"\n":
                        completed_frame = True
                        break
                if stderr_size:
                    stderr_file.seek(stderr_size - 1)
                    if stderr_file.read(1) == b"\n":
                        break
                remaining = runtime_deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, _CHILD_TIMEOUT_SECONDS)
                time.sleep(min(_CHILD_POLL_SECONDS, remaining))
        finally:
            cleanup_started = time.monotonic()
            try:
                if worker_pid is None:
                    os.close(shutdown_write)
                    _force_process_group_cleanup(
                        process,
                        deadline=cleanup_started + _CHILD_CLEANUP_SECONDS,
                    )
                else:
                    supervisor_returncode = _shutdown_supervised_process(
                        process,
                        nonce=supervision_nonce,
                        worker_pid=worker_pid,
                        shutdown_descriptor=shutdown_write,
                        acknowledgement_descriptor=acknowledgement_read,
                        acknowledgement_buffer=acknowledgement_buffer,
                        deadline=cleanup_started + (_CHILD_CLEANUP_SECONDS / 2),
                    )
            except BaseException:
                with suppress(OSError):
                    os.close(shutdown_write)
                _force_process_group_cleanup(
                    process,
                    deadline=cleanup_started + _CHILD_CLEANUP_SECONDS,
                )
                raise
            finally:
                with suppress(OSError):
                    os.close(acknowledgement_read)
        if supervisor_returncode not in (None, 0):
            raise RuntimeError("supervisor-shutdown-failed")
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read(_MAX_CHILD_OUTPUT_BYTES + 1)
        stderr = stderr_file.read(_MAX_CHILD_OUTPUT_BYTES + 1)
    if len(stdout) > _MAX_CHILD_OUTPUT_BYTES or len(stderr) > _MAX_CHILD_OUTPUT_BYTES:
        raise ValueError("child-output-limit-exceeded")
    return subprocess.CompletedProcess(
        command,
        0 if completed_frame else 1,
        stdout,
        stderr,
    )


async def _execute(
    inputs: tuple[Any, ...],
    turns: int,
    assert_resource_bounds: bool,
    turn_observer: Callable[[int], object] | None,
) -> tuple[tuple[Any, ...], Any]:
    from tuntun_testing.scenario import (
        FoundationResourceEvidence,
        ScenarioGateRecord,
        ScenarioRunner,
        result_chain,
    )

    await asyncio.sleep(0)
    gc.collect()
    fd_baseline = _fd_count() if assert_resource_bounds else None
    task_baseline = _pending_task_count() if assert_resource_bounds else None
    for value in inputs:
        await ScenarioRunner().run_async(value, turn_index=0)
    await asyncio.sleep(0)
    gc.collect()
    if assert_resource_bounds:
        if fd_baseline is None or task_baseline is None:
            raise AssertionError("resource-measurement-missing")
        if _fd_count() != fd_baseline or _pending_task_count() != task_baseline:
            raise AssertionError("resource-bound-failed")
    records: list[Any] = []
    global_turn = 0
    for value in inputs:
        results = []
        for turn_index in range(turns):
            results.append(await ScenarioRunner().run_async(value, turn_index=turn_index))
            if turn_observer is not None:
                observed = turn_observer(global_turn)
                if inspect.isawaitable(observed):
                    await observed
            global_turn += 1
        records.append(
            ScenarioGateRecord(
                name=results[0].scenario,
                turns=turns,
                result_chain_sha256=result_chain(tuple(results)),
            )
        )
    await asyncio.sleep(0)
    gc.collect()
    if assert_resource_bounds:
        fd_after = _fd_count()
        task_after = _pending_task_count()
        if fd_baseline is None or task_baseline is None:
            raise AssertionError("resource-measurement-missing")
        evidence = FoundationResourceEvidence(
            status="pass",
            fd_baseline=fd_baseline,
            fd_after=fd_after,
            fd_delta=fd_after - fd_baseline,
            pending_tasks_baseline=task_baseline,
            pending_tasks_after=task_after,
            pending_tasks_delta=task_after - task_baseline,
        )
        if evidence.fd_delta != 0 or evidence.pending_tasks_delta != 0:
            raise AssertionError("resource-bound-failed")
    else:
        evidence = FoundationResourceEvidence.not_measured()
    return tuple(records), evidence


def _build_gate_document(
    inputs: tuple[Any, ...],
    values: argparse.Namespace,
    turn_observer: Callable[[int], object] | None,
) -> Any:
    from tuntun_testing.scenario import ScenarioGateDocument

    records, evidence = asyncio.run(
        _execute(
            inputs,
            values.turns,
            values.assert_resource_bounds,
            turn_observer,
        )
    )
    return ScenarioGateDocument(scenarios=records, foundation_resources=evidence)


def _run_gate_in_process(
    argv: Sequence[str],
    *,
    _after_guard: Callable[[], object] | None = None,
    _turn_observer: Callable[[int], object] | None = None,
    _repository_root: Path | None = None,
) -> int:
    try:
        values = _arguments(argv)
    except _InputFailure:
        print("scenario-gate: invalid-input", file=sys.stderr)
        return 2
    try:
        from tuntun_testing.network_guard import install_network_guard

        install_network_guard()
        if _after_guard is not None:
            guarded_result = _after_guard()
            if inspect.isawaitable(guarded_result):
                raise AssertionError("invalid-guard-hook")
        from tuntun_testing.scenario import ScenarioSchemaError
        from tuntun_testing.scenario_io import (
            ScenarioInputError,
            load_scenario_inputs,
        )
    except BaseException:
        print("scenario-gate: failed", file=sys.stderr)
        return 1
    try:
        repository_root = (
            Path(__file__).absolute().parent.parent
            if _repository_root is None
            else _repository_root
        )
        default_directory = Path("tests/fixtures/scenarios")
        inputs = load_scenario_inputs(
            (Path(item) for item in values.scenario),
            trusted_root=repository_root,
            default_directory=default_directory,
        )
        if len(inputs) * values.turns > MAX_TOTAL_TURNS:
            raise _InputFailure("invalid-input")
        document = _build_gate_document(inputs, values, _turn_observer)
        if values.json:
            sys.stdout.buffer.write(document.canonical_json() + b"\n")
        else:
            print("scenario-gate: PASS")
        return 0
    except (_InputFailure, ScenarioInputError, ScenarioSchemaError):
        print("scenario-gate: invalid-input", file=sys.stderr)
        return 2
    except BaseException:
        print("scenario-gate: failed", file=sys.stderr)
        return 1


def _run_gate_child(argv: Sequence[str], repository_root: Path) -> int:
    try:
        prepared = _prepare_gate_invocation(argv, repository_root)
    except (_InputFailure, ValueError):
        print("scenario-gate: invalid-input", file=sys.stderr)
        return 2
    except BaseException:
        print("scenario-gate: failed", file=sys.stderr)
        return 1
    layout: _RuntimeLayout | None = None
    try:
        nonce = secrets.token_hex(32)
        code_root = Path(__file__).absolute().parent.parent
        layout = _open_runtime_layout(
            code_root,
            sys.executable,
            script_relative="scripts/run_scenarios.py",
        )
        configuration = {
            "inputs": [
                {
                    **reference,
                    "raw_b64": base64.b64encode(value.raw).decode("ascii"),
                }
                for reference, value in zip(
                    prepared.input_references,
                    prepared.inputs,
                    strict=True,
                )
            ],
            "invocation": prepared.invocation,
            "invocation_commitment": prepared.invocation_commitment,
            "nonce": nonce,
            "schema_version": "scenario_child_config.v1",
        }
        _revalidate_runtime_executable(layout)
        result = _run_bounded_process(
            (
                str(layout.executable),
                "-I",
                "-S",
                "-c",
                _CHILD_BOOTSTRAP,
                nonce,
                str(_MAX_CHILD_OUTPUT_BYTES),
                layout.manifest_b64,
            ),
            payload=_canonical_bytes(configuration),
            cwd=repository_root,
            environment={},
            supervision_nonce=nonce,
            inherited_descriptors=layout.descriptors,
        )
    except BaseException:
        print("scenario-gate: failed", file=sys.stderr)
        return 1
    finally:
        if layout is not None:
            _close_runtime_layout(layout)
    if result.returncode == 0 and result.stderr == b"":
        try:
            sys.stdout.buffer.write(_validated_gate_envelope(result.stdout, prepared, nonce))
            return 0
        except BaseException:
            print("scenario-gate: failed", file=sys.stderr)
            return 1
    if result.stdout == b"" and result.stderr == b"scenario-gate: invalid-input\n":
        print("scenario-gate: invalid-input", file=sys.stderr)
        return 2
    print("scenario-gate: failed", file=sys.stderr)
    return 1


def _child_main_from_stdin(expected_nonce: str) -> int:
    try:
        raw = sys.stdin.buffer.readline(_MAX_CHILD_CONFIGURATION_BYTES + 2)
        if (
            len(raw) > _MAX_CHILD_CONFIGURATION_BYTES + 1
            or not raw.endswith(b"\n")
            or sys.stdin.buffer.read(1) != b""
        ):
            raise ValueError("invalid-child-configuration")
        configuration = _canonical_json_object(
            raw,
            maximum=_MAX_CHILD_CONFIGURATION_BYTES + 1,
        )
        invocation = configuration["invocation"]
        configured_inputs = configuration["inputs"]
        if (
            set(configuration)
            != {
                "inputs",
                "invocation",
                "invocation_commitment",
                "nonce",
                "schema_version",
            }
            or configuration["schema_version"] != "scenario_child_config.v1"
            or configuration["nonce"] != expected_nonce
            or type(configuration["nonce"]) is not str
            or _DIGEST_PATTERN.fullmatch(configuration["nonce"]) is None
            or type(invocation) is not dict
            or set(invocation)
            != {
                "assert_resource_bounds",
                "input_reference_set_sha256",
                "json_output",
                "schema_version",
                "turns",
            }
            or invocation["schema_version"] != "scenario_invocation.v1"
            or type(invocation["assert_resource_bounds"]) is not bool
            or type(invocation["json_output"]) is not bool
            or type(invocation["turns"]) is not int
            or not MIN_TURNS <= invocation["turns"] <= MAX_TURNS
            or type(invocation["input_reference_set_sha256"]) is not str
            or _DIGEST_PATTERN.fullmatch(invocation["input_reference_set_sha256"]) is None
            or type(configured_inputs) is not list
            or not 1 <= len(configured_inputs) <= 32
            or len(configured_inputs) * invocation["turns"] > MAX_TOTAL_TURNS
            or type(configuration["invocation_commitment"]) is not str
            or _DIGEST_PATTERN.fullmatch(configuration["invocation_commitment"]) is None
            or configuration["invocation_commitment"]
            != sha256(_canonical_bytes(invocation)).hexdigest()
        ):
            raise ValueError("invalid-child-configuration")
        from tuntun_testing.scenario_io import ScenarioInput

        inputs: list[Any] = []
        references: list[dict[str, str]] = []
        for index, configured in enumerate(configured_inputs, start=1):
            reference = {key: configured.get(key) for key in ("content_sha256", "path", "scenario")}
            if (
                type(reference) is not dict
                or set(reference) != {"content_sha256", "path", "scenario"}
                or type(configured) is not dict
                or set(configured) != {"content_sha256", "path", "raw_b64", "scenario"}
                or type(reference["path"]) is not str
                or reference["path"].startswith("/")
                or not 1 <= len(reference["path"].encode("utf-8")) <= 4_096
                or reference["path"] != unicodedata.normalize("NFC", reference["path"])
                or any(
                    part in {"", ".", ".."}
                    or len(part.encode("utf-8")) > 255
                    or any(ord(character) < 32 or ord(character) == 127 for character in part)
                    for part in reference["path"].split("/")
                )
                or type(reference["scenario"]) is not str
                or _SCENARIO_NAME_PATTERN.fullmatch(reference["scenario"]) is None
                or reference["path"].rsplit("/", 1)[-1] != f"{reference['scenario']}.yaml"
                or type(reference["content_sha256"]) is not str
                or _DIGEST_PATTERN.fullmatch(reference["content_sha256"]) is None
                or type(configured["raw_b64"]) is not str
            ):
                raise ValueError("invalid-child-configuration")
            decoded = base64.b64decode(configured["raw_b64"], validate=True)
            if (
                not 1 <= len(decoded) <= _MAX_SCENARIO_BYTES
                or sha256(decoded).hexdigest() != reference["content_sha256"]
            ):
                raise ValueError("invalid-child-configuration")
            references.append(reference)
            inputs.append(
                ScenarioInput(
                    normalized_name=reference["path"],
                    raw=decoded,
                    device=0,
                    inode=index,
                )
            )
        if _reference_set_commitment(tuple(references)) != invocation["input_reference_set_sha256"]:
            raise ValueError("invalid-child-configuration")
        values = argparse.Namespace(
            assert_resource_bounds=invocation["assert_resource_bounds"],
            json=invocation["json_output"],
            scenario=[],
            turns=invocation["turns"],
        )
    except BaseException:
        return 1
    try:
        from tuntun_testing.scenario import ScenarioSchemaError

        document = _build_gate_document(tuple(inputs), values, None)
    except (ScenarioSchemaError, _InputFailure):
        return 2
    except BaseException:
        return 1
    envelope = {
        "document": document.to_mapping(),
        "input_reference_set_sha256": invocation["input_reference_set_sha256"],
        "invocation_commitment": configuration["invocation_commitment"],
        "nonce": expected_nonce,
        "schema_version": "scenario_supervisor_envelope.v1",
    }
    try:
        sys.stdout.buffer.write(_canonical_bytes(envelope) + b"\n")
        sys.stdout.buffer.flush()
        while True:
            signal.pause()
    except BaseException:
        return 1


def main(
    argv: Sequence[str] | None = None,
    *,
    _after_guard: Callable[[], object] | None = None,
    _turn_observer: Callable[[int], object] | None = None,
    _repository_root: Path | None = None,
) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if _after_guard is not None or _turn_observer is not None:
        return _run_gate_in_process(
            arguments,
            _after_guard=_after_guard,
            _turn_observer=_turn_observer,
            _repository_root=_repository_root,
        )
    try:
        _arguments(arguments)
    except _InputFailure:
        print("scenario-gate: invalid-input", file=sys.stderr)
        return 2
    repository_root = (
        Path(__file__).absolute().parent.parent if _repository_root is None else _repository_root
    )
    return _run_gate_child(arguments, repository_root)


if __name__ == "__main__":
    raise SystemExit(main())
