from __future__ import annotations

import base64
import errno
import importlib.util
import json
import os
import re
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Any, Never
from uuid import UUID

import typer

_SIMULATION_TIMEOUT_SECONDS = 120.0
_SIMULATION_CLEANUP_SECONDS = 5.0
_SIMULATION_POLL_SECONDS = 0.01
_MAX_SIMULATION_OUTPUT_BYTES = 65_536
_MAX_SIMULATION_CONFIGURATION_BYTES = 1_048_576
_SCENARIO_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_EVENT_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_SIMULATE_BOOTSTRAP = """
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
    worker_status = 2
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
                "simulation-extra-required\\n"
                if worker_status == 3
                else "simulation-invalid-input\\n"
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


def _runtime_item(value: object, *, keys: set[str]) -> int:
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
    if (
        not stat.S_ISDIR(actual.st_mode)
        or actual.st_uid != os.geteuid()
        or actual.st_mode & 0o022
        or _identity(actual) != expected
    ):
        raise ValueError("invalid-runtime-layout")
    return descriptor


if (
    set(runtime_manifest)
    != {"root", "schema_version", "script", "site_packages", "workspace"}
    or runtime_manifest["schema_version"] != "runtime_layout.v1"
    or runtime_manifest["script"] is not None
):
    raise SystemExit(97)
root_fd = _runtime_item(runtime_manifest["root"], keys={"fd", "identity"})
site_fd = _runtime_item(runtime_manifest["site_packages"], keys={"fd", "identity"})
workspace_values = runtime_manifest["workspace"]
if type(workspace_values) is not list or len(workspace_values) != 3:
    raise SystemExit(97)
workspace: dict[str, int] = {}
for item, expected_package in zip(
    workspace_values,
    ("tuntun_testing", "tuntun_contracts", "tuntun_core"),
    strict=True,
):
    descriptor = _runtime_item(item, keys={"fd", "identity", "package"})
    if item["package"] != expected_package:
        raise SystemExit(97)
    workspace[expected_package] = descriptor
all_runtime_fds = (root_fd, site_fd, *workspace.values())
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
"""
_SIMULATE_CHILD_CODE = """
import base64
import json
import os
import signal
import sys
import unicodedata
from hashlib import sha256

try:
    from tuntun_testing.scenario import ScenarioRunner
    from tuntun_testing.scenario_io import ScenarioInput

    raw = sys.stdin.buffer.readline(1048578)
    if len(raw) > 1048577 or not raw.endswith(b"\\n") or sys.stdin.buffer.read(1) != b"":
        raise ValueError("invalid-child-configuration")
    configuration = json.loads(raw)
    canonical_configuration = json.dumps(
        configuration,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if canonical_configuration != raw[:-1]:
        raise ValueError("invalid-child-configuration")
    invocation = configuration["invocation"]
    reference = invocation["input"]
    configured_input = configuration["input"]
    if (
        type(configuration) is not dict
        or set(configuration)
        != {"input", "invocation", "invocation_commitment", "nonce", "schema_version"}
        or configuration["schema_version"] != "simulation_child_config.v1"
        or configuration["nonce"] != nonce
        or type(configuration["nonce"]) is not str
        or len(configuration["nonce"]) != 64
        or any(character not in "0123456789abcdef" for character in configuration["nonce"])
        or type(invocation) is not dict
        or set(invocation) != {"input", "json_output", "schema_version"}
        or invocation["schema_version"] != "simulation_invocation.v1"
        or type(invocation["json_output"]) is not bool
        or type(reference) is not dict
        or set(reference) != {"content_sha256", "path", "scenario"}
        or type(reference["content_sha256"]) is not str
        or len(reference["content_sha256"]) != 64
        or any(character not in "0123456789abcdef" for character in reference["content_sha256"])
        or type(reference["path"]) is not str
        or not 1 <= len(reference["path"].encode("utf-8")) <= 4096
        or reference["path"].startswith("/")
        or reference["path"] != unicodedata.normalize("NFC", reference["path"])
        or any(
            part in {"", ".", ".."}
            or len(part.encode("utf-8")) > 255
            or any(ord(character) < 32 or ord(character) == 127 for character in part)
            for part in reference["path"].split("/")
        )
        or type(reference["scenario"]) is not str
        or not 2 <= len(reference["scenario"]) <= 64
        or reference["scenario"][0] not in "abcdefghijklmnopqrstuvwxyz"
        or not all(
            character in "abcdefghijklmnopqrstuvwxyz0123456789-"
            for character in reference["scenario"]
        )
        or reference["path"].rsplit("/", 1)[-1] != reference["scenario"] + ".yaml"
        or type(configured_input) is not dict
        or set(configured_input) != {"content_sha256", "path", "raw_b64", "scenario"}
        or {key: configured_input[key] for key in reference} != reference
        or type(configured_input["raw_b64"]) is not str
        or type(configuration["invocation_commitment"]) is not str
        or len(configuration["invocation_commitment"]) != 64
        or any(
            character not in "0123456789abcdef"
            for character in configuration["invocation_commitment"]
        )
        or configuration["invocation_commitment"] != sha256(
            json.dumps(
                invocation,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
    ):
        raise ValueError("invalid-child-configuration")
    scenario_raw = base64.b64decode(configured_input["raw_b64"], validate=True)
    if (
        not 1 <= len(scenario_raw) <= 65536
        or sha256(scenario_raw).hexdigest() != reference["content_sha256"]
    ):
        raise ValueError("invalid-child-configuration")
    scenario_input = ScenarioInput(
        normalized_name=reference["path"],
        raw=scenario_raw,
        device=0,
        inode=1,
    )
    result = ScenarioRunner().run(scenario_input)
    envelope = {
        "document": result.to_mapping(),
        "input_reference": reference,
        "invocation_commitment": configuration["invocation_commitment"],
        "nonce": nonce,
        "schema_version": "simulation_supervisor_envelope.v1",
    }
    sys.stdout.write(
        json.dumps(
            envelope,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\\n"
    )
    sys.stdout.flush()
    while True:
        signal.pause()
except ImportError:
    raise SystemExit(3)
except BaseException:
    raise SystemExit(2)
"""


@dataclass(frozen=True, slots=True)
class _PreparedSimulationInvocation:
    input_reference: dict[str, str]
    invocation: dict[str, Any]
    invocation_commitment: str
    raw: bytes


@dataclass(frozen=True, slots=True)
class _RuntimeLayout:
    root_descriptor: int
    workspace_descriptors: tuple[int, ...]
    site_packages_descriptor: int
    script_descriptor: int | None
    descriptors: tuple[int, ...]
    manifest_b64: str
    executable: Path
    executable_identity: tuple[int, int, int, int, int, int]


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
    maximum: int = _MAX_SIMULATION_OUTPUT_BYTES,
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


def _validate_path_part(part: str) -> str:
    if (
        not part
        or part in {".", ".."}
        or part != unicodedata.normalize("NFC", part)
        or len(part.encode("utf-8")) > 255
        or any(ord(character) < 32 or ord(character) == 127 for character in part)
    ):
        raise ValueError("invalid-scenario-input")
    return part


def _relative_path_parts(path: Path, trusted_root: Path) -> tuple[str, ...]:
    if not trusted_root.is_absolute():
        raise ValueError("invalid-scenario-input")
    if path.is_absolute():
        try:
            relative = path.relative_to(trusted_root)
        except ValueError as error:
            raise ValueError("invalid-scenario-input") from error
    else:
        relative = path
    parts = tuple(_validate_path_part(part) for part in relative.parts)
    if not parts or len("/".join(parts).encode("utf-8")) > 4_096:
        raise ValueError("invalid-scenario-input")
    return parts


def _open_trusted_root(trusted_root: Path) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for part in trusted_root.parts[1:]:
            next_descriptor = os.open(_validate_path_part(part), flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_exact(descriptor: int, size: int) -> bytes:
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
            raise ValueError("invalid-scenario-input")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise ValueError("invalid-scenario-input")
    return b"".join(chunks)


def _stable_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _snapshot_scenario(path: Path, trusted_root: Path) -> tuple[str, bytes]:
    root_descriptor = -1
    descriptor = -1
    try:
        parts = _relative_path_parts(path, trusted_root)
        root_descriptor = _open_trusted_root(trusted_root)
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        for part in parts[:-1]:
            next_descriptor = os.open(part, directory_flags, dir_fd=root_descriptor)
            os.close(root_descriptor)
            root_descriptor = next_descriptor
        name = parts[-1]
        if not name.endswith(".yaml"):
            raise ValueError("invalid-scenario-input")
        before_path = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=root_descriptor,
        )
        before_fd = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before_fd.st_mode)
            or before_fd.st_nlink != 1
            or not 1 <= before_fd.st_size <= 65_536
            or _stable_identity(before_path) != _stable_identity(before_fd)
        ):
            raise ValueError("invalid-scenario-input")
        raw = _read_exact(descriptor, before_fd.st_size)
        after_fd = os.fstat(descriptor)
        after_path = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
        if (
            _stable_identity(before_fd) != _stable_identity(after_fd)
            or _stable_identity(before_fd) != _stable_identity(after_path)
            or after_fd.st_nlink != 1
        ):
            raise ValueError("invalid-scenario-input")
        return "/".join(parts), raw
    except (OSError, UnicodeError) as error:
        raise ValueError("invalid-scenario-input") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if root_descriptor >= 0:
            os.close(root_descriptor)


def _runtime_identity(value: os.stat_result) -> tuple[int, int, int, int]:
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
    path = Path(relative)
    parts = tuple(_validate_path_part(part) for part in path.parts)
    if path.is_absolute() or not parts or "/".join(parts) != relative:
        raise ValueError("invalid-runtime-path")
    descriptor = os.dup(root_descriptor)
    try:
        for index, part in enumerate(parts):
            terminal = index == len(parts) - 1
            flags = os.O_RDONLY | os.O_NOFOLLOW
            if not terminal or directory:
                flags |= os.O_DIRECTORY
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            try:
                _require_runtime_node(
                    os.fstat(next_descriptor),
                    directory=not terminal or directory,
                )
            except BaseException:
                with suppress(OSError):
                    os.close(next_descriptor)
                raise
            previous_descriptor = descriptor
            descriptor = next_descriptor
            os.close(previous_descriptor)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _validate_runtime_executable(
    code_root: Path,
    executable: str,
) -> tuple[Path, tuple[int, int, int, int, int, int]]:
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
    return executable_path, _stable_identity(resolved_stat)


def _open_runtime_layout(
    code_root: Path,
    executable: str,
    *,
    script_relative: str | None,
) -> _RuntimeLayout:
    descriptors: list[int] = []

    def remember(descriptor: int) -> int:
        try:
            descriptors.append(descriptor)
        except BaseException:
            with suppress(OSError):
                os.close(descriptor)
            raise
        return descriptor

    try:
        if not code_root.is_absolute():
            raise ValueError("invalid-runtime-path")
        root_descriptor = remember(_open_trusted_root(code_root))
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
            remember(_open_runtime_relative(root_descriptor, relative, directory=True))
            for relative in workspace_relative
        )
        site_relative = (
            f".venv/lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages"
        )
        site_packages_descriptor = remember(
            _open_runtime_relative(
                root_descriptor,
                site_relative,
                directory=True,
            )
        )
        script_descriptor = (
            None
            if script_relative is None
            else remember(_open_runtime_relative(root_descriptor, script_relative, directory=False))
        )
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


def _prepare_simulation_invocation(
    scenario: Path,
    *,
    json_output: bool,
    repository_root: Path,
) -> _PreparedSimulationInvocation:
    normalized_path, raw = _snapshot_scenario(scenario, repository_root)
    scenario_name = normalized_path.rsplit("/", 1)[-1].removesuffix(".yaml")
    if _SCENARIO_NAME_PATTERN.fullmatch(scenario_name) is None:
        raise ValueError("invalid-scenario-input")
    reference = {
        "content_sha256": sha256(raw).hexdigest(),
        "path": normalized_path,
        "scenario": scenario_name,
    }
    invocation: dict[str, Any] = {
        "input": reference,
        "json_output": json_output,
        "schema_version": "simulation_invocation.v1",
    }
    return _PreparedSimulationInvocation(
        input_reference=reference,
        invocation=invocation,
        invocation_commitment=sha256(_canonical_bytes(invocation)).hexdigest(),
        raw=raw,
    )


def _valid_text(value: Any, *, maximum: int, prefix: str | None = None) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= maximum
        and len(value.encode("utf-8")) <= maximum * 4
        and value == unicodedata.normalize("NFC", value)
        and value.isprintable()
        and (prefix is None or value.startswith(prefix))
    )


def _valid_uuid(value: Any) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _valid_usage(value: Any) -> bool:
    keys = {
        "input_audio_bytes",
        "output_audio_bytes",
        "response_characters",
        "transcript_characters",
    }
    return (
        type(value) is dict
        and set(value) == keys
        and all(type(value[key]) is int and 0 <= value[key] <= 1_000_000 for key in keys)
    )


def _valid_simulation_document(
    value: Any,
    prepared: _PreparedSimulationInvocation,
) -> bool:
    if type(value) is not dict:
        return False
    keys = {
        "audit_receipt_ids",
        "events",
        "identity",
        "language",
        "outcome",
        "response",
        "scenario",
        "schema_version",
        "transcript",
        "turn_id",
        "turn_index",
        "usage",
    }
    audit_ids = value.get("audit_receipt_ids")
    events = value.get("events")
    scenario = value.get("scenario")
    return not (
        set(value) != keys
        or value["schema_version"] != "scenario_result.v1"
        or type(scenario) is not str
        or _SCENARIO_NAME_PATTERN.fullmatch(scenario) is None
        or scenario != prepared.input_reference["scenario"]
        or value["identity"] != "guest"
        or value["language"] not in {"en", "hi", "hinglish"}
        or value["outcome"] != "completed"
        or not _valid_text(value["transcript"], maximum=256, prefix="synthetic-")
        or not _valid_text(value["response"], maximum=256, prefix="synthetic-")
        or type(value["turn_index"]) is not int
        or value["turn_index"] != 0
        or not _valid_uuid(value["turn_id"])
        or type(audit_ids) is not list
        or not 1 <= len(audit_ids) <= 16
        or not all(_valid_uuid(item) for item in audit_ids)
        or type(events) is not list
        or not 1 <= len(events) <= 64
        or not all(type(item) is str and _EVENT_PATTERN.fullmatch(item) for item in events)
        or not _valid_usage(value["usage"])
    )


def _validated_simulation_envelope(
    raw: bytes,
    prepared: _PreparedSimulationInvocation,
    nonce: str,
    *,
    json_output: bool,
) -> bytes:
    envelope = _canonical_json_object(raw)
    if (
        set(envelope)
        != {
            "document",
            "input_reference",
            "invocation_commitment",
            "nonce",
            "schema_version",
        }
        or envelope["schema_version"] != "simulation_supervisor_envelope.v1"
        or envelope["nonce"] != nonce
        or envelope["invocation_commitment"] != prepared.invocation_commitment
        or envelope["input_reference"] != prepared.input_reference
        or not _valid_simulation_document(envelope["document"], prepared)
    ):
        raise ValueError("invalid-child-output")
    if json_output:
        return _canonical_bytes(envelope["document"]) + b"\n"
    return b"simulation: PASS\n"


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
        if len(payload) > _MAX_SIMULATION_CONFIGURATION_BYTES:
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
        runtime_deadline = time.monotonic() + _SIMULATION_TIMEOUT_SECONDS
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
                if (
                    stdout_size > _MAX_SIMULATION_OUTPUT_BYTES
                    or stderr_size > _MAX_SIMULATION_OUTPUT_BYTES
                ):
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
                    raise subprocess.TimeoutExpired(command, _SIMULATION_TIMEOUT_SECONDS)
                time.sleep(min(_SIMULATION_POLL_SECONDS, remaining))
        finally:
            cleanup_started = time.monotonic()
            try:
                if worker_pid is None:
                    os.close(shutdown_write)
                    _force_process_group_cleanup(
                        process,
                        deadline=cleanup_started + _SIMULATION_CLEANUP_SECONDS,
                    )
                else:
                    supervisor_returncode = _shutdown_supervised_process(
                        process,
                        nonce=supervision_nonce,
                        worker_pid=worker_pid,
                        shutdown_descriptor=shutdown_write,
                        acknowledgement_descriptor=acknowledgement_read,
                        acknowledgement_buffer=acknowledgement_buffer,
                        deadline=cleanup_started + (_SIMULATION_CLEANUP_SECONDS / 2),
                    )
            except BaseException:
                with suppress(OSError):
                    os.close(shutdown_write)
                _force_process_group_cleanup(
                    process,
                    deadline=cleanup_started + _SIMULATION_CLEANUP_SECONDS,
                )
                raise
            finally:
                with suppress(OSError):
                    os.close(acknowledgement_read)
        if supervisor_returncode not in (None, 0):
            raise RuntimeError("supervisor-shutdown-failed")
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read(_MAX_SIMULATION_OUTPUT_BYTES + 1)
        stderr = stderr_file.read(_MAX_SIMULATION_OUTPUT_BYTES + 1)
    if len(stdout) > _MAX_SIMULATION_OUTPUT_BYTES or len(stderr) > _MAX_SIMULATION_OUTPUT_BYTES:
        raise ValueError("child-output-limit-exceeded")
    return subprocess.CompletedProcess(
        command,
        0 if completed_frame else 1,
        stdout,
        stderr,
    )


def _run_simulation_child(
    *,
    repository_root: Path,
    configuration: bytes,
) -> subprocess.CompletedProcess[bytes]:
    if len(configuration) > _MAX_SIMULATION_CONFIGURATION_BYTES:
        raise ValueError("child-configuration-limit-exceeded")
    configuration_value = _canonical_json_object(
        configuration + b"\n",
        maximum=_MAX_SIMULATION_CONFIGURATION_BYTES + 1,
    )
    nonce = configuration_value.get("nonce")
    if type(nonce) is not str or _DIGEST_PATTERN.fullmatch(nonce) is None:
        raise ValueError("invalid-child-configuration")
    layout = _open_runtime_layout(
        repository_root,
        sys.executable,
        script_relative=None,
    )
    try:
        _revalidate_runtime_executable(layout)
        return _run_bounded_process(
            (
                str(layout.executable),
                "-I",
                "-S",
                "-c",
                _SIMULATE_BOOTSTRAP + _SIMULATE_CHILD_CODE,
                nonce,
                str(_MAX_SIMULATION_OUTPUT_BYTES),
                layout.manifest_b64,
            ),
            payload=configuration,
            cwd=repository_root,
            environment={},
            supervision_nonce=nonce,
            inherited_descriptors=layout.descriptors,
        )
    finally:
        _close_runtime_layout(layout)


def simulate(
    scenario: Annotated[Path, typer.Option("--scenario")],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run a synthetic scenario; the installed CLI requires a trusted Python environment."""
    try:
        simulation_available = importlib.util.find_spec("tuntun_testing") is not None
    except BaseException:
        typer.echo("simulation-invalid-input", err=True)
        raise typer.Exit(2) from None
    if not simulation_available:
        typer.echo("simulation-extra-required", err=True)
        raise typer.Exit(2) from None
    repository_root = Path(__file__).absolute().parents[6]
    try:
        prepared = _prepare_simulation_invocation(
            scenario,
            json_output=json_output,
            repository_root=repository_root,
        )
        nonce = os.urandom(32).hex()
        configuration = {
            "input": {
                **prepared.input_reference,
                "raw_b64": base64.b64encode(prepared.raw).decode("ascii"),
            },
            "invocation": prepared.invocation,
            "invocation_commitment": prepared.invocation_commitment,
            "nonce": nonce,
            "schema_version": "simulation_child_config.v1",
        }
        result = _run_simulation_child(
            repository_root=repository_root,
            configuration=_canonical_bytes(configuration),
        )
        if result.returncode == 0 and result.stderr == b"":
            output = _validated_simulation_envelope(
                result.stdout,
                prepared,
                nonce,
                json_output=json_output,
            )
        else:
            output = None
    except BaseException:
        typer.echo("simulation-invalid-input", err=True)
        raise typer.Exit(2) from None
    if output is not None:
        typer.echo(output.decode("utf-8"), nl=False)
        return
    if result.stdout == b"" and result.stderr == b"simulation-extra-required\n":
        typer.echo("simulation-extra-required", err=True)
        raise typer.Exit(2) from None
    typer.echo("simulation-invalid-input", err=True)
    raise typer.Exit(2) from None
